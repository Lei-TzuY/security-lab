#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn run(
    _policy: &crate::SandboxPolicy,
) -> Result<crate::ChildOutcome, crate::SandboxError> {
    Err(crate::SandboxError::UnsupportedPlatform(
        "sandbox enforcement currently supports Linux x86_64 only".to_owned(),
    ))
}

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use crate::{ChildOutcome, PolicyError, ResourceLimits, SandboxError, SandboxPolicy};
    use std::fs;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;

    // Linux UAPI CLOSE_RANGE_CLOEXEC. Defining the flag locally keeps the
    // enforcement contract explicit instead of depending on libc exposing a
    // particular header version.
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const FIRST_NON_STDIO_FD: libc::c_uint = 3;

    pub(crate) fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
        preflight(policy)?;
        let limits = policy.limits;
        let filter = compile_seccomp(policy)?;

        let mut command = Command::new(&policy.executable);
        command
            .args(&policy.args)
            .env_clear()
            .envs(&policy.environment)
            .current_dir(&policy.working_dir);

        // SAFETY: the closure performs only direct libc syscalls and accesses
        // data prepared in the parent. Descriptor sanitization uses CLOEXEC
        // rather than closing descriptors immediately so std::process::Command's
        // private child-error pipe remains usable until a successful exec.
        // No fallback path exists if any step fails: Command::spawn returns the
        // pre-exec error to the parent.
        unsafe {
            command.pre_exec(move || {
                sanitize_inherited_fds()?;
                apply_resource_limits(limits)?;
                apply_no_new_privs()?;
                install_seccomp(&filter)?;
                Ok(())
            });
        }

        let status = command
            .status()
            .map_err(|err| SandboxError::SetupFailed(format!("launch failed closed: {err}")))?;

        if let Some(code) = status.code() {
            Ok(ChildOutcome::Exited(code))
        } else if let Some(signal) = status.signal() {
            Ok(ChildOutcome::Signaled(signal))
        } else {
            Err(SandboxError::SetupFailed(
                "child returned neither an exit code nor a signal".to_owned(),
            ))
        }
    }

    fn preflight(policy: &SandboxPolicy) -> Result<(), SandboxError> {
        let executable = fs::metadata(&policy.executable).map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot inspect executable {}: {err}",
                policy.executable.display()
            ))
        })?;
        if !executable.is_file() {
            return Err(SandboxError::SetupFailed(format!(
                "executable is not a regular file: {}",
                policy.executable.display()
            )));
        }
        if executable.permissions().mode() & 0o111 == 0 {
            return Err(SandboxError::SetupFailed(format!(
                "executable has no execute bit: {}",
                policy.executable.display()
            )));
        }

        let working_dir = fs::metadata(&policy.working_dir).map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot inspect working directory {}: {err}",
                policy.working_dir.display()
            ))
        })?;
        if !working_dir.is_dir() {
            return Err(SandboxError::SetupFailed(format!(
                "working_dir is not a directory: {}",
                policy.working_dir.display()
            )));
        }

        ensure_fd_sanitization_supported()?;
        Ok(())
    }

    fn ensure_fd_sanitization_supported() -> Result<(), SandboxError> {
        // Probe a range that cannot contain a normal userspace descriptor. A
        // supporting kernel returns success without changing process state.
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                u32::MAX,
                u32::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if result == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => Err(SandboxError::UnsupportedPlatform(
                format!(
                    "inherited-FD sanitization requires close_range(CLOSE_RANGE_CLOEXEC) support: {err}"
                ),
            )),
            _ => Err(SandboxError::SetupFailed(format!(
                "cannot verify inherited-FD sanitization support: {err}"
            ))),
        }
    }

    fn compile_seccomp(policy: &SandboxPolicy) -> Result<Vec<libc::sock_filter>, SandboxError> {
        let mut numbers = Vec::with_capacity(policy.seccomp.allowed_syscalls.len());
        for name in &policy.seccomp.allowed_syscalls {
            let number = syscall_number(name).ok_or_else(|| {
                SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "unsupported Linux x86_64 syscall name: {name}"
                )))
            })?;
            numbers.push(number as u32);
        }
        numbers.sort_unstable();
        numbers.dedup();

        if !policy.seccomp.allowed_syscalls.contains("execve") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execve so the requested child can start",
            )));
        }

        // seccomp_data offsets are stable UAPI: nr @ 0, arch @ 4.
        let mut filter = Vec::with_capacity(5 + numbers.len() * 2);
        filter.push(stmt(BPF_LD_W_ABS, 4));
        filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(stmt(BPF_LD_W_ABS, 0));
        for number in numbers {
            filter.push(jump(BPF_JMP_JEQ_K, number, 0, 1));
            filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        }
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
        Ok(filter)
    }

    unsafe fn sanitize_inherited_fds() -> io::Result<()> {
        // Mark every non-stdio descriptor CLOEXEC atomically in the child. The
        // descriptors remain open during pre-exec setup, which preserves the
        // standard library's setup-error transport, but none survive a
        // successful exec into the target image.
        if libc::syscall(
            libc::SYS_close_range,
            FIRST_NON_STDIO_FD,
            u32::MAX,
            CLOSE_RANGE_CLOEXEC,
        ) == -1
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    unsafe fn apply_resource_limits(limits: ResourceLimits) -> io::Result<()> {
        set_limit(libc::RLIMIT_CPU, limits.cpu_seconds)?;
        set_limit(libc::RLIMIT_AS, limits.address_space_bytes)?;
        set_limit(libc::RLIMIT_FSIZE, limits.file_size_bytes)?;
        set_limit(libc::RLIMIT_NOFILE, limits.open_files)?;
        Ok(())
    }

    unsafe fn set_limit(resource: libc::c_uint, value: u64) -> io::Result<()> {
        let limit = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        if libc::setrlimit(resource as _, &limit) == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    unsafe fn apply_no_new_privs() -> io::Result<()> {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    unsafe fn install_seccomp(filter: &[libc::sock_filter]) -> io::Result<()> {
        if filter.len() > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seccomp program is too large",
            ));
        }
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        ) == -1
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    const fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn syscall_number(name: &str) -> Option<libc::c_long> {
        Some(match name {
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "close" => libc::SYS_close,
            "fstat" => libc::SYS_fstat,
            "lseek" => libc::SYS_lseek,
            "mmap" => libc::SYS_mmap,
            "mprotect" => libc::SYS_mprotect,
            "munmap" => libc::SYS_munmap,
            "brk" => libc::SYS_brk,
            "rt_sigaction" => libc::SYS_rt_sigaction,
            "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
            "rt_sigreturn" => libc::SYS_rt_sigreturn,
            "ioctl" => libc::SYS_ioctl,
            "pread64" => libc::SYS_pread64,
            "access" => libc::SYS_access,
            "mremap" => libc::SYS_mremap,
            "madvise" => libc::SYS_madvise,
            "getpid" => libc::SYS_getpid,
            "sched_yield" => libc::SYS_sched_yield,
            "nanosleep" => libc::SYS_nanosleep,
            "getuid" => libc::SYS_getuid,
            "getgid" => libc::SYS_getgid,
            "geteuid" => libc::SYS_geteuid,
            "getegid" => libc::SYS_getegid,
            "fcntl" => libc::SYS_fcntl,
            "getcwd" => libc::SYS_getcwd,
            "readlink" => libc::SYS_readlink,
            "sigaltstack" => libc::SYS_sigaltstack,
            "arch_prctl" => libc::SYS_arch_prctl,
            "gettid" => libc::SYS_gettid,
            "futex" => libc::SYS_futex,
            "sched_getaffinity" => libc::SYS_sched_getaffinity,
            "set_tid_address" => libc::SYS_set_tid_address,
            "exit" => libc::SYS_exit,
            "tgkill" => libc::SYS_tgkill,
            "openat" => libc::SYS_openat,
            "newfstatat" => libc::SYS_newfstatat,
            "set_robust_list" => libc::SYS_set_robust_list,
            "prlimit64" => libc::SYS_prlimit64,
            "getrandom" => libc::SYS_getrandom,
            "execve" => libc::SYS_execve,
            "exit_group" => libc::SYS_exit_group,
            "statx" => libc::SYS_statx,
            "rseq" => libc::SYS_rseq,
            "prctl" => libc::SYS_prctl,
            "clock_gettime" => libc::SYS_clock_gettime,
            "uname" => libc::SYS_uname,
            "readlinkat" => libc::SYS_readlinkat,
            _ => return None,
        })
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::run;
