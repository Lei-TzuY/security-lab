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
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::ptr;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;

    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const FIRST_NON_STDIO_FD: libc::c_uint = 3;

    const PHASE_CHDIR: u32 = 1;
    const PHASE_FD_SANITIZE: u32 = 2;
    const PHASE_RLIMIT_CPU: u32 = 3;
    const PHASE_RLIMIT_AS: u32 = 4;
    const PHASE_RLIMIT_FSIZE: u32 = 5;
    const PHASE_RLIMIT_NOFILE: u32 = 6;
    const PHASE_NO_NEW_PRIVS: u32 = 7;
    const PHASE_SECCOMP: u32 = 8;
    const PHASE_EXECVE: u32 = 9;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LaunchErrorRecord {
        errno: i32,
        phase: u32,
    }

    struct SharedLaunchState {
        record: *mut LaunchErrorRecord,
    }

    impl SharedLaunchState {
        fn new() -> Result<Self, SandboxError> {
            let length = std::mem::size_of::<LaunchErrorRecord>();
            let mapping = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                return Err(SandboxError::SetupFailed(format!(
                    "cannot allocate shared launch state: {}",
                    io::Error::last_os_error()
                )));
            }

            let record = mapping.cast::<LaunchErrorRecord>();
            unsafe {
                ptr::write_volatile(
                    record,
                    LaunchErrorRecord {
                        errno: 0,
                        phase: 0,
                    },
                );
            }
            Ok(Self { record })
        }

        fn snapshot(&self) -> LaunchErrorRecord {
            unsafe { ptr::read_volatile(self.record) }
        }
    }

    impl Drop for SharedLaunchState {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(
                    self.record.cast::<libc::c_void>(),
                    std::mem::size_of::<LaunchErrorRecord>(),
                );
            }
        }
    }

    struct PreparedLaunch {
        executable: CString,
        working_dir: CString,
        _args: Vec<CString>,
        _environment: Vec<CString>,
        argv: Vec<*const libc::c_char>,
        envp: Vec<*const libc::c_char>,
    }

    impl PreparedLaunch {
        fn new(policy: &SandboxPolicy) -> Result<Self, SandboxError> {
            let executable = cstring_bytes(
                "executable",
                policy.executable.as_os_str().as_bytes(),
            )?;
            let working_dir = cstring_bytes(
                "working_dir",
                policy.working_dir.as_os_str().as_bytes(),
            )?;

            let mut args = Vec::with_capacity(policy.args.len());
            for arg in &policy.args {
                args.push(cstring_bytes("argument", arg.as_bytes())?);
            }

            let mut environment = Vec::with_capacity(policy.environment.len());
            for (key, value) in &policy.environment {
                let entry = format!("{key}={value}");
                environment.push(cstring_bytes("environment entry", entry.as_bytes())?);
            }

            let mut argv = Vec::with_capacity(args.len() + 2);
            argv.push(executable.as_ptr());
            argv.extend(args.iter().map(|arg| arg.as_ptr()));
            argv.push(ptr::null());

            let mut envp = Vec::with_capacity(environment.len() + 1);
            envp.extend(environment.iter().map(|entry| entry.as_ptr()));
            envp.push(ptr::null());

            Ok(Self {
                executable,
                working_dir,
                _args: args,
                _environment: environment,
                argv,
                envp,
            })
        }
    }

    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    pub(crate) fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
        preflight(policy)?;
        let prepared = PreparedLaunch::new(policy)?;
        let seccomp = compile_seccomp(policy)?;
        let launch_state = SharedLaunchState::new()?;

        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "fork failed closed: {}",
                io::Error::last_os_error()
            )));
        }

        if pid == 0 {
            unsafe {
                child_exec(
                    &prepared,
                    policy.limits,
                    &seccomp,
                    launch_state.record,
                )
            }
        }

        let status = wait_for_child(pid)?;
        let launch_error = launch_state.snapshot();
        if launch_error.phase != 0 {
            return Err(SandboxError::SetupFailed(format_launch_error(launch_error)));
        }

        decode_wait_status(status)
    }

    fn cstring_bytes(label: &str, bytes: &[u8]) -> Result<CString, SandboxError> {
        CString::new(bytes).map_err(|_| {
            SandboxError::InvalidPolicy(PolicyError::new(format!(
                "{label} must not contain NUL bytes"
            )))
        })
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

    fn compile_seccomp(policy: &SandboxPolicy) -> Result<CompiledSeccomp, SandboxError> {
        let error_exit_syscall = if policy.seccomp.allowed_syscalls.contains("exit") {
            libc::SYS_exit
        } else if policy.seccomp.allowed_syscalls.contains("exit_group") {
            libc::SYS_exit_group
        } else {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include exit or exit_group so launch failures can terminate after filter installation",
            )));
        };

        if !policy.seccomp.allowed_syscalls.contains("execve") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execve so the requested child can start",
            )));
        }

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

        if filter.len() > u16::MAX as usize {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp program is too large",
            )));
        }

        Ok(CompiledSeccomp {
            filter,
            error_exit_syscall,
        })
    }

    unsafe fn child_exec(
        prepared: &PreparedLaunch,
        limits: ResourceLimits,
        seccomp: &CompiledSeccomp,
        launch_error: *mut LaunchErrorRecord,
    ) -> ! {
        if libc::chdir(prepared.working_dir.as_ptr()) == -1 {
            child_fail(launch_error, PHASE_CHDIR, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_close_range,
            FIRST_NON_STDIO_FD,
            u32::MAX,
            CLOSE_RANGE_CLOEXEC,
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_FD_SANITIZE,
                seccomp.error_exit_syscall,
            );
        }

        set_limit_or_fail(
            libc::RLIMIT_CPU,
            limits.cpu_seconds,
            launch_error,
            PHASE_RLIMIT_CPU,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_AS,
            limits.address_space_bytes,
            launch_error,
            PHASE_RLIMIT_AS,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_FSIZE,
            limits.file_size_bytes,
            launch_error,
            PHASE_RLIMIT_FSIZE,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_NOFILE,
            limits.open_files,
            launch_error,
            PHASE_RLIMIT_NOFILE,
            seccomp.error_exit_syscall,
        );

        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            child_fail(
                launch_error,
                PHASE_NO_NEW_PRIVS,
                seccomp.error_exit_syscall,
            );
        }

        let program = libc::sock_fprog {
            len: seccomp.filter.len() as u16,
            filter: seccomp.filter.as_ptr() as *mut libc::sock_filter,
        };
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        ) == -1
        {
            child_fail(launch_error, PHASE_SECCOMP, seccomp.error_exit_syscall);
        }

        libc::execve(
            prepared.executable.as_ptr(),
            prepared.argv.as_ptr(),
            prepared.envp.as_ptr(),
        );
        child_fail(launch_error, PHASE_EXECVE, seccomp.error_exit_syscall)
    }

    unsafe fn set_limit_or_fail(
        resource: libc::c_uint,
        value: u64,
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) {
        let limit = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        if libc::setrlimit(resource as _, &limit) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
    }

    unsafe fn child_fail(
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) -> ! {
        let errno = *libc::__errno_location();
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).errno), errno);
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).phase), phase);

        loop {
            libc::syscall(error_exit_syscall, 127 as libc::c_int);
        }
    }

    fn wait_for_child(pid: libc::pid_t) -> Result<libc::c_int, SandboxError> {
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(status);
            }
            if result == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!(
                    "waitpid failed: {err}"
                )));
            }
        }
    }

    fn decode_wait_status(status: libc::c_int) -> Result<ChildOutcome, SandboxError> {
        if libc::WIFEXITED(status) {
            Ok(ChildOutcome::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Ok(ChildOutcome::Signaled(libc::WTERMSIG(status)))
        } else {
            Err(SandboxError::SetupFailed(format!(
                "child returned unsupported wait status 0x{status:x}"
            )))
        }
    }

    fn format_launch_error(record: LaunchErrorRecord) -> String {
        let phase = match record.phase {
            PHASE_CHDIR => "chdir",
            PHASE_FD_SANITIZE => "inherited-FD sanitization",
            PHASE_RLIMIT_CPU => "RLIMIT_CPU",
            PHASE_RLIMIT_AS => "RLIMIT_AS",
            PHASE_RLIMIT_FSIZE => "RLIMIT_FSIZE",
            PHASE_RLIMIT_NOFILE => "RLIMIT_NOFILE",
            PHASE_NO_NEW_PRIVS => "PR_SET_NO_NEW_PRIVS",
            PHASE_SECCOMP => "seccomp installation",
            PHASE_EXECVE => "execve",
            _ => "unknown launch phase",
        };
        let errno = if record.errno == 0 {
            libc::EIO
        } else {
            record.errno
        };
        format!(
            "child {phase} failed closed: {}",
            io::Error::from_raw_os_error(errno)
        )
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
