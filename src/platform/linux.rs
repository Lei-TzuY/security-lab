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
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;
    use std::path::{Path, PathBuf};
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

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const AT_EMPTY_PATH: libc::c_int = 0x1000;

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAPBSET_DROP: libc::c_int = 24;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    const PHASE_NAMESPACE: u32 = 1;
    const PHASE_SETGROUPS: u32 = 2;
    const PHASE_UID_MAP: u32 = 3;
    const PHASE_GID_MAP: u32 = 4;
    const PHASE_MOUNT_PRIVATE: u32 = 5;
    const PHASE_STDIO: u32 = 6;
    const PHASE_ROOT_FCHDIR: u32 = 7;
    const PHASE_CHROOT: u32 = 8;
    const PHASE_CWD_FCHDIR: u32 = 9;
    const PHASE_FD_SANITIZE: u32 = 10;
    const PHASE_RLIMIT_CPU: u32 = 11;
    const PHASE_RLIMIT_AS: u32 = 12;
    const PHASE_RLIMIT_FSIZE: u32 = 13;
    const PHASE_RLIMIT_NOFILE: u32 = 14;
    const PHASE_CAP_BOUNDING: u32 = 15;
    const PHASE_CAP_AMBIENT: u32 = 16;
    const PHASE_CAP_CURRENT: u32 = 17;
    const PHASE_NO_NEW_PRIVS: u32 = 18;
    const PHASE_SECCOMP: u32 = 19;
    const PHASE_EXECVEAT: u32 = 20;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct LaunchErrorRecord {
        errno: i32,
        phase: u32,
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    struct OwnedFd(RawFd);

    impl OwnedFd {
        fn raw(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
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
                ptr::write_volatile(record, LaunchErrorRecord { errno: 0, phase: 0 });
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
        root_fd: OwnedFd,
        cwd_fd: OwnedFd,
        executable_fd: OwnedFd,
        _argv0: CString,
        _args: Vec<CString>,
        _environment: Vec<CString>,
        argv: Vec<*const libc::c_char>,
        envp: Vec<*const libc::c_char>,
        uid_map: Vec<u8>,
        gid_map: Vec<u8>,
    }

    impl PreparedLaunch {
        fn new(policy: &SandboxPolicy) -> Result<Self, SandboxError> {
            let root_fd = open_root(&policy.root_dir)?;
            let cwd_fd = open_beneath_root(
                root_fd.raw(),
                &policy.working_dir,
                (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                "working directory",
            )?;
            let executable_fd = open_beneath_root(
                root_fd.raw(),
                &policy.executable,
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                "executable",
            )?;
            validate_executable_fd(executable_fd.raw(), &policy.executable)?;

            let argv0 = cstring_bytes("executable", policy.executable.as_os_str().as_bytes())?;
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
            argv.push(argv0.as_ptr());
            argv.extend(args.iter().map(|arg| arg.as_ptr()));
            argv.push(ptr::null());

            let mut envp = Vec::with_capacity(environment.len() + 1);
            envp.extend(environment.iter().map(|entry| entry.as_ptr()));
            envp.push(ptr::null());

            let uid_map = format!("0 {} 1\n", unsafe { libc::geteuid() }).into_bytes();
            let gid_map = format!("0 {} 1\n", unsafe { libc::getegid() }).into_bytes();

            Ok(Self {
                root_fd,
                cwd_fd,
                executable_fd,
                _argv0: argv0,
                _args: args,
                _environment: environment,
                argv,
                envp,
                uid_map,
                gid_map,
            })
        }
    }

    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    pub(crate) fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
        ensure_fd_sanitization_supported()?;
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
            unsafe { child_exec(&prepared, policy.limits, &seccomp, launch_state.record) }
        }

        let status = wait_for_child(pid)?;
        let launch_error = launch_state.snapshot();
        if launch_error.phase != 0 {
            return decode_launch_error(launch_error);
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

    fn sandbox_relative(path: &Path) -> Result<CString, SandboxError> {
        let relative = path.strip_prefix(Path::new("/")).map_err(|_| {
            SandboxError::InvalidPolicy(PolicyError::new("sandbox paths must be absolute"))
        })?;
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative.to_path_buf()
        };
        cstring_bytes("sandbox path", relative.as_os_str().as_bytes())
    }

    fn open_root(path: &Path) -> Result<OwnedFd, SandboxError> {
        let path = cstring_bytes("filesystem.root", path.as_os_str().as_bytes())?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        match openat2(libc::AT_FDCWD, &path, &how) {
            Ok(fd) => Ok(OwnedFd(fd)),
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) => {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "filesystem confinement requires Linux openat2 support: {err}"
                )))
            }
            Err(err) => Err(SandboxError::SetupFailed(format!(
                "cannot pin filesystem.root without symlink traversal: {err}"
            ))),
        }
    }

    fn open_beneath_root(
        root_fd: RawFd,
        path: &Path,
        flags: u64,
        label: &str,
    ) -> Result<OwnedFd, SandboxError> {
        let path = sandbox_relative(path)?;
        let how = OpenHow {
            flags,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        openat2(root_fd, &path, &how).map(OwnedFd).map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot pin sandbox {label} beneath filesystem.root: {err}"
            ))
        })
    }

    fn openat2(dirfd: RawFd, path: &CString, how: &OpenHow) -> io::Result<RawFd> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as RawFd)
        }
    }

    fn validate_executable_fd(fd: RawFd, path: &Path) -> Result<(), SandboxError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut stat) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot inspect pinned executable {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SandboxError::SetupFailed(format!(
                "sandbox executable is not a regular file: {}",
                path.display()
            )));
        }
        if stat.st_mode & 0o111 == 0 {
            return Err(SandboxError::SetupFailed(format!(
                "sandbox executable has no execute bit: {}",
                path.display()
            )));
        }
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

        if !policy.seccomp.allowed_syscalls.contains("execveat") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execveat so the pinned child can start",
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
        if libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER | libc::CLONE_NEWNS) == -1 {
            child_fail(launch_error, PHASE_NAMESPACE, seccomp.error_exit_syscall);
        }

        write_proc_file_or_fail(
            b"/proc/self/setgroups\0",
            b"deny\n",
            launch_error,
            PHASE_SETGROUPS,
            seccomp.error_exit_syscall,
        );
        write_proc_file_or_fail(
            b"/proc/self/uid_map\0",
            &prepared.uid_map,
            launch_error,
            PHASE_UID_MAP,
            seccomp.error_exit_syscall,
        );
        write_proc_file_or_fail(
            b"/proc/self/gid_map\0",
            &prepared.gid_map,
            launch_error,
            PHASE_GID_MAP,
            seccomp.error_exit_syscall,
        );

        if libc::syscall(
            libc::SYS_mount,
            ptr::null::<libc::c_char>(),
            b"/\0".as_ptr().cast::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null::<libc::c_void>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_MOUNT_PRIVATE,
                seccomp.error_exit_syscall,
            );
        }

        reject_directory_stdio_or_fail(launch_error, seccomp.error_exit_syscall);

        if libc::syscall(libc::SYS_fchdir, prepared.root_fd.raw()) == -1 {
            child_fail(launch_error, PHASE_ROOT_FCHDIR, seccomp.error_exit_syscall);
        }
        if libc::syscall(libc::SYS_chroot, b".\0".as_ptr().cast::<libc::c_char>()) == -1 {
            child_fail(launch_error, PHASE_CHROOT, seccomp.error_exit_syscall);
        }
        if libc::syscall(libc::SYS_fchdir, prepared.cwd_fd.raw()) == -1 {
            child_fail(launch_error, PHASE_CWD_FCHDIR, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_close_range,
            FIRST_NON_STDIO_FD,
            u32::MAX,
            CLOSE_RANGE_CLOEXEC,
        ) == -1
        {
            child_fail(launch_error, PHASE_FD_SANITIZE, seccomp.error_exit_syscall);
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

        drop_capabilities_or_fail(launch_error, seccomp.error_exit_syscall);

        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);
        }

        let program = libc::sock_fprog {
            len: seccomp.filter.len() as u16,
            filter: seccomp.filter.as_ptr() as *mut libc::sock_filter,
        };
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
            0,
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_SECCOMP, seccomp.error_exit_syscall);
        }

        libc::syscall(
            libc::SYS_execveat,
            prepared.executable_fd.raw(),
            b"\0".as_ptr().cast::<libc::c_char>(),
            prepared.argv.as_ptr(),
            prepared.envp.as_ptr(),
            AT_EMPTY_PATH,
        );
        child_fail(launch_error, PHASE_EXECVEAT, seccomp.error_exit_syscall)
    }

    unsafe fn write_proc_file_or_fail(
        path: &'static [u8],
        data: &[u8],
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) {
        let fd = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr().cast::<libc::c_char>(),
            libc::O_WRONLY | libc::O_CLOEXEC,
            0,
        );
        if fd == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }

        let fd = fd as RawFd;
        let mut offset = 0usize;
        while offset < data.len() {
            let written = libc::syscall(
                libc::SYS_write,
                fd,
                data.as_ptr().add(offset),
                data.len() - offset,
            );
            if written == -1 {
                let errno = *libc::__errno_location();
                libc::syscall(libc::SYS_close, fd);
                child_fail_errno(launch_error, phase, errno, error_exit_syscall);
            }
            if written == 0 {
                libc::syscall(libc::SYS_close, fd);
                child_fail_errno(launch_error, phase, libc::EIO, error_exit_syscall);
            }
            offset += written as usize;
        }
        if libc::syscall(libc::SYS_close, fd) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
    }

    unsafe fn reject_directory_stdio_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        for fd in 0..=2 {
            let mut stat = std::mem::zeroed::<libc::stat>();
            if libc::fstat(fd, &mut stat) == -1 {
                let errno = *libc::__errno_location();
                if errno == libc::EBADF {
                    continue;
                }
                child_fail_errno(launch_error, PHASE_STDIO, errno, error_exit_syscall);
            }
            if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                child_fail_errno(launch_error, PHASE_STDIO, libc::EISDIR, error_exit_syscall);
            }
        }
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

    unsafe fn drop_capabilities_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        for capability in 0..=64u64 {
            if libc::syscall(libc::SYS_prctl, PR_CAPBSET_DROP, capability, 0, 0, 0) == -1 {
                let errno = *libc::__errno_location();
                if errno == libc::EINVAL {
                    break;
                }
                child_fail_errno(launch_error, PHASE_CAP_BOUNDING, errno, error_exit_syscall);
            }
        }

        if libc::syscall(
            libc::SYS_prctl,
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_CAP_AMBIENT, error_exit_syscall);
        }

        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapabilityHeader,
            data.as_ptr(),
        ) == -1
        {
            child_fail(launch_error, PHASE_CAP_CURRENT, error_exit_syscall);
        }
    }

    unsafe fn child_fail(
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) -> ! {
        child_fail_errno(
            launch_error,
            phase,
            *libc::__errno_location(),
            error_exit_syscall,
        )
    }

    unsafe fn child_fail_errno(
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        errno: i32,
        error_exit_syscall: libc::c_long,
    ) -> ! {
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).errno), errno);
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).phase), phase);

        loop {
            libc::syscall(error_exit_syscall, 127);
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
                return Err(SandboxError::SetupFailed(format!("waitpid failed: {err}")));
            }
        }
    }

    fn decode_launch_error(record: LaunchErrorRecord) -> Result<ChildOutcome, SandboxError> {
        let message = format_launch_error(record);
        if record.phase == PHASE_NAMESPACE
            && matches!(record.errno, libc::EPERM | libc::EACCES | libc::ENOSYS)
        {
            Err(SandboxError::UnsupportedPlatform(format!(
                "user/mount namespace isolation is unavailable: {message}"
            )))
        } else {
            Err(SandboxError::SetupFailed(message))
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
            PHASE_NAMESPACE => "user/mount namespace creation",
            PHASE_SETGROUPS => "setgroups deny",
            PHASE_UID_MAP => "uid_map",
            PHASE_GID_MAP => "gid_map",
            PHASE_MOUNT_PRIVATE => "mount propagation isolation",
            PHASE_STDIO => "stdio directory escape check",
            PHASE_ROOT_FCHDIR => "filesystem root pin",
            PHASE_CHROOT => "chroot",
            PHASE_CWD_FCHDIR => "working-directory pin",
            PHASE_FD_SANITIZE => "inherited-FD sanitization",
            PHASE_RLIMIT_CPU => "RLIMIT_CPU",
            PHASE_RLIMIT_AS => "RLIMIT_AS",
            PHASE_RLIMIT_FSIZE => "RLIMIT_FSIZE",
            PHASE_RLIMIT_NOFILE => "RLIMIT_NOFILE",
            PHASE_CAP_BOUNDING => "capability bounding-set drop",
            PHASE_CAP_AMBIENT => "ambient capability clear",
            PHASE_CAP_CURRENT => "effective/permitted/inheritable capability clear",
            PHASE_NO_NEW_PRIVS => "PR_SET_NO_NEW_PRIVS",
            PHASE_SECCOMP => "seccomp installation",
            PHASE_EXECVEAT => "execveat",
            _ => "unknown launch phase",
        };
        format!(
            "launch failed closed during {phase}: {}",
            io::Error::from_raw_os_error(record.errno)
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
            "getgroups" => libc::SYS_getgroups,
            "capget" => libc::SYS_capget,
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
            "execveat" => libc::SYS_execveat,
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
