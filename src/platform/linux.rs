#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
    _cancellation: Option<&crate::CancellationToken>,
) -> Result<crate::RunReport, crate::SandboxError> {
    Err(crate::SandboxError::UnsupportedPlatform(
        "sandbox enforcement currently supports Linux x86_64 only".to_owned(),
    ))
}

#[cfg(target_arch = "x86_64")]
#[path = "linux_pid_lifecycle.rs"]
mod pid_lifecycle;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::pid_lifecycle::{
        self, LaunchErrorRecord, SharedTargetLifecycle, TargetLifecycleRecord,
        TargetSupervisionPhases,
    };
    use crate::policy::{StdioMode, StdioPolicy};
    use crate::{
        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ResourceLimits, RunReport,
        SandboxError, SandboxPolicy,
    };
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
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const FIRST_NON_STDIO_FD: libc::c_uint = 3;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const AT_EMPTY_PATH: libc::c_uint = 0x1000;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;

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
    const PHASE_ROOT_CLONE: u32 = 7;
    const PHASE_ROOT_READONLY: u32 = 8;
    const PHASE_ROOT_ATTACH: u32 = 9;
    const PHASE_ROOT_FCHDIR: u32 = 10;
    const PHASE_SCRATCH_MOUNT: u32 = 11;
    const PHASE_CWD_PIN: u32 = 12;
    const PHASE_CHROOT: u32 = 13;
    const PHASE_CWD_FCHDIR: u32 = 14;
    const PHASE_FD_SANITIZE: u32 = 15;
    const PHASE_RLIMIT_CPU: u32 = 16;
    const PHASE_RLIMIT_AS: u32 = 17;
    const PHASE_RLIMIT_FSIZE: u32 = 18;
    const PHASE_RLIMIT_NOFILE: u32 = 19;
    const PHASE_CAP_BOUNDING: u32 = 20;
    const PHASE_CAP_AMBIENT: u32 = 21;
    const PHASE_CAP_CURRENT: u32 = 22;
    const PHASE_NO_NEW_PRIVS: u32 = 23;
    const PHASE_SECCOMP: u32 = 24;
    const PHASE_EXECVEAT: u32 = 25;
    const PHASE_ROOT_REVALIDATE: u32 = 26;
    const PHASE_STDIO_REDIRECT: u32 = 27;
    const PHASE_STDOUT_CAPTURE: u32 = 28;
    const PHASE_PID_INIT_FORK: u32 = 29;
    const PHASE_TARGET_FORK: u32 = 30;
    const PHASE_PROCESS_TREE_KILL: u32 = 31;
    const PHASE_PROCESS_TREE_REAP: u32 = 32;
    const PHASE_PID_INIT_WAIT: u32 = 33;
    const PHASE_DEADLINE_PIDFD: u32 = 34;
    const PHASE_DEADLINE_TIMERFD: u32 = 35;
    const PHASE_DEADLINE_TIMER_ARM: u32 = 36;
    const PHASE_DEADLINE_POLL: u32 = 37;
    const PHASE_HOSTNAME: u32 = 38;
    const PHASE_SELECTED_HANDLES: u32 = 39;
    const PHASE_CANCELLATION_PIDFD: u32 = 40;
    const PHASE_CANCELLATION_POLL: u32 = 41;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
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

    struct CapturePipe {
        read_fd: OwnedFd,
        write_fd: OwnedFd,
        limit: usize,
    }

    struct PreparedSelectedHandle {
        storage_fd: OwnedFd,
        target_fd: RawFd,
    }

    impl CapturePipe {
        fn new(limit: u64) -> Result<Self, SandboxError> {
            let mut fds = [-1; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
                return Err(SandboxError::SetupFailed(format!(
                    "cannot create stdout capture pipe: {}",
                    io::Error::last_os_error()
                )));
            }

            let read_fd = move_parent_fd_above_stdio(OwnedFd(fds[0]), "capture read end")?;
            let write_fd = move_parent_fd_above_stdio(OwnedFd(fds[1]), "capture write end")?;
            Ok(Self {
                read_fd,
                write_fd,
                limit: limit as usize,
            })
        }
    }

    fn move_parent_fd_above_stdio(fd: OwnedFd, label: &str) -> Result<OwnedFd, SandboxError> {
        if fd.raw() >= FIRST_NON_STDIO_FD as RawFd {
            return Ok(fd);
        }
        let moved = unsafe {
            libc::fcntl(
                fd.raw(),
                libc::F_DUPFD_CLOEXEC,
                FIRST_NON_STDIO_FD as libc::c_int,
            )
        };
        if moved == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot normalize {label} above standard descriptors: {}",
                io::Error::last_os_error()
            )));
        }
        drop(fd);
        Ok(OwnedFd(moved))
    }

    fn move_owned_fd_to_selected_storage(
        fd: OwnedFd,
        storage_floor: RawFd,
        label: &str,
    ) -> Result<OwnedFd, SandboxError> {
        if fd.raw() >= storage_floor {
            return Ok(fd);
        }
        let moved = unsafe { libc::fcntl(fd.raw(), libc::F_DUPFD_CLOEXEC, storage_floor) };
        if moved == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot move {label} into the selected-handle storage plane at fd {storage_floor} or above: {}",
                io::Error::last_os_error()
            )));
        }
        drop(fd);
        Ok(OwnedFd(moved))
    }

    fn pin_selected_handle(
        source_fd: u32,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        if source_fd > i32::MAX as u32 {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                "selected handle source fd exceeds the Linux descriptor range: {source_fd}"
            ))));
        }
        let source_fd = source_fd as RawFd;
        let pinned = unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, storage_floor) };
        if pinned == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot pin selected handle source fd {source_fd} for target fd {target_fd}: {}",
                io::Error::last_os_error()
            )));
        }
        let storage_fd = OwnedFd(pinned);
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(storage_fd.raw(), &mut stat) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot inspect selected handle source fd {source_fd}: {}",
                io::Error::last_os_error()
            )));
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                "selected handle source fd {source_fd} is a directory descriptor"
            ))));
        }
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
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
        root_path: CString,
        executable_fd: OwnedFd,
        selected_handles: Vec<PreparedSelectedHandle>,
        cancellation_fd: Option<OwnedFd>,
        cwd_relative: CString,
        scratch_relative: Option<CString>,
        scratch_options: Option<CString>,
        stdout_redirect_relative: Option<CString>,
        _argv0: CString,
        _args: Vec<CString>,
        _environment: Vec<CString>,
        argv: Vec<*const libc::c_char>,
        envp: Vec<*const libc::c_char>,
        uid_map: Vec<u8>,
        gid_map: Vec<u8>,
        hostname: Vec<u8>,
    }

    impl PreparedLaunch {
        fn new(
            policy: &SandboxPolicy,
            cancellation: Option<&CancellationToken>,
        ) -> Result<Self, SandboxError> {
            let root_fd = open_root(&policy.root_dir)?;
            let root_path =
                cstring_bytes("filesystem.root", policy.root_dir.as_os_str().as_bytes())?;
            let cwd_check = open_beneath_root(
                root_fd.raw(),
                &policy.working_dir,
                (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                "working directory",
            )?;
            drop(cwd_check);

            let executable_fd = open_beneath_root(
                root_fd.raw(),
                &policy.executable,
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                "executable",
            )?;
            validate_executable_fd(executable_fd.raw(), &policy.executable)?;
            // Keep every launcher-owned source above all target-visible handle
            // destinations. With no selected handles this floor is only 3, so
            // existing sandboxes do not gain an unnecessary fd>=64 requirement.
            let selected_storage_floor = policy
                .selected_handles
                .keys()
                .next_back()
                .map_or(FIRST_NON_STDIO_FD as RawFd, |target_fd| {
                    *target_fd as RawFd + 1
                });
            let executable_fd = move_owned_fd_to_selected_storage(
                executable_fd,
                selected_storage_floor,
                "pinned executable",
            )?;

            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());
            for (target_fd, source_fd) in &policy.selected_handles {
                selected_handles.push(pin_selected_handle(
                    *source_fd,
                    *target_fd,
                    selected_storage_floor,
                )?);
            }
            let cancellation_fd = cancellation
                .map(|token| {
                    let pinned = unsafe {
                        libc::fcntl(
                            token.raw_fd(),
                            libc::F_DUPFD_CLOEXEC,
                            selected_storage_floor,
                        )
                    };
                    if pinned == -1 {
                        Err(SandboxError::SetupFailed(format!(
                            "cannot pin external cancellation eventfd before fork: {}",
                            io::Error::last_os_error()
                        )))
                    } else {
                        Ok(OwnedFd(pinned))
                    }
                })
                .transpose()?;

            let cwd_relative = sandbox_relative(&policy.working_dir)?;
            let (scratch_relative, scratch_options) = match (
                &policy.scratch_dir,
                policy.scratch_bytes,
            ) {
                (Some(path), Some(bytes)) => {
                    let scratch_check = open_beneath_root(
                        root_fd.raw(),
                        path,
                        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                        "scratch directory",
                    )?;
                    drop(scratch_check);
                    let relative = sandbox_relative(path)?;
                    let options = cstring_bytes(
                        "scratch mount options",
                        format!("size={bytes},mode=0700").as_bytes(),
                    )?;
                    (Some(relative), Some(options))
                }
                (None, None) => (None, None),
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "filesystem.scratch and filesystem.scratch_bytes must be specified together",
                    )));
                }
            };
            let stdout_redirect_relative = policy
                .stdout_redirect
                .as_ref()
                .map(|path| sandbox_relative(path))
                .transpose()?;

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
            let hostname = policy.hostname.as_bytes().to_vec();

            Ok(Self {
                root_fd,
                root_path,
                executable_fd,
                selected_handles,
                cancellation_fd,
                cwd_relative,
                scratch_relative,
                scratch_options,
                stdout_redirect_relative,
                _argv0: argv0,
                _args: args,
                _environment: environment,
                argv,
                envp,
                uid_map,
                gid_map,
                hostname,
            })
        }
    }

    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    #[derive(Clone, Copy)]
    struct ChildControl {
        launch_error: *mut LaunchErrorRecord,
        target_lifecycle: *mut TargetLifecycleRecord,
        capture_read_fd: RawFd,
        capture_write_fd: RawFd,
        wall_clock_milliseconds: u64,
    }

    pub(crate) fn run_report(
        policy: &SandboxPolicy,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunReport, SandboxError> {
        ensure_fd_sanitization_supported()?;
        ensure_supervision_support(policy.wall_clock_milliseconds, cancellation.is_some())?;
        let prepared = PreparedLaunch::new(policy, cancellation)?;
        let seccomp = compile_seccomp(policy)?;
        let launch_state = SharedLaunchState::new()?;
        let lifecycle = SharedTargetLifecycle::new().map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot allocate shared target lifecycle state: {err}"
            ))
        })?;
        let capture = if policy.stdio.stdout == StdioMode::Capture {
            Some(CapturePipe::new(policy.stdout_capture_bytes.ok_or_else(
                || {
                    SandboxError::InvalidPolicy(PolicyError::new(
                        "stdio.stdout = capture requires stdio.stdout_capture_bytes",
                    ))
                },
            )?)?)
        } else {
            None
        };
        let capture_read_fd = capture.as_ref().map_or(-1, |pipe| pipe.read_fd.raw());
        let capture_write_fd = capture.as_ref().map_or(-1, |pipe| pipe.write_fd.raw());
        let child_control = ChildControl {
            launch_error: launch_state.record,
            target_lifecycle: lifecycle.raw(),
            capture_read_fd,
            capture_write_fd,
            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),
        };

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
                    policy.stdio,
                    policy.limits,
                    &seccomp,
                    child_control,
                )
            }
        }
        // The host parent does not retain launcher-owned duplicates of selected
        // object capabilities while the target runs. Caller-owned source FDs
        // remain under caller control.
        drop(prepared);

        let capture_result = capture.map(|pipe| {
            let CapturePipe {
                read_fd,
                write_fd,
                limit,
            } = pipe;
            drop(write_fd);
            let result = read_capture(read_fd.raw(), limit);
            drop(read_fd);
            result
        });

        let bootstrap_status = wait_for_child(pid)?;
        let launch_error = launch_state.snapshot();
        if launch_error.phase != 0 {
            return decode_launch_error(launch_error).map(|outcome| RunReport {
                outcome,
                stdout: None,
                reaped_descendants: 0,
            });
        }

        let lifecycle_record = lifecycle.snapshot();
        if lifecycle_record.ready != 1 {
            return Err(SandboxError::SetupFailed(format!(
                "PID namespace lifecycle did not publish target status; bootstrap wait status 0x{bootstrap_status:x}"
            )));
        }

        let stdout = match capture_result {
            Some(result) => Some(result?),
            None => None,
        };
        let outcome = match (lifecycle_record.timed_out, lifecycle_record.cancelled) {
            (0, 0) => decode_wait_status(lifecycle_record.status)?,
            (1, 0) => ChildOutcome::TimedOut,
            (0, 1) => ChildOutcome::Cancelled,
            (timed_out, cancelled) => {
                return Err(SandboxError::SetupFailed(format!(
                    "PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}"
                )));
            }
        };
        Ok(RunReport {
            outcome,
            stdout,
            reaped_descendants: lifecycle_record.reaped_descendants,
        })
    }

    fn read_capture(fd: RawFd, limit: usize) -> Result<CapturedOutput, SandboxError> {
        let mut bytes = Vec::with_capacity(limit.min(8192));
        let mut truncated = false;
        let mut buffer = [0u8; 8192];

        loop {
            let read =
                unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len()) };
            if read == 0 {
                break;
            }
            if read == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!(
                    "stdout capture read failed: {err}"
                )));
            }

            let read = read as usize;
            let remaining = limit.saturating_sub(bytes.len());
            let retained = remaining.min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            if retained < read {
                truncated = true;
            }
        }

        Ok(CapturedOutput { bytes, truncated })
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

    fn ensure_supervision_support(
        deadline: Option<u64>,
        cancellable: bool,
    ) -> Result<(), SandboxError> {
        if deadline.is_none() && !cancellable {
            return Ok(());
        }

        let purpose = match (deadline.is_some(), cancellable) {
            (true, true) => "deadline/cancellation supervision",
            (true, false) => "wall-clock deadline",
            (false, true) => "external cancellation",
            (false, false) => unreachable!(),
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
        if pidfd == -1 {
            return Err(supervision_support_error(
                purpose,
                "pidfd_open",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(pidfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close {purpose} pidfd probe: {}",
                io::Error::last_os_error()
            )));
        }

        if deadline.is_none() {
            return Ok(());
        }
        let timerfd = unsafe {
            libc::syscall(
                libc::SYS_timerfd_create,
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC,
            )
        };
        if timerfd == -1 {
            return Err(supervision_support_error(
                purpose,
                "timerfd_create(CLOCK_MONOTONIC)",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(timerfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close {purpose} timerfd probe: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn supervision_support_error(purpose: &str, mechanism: &str, error: io::Error) -> SandboxError {
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
        ) {
            SandboxError::UnsupportedPlatform(format!("{purpose} requires {mechanism}: {error}"))
        } else {
            SandboxError::SetupFailed(format!(
                "cannot verify {purpose} mechanism {mechanism}: {error}"
            ))
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

        let mut syscalls = Vec::with_capacity(policy.seccomp.allowed_syscalls.len());
        for name in &policy.seccomp.allowed_syscalls {
            let number = syscall_number(name).ok_or_else(|| {
                SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "unsupported Linux x86_64 syscall name: {name}"
                )))
            })?;
            syscalls.push((number as u32, name.as_str()));
        }
        syscalls.sort_unstable_by_key(|(number, _)| *number);
        for pair in syscalls.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "multiple syscall names resolve to Linux x86_64 number {}",
                    pair[0].0
                ))));
            }
        }

        let mut filter = vec![
            stmt(BPF_LD_W_ABS, 4),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, 0),
        ];

        for (number, name) in syscalls {
            let mut checks = Vec::new();
            if let Some(rules) = policy.seccomp.argument_rules.get(name) {
                for (argument_index, rule) in rules {
                    append_seccomp_argument_checks(
                        &mut checks,
                        *argument_index,
                        rule.mask,
                        rule.value,
                    );
                }
            }
            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            if checks.len() > u8::MAX as usize {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "seccomp argument-check block for {name} is too large"
                ))));
            }
            filter.push(jump(BPF_JMP_JEQ_K, number, 0, checks.len() as u8));
            filter.extend(checks);
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

    fn append_seccomp_argument_checks(
        filter: &mut Vec<libc::sock_filter>,
        argument_index: u8,
        mask: u64,
        value: u64,
    ) {
        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;
        append_seccomp_argument_word_check(filter, argument_offset, mask as u32, value as u32);
        append_seccomp_argument_word_check(
            filter,
            argument_offset + 4,
            (mask >> 32) as u32,
            (value >> 32) as u32,
        );
    }

    fn append_seccomp_argument_word_check(
        filter: &mut Vec<libc::sock_filter>,
        offset: u32,
        mask: u32,
        value: u32,
    ) {
        if mask == 0 {
            return;
        }
        filter.push(stmt(BPF_LD_W_ABS, offset));
        if mask != u32::MAX {
            filter.push(stmt(BPF_ALU_AND_K, mask));
        }
        filter.push(jump(BPF_JMP_JEQ_K, value, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }

    unsafe fn child_exec(
        prepared: &PreparedLaunch,
        stdio: StdioPolicy,
        limits: ResourceLimits,
        seccomp: &CompiledSeccomp,
        control: ChildControl,
    ) -> ! {
        let ChildControl {
            launch_error,
            target_lifecycle,
            capture_read_fd,
            capture_write_fd,
            wall_clock_milliseconds,
        } = control;
        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {
            child_fail(
                launch_error,
                PHASE_STDOUT_CAPTURE,
                seccomp.error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_unshare,
            libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS,
        ) == -1
        {
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
            libc::SYS_sethostname,
            prepared.hostname.as_ptr(),
            prepared.hostname.len(),
        ) == -1
        {
            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);
        }

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

        let current_root_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let current_root_fd = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            prepared.root_path.as_ptr(),
            &current_root_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if current_root_fd == -1 {
            child_fail(
                launch_error,
                PHASE_ROOT_REVALIDATE,
                seccomp.error_exit_syscall,
            );
        }
        let current_root_fd = current_root_fd as RawFd;
        revalidate_root_identity_or_fail(
            prepared.root_fd.raw(),
            current_root_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );

        let root_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_root_fd,
            b".\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if root_tree_fd == -1 {
            child_fail(launch_error, PHASE_ROOT_CLONE, seccomp.error_exit_syscall);
        }
        let root_tree_fd = root_tree_fd as RawFd;

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH | AT_RECURSIVE,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_ROOT_READONLY,
                seccomp.error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_move_mount,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            current_root_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_ROOT_ATTACH, seccomp.error_exit_syscall);
        }

        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {
            child_fail(launch_error, PHASE_ROOT_FCHDIR, seccomp.error_exit_syscall);
        }

        if let (Some(scratch), Some(options)) =
            (&prepared.scratch_relative, &prepared.scratch_options)
        {
            if libc::syscall(
                libc::SYS_mount,
                b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
                scratch.as_ptr(),
                b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                options.as_ptr(),
            ) == -1
            {
                child_fail(
                    launch_error,
                    PHASE_SCRATCH_MOUNT,
                    seccomp.error_exit_syscall,
                );
            }
        }

        let stdout_redirect_fd = if let Some(path) = &prepared.stdout_redirect_relative {
            open_stdout_redirect_or_fail(
                root_tree_fd,
                path,
                launch_error,
                seccomp.error_exit_syscall,
            )
        } else {
            -1
        };

        let cwd_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let cwd_fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            prepared.cwd_relative.as_ptr(),
            &cwd_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if cwd_fd == -1 {
            child_fail(launch_error, PHASE_CWD_PIN, seccomp.error_exit_syscall);
        }
        let cwd_fd = cwd_fd as RawFd;

        if libc::syscall(libc::SYS_chroot, b".\0".as_ptr().cast::<libc::c_char>()) == -1 {
            child_fail(launch_error, PHASE_CHROOT, seccomp.error_exit_syscall);
        }
        if libc::syscall(libc::SYS_fchdir, cwd_fd) == -1 {
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

        pid_lifecycle::become_pid_namespace_init_or_exit(
            launch_error,
            PHASE_PID_INIT_FORK,
            PHASE_PID_INIT_WAIT,
            PHASE_FD_SANITIZE,
        );
        pid_lifecycle::become_direct_target_or_reap(
            target_lifecycle,
            launch_error,
            wall_clock_milliseconds,
            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),
            TargetSupervisionPhases {
                fork: PHASE_TARGET_FORK,
                kill: PHASE_PROCESS_TREE_KILL,
                reap: PHASE_PROCESS_TREE_REAP,
                close: PHASE_FD_SANITIZE,
                pidfd: PHASE_DEADLINE_PIDFD,
                timerfd: PHASE_DEADLINE_TIMERFD,
                timer_arm: PHASE_DEADLINE_TIMER_ARM,
                poll: PHASE_DEADLINE_POLL,
                cancellation_pidfd: PHASE_CANCELLATION_PIDFD,
                cancellation_poll: PHASE_CANCELLATION_POLL,
            },
        );

        apply_stdio_policy_or_fail(
            stdio,
            stdout_redirect_fd,
            capture_write_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );
        install_selected_handles_or_fail(
            &prepared.selected_handles,
            launch_error,
            seccomp.error_exit_syscall,
        );

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
            EXECVEAT_AT_EMPTY_PATH,
        );
        child_fail(launch_error, PHASE_EXECVEAT, seccomp.error_exit_syscall)
    }

    unsafe fn open_stdout_redirect_or_fail(
        root_tree_fd: RawFd,
        path: &CString,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        let how = OpenHow {
            flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC) as u64,
            mode: 0o600,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if fd == -1 {
            child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
        }
        move_fd_above_stdio_or_fail(
            fd as RawFd,
            launch_error,
            PHASE_STDIO_REDIRECT,
            error_exit_syscall,
        )
    }

    unsafe fn move_fd_above_stdio_or_fail(
        fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        if fd >= FIRST_NON_STDIO_FD as RawFd {
            return fd;
        }
        let moved = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FIRST_NON_STDIO_FD as libc::c_int);
        if moved == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        if libc::close(fd) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        moved
    }

    unsafe fn revalidate_root_identity_or_fail(
        pinned_root_fd: RawFd,
        current_root_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let mut pinned = std::mem::zeroed::<libc::stat>();
        if libc::fstat(pinned_root_fd, &mut pinned) == -1 {
            child_fail(launch_error, PHASE_ROOT_REVALIDATE, error_exit_syscall);
        }
        let mut current = std::mem::zeroed::<libc::stat>();
        if libc::fstat(current_root_fd, &mut current) == -1 {
            child_fail(launch_error, PHASE_ROOT_REVALIDATE, error_exit_syscall);
        }
        if pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino {
            child_fail_errno(
                launch_error,
                PHASE_ROOT_REVALIDATE,
                libc::ESTALE,
                error_exit_syscall,
            );
        }
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

    unsafe fn apply_stdio_policy_or_fail(
        stdio: StdioPolicy,
        stdout_redirect_fd: RawFd,
        stdout_capture_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let modes = [stdio.stdin, stdio.stdout, stdio.stderr];
        for (fd, mode) in modes.into_iter().enumerate() {
            let fd = fd as RawFd;
            match mode {
                StdioMode::Closed => {
                    if libc::close(fd) == -1 {
                        let errno = *libc::__errno_location();
                        if errno != libc::EBADF {
                            child_fail_errno(launch_error, PHASE_STDIO, errno, error_exit_syscall);
                        }
                    }
                }
                StdioMode::Inherit => {
                    let mut stat = std::mem::zeroed::<libc::stat>();
                    if libc::fstat(fd, &mut stat) == -1 {
                        child_fail(launch_error, PHASE_STDIO, error_exit_syscall);
                    }
                    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDIO,
                            libc::EISDIR,
                            error_exit_syscall,
                        );
                    }
                }
                StdioMode::Redirect => {
                    if fd != libc::STDOUT_FILENO || stdout_redirect_fd < FIRST_NON_STDIO_FD as RawFd
                    {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDIO_REDIRECT,
                            libc::EINVAL,
                            error_exit_syscall,
                        );
                    }
                    if libc::dup2(stdout_redirect_fd, fd) == -1 {
                        child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
                    }
                }
                StdioMode::Capture => {
                    if fd != libc::STDOUT_FILENO || stdout_capture_fd < FIRST_NON_STDIO_FD as RawFd
                    {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDOUT_CAPTURE,
                            libc::EINVAL,
                            error_exit_syscall,
                        );
                    }
                    if libc::dup2(stdout_capture_fd, fd) == -1 {
                        child_fail(launch_error, PHASE_STDOUT_CAPTURE, error_exit_syscall);
                    }
                }
            }
        }
        if stdout_redirect_fd >= FIRST_NON_STDIO_FD as RawFd
            && libc::close(stdout_redirect_fd) == -1
        {
            child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
        }
        if stdout_capture_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(stdout_capture_fd) == -1
        {
            child_fail(launch_error, PHASE_STDOUT_CAPTURE, error_exit_syscall);
        }
    }

    unsafe fn install_selected_handles_or_fail(
        handles: &[PreparedSelectedHandle],
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        for handle in handles {
            if libc::syscall(
                libc::SYS_dup3,
                handle.storage_fd.raw(),
                handle.target_fd,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);
            }
        }
        for handle in handles {
            if libc::close(handle.storage_fd.raw()) == -1 {
                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);
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
        let namespace_unavailable = record.phase == PHASE_NAMESPACE
            && matches!(record.errno, libc::EPERM | libc::EACCES | libc::ENOSYS);
        let mount_boundary_unavailable = matches!(
            record.phase,
            PHASE_ROOT_CLONE | PHASE_ROOT_READONLY | PHASE_ROOT_ATTACH | PHASE_SCRATCH_MOUNT
        ) && matches!(
            record.errno,
            libc::EPERM | libc::EACCES | libc::ENOSYS | libc::ENODEV
        );
        if namespace_unavailable || mount_boundary_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "required namespace/mount isolation is unavailable: {message}"
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
            PHASE_NAMESPACE => "user/mount/PID/network/IPC/UTS namespace creation",
            PHASE_SETGROUPS => "setgroups deny",
            PHASE_UID_MAP => "uid_map",
            PHASE_GID_MAP => "gid_map",
            PHASE_MOUNT_PRIVATE => "mount propagation isolation",
            PHASE_STDIO => "explicit stdio disposition",
            PHASE_ROOT_CLONE => "detached root mount clone",
            PHASE_ROOT_READONLY => "recursive read-only root attributes",
            PHASE_ROOT_ATTACH => "read-only root mount attachment",
            PHASE_ROOT_FCHDIR => "read-only root selection",
            PHASE_SCRATCH_MOUNT => "writable scratch tmpfs mount",
            PHASE_CWD_PIN => "working-directory pin inside read-only root",
            PHASE_CHROOT => "chroot",
            PHASE_CWD_FCHDIR => "working-directory selection",
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
            PHASE_ROOT_REVALIDATE => "filesystem root revalidation in mount namespace",
            PHASE_STDIO_REDIRECT => "owned stdout redirection",
            PHASE_STDOUT_CAPTURE => "bounded stdout capture",
            PHASE_PID_INIT_FORK => "PID namespace init fork",
            PHASE_TARGET_FORK => "direct target fork",
            PHASE_PROCESS_TREE_KILL => "process-tree termination",
            PHASE_PROCESS_TREE_REAP => "process-tree reaping",
            PHASE_PID_INIT_WAIT => "PID namespace init wait",
            PHASE_DEADLINE_PIDFD => "wall-clock deadline pidfd supervision",
            PHASE_DEADLINE_TIMERFD => "wall-clock deadline timer creation",
            PHASE_DEADLINE_TIMER_ARM => "wall-clock deadline timer arming",
            PHASE_DEADLINE_POLL => "wall-clock deadline supervision poll",
            PHASE_HOSTNAME => "UTS hostname installation",
            PHASE_SELECTED_HANDLES => "selected non-stdio handle installation",
            PHASE_CANCELLATION_PIDFD => "external cancellation pidfd supervision",
            PHASE_CANCELLATION_POLL => "external cancellation supervision poll",
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
            "socket" => libc::SYS_socket,
            "connect" => libc::SYS_connect,
            "msgget" => libc::SYS_msgget,
            "pread64" => libc::SYS_pread64,
            "access" => libc::SYS_access,
            "mremap" => libc::SYS_mremap,
            "madvise" => libc::SYS_madvise,
            "getpid" => libc::SYS_getpid,
            "getppid" => libc::SYS_getppid,
            "fork" => libc::SYS_fork,
            "pause" => libc::SYS_pause,
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
pub(crate) use x86_64::run_report;
