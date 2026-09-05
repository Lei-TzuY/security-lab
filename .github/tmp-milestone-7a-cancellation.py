from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Public one-shot cancellation token. eventfd stays readable once cancelled, so
# cancellation is level-triggered and reusable across clones without a consume race.
cancel_path = Path("src/cancellation.rs")
if cancel_path.exists():
    raise SystemExit("src/cancellation.rs already exists")
cancel_path.write_text(r'''use crate::SandboxError;

#[cfg(target_os = "linux")]
mod imp {
    use super::SandboxError;
    use std::io;
    use std::os::unix::io::RawFd;
    use std::sync::Arc;

    #[derive(Debug)]
    struct Inner {
        fd: RawFd,
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    /// Cloneable launcher control-plane token used to request asynchronous
    /// cancellation of a cancellable sandbox run.
    ///
    /// Cancellation is one-way: once any clone signals the token, future runs
    /// using the same token observe it as already cancelled.
    #[derive(Clone, Debug)]
    pub struct CancellationToken {
        inner: Arc<Inner>,
    }

    impl CancellationToken {
        /// Create a Linux eventfd-backed cancellation token.
        pub fn new() -> Result<Self, SandboxError> {
            let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
            if fd == -1 {
                let error = io::Error::last_os_error();
                return if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
                ) {
                    Err(SandboxError::UnsupportedPlatform(format!(
                        "external cancellation requires eventfd support: {error}"
                    )))
                } else {
                    Err(SandboxError::SetupFailed(format!(
                        "cannot create external cancellation eventfd: {error}"
                    )))
                };
            }
            Ok(Self {
                inner: Arc::new(Inner { fd }),
            })
        }

        /// Request cancellation. Repeated calls are harmless; the eventfd is
        /// intentionally never drained by the launcher, so readiness persists.
        pub fn cancel(&self) -> Result<(), SandboxError> {
            let value = 1u64;
            loop {
                let written = unsafe {
                    libc::write(
                        self.inner.fd,
                        (&value as *const u64).cast::<libc::c_void>(),
                        std::mem::size_of::<u64>(),
                    )
                };
                if written == std::mem::size_of::<u64>() as isize {
                    return Ok(());
                }
                if written == -1 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(SandboxError::SetupFailed(format!(
                        "cannot signal external cancellation eventfd: {error}"
                    )));
                }
                return Err(SandboxError::SetupFailed(
                    "external cancellation eventfd accepted a short write".to_owned(),
                ));
            }
        }

        pub(crate) fn raw_fd(&self) -> RawFd {
            self.inner.fd
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::SandboxError;

    #[derive(Clone, Debug)]
    pub struct CancellationToken;

    impl CancellationToken {
        pub fn new() -> Result<Self, SandboxError> {
            Err(SandboxError::UnsupportedPlatform(
                "external cancellation currently requires Linux eventfd".to_owned(),
            ))
        }

        pub fn cancel(&self) -> Result<(), SandboxError> {
            Err(SandboxError::UnsupportedPlatform(
                "external cancellation currently requires Linux eventfd".to_owned(),
            ))
        }

        pub(crate) fn raw_fd(&self) -> i32 {
            -1
        }
    }
}

pub use imp::CancellationToken;
''')

# Public API and outcome.
replace_one(
    "src/lib.rs",
    "mod platform;\npub mod policy;\npub mod report;\n",
    "mod cancellation;\nmod platform;\npub mod policy;\npub mod report;\n",
    "lib cancellation module",
)
replace_one(
    "src/lib.rs",
    "pub use policy::{\n",
    "pub use cancellation::CancellationToken;\npub use policy::{\n",
    "lib cancellation reexport",
)
replace_one(
    "src/lib.rs",
    '''pub fn run_report(policy: &SandboxPolicy) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy)
}
''',
    '''pub fn run_report(policy: &SandboxPolicy) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, None)
}

/// Validate and execute the invocation while allowing another thread holding a
/// clone of `cancellation` to request launcher-owned process-tree termination.
pub fn run_report_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, Some(cancellation))
}
''',
    "lib cancellable report API",
)
replace_one(
    "src/lib.rs",
    '''pub fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report(policy)?.outcome)
}
''',
    '''pub fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report(policy)?.outcome)
}

/// Status-only counterpart to [`run_report_with_cancel`].
pub fn run_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report_with_cancel(policy, cancellation)?.outcome)
}
''',
    "lib cancellable status API",
)
replace_one(
    "src/report.rs",
    '''    /// Launcher-owned wall-clock deadline expired before the direct target
    /// became waitable. This is distinct from an ordinary target signal.
    TimedOut,
''',
    '''    /// Launcher-owned wall-clock deadline expired before the direct target
    /// became waitable. This is distinct from an ordinary target signal.
    TimedOut,
    /// A caller-controlled cancellation token became ready while the direct
    /// target was still running. PID 1 owns the resulting tree teardown.
    Cancelled,
''',
    "cancelled outcome variant",
)
replace_one(
    "src/report.rs",
    '''            Self::TimedOut => f.write_str("timed out"),
''',
    '''            Self::TimedOut => f.write_str("timed out"),
            Self::Cancelled => f.write_str("cancelled"),
''',
    "cancelled outcome display",
)
replace_one(
    "src/main.rs",
    '''                ChildOutcome::TimedOut => process::exit(124),
''',
    '''                ChildOutcome::TimedOut => process::exit(124),
                ChildOutcome::Cancelled => process::exit(130),
''',
    "CLI cancelled exhaustiveness",
)

# Platform routing takes an optional control-plane token.
replace_one(
    "src/platform/mod.rs",
    '''pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
) -> Result<crate::RunReport, crate::SandboxError> {
''',
    '''pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
    _cancellation: Option<&crate::CancellationToken>,
) -> Result<crate::RunReport, crate::SandboxError> {
''',
    "nonlinux platform cancellation signature",
)
replace_one(
    "src/platform/linux.rs",
    '''pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
) -> Result<crate::RunReport, crate::SandboxError> {
''',
    '''pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
    _cancellation: Option<&crate::CancellationToken>,
) -> Result<crate::RunReport, crate::SandboxError> {
''',
    "non-x86 linux cancellation signature",
)
replace_one(
    "src/platform/linux.rs",
    '''        CapturedOutput, ChildOutcome, PolicyError, ResourceLimits, RunReport, SandboxError,
        SandboxPolicy,
''',
    '''        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ResourceLimits,
        RunReport, SandboxError, SandboxPolicy,
''',
    "linux cancellation import",
)
replace_one(
    "src/platform/linux.rs",
    '''    const PHASE_SELECTED_HANDLES: u32 = 39;
''',
    '''    const PHASE_SELECTED_HANDLES: u32 = 39;
    const PHASE_CANCELLATION_PIDFD: u32 = 40;
    const PHASE_CANCELLATION_POLL: u32 = 41;
''',
    "cancellation phases",
)
replace_one(
    "src/platform/linux.rs",
    '''        selected_handles: Vec<PreparedSelectedHandle>,
        cwd_relative: CString,
''',
    '''        selected_handles: Vec<PreparedSelectedHandle>,
        cancellation_fd: Option<OwnedFd>,
        cwd_relative: CString,
''',
    "prepared cancellation fd field",
)
replace_one(
    "src/platform/linux.rs",
    '''    impl PreparedLaunch {
        fn new(policy: &SandboxPolicy) -> Result<Self, SandboxError> {
''',
    '''    impl PreparedLaunch {
        fn new(
            policy: &SandboxPolicy,
            cancellation: Option<&CancellationToken>,
        ) -> Result<Self, SandboxError> {
''',
    "prepared cancellation constructor",
)
replace_one(
    "src/platform/linux.rs",
    '''            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());
            for (target_fd, source_fd) in &policy.selected_handles {
                selected_handles.push(pin_selected_handle(
                    *source_fd,
                    *target_fd,
                    selected_storage_floor,
                )?);
            }

            let cwd_relative = sandbox_relative(&policy.working_dir)?;
''',
    '''            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());
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
''',
    "pin cancellation before fork",
)
replace_one(
    "src/platform/linux.rs",
    '''                executable_fd,
                selected_handles,
                cwd_relative,
''',
    '''                executable_fd,
                selected_handles,
                cancellation_fd,
                cwd_relative,
''',
    "prepared cancellation init",
)
replace_one(
    "src/platform/linux.rs",
    '''    pub(crate) fn run_report(policy: &SandboxPolicy) -> Result<RunReport, SandboxError> {
        ensure_fd_sanitization_supported()?;
        ensure_deadline_support(policy.wall_clock_milliseconds)?;
        let prepared = PreparedLaunch::new(policy)?;
''',
    '''    pub(crate) fn run_report(
        policy: &SandboxPolicy,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunReport, SandboxError> {
        ensure_fd_sanitization_supported()?;
        ensure_supervision_support(policy.wall_clock_milliseconds, cancellation.is_some())?;
        let prepared = PreparedLaunch::new(policy, cancellation)?;
''',
    "linux cancellable run_report",
)
replace_one(
    "src/platform/linux.rs",
    '''        let outcome = match lifecycle_record.timed_out {
            0 => decode_wait_status(lifecycle_record.status)?,
            1 => ChildOutcome::TimedOut,
            value => {
                return Err(SandboxError::SetupFailed(format!(
                    "PID namespace lifecycle published invalid timeout flag {value}"
                )));
            }
        };
''',
    '''        let outcome = match (lifecycle_record.timed_out, lifecycle_record.cancelled) {
            (0, 0) => decode_wait_status(lifecycle_record.status)?,
            (1, 0) => ChildOutcome::TimedOut,
            (0, 1) => ChildOutcome::Cancelled,
            (timed_out, cancelled) => {
                return Err(SandboxError::SetupFailed(format!(
                    "PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}"
                )));
            }
        };
''',
    "cancelled lifecycle mapping",
)
replace_one(
    "src/platform/linux.rs",
    '''    fn ensure_deadline_support(deadline: Option<u64>) -> Result<(), SandboxError> {
        if deadline.is_none() {
            return Ok(());
        }

        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
        if pidfd == -1 {
            return Err(deadline_support_error(
                "pidfd_open",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(pidfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close wall-clock deadline pidfd probe: {}",
                io::Error::last_os_error()
            )));
        }

        let timerfd = unsafe {
            libc::syscall(
                libc::SYS_timerfd_create,
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC,
            )
        };
        if timerfd == -1 {
            return Err(deadline_support_error(
                "timerfd_create(CLOCK_MONOTONIC)",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(timerfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close wall-clock deadline timerfd probe: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn deadline_support_error(mechanism: &str, error: io::Error) -> SandboxError {
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
        ) {
            SandboxError::UnsupportedPlatform(format!(
                "wall-clock deadline requires {mechanism}: {error}"
            ))
        } else {
            SandboxError::SetupFailed(format!(
                "cannot verify wall-clock deadline mechanism {mechanism}: {error}"
            ))
        }
    }
''',
    '''    fn ensure_supervision_support(
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

    fn supervision_support_error(
        purpose: &str,
        mechanism: &str,
        error: io::Error,
    ) -> SandboxError {
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
        ) {
            SandboxError::UnsupportedPlatform(format!(
                "{purpose} requires {mechanism}: {error}"
            ))
        } else {
            SandboxError::SetupFailed(format!(
                "cannot verify {purpose} mechanism {mechanism}: {error}"
            ))
        }
    }
''',
    "general supervision preflight",
)
replace_one(
    "src/platform/linux.rs",
    '''        pid_lifecycle::become_direct_target_or_reap(
            target_lifecycle,
            launch_error,
            wall_clock_milliseconds,
            TargetSupervisionPhases {
''',
    '''        pid_lifecycle::become_direct_target_or_reap(
            target_lifecycle,
            launch_error,
            wall_clock_milliseconds,
            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),
            TargetSupervisionPhases {
''',
    "pass cancellation fd to PID1",
)
replace_one(
    "src/platform/linux.rs",
    '''                poll: PHASE_DEADLINE_POLL,
            },
''',
    '''                poll: PHASE_DEADLINE_POLL,
                cancellation_pidfd: PHASE_CANCELLATION_PIDFD,
                cancellation_poll: PHASE_CANCELLATION_POLL,
            },
''',
    "cancellation supervision phases",
)
replace_one(
    "src/platform/linux.rs",
    '''            PHASE_SELECTED_HANDLES => "selected non-stdio handle installation",
            _ => "unknown launch phase",
''',
    '''            PHASE_SELECTED_HANDLES => "selected non-stdio handle installation",
            PHASE_CANCELLATION_PIDFD => "external cancellation pidfd supervision",
            PHASE_CANCELLATION_POLL => "external cancellation supervision poll",
            _ => "unknown launch phase",
''',
    "cancellation phase decoding",
)

# PID1 lifecycle: preserve only the eventfd, exclude it from target, and make
# natural-exit > explicit-cancel > deadline the documented wake arbitration.
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''pub(super) struct TargetLifecycleRecord {
    pub(super) status: libc::c_int,
    pub(super) reaped_descendants: u32,
    pub(super) timed_out: u32,
    pub(super) ready: u32,
}
''',
    '''pub(super) struct TargetLifecycleRecord {
    pub(super) status: libc::c_int,
    pub(super) reaped_descendants: u32,
    pub(super) timed_out: u32,
    pub(super) cancelled: u32,
    pub(super) ready: u32,
}
''',
    "lifecycle cancelled field",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''                    timed_out: 0,
                    ready: 0,
''',
    '''                    timed_out: 0,
                    cancelled: 0,
                    ready: 0,
''',
    "lifecycle cancelled initialization",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''    pub(super) poll: u32,
}
''',
    '''    pub(super) poll: u32,
    pub(super) cancellation_pidfd: u32,
    pub(super) cancellation_poll: u32,
}
''',
    "cancellation phase fields",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''    wall_clock_milliseconds: u64,
    phases: TargetSupervisionPhases,
) {
''',
    '''    wall_clock_milliseconds: u64,
    cancellation_fd: libc::c_int,
    phases: TargetSupervisionPhases,
) {
''',
    "PID1 cancellation parameter",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''    if pid == 0 {
        return;
    }
    let pid = pid as libc::pid_t;

    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
        let errno = *libc::__errno_location();
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
        let _ = wait_specific(pid);
        let _ = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);
        fail_errno(launch_error, phases.close, errno);
    }

    let (direct_status, timed_out) =
        wait_direct_target(pid, wall_clock_milliseconds, launch_error, phases);
''',
    '''    if pid == 0 {
        if cancellation_fd >= 3 && libc::close(cancellation_fd) == -1 {
            fail(launch_error, phases.close);
        }
        return;
    }
    let pid = pid as libc::pid_t;

    if let Err(errno) = close_nonstdio_except(cancellation_fd) {
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
        let _ = wait_specific(pid);
        let _ = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);
        fail_errno(launch_error, phases.close, errno);
    }

    let (direct_status, timed_out, cancelled) = wait_direct_target(
        pid,
        wall_clock_milliseconds,
        cancellation_fd,
        launch_error,
        phases,
    );
''',
    "PID1 cancellation ownership",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).timed_out),
        u32::from(timed_out),
    );
    // Publish readiness last: the host treats ready != 1 as an incomplete
''',
    '''    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).timed_out),
        u32::from(timed_out),
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).cancelled),
        u32::from(cancelled),
    );
    // Publish readiness last: the host treats ready != 1 as an incomplete
''',
    "publish cancelled state",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    '''unsafe fn wait_direct_target(
    pid: libc::pid_t,
    wall_clock_milliseconds: u64,
    launch_error: *mut LaunchErrorRecord,
    phases: TargetSupervisionPhases,
) -> (libc::c_int, bool) {
    if wall_clock_milliseconds == 0 {
        return match wait_specific(pid) {
            Ok(status) => (status, false),
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        };
    }

    let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0u32);
    if pidfd == -1 {
        fail(launch_error, phases.pidfd);
    }
    let pidfd = pidfd as libc::c_int;

    let timerfd = libc::syscall(
        libc::SYS_timerfd_create,
        libc::CLOCK_MONOTONIC,
        libc::TFD_CLOEXEC,
    );
    if timerfd == -1 {
        fail(launch_error, phases.timerfd);
    }
    let timerfd = timerfd as libc::c_int;

    let specification = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: (wall_clock_milliseconds / 1000) as libc::time_t,
            tv_nsec: ((wall_clock_milliseconds % 1000) * 1_000_000) as libc::c_long,
        },
    };
    if libc::syscall(
        libc::SYS_timerfd_settime,
        timerfd,
        0,
        &specification as *const libc::itimerspec,
        ptr::null_mut::<libc::itimerspec>(),
    ) == -1
    {
        fail(launch_error, phases.timer_arm);
    }

    let mut fds = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: timerfd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        fds[0].revents = 0;
        fds[1].revents = 0;
        let polled = libc::syscall(
            libc::SYS_poll,
            fds.as_mut_ptr(),
            fds.len(),
            -1 as libc::c_int,
        );
        if polled == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            fail_errno(launch_error, phases.poll, errno);
        }

        // One nonblocking reap check is the race arbiter. If the direct target
        // was already waitable when supervision woke, natural termination wins
        // even when the timer became readable in the same poll cycle.
        match wait_specific_nohang(pid) {
            Ok(Some(status)) => return (status, false),
            Ok(None) => {}
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        }

        let invalid_events = libc::POLLERR | libc::POLLNVAL;
        if fds[0].revents & invalid_events != 0 || fds[1].revents & invalid_events != 0 {
            fail_errno(launch_error, phases.poll, libc::EIO);
        }

        if fds[1].revents & libc::POLLIN != 0 {
            // From this point the deadline owns the race. A target that exits
            // immediately after the WNOHANG check is still reported TimedOut.
            let killed = libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
            if killed == -1 {
                let errno = *libc::__errno_location();
                if errno != libc::ESRCH {
                    fail_errno(launch_error, phases.kill, errno);
                }
            }
            let status = match wait_specific(pid) {
                Ok(status) => status,
                Err(errno) => fail_errno(launch_error, phases.reap, errno),
            };
            return (status, true);
        }
    }
}
''',
    '''unsafe fn wait_direct_target(
    pid: libc::pid_t,
    wall_clock_milliseconds: u64,
    cancellation_fd: libc::c_int,
    launch_error: *mut LaunchErrorRecord,
    phases: TargetSupervisionPhases,
) -> (libc::c_int, bool, bool) {
    if wall_clock_milliseconds == 0 && cancellation_fd < 0 {
        return match wait_specific(pid) {
            Ok(status) => (status, false, false),
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        };
    }

    let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0u32);
    if pidfd == -1 {
        let phase = if cancellation_fd >= 0 {
            phases.cancellation_pidfd
        } else {
            phases.pidfd
        };
        fail(launch_error, phase);
    }
    let pidfd = pidfd as libc::c_int;

    let timerfd = if wall_clock_milliseconds == 0 {
        -1
    } else {
        let timerfd = libc::syscall(
            libc::SYS_timerfd_create,
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC,
        );
        if timerfd == -1 {
            fail(launch_error, phases.timerfd);
        }
        let timerfd = timerfd as libc::c_int;
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: (wall_clock_milliseconds / 1000) as libc::time_t,
                tv_nsec: ((wall_clock_milliseconds % 1000) * 1_000_000) as libc::c_long,
            },
        };
        if libc::syscall(
            libc::SYS_timerfd_settime,
            timerfd,
            0,
            &specification as *const libc::itimerspec,
            ptr::null_mut::<libc::itimerspec>(),
        ) == -1
        {
            fail(launch_error, phases.timer_arm);
        }
        timerfd
    };

    let mut fds = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: timerfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancellation_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        for fd in &mut fds {
            fd.revents = 0;
        }
        let polled = libc::syscall(
            libc::SYS_poll,
            fds.as_mut_ptr(),
            fds.len(),
            -1 as libc::c_int,
        );
        if polled == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            let phase = if cancellation_fd >= 0 {
                phases.cancellation_poll
            } else {
                phases.poll
            };
            fail_errno(launch_error, phase, errno);
        }

        // One nonblocking reap check is the race arbiter. If the direct target
        // was already waitable when supervision woke, natural termination wins.
        match wait_specific_nohang(pid) {
            Ok(Some(status)) => return (status, false, false),
            Ok(None) => {}
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        }

        let invalid_events = libc::POLLERR | libc::POLLNVAL;
        if fds.iter().any(|fd| fd.fd >= 0 && fd.revents & invalid_events != 0) {
            let phase = if cancellation_fd >= 0 {
                phases.cancellation_poll
            } else {
                phases.poll
            };
            fail_errno(launch_error, phase, libc::EIO);
        }

        if fds[2].revents & libc::POLLIN != 0 {
            let status = terminate_direct_target(pid, launch_error, phases);
            return (status, false, true);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let status = terminate_direct_target(pid, launch_error, phases);
            return (status, true, false);
        }
    }
}

unsafe fn terminate_direct_target(
    pid: libc::pid_t,
    launch_error: *mut LaunchErrorRecord,
    phases: TargetSupervisionPhases,
) -> libc::c_int {
    let killed = libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
    if killed == -1 {
        let errno = *libc::__errno_location();
        if errno != libc::ESRCH {
            fail_errno(launch_error, phases.kill, errno);
        }
    }
    match wait_specific(pid) {
        Ok(status) => status,
        Err(errno) => fail_errno(launch_error, phases.reap, errno),
    }
}

unsafe fn close_nonstdio_except(keep_fd: libc::c_int) -> Result<(), i32> {
    if keep_fd < 3 {
        if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
            return Err(*libc::__errno_location());
        }
        return Ok(());
    }

    let keep = keep_fd as u32;
    if keep > 3 && libc::syscall(libc::SYS_close_range, 3u32, keep - 1, 0u32) == -1 {
        return Err(*libc::__errno_location());
    }
    if libc::syscall(libc::SYS_close_range, keep + 1, u32::MAX, 0u32) == -1 {
        return Err(*libc::__errno_location());
    }
    Ok(())
}
''',
    "PID1 cancellable supervision",
)

# Tests: deterministic ready handshake, no sleeps, plus natural-exit regression.
replace_one(
    "tests/sandbox.rs",
    '''use security_lab::{
    run, run_report, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy, SeccompArgRule,
    SeccompPolicy, StdioMode, StdioPolicy,
};
''',
    '''use security_lab::{
    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, ResourceLimits,
    SandboxError, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,
};
''',
    "test cancellation imports",
)
replace_one(
    "tests/sandbox.rs",
    '''use std::sync::OnceLock;
''',
    '''use std::sync::OnceLock;
use std::thread;
''',
    "test thread import",
)
replace_one(
    "tests/sandbox.rs",
    '''fn fixture_root() -> &'static Path {
''',
    '''fn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let read = unsafe {
            libc::read(
                fd,
                buffer[offset..].as_mut_ptr().cast::<libc::c_void>(),
                buffer.len() - offset,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("ready-handshake read failed: {error}");
        }
        assert!(read > 0, "ready-handshake pipe reached EOF early");
        offset += read as usize;
    }
}

fn fixture_root() -> &'static Path {
''',
    "test read exact helper",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn network_namespace_cannot_reach_host_loopback_listener() {
''',
    '''#[test]
fn external_cancellation_owns_process_tree_after_ready_handshake() {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "create cancellation readiness pipe"
    );
    let read_end = TestFd(pipe[0]);
    let write_end = TestFd(pipe[1]);
    let cancellation = CancellationToken::new().expect("create cancellation token");
    let runner_token = cancellation.clone();

    let runner = thread::spawn(move || {
        let mut cancellable = policy(
            "c",
            &[],
            &["execveat", "write", "fork", "pause", "exit"],
        );
        cancellable.selected_handles.insert(9, write_end.raw() as u32);
        // A watchdog makes a broken cancellation path fail as TimedOut rather
        // than hanging CI; the ready handshake ensures cancellation itself is
        // never timing-based.
        cancellable.wall_clock_milliseconds = Some(5000);
        run_report_with_cancel(&cancellable, &runner_token)
    });

    let mut marker = [0u8; 25];
    read_exact_fd(read_end.raw(), &mut marker);
    assert_eq!(&marker, b"cancellation-target-ready\n");
    cancellation.cancel().expect("signal cancellation");

    let report = runner
        .join()
        .expect("cancellable sandbox thread panicked")
        .expect("cancellable sandbox run failed");
    assert_eq!(report.outcome, ChildOutcome::Cancelled);
    assert_eq!(report.reaped_descendants, 1);
}

#[test]
fn uncancelled_token_preserves_natural_completion() {
    let cancellation = CancellationToken::new().expect("create cancellation token");
    let report = run_report_with_cancel(
        &policy("X", &[], &["execveat", "exit"]),
        &cancellation,
    )
    .expect("uncancelled run failed");
    assert_eq!(report.outcome, ChildOutcome::Exited(42));
    assert_eq!(report.reaped_descendants, 0);
}

#[test]
fn network_namespace_cannot_reach_host_loopback_listener() {
''',
    "cancellation integration tests",
)

# Raw fixture mode 'c': fork descendant first, then publish ready and pause.
replace_one(
    "tests/fixtures/probe.S",
    '''#   G assert one selected non-stdio handle is remapped without ambient FD leakage
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM
''',
    '''#   G assert one selected non-stdio handle is remapped without ambient FD leakage
#   c fork a descendant, publish cancellation readiness on fd 9, then pause
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM
''',
    "probe cancellation comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $71, %al
    je .selected_handle
    cmp $70, %al
''',
    '''    cmp $71, %al
    je .selected_handle
    cmp $99, %al
    je .cancellation_tree
    cmp $70, %al
''',
    "probe cancellation dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi
    jmp .exit

.forbidden:
''',
    '''    xor %edi, %edi
    jmp .exit

.cancellation_tree:
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail31
    jz .cancellation_descendant_pause

    mov $1, %eax
    mov $9, %edi
    lea cancellation_ready_message(%rip), %rsi
    mov $cancellation_ready_message_len, %edx
    syscall
    cmp $cancellation_ready_message_len, %rax
    jne .fail31
.cancellation_parent_pause:
    mov $34, %eax
    syscall
    jmp .cancellation_parent_pause

.cancellation_descendant_pause:
    mov $34, %eax
    syscall
    jmp .cancellation_descendant_pause

.forbidden:
''',
    "probe cancellation oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    '''.fail30:
    mov $30, %edi

.exit:
''',
    '''.fail30:
    mov $30, %edi
    jmp .exit
.fail31:
    mov $31, %edi

.exit:
''',
    "probe fail31",
)
replace_one(
    "tests/fixtures/probe.S",
    '''selected_handle_message:
    .ascii "selected-handle-ok"
.set selected_handle_message_len, . - selected_handle_message
deadline_message:
''',
    '''selected_handle_message:
    .ascii "selected-handle-ok"
.set selected_handle_message_len, . - selected_handle_message
cancellation_ready_message:
    .ascii "cancellation-target-ready\\n"
.set cancellation_ready_message_len, . - cancellation_ready_message
deadline_message:
''',
    "probe cancellation ready message",
)
