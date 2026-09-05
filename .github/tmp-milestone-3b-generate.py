from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


# policy.rs
path = Path("src/policy.rs")
text = path.read_text()
text = replace_once(
    text,
    "const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;\n",
    "const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;\n"
    "const MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;\n"
    "const MAX_WALL_CLOCK_MILLISECONDS: u64 = 24 * 60 * 60 * 1000;\n",
    "policy deadline constants",
)
text = replace_once(
    text,
    "    pub stdout_capture_bytes: Option<u64>,\n    pub limits: ResourceLimits,\n",
    "    pub stdout_capture_bytes: Option<u64>,\n"
    "    /// Optional launcher-owned wall-clock deadline measured from PID 1\n"
    "    /// beginning supervision of the direct target.\n"
    "    pub wall_clock_milliseconds: Option<u64>,\n"
    "    pub limits: ResourceLimits,\n",
    "policy deadline field",
)
text = replace_once(
    text,
    "        if self.args.len() > MAX_ARGS {\n",
    "        if let Some(milliseconds) = self.wall_clock_milliseconds {\n"
    "            if !(MIN_WALL_CLOCK_MILLISECONDS..=MAX_WALL_CLOCK_MILLISECONDS)\n"
    "                .contains(&milliseconds)\n"
    "            {\n"
    "                return Err(PolicyError::new(format!(\n"
    "                    \"limit.wall_clock_milliseconds must be between {MIN_WALL_CLOCK_MILLISECONDS} and {MAX_WALL_CLOCK_MILLISECONDS}\"\n"
    "                )));\n"
    "            }\n"
    "        }\n\n"
    "        if self.args.len() > MAX_ARGS {\n",
    "policy deadline validation",
)
text = replace_once(
    text,
    "        let mut stdout_capture_bytes = None;\n        let mut cpu_seconds = None;\n",
    "        let mut stdout_capture_bytes = None;\n"
    "        let mut wall_clock_milliseconds = None;\n"
    "        let mut cpu_seconds = None;\n",
    "policy parser local",
)
text = replace_once(
    text,
    "                \"limit.cpu_seconds\" => set_once(\n",
    "                \"limit.wall_clock_milliseconds\" => set_once(\n"
    "                    &mut wall_clock_milliseconds,\n"
    "                    parse_u64(value, line_no, key)?,\n"
    "                    line_no,\n"
    "                    key,\n"
    "                )?,\n"
    "                \"limit.cpu_seconds\" => set_once(\n",
    "policy parser key",
)
text = replace_once(
    text,
    "            stdout_capture_bytes,\n            limits: ResourceLimits {\n",
    "            stdout_capture_bytes,\n"
    "            wall_clock_milliseconds,\n"
    "            limits: ResourceLimits {\n",
    "policy parser struct",
)
text = replace_once(
    text,
    "        assert_eq!(policy.stdout_capture_bytes, None);\n        assert_eq!(\n",
    "        assert_eq!(policy.stdout_capture_bytes, None);\n"
    "        assert_eq!(policy.wall_clock_milliseconds, None);\n"
    "        assert_eq!(\n",
    "policy default assertion",
)
text = replace_once(
    text,
    "    #[test]\n    fn rejects_redirect_path_outside_scratch() {\n",
    "    #[test]\n"
    "    fn parses_wall_clock_deadline() {\n"
    "        let text = format!(\"{VALID}\\nlimit.wall_clock_milliseconds = 1500\");\n"
    "        let policy: SandboxPolicy = text.parse().unwrap();\n"
    "        assert_eq!(policy.wall_clock_milliseconds, Some(1500));\n"
    "    }\n\n"
    "    #[test]\n"
    "    fn rejects_zero_wall_clock_deadline() {\n"
    "        let text = format!(\"{VALID}\\nlimit.wall_clock_milliseconds = 0\");\n"
    "        assert!(text.parse::<SandboxPolicy>().is_err());\n"
    "    }\n\n"
    "    #[test]\n"
    "    fn rejects_oversized_wall_clock_deadline() {\n"
    "        let text = format!(\n"
    "            \"{VALID}\\nlimit.wall_clock_milliseconds = {}\",\n"
    "            MAX_WALL_CLOCK_MILLISECONDS + 1\n"
    "        );\n"
    "        assert!(text.parse::<SandboxPolicy>().is_err());\n"
    "    }\n\n"
    "    #[test]\n"
    "    fn rejects_duplicate_wall_clock_deadline() {\n"
    "        let text = format!(\n"
    "            \"{VALID}\\nlimit.wall_clock_milliseconds = 1000\\nlimit.wall_clock_milliseconds = 2000\"\n"
    "        );\n"
    "        assert!(text.parse::<SandboxPolicy>().is_err());\n"
    "    }\n\n"
    "    #[test]\n"
    "    fn rejects_redirect_path_outside_scratch() {\n",
    "policy deadline tests",
)
path.write_text(text)

# report.rs
path = Path("src/report.rs")
text = path.read_text()
text = replace_once(
    text,
    "pub enum ChildOutcome {\n    Exited(i32),\n    Signaled(i32),\n}\n",
    "pub enum ChildOutcome {\n"
    "    Exited(i32),\n"
    "    Signaled(i32),\n"
    "    /// Launcher-owned wall-clock deadline expired before the direct target\n"
    "    /// became waitable. This is distinct from an ordinary target signal.\n"
    "    TimedOut,\n"
    "}\n",
    "report timeout variant",
)
text = replace_once(
    text,
    "            Self::Signaled(signal) => write!(f, \"signaled signal={signal}\"),\n",
    "            Self::Signaled(signal) => write!(f, \"signaled signal={signal}\"),\n"
    "            Self::TimedOut => f.write_str(\"timed out\"),\n",
    "report timeout display",
)
path.write_text(text)

# main.rs
path = Path("src/main.rs")
text = path.read_text()
text = replace_once(
    text,
    "                ChildOutcome::Signaled(signal) => process::exit(128 + signal),\n",
    "                ChildOutcome::Signaled(signal) => process::exit(128 + signal),\n"
    "                ChildOutcome::TimedOut => process::exit(124),\n",
    "cli timeout exit",
)
path.write_text(text)

# linux_pid_lifecycle.rs
path = Path("src/platform/linux_pid_lifecycle.rs")
text = path.read_text()
text = replace_once(
    text,
    "pub(super) struct TargetLifecycleRecord {\n    pub(super) status: libc::c_int,\n    pub(super) reaped_descendants: u32,\n    pub(super) ready: u32,\n}\n",
    "pub(super) struct TargetLifecycleRecord {\n"
    "    pub(super) status: libc::c_int,\n"
    "    pub(super) reaped_descendants: u32,\n"
    "    pub(super) timed_out: u32,\n"
    "    pub(super) ready: u32,\n"
    "}\n",
    "lifecycle timeout record",
)
text = replace_once(
    text,
    "                    reaped_descendants: 0,\n                    ready: 0,\n",
    "                    reaped_descendants: 0,\n"
    "                    timed_out: 0,\n"
    "                    ready: 0,\n",
    "lifecycle timeout init",
)
start = text.index("/// Called by the launcher-owned namespace init (PID 1). Fork the direct target.\n")
end = text.index("unsafe fn kill_and_reap_remaining(", start)
new_block = r'''#[derive(Clone, Copy)]
pub(super) struct TargetSupervisionPhases {
    pub(super) fork: u32,
    pub(super) kill: u32,
    pub(super) reap: u32,
    pub(super) close: u32,
    pub(super) pidfd: u32,
    pub(super) timerfd: u32,
    pub(super) timer_arm: u32,
    pub(super) poll: u32,
}

/// Called by the launcher-owned namespace init (PID 1). Fork the direct target.
/// The target child returns to the caller and continues into stdio/rlimit/
/// capability/seccomp/exec setup. PID 1 instead supervises the direct target,
/// optionally enforces a monotonic wall-clock deadline, kills and reaps every
/// remaining descendant, publishes the target lifecycle, and exits without
/// ever inheriting the target seccomp policy.
pub(super) unsafe fn become_direct_target_or_reap(
    lifecycle: *mut TargetLifecycleRecord,
    launch_error: *mut LaunchErrorRecord,
    wall_clock_milliseconds: u64,
    phases: TargetSupervisionPhases,
) {
    let pid = libc::syscall(libc::SYS_fork);
    if pid == -1 {
        fail(launch_error, phases.fork);
    }
    if pid == 0 {
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

    let (direct_status, timed_out) = wait_direct_target(
        pid,
        wall_clock_milliseconds,
        launch_error,
        phases,
    );
    let reaped_descendants = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);

    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).status), direct_status);
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).reaped_descendants),
        reaped_descendants,
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).timed_out),
        u32::from(timed_out),
    );
    // Publish readiness last: the host treats ready != 1 as an incomplete
    // process-tree lifecycle and fails closed.
    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).ready), 1);
    raw_exit(0)
}

unsafe fn wait_direct_target(
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

unsafe fn wait_specific_nohang(pid: libc::pid_t) -> Result<Option<libc::c_int>, i32> {
    loop {
        let mut status = 0;
        let waited = libc::syscall(
            libc::SYS_wait4,
            pid,
            &mut status as *mut libc::c_int,
            libc::WNOHANG,
            ptr::null_mut::<libc::rusage>(),
        );
        if waited == pid as libc::c_long {
            return Ok(Some(status));
        }
        if waited == 0 {
            return Ok(None);
        }
        if waited == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
    }
}

'''
text = text[:start] + new_block + text[end:]
path.write_text(text)

# linux.rs
path = Path("src/platform/linux.rs")
text = path.read_text()
text = replace_once(
    text,
    "        self, LaunchErrorRecord, SharedTargetLifecycle, TargetLifecycleRecord,\n",
    "        self, LaunchErrorRecord, SharedTargetLifecycle, TargetLifecycleRecord,\n"
    "        TargetSupervisionPhases,\n",
    "linux lifecycle import",
)
text = replace_once(
    text,
    "    const PHASE_PID_INIT_WAIT: u32 = 33;\n",
    "    const PHASE_PID_INIT_WAIT: u32 = 33;\n"
    "    const PHASE_DEADLINE_PIDFD: u32 = 34;\n"
    "    const PHASE_DEADLINE_TIMERFD: u32 = 35;\n"
    "    const PHASE_DEADLINE_TIMER_ARM: u32 = 36;\n"
    "    const PHASE_DEADLINE_POLL: u32 = 37;\n",
    "linux deadline phases",
)
text = replace_once(
    text,
    "        capture_write_fd: RawFd,\n    }\n",
    "        capture_write_fd: RawFd,\n"
    "        wall_clock_milliseconds: u64,\n"
    "    }\n",
    "child control deadline",
)
text = replace_once(
    text,
    "        ensure_fd_sanitization_supported()?;\n        let prepared = PreparedLaunch::new(policy)?;\n",
    "        ensure_fd_sanitization_supported()?;\n"
    "        ensure_deadline_support(policy.wall_clock_milliseconds)?;\n"
    "        let prepared = PreparedLaunch::new(policy)?;\n",
    "deadline preflight call",
)
text = replace_once(
    text,
    "            capture_write_fd,\n        };\n",
    "            capture_write_fd,\n"
    "            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),\n"
    "        };\n",
    "child control deadline init",
)
text = replace_once(
    text,
    "            capture_read_fd,\n            capture_write_fd,\n        } = control;\n",
    "            capture_read_fd,\n"
    "            capture_write_fd,\n"
    "            wall_clock_milliseconds,\n"
    "        } = control;\n",
    "child control deadline destructure",
)
text = replace_once(
    text,
    "        pid_lifecycle::become_direct_target_or_reap(\n            target_lifecycle,\n            launch_error,\n            PHASE_TARGET_FORK,\n            PHASE_PROCESS_TREE_KILL,\n            PHASE_PROCESS_TREE_REAP,\n            PHASE_FD_SANITIZE,\n        );\n",
    "        pid_lifecycle::become_direct_target_or_reap(\n"
    "            target_lifecycle,\n"
    "            launch_error,\n"
    "            wall_clock_milliseconds,\n"
    "            TargetSupervisionPhases {\n"
    "                fork: PHASE_TARGET_FORK,\n"
    "                kill: PHASE_PROCESS_TREE_KILL,\n"
    "                reap: PHASE_PROCESS_TREE_REAP,\n"
    "                close: PHASE_FD_SANITIZE,\n"
    "                pidfd: PHASE_DEADLINE_PIDFD,\n"
    "                timerfd: PHASE_DEADLINE_TIMERFD,\n"
    "                timer_arm: PHASE_DEADLINE_TIMER_ARM,\n"
    "                poll: PHASE_DEADLINE_POLL,\n"
    "            },\n"
    "        );\n",
    "lifecycle deadline call",
)
text = replace_once(
    text,
    "        let outcome = decode_wait_status(lifecycle_record.status)?;\n",
    "        let outcome = match lifecycle_record.timed_out {\n"
    "            0 => decode_wait_status(lifecycle_record.status)?,\n"
    "            1 => ChildOutcome::TimedOut,\n"
    "            value => {\n"
    "                return Err(SandboxError::SetupFailed(format!(\n"
    "                    \"PID namespace lifecycle published invalid timeout flag {value}\"\n"
    "                )));\n"
    "            }\n"
    "        };\n",
    "host timeout outcome",
)
insert_anchor = "    fn compile_seccomp(policy: &SandboxPolicy) -> Result<CompiledSeccomp, SandboxError> {\n"
if text.count(insert_anchor) != 1:
    raise SystemExit("deadline support insertion anchor mismatch")
preflight = r'''    fn ensure_deadline_support(deadline: Option<u64>) -> Result<(), SandboxError> {
        if deadline.is_none() {
            return Ok(());
        }

        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
        if pidfd == -1 {
            return Err(deadline_support_error("pidfd_open", io::Error::last_os_error()));
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

'''
text = text.replace(insert_anchor, preflight + insert_anchor, 1)
text = replace_once(
    text,
    "            PHASE_PID_INIT_WAIT => \"PID namespace init wait\",\n",
    "            PHASE_PID_INIT_WAIT => \"PID namespace init wait\",\n"
    "            PHASE_DEADLINE_PIDFD => \"wall-clock deadline pidfd supervision\",\n"
    "            PHASE_DEADLINE_TIMERFD => \"wall-clock deadline timer creation\",\n"
    "            PHASE_DEADLINE_TIMER_ARM => \"wall-clock deadline timer arming\",\n"
    "            PHASE_DEADLINE_POLL => \"wall-clock deadline supervision poll\",\n",
    "deadline phase formatting",
)
path.write_text(text)

# tests/sandbox.rs
path = Path("tests/sandbox.rs")
text = path.read_text()
text = replace_once(
    text,
    "        stdout_capture_bytes: None,\n        limits: ResourceLimits {\n",
    "        stdout_capture_bytes: None,\n"
    "        wall_clock_milliseconds: None,\n"
    "        limits: ResourceLimits {\n",
    "test policy deadline field",
)
text = replace_once(
    text,
    "    #[test]\nfn forbidden_syscall_is_denied_with_eperm() {",
    "    #[test]\n"
    "fn wall_clock_deadline_terminates_process_tree_and_releases_capture() {\n"
    "    let mut deadline = policy(\n"
    "        \"Q\",\n"
    "        &[],\n"
    "        &[\"execveat\", \"write\", \"fork\", \"nanosleep\", \"pause\", \"exit\"],\n"
    "    );\n"
    "    deadline.wall_clock_milliseconds = Some(1000);\n"
    "    deadline.stdio.stdout = StdioMode::Capture;\n"
    "    deadline.stdout_capture_bytes = Some(4096);\n\n"
    "    let report = run_report(&deadline).unwrap();\n"
    "    assert_eq!(report.outcome, ChildOutcome::TimedOut);\n"
    "    assert_eq!(report.reaped_descendants, 1);\n"
    "    let stdout = report.stdout.expect(\"capture result must be present\");\n"
    "    assert_eq!(stdout.bytes, b\"deadline target started\\n\");\n"
    "    assert!(!stdout.truncated);\n"
    "}\n\n"
    "#[test]\n"
    "fn natural_target_exit_wins_before_wall_clock_deadline() {\n"
    "    let mut natural = policy(\"X\", &[], &[\"execveat\", \"exit\"]);\n"
    "    natural.wall_clock_milliseconds = Some(5000);\n"
    "    assert_eq!(run(&natural).unwrap(), ChildOutcome::Exited(42));\n"
    "}\n\n"
    "#[test]\nfn forbidden_syscall_is_denied_with_eperm() {",
    "deadline integration tests",
)
path.write_text(text)

# probe.S
path = Path("tests/fixtures/probe.S")
text = path.read_text()
text = replace_once(
    text,
    "#   Z fork a live descendant that must be killed/reaped by namespace init\n",
    "#   Z fork a live descendant that must be killed/reaped by namespace init\n"
    "#   Q emit a marker, fork a descendant, then remain live past the policy deadline\n",
    "probe deadline comment",
)
text = replace_once(
    text,
    "    cmp $90, %al\n    je .live_descendant\n    jmp .fail2\n",
    "    cmp $90, %al\n"
    "    je .live_descendant\n"
    "    cmp $81, %al\n"
    "    je .deadline_tree\n"
    "    jmp .fail2\n",
    "probe deadline dispatch",
)
text = replace_once(
    text,
    ".descendant_pause:\n    mov $34, %eax\n    syscall\n    jmp .descendant_pause\n\n.str_eq:\n",
    ".descendant_pause:\n"
    "    mov $34, %eax\n"
    "    syscall\n"
    "    jmp .descendant_pause\n\n"
    ".deadline_tree:\n"
    "    mov $1, %eax\n"
    "    mov $1, %edi\n"
    "    lea deadline_message(%rip), %rsi\n"
    "    mov $deadline_message_len, %edx\n"
    "    syscall\n"
    "    cmp $deadline_message_len, %rax\n"
    "    jne .fail25\n\n"
    "    mov $57, %eax\n"
    "    syscall\n"
    "    test %rax, %rax\n"
    "    js .fail25\n"
    "    jz .deadline_descendant_pause\n\n"
    "    lea deadline_watchdog_sleep(%rip), %rdi\n"
    "    xor %esi, %esi\n"
    "    mov $35, %eax\n"
    "    syscall\n"
    "    test %rax, %rax\n"
    "    js .fail25\n"
    "    mov $99, %edi\n"
    "    jmp .exit\n\n"
    ".deadline_descendant_pause:\n"
    "    mov $34, %eax\n"
    "    syscall\n"
    "    jmp .deadline_descendant_pause\n\n"
    ".str_eq:\n",
    "probe deadline behavior",
)
text = replace_once(
    text,
    ".fail24:\n    mov $24, %edi\n\n.exit:\n",
    ".fail24:\n"
    "    mov $24, %edi\n"
    "    jmp .exit\n"
    ".fail25:\n"
    "    mov $25, %edi\n\n"
    ".exit:\n",
    "probe deadline failure",
)
text = replace_once(
    text,
    "capture_chunk:\n    .ascii \"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\"\n",
    "capture_chunk:\n"
    "    .ascii \"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\"\n"
    "deadline_message:\n"
    "    .ascii \"deadline target started\\n\"\n"
    ".set deadline_message_len, . - deadline_message\n"
    ".balign 8\n"
    "deadline_watchdog_sleep:\n"
    "    .quad 5\n"
    "    .quad 0\n",
    "probe deadline data",
)
path.write_text(text)
