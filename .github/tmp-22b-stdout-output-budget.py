from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, addition: str, label: str) -> None:
    replace_one(path, marker, addition + marker, label)


# Policy surface: an optional observed total-output budget, separate from retained bytes.
replace_one(
    "src/policy.rs",
    "const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;\nconst MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;",
    "const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;\nconst MAX_STDOUT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;\nconst MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;",
    "policy total-output constant",
)
replace_one(
    "src/policy.rs",
    "    pub stdout_capture_bytes: Option<u64>,\n    /// Optional launcher-owned wall-clock deadline measured from PID 1",
    "    pub stdout_capture_bytes: Option<u64>,\n    /// Optional total number of stdout bytes the launcher may observe before\n    /// requesting launcher-owned process-tree termination. This is distinct\n    /// from the retained capture-memory ceiling.\n    pub stdout_total_bytes: Option<u64>,\n    /// Optional launcher-owned wall-clock deadline measured from PID 1",
    "policy stdout total field",
)
insert_before(
    "src/policy.rs",
    "        match self.stdio.stdout {\n",
    "        if self.stdio.stdout != StdioMode::Capture && self.stdout_total_bytes.is_some() {\n            return Err(PolicyError::new(\n                \"limit.stdout_total_bytes is only valid when stdio.stdout = capture\",\n            ));\n        }\n\n",
    "policy stdout total mode validation",
)
replace_one(
    "src/policy.rs",
    "                if !(MIN_CAPTURE_BYTES..=MAX_CAPTURE_BYTES).contains(&bytes) {\n                    return Err(PolicyError::new(format!(\n                        \"stdio.stdout_capture_bytes must be between {MIN_CAPTURE_BYTES} and {MAX_CAPTURE_BYTES}\"\n                    )));\n                }\n",
    "                if !(MIN_CAPTURE_BYTES..=MAX_CAPTURE_BYTES).contains(&bytes) {\n                    return Err(PolicyError::new(format!(\n                        \"stdio.stdout_capture_bytes must be between {MIN_CAPTURE_BYTES} and {MAX_CAPTURE_BYTES}\"\n                    )));\n                }\n                if let Some(total_bytes) = self.stdout_total_bytes {\n                    if !(MIN_CAPTURE_BYTES..=MAX_STDOUT_TOTAL_BYTES).contains(&total_bytes) {\n                        return Err(PolicyError::new(format!(\n                            \"limit.stdout_total_bytes must be between {MIN_CAPTURE_BYTES} and {MAX_STDOUT_TOTAL_BYTES}\"\n                        )));\n                    }\n                    if bytes > total_bytes {\n                        return Err(PolicyError::new(\n                            \"stdio.stdout_capture_bytes must not exceed limit.stdout_total_bytes\",\n                        ));\n                    }\n                }\n",
    "policy stdout total range validation",
)
replace_one(
    "src/policy.rs",
    "        let mut stdout_capture_bytes = None;\n        let mut wall_clock_milliseconds = None;",
    "        let mut stdout_capture_bytes = None;\n        let mut stdout_total_bytes = None;\n        let mut wall_clock_milliseconds = None;",
    "policy parser stdout total variable",
)
replace_one(
    "src/policy.rs",
    "                \"limit.wall_clock_milliseconds\" => set_once(\n                    &mut wall_clock_milliseconds,",
    "                \"limit.stdout_total_bytes\" => set_once(\n                    &mut stdout_total_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"limit.wall_clock_milliseconds\" => set_once(\n                    &mut wall_clock_milliseconds,",
    "policy parser stdout total key",
)
replace_one(
    "src/policy.rs",
    "            stdout_capture_bytes,\n            wall_clock_milliseconds,",
    "            stdout_capture_bytes,\n            stdout_total_bytes,\n            wall_clock_milliseconds,",
    "policy construction stdout total",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.stdout_capture_bytes, None);\n        assert_eq!(policy.wall_clock_milliseconds, None);",
    "        assert_eq!(policy.stdout_capture_bytes, None);\n        assert_eq!(policy.stdout_total_bytes, None);\n        assert_eq!(policy.wall_clock_milliseconds, None);",
    "policy default stdout total assertion",
)
insert_before(
    "src/policy.rs",
    "    #[test]\n    fn parses_wall_clock_deadline() {\n",
    "    #[test]\n    fn parses_and_bounds_stdout_total_budget() {\n        let text = VALID.replace(\n            \"stdio.stdout = inherit\",\n            \"stdio.stdout = capture\\n        stdio.stdout_capture_bytes = 1024\\n        limit.stdout_total_bytes = 65536\",\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.stdout_capture_bytes, Some(1024));\n        assert_eq!(policy.stdout_total_bytes, Some(65536));\n\n        let wrong_mode = format!(\"{VALID}\\nlimit.stdout_total_bytes = 4096\");\n        assert!(wrong_mode.parse::<SandboxPolicy>().is_err());\n\n        let zero = VALID.replace(\n            \"stdio.stdout = inherit\",\n            \"stdio.stdout = capture\\n        stdio.stdout_capture_bytes = 1\\n        limit.stdout_total_bytes = 0\",\n        );\n        assert!(zero.parse::<SandboxPolicy>().is_err());\n\n        let retained_exceeds_total = VALID.replace(\n            \"stdio.stdout = inherit\",\n            \"stdio.stdout = capture\\n        stdio.stdout_capture_bytes = 4096\\n        limit.stdout_total_bytes = 1024\",\n        );\n        assert!(retained_exceeds_total.parse::<SandboxPolicy>().is_err());\n\n        let oversized = VALID.replace(\n            \"stdio.stdout = inherit\",\n            &format!(\n                \"stdio.stdout = capture\\n        stdio.stdout_capture_bytes = 1\\n        limit.stdout_total_bytes = {}\",\n                MAX_STDOUT_TOTAL_BYTES + 1\n            ),\n        );\n        assert!(oversized.parse::<SandboxPolicy>().is_err());\n    }\n\n",
    "policy stdout total tests",
)

# Public result surface.
replace_one(
    "src/report.rs",
    "    Cancelled,\n}",
    "    Cancelled,\n    /// The host capture path observed stdout beyond the declared total-output\n    /// budget and requested launcher-owned process-tree termination.\n    OutputLimitExceeded,\n}",
    "report output limit variant",
)
replace_one(
    "src/report.rs",
    "            Self::Cancelled => f.write_str(\"cancelled\"),\n",
    "            Self::Cancelled => f.write_str(\"cancelled\"),\n            Self::OutputLimitExceeded => f.write_str(\"stdout output limit exceeded\"),\n",
    "report output limit display",
)

# CLI/JSON output mapping for the new observable outcome.
replace_one(
    "src/cli_json.rs",
    "        ChildOutcome::Cancelled => 130,\n",
    "        ChildOutcome::Cancelled => 130,\n        ChildOutcome::OutputLimitExceeded => 122,\n",
    "cli output limit exit code",
)
replace_one(
    "src/cli_json.rs",
    "        ChildOutcome::Cancelled => output.push_str(\"{\\\"kind\\\":\\\"cancelled\\\"}\"),\n",
    "        ChildOutcome::Cancelled => output.push_str(\"{\\\"kind\\\":\\\"cancelled\\\"}\"),\n        ChildOutcome::OutputLimitExceeded => {\n            output.push_str(\"{\\\"kind\\\":\\\"output_limit_exceeded\\\"}\")\n        }\n",
    "cli output limit json",
)
replace_one(
    "src/cli_json.rs",
    "        assert_eq!(outcome_exit_code(ChildOutcome::Cancelled), 130);\n",
    "        assert_eq!(outcome_exit_code(ChildOutcome::Cancelled), 130);\n        assert_eq!(outcome_exit_code(ChildOutcome::OutputLimitExceeded), 122);\n",
    "cli output limit exit test",
)
insert_before(
    "src/cli_json.rs",
    "    #[test]\n    fn escapes_json_error_strings() {\n",
    "    #[test]\n    fn serializes_stdout_output_limit_outcome() {\n        let report = RunReport {\n            outcome: ChildOutcome::OutputLimitExceeded,\n            stdout: Some(CapturedOutput {\n                bytes: b\"prefix\".to_vec(),\n                truncated: true,\n            }),\n            reaped_descendants: 1,\n            process_tree_usage: ProcessTreeUsage::default(),\n        };\n        assert!(report_json(&report).contains(\"\\\"kind\\\":\\\"output_limit_exceeded\\\"\"));\n    }\n\n",
    "cli output limit json test",
)

# PID1 lifecycle: output-overrun is a launcher control event with explicit precedence.
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    pub(super) cancelled: u32,\n    pub(super) user_cpu_micros: u64,",
    "    pub(super) cancelled: u32,\n    pub(super) output_limit_exceeded: u32,\n    pub(super) user_cpu_micros: u64,",
    "lifecycle output flag field",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "                    cancelled: 0,\n                    user_cpu_micros: 0,",
    "                    cancelled: 0,\n                    output_limit_exceeded: 0,\n                    user_cpu_micros: 0,",
    "lifecycle output flag init",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    pub(super) cancellation_poll: u32,\n    pub(super) usage: u32,",
    "    pub(super) cancellation_poll: u32,\n    pub(super) output_limit_pidfd: u32,\n    pub(super) output_limit_poll: u32,\n    pub(super) usage: u32,",
    "lifecycle output phases",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    cancellation_fd: libc::c_int,\n    phases: TargetSupervisionPhases,",
    "    cancellation_fd: libc::c_int,\n    output_limit_fd: libc::c_int,\n    phases: TargetSupervisionPhases,",
    "lifecycle direct target output fd arg",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    if pid == 0 {\n        if cancellation_fd >= 3 && libc::close(cancellation_fd) == -1 {\n            fail(launch_error, phases.close);\n        }\n        return;\n    }",
    "    if pid == 0 {\n        for control_fd in [cancellation_fd, output_limit_fd] {\n            if control_fd >= 3 && libc::close(control_fd) == -1 {\n                fail(launch_error, phases.close);\n            }\n        }\n        return;\n    }",
    "lifecycle target control fd close",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    if let Err(errno) = close_nonstdio_except(cancellation_fd) {",
    "    if let Err(errno) = close_nonstdio_except(cancellation_fd, output_limit_fd) {",
    "lifecycle pid1 retained controls",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    let (direct_status, timed_out, cancelled) = wait_direct_target(\n        pid,\n        wall_clock_milliseconds,\n        cancellation_fd,\n        launch_error,\n        phases,\n    );",
    "    let (direct_status, timed_out, cancelled, output_limit_exceeded) = wait_direct_target(\n        pid,\n        wall_clock_milliseconds,\n        cancellation_fd,\n        output_limit_fd,\n        launch_error,\n        phases,\n    );",
    "lifecycle wait tuple",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).cancelled),\n        u32::from(cancelled),\n    );\n",
    "    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).cancelled),\n        u32::from(cancelled),\n    );\n    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).output_limit_exceeded),\n        u32::from(output_limit_exceeded),\n    );\n",
    "lifecycle publish output flag",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    cancellation_fd: libc::c_int,\n    launch_error: *mut LaunchErrorRecord,\n    phases: TargetSupervisionPhases,\n) -> (libc::c_int, bool, bool) {\n    if wall_clock_milliseconds == 0 && cancellation_fd < 0 {\n        return match wait_specific(pid) {\n            Ok(status) => (status, false, false),",
    "    cancellation_fd: libc::c_int,\n    output_limit_fd: libc::c_int,\n    launch_error: *mut LaunchErrorRecord,\n    phases: TargetSupervisionPhases,\n) -> (libc::c_int, bool, bool, bool) {\n    if wall_clock_milliseconds == 0 && cancellation_fd < 0 && output_limit_fd < 0 {\n        return match wait_specific(pid) {\n            Ok(status) => (status, false, false, false),",
    "lifecycle wait signature",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "        let phase = if cancellation_fd >= 0 {\n            phases.cancellation_pidfd\n        } else {\n            phases.pidfd\n        };",
    "        let phase = if output_limit_fd >= 0 {\n            phases.output_limit_pidfd\n        } else if cancellation_fd >= 0 {\n            phases.cancellation_pidfd\n        } else {\n            phases.pidfd\n        };",
    "lifecycle pidfd phase",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "        libc::pollfd {\n            fd: cancellation_fd,\n            events: libc::POLLIN,\n            revents: 0,\n        },\n    ];",
    "        libc::pollfd {\n            fd: cancellation_fd,\n            events: libc::POLLIN,\n            revents: 0,\n        },\n        libc::pollfd {\n            fd: output_limit_fd,\n            events: libc::POLLIN,\n            revents: 0,\n        },\n    ];",
    "lifecycle output pollfd",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "            let phase = if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };",
    "            let phase = if output_limit_fd >= 0 {\n                phases.output_limit_poll\n            } else if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };",
    "lifecycle poll error phase",
)
# There are two identical phase-selection blocks: replace the remaining one for invalid poll events.
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "            let phase = if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };",
    "            let phase = if output_limit_fd >= 0 {\n                phases.output_limit_poll\n            } else if cancellation_fd >= 0 {\n                phases.cancellation_poll\n            } else {\n                phases.poll\n            };",
    "lifecycle invalid poll phase",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "        // One nonblocking reap check is the race arbiter. If the direct target\n        // was already waitable when supervision woke, natural termination wins.\n        match wait_specific_nohang(pid) {",
    "        // Once the host has observed bytes beyond the output budget, that\n        // policy violation owns the result even if the target became waitable\n        // in the same poll cycle. Other control paths preserve natural-exit-first.\n        if fds[3].revents & libc::POLLIN != 0 {\n            let status = terminate_direct_target(pid, launch_error, phases);\n            return (status, false, false, true);\n        }\n\n        // One nonblocking reap check remains the race arbiter for ordinary\n        // cancellation/deadline supervision.\n        match wait_specific_nohang(pid) {",
    "lifecycle output precedence",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "            Ok(Some(status)) => return (status, false, false),",
    "            Ok(Some(status)) => return (status, false, false, false),",
    "lifecycle natural return tuple",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "            return (status, false, true);",
    "            return (status, false, true, false);",
    "lifecycle cancellation tuple",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "            return (status, true, false);",
    "            return (status, true, false, false);",
    "lifecycle deadline tuple",
)
# Replace the one-control close helper with a two-control range-safe helper.
start = Path("src/platform/linux_pid_lifecycle.rs").read_text().index(
    "unsafe fn close_nonstdio_except(keep_fd: libc::c_int) -> Result<(), i32> {"
)
end_marker = "\nunsafe fn wait_specific_nohang("
text = Path("src/platform/linux_pid_lifecycle.rs").read_text()
end = text.index(end_marker, start)
new_helper = '''unsafe fn close_nonstdio_except(
    keep_a: libc::c_int,
    keep_b: libc::c_int,
) -> Result<(), i32> {
    let mut keep = [keep_a, keep_b];
    keep.sort_unstable();
    let mut cursor = 3u64;
    let mut previous = -1;
    for fd in keep {
        if fd < 3 || fd == previous {
            continue;
        }
        previous = fd;
        let keep_fd = fd as u32;
        if cursor < u64::from(keep_fd)
            && libc::syscall(
                libc::SYS_close_range,
                cursor as u32,
                keep_fd - 1,
                0u32,
            ) == -1
        {
            return Err(*libc::__errno_location());
        }
        cursor = u64::from(keep_fd) + 1;
    }
    if cursor <= u64::from(u32::MAX)
        && libc::syscall(
            libc::SYS_close_range,
            cursor as u32,
            u32::MAX,
            0u32,
        ) == -1
    {
        return Err(*libc::__errno_location());
    }
    Ok(())
}
'''
Path("src/platform/linux_pid_lifecycle.rs").write_text(text[:start] + new_helper + text[end:])

# Linux host/PID1 glue.
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_PROCESS_TREE_USAGE: u32 = 53;\n",
    "    const PHASE_PROCESS_TREE_USAGE: u32 = 53;\n    const PHASE_OUTPUT_LIMIT_PIDFD: u32 = 54;\n    const PHASE_OUTPUT_LIMIT_POLL: u32 = 55;\n",
    "linux output phases",
)
replace_one(
    "src/platform/linux.rs",
    "        capture_write_fd: RawFd,\n        wall_clock_milliseconds: u64,",
    "        capture_write_fd: RawFd,\n        output_limit_fd: RawFd,\n        wall_clock_milliseconds: u64,",
    "linux child control output fd",
)
replace_one(
    "src/platform/linux.rs",
    "        ensure_supervision_support(policy.wall_clock_milliseconds, cancellation.is_some())?;",
    "        ensure_supervision_support(\n            policy.wall_clock_milliseconds,\n            cancellation.is_some(),\n            policy.stdout_total_bytes.is_some(),\n        )?;",
    "linux output supervision preflight",
)
insert_before(
    "src/platform/linux.rs",
    "    pub(crate) fn run_report(\n",
    '''    fn create_output_limit_eventfd() -> Result<OwnedFd, SandboxError> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd == -1 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
            ) {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "stdout output-limit supervision requires eventfd support: {error}"
                )))
            } else {
                Err(SandboxError::SetupFailed(format!(
                    "cannot create stdout output-limit eventfd: {error}"
                )))
            };
        }
        move_parent_fd_above_stdio(OwnedFd(fd), "stdout output-limit eventfd")
    }

    fn signal_output_limit(fd: RawFd) -> Result<(), SandboxError> {
        if fd < FIRST_NON_STDIO_FD as RawFd {
            return Err(SandboxError::SetupFailed(
                "stdout output-limit eventfd is unavailable".to_owned(),
            ));
        }
        let value = 1u64;
        loop {
            let written = unsafe {
                libc::write(
                    fd,
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
                    "cannot signal stdout output-limit eventfd: {error}"
                )));
            }
            return Err(SandboxError::SetupFailed(
                "stdout output-limit eventfd accepted a short write".to_owned(),
            ));
        }
    }

''',
    "linux output event helpers",
)
replace_one(
    "src/platform/linux.rs",
    "        let capture = if policy.stdio.stdout == StdioMode::Capture {",
    "        let output_limit_event = policy\n            .stdout_total_bytes\n            .map(|_| create_output_limit_eventfd())\n            .transpose()?;\n        let output_limit_fd = output_limit_event.as_ref().map_or(-1, |fd| fd.raw());\n        let capture = if policy.stdio.stdout == StdioMode::Capture {",
    "linux create output event",
)
replace_one(
    "src/platform/linux.rs",
    "            capture_read_fd,\n            capture_write_fd,\n            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),",
    "            capture_read_fd,\n            capture_write_fd,\n            output_limit_fd,\n            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),",
    "linux child control init output fd",
)
replace_one(
    "src/platform/linux.rs",
    "            let result = read_capture(read_fd.raw(), limit);",
    "            let result = read_capture(\n                read_fd.raw(),\n                limit,\n                policy.stdout_total_bytes,\n                output_limit_fd,\n            );",
    "linux read capture output args",
)
replace_one(
    "src/platform/linux.rs",
    "        let stdout = match capture_result {\n            Some(result) => Some(result?),\n            None => None,\n        };\n        let outcome = match (lifecycle_record.timed_out, lifecycle_record.cancelled) {\n            (0, 0) => decode_wait_status(lifecycle_record.status)?,\n            (1, 0) => ChildOutcome::TimedOut,\n            (0, 1) => ChildOutcome::Cancelled,\n            (timed_out, cancelled) => {\n                return Err(SandboxError::SetupFailed(format!(\n                    \"PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}\"\n                )));\n            }\n        };",
    "        let (stdout, output_limit_observed) = match capture_result {\n            Some(result) => {\n                let (captured, exceeded) = result?;\n                (Some(captured), exceeded)\n            }\n            None => (None, false),\n        };\n        let control_flags = lifecycle_record.timed_out\n            + lifecycle_record.cancelled\n            + lifecycle_record.output_limit_exceeded;\n        if control_flags > 1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"PID namespace lifecycle published conflicting termination flags timed_out={} cancelled={} output_limit_exceeded={}\",\n                lifecycle_record.timed_out,\n                lifecycle_record.cancelled,\n                lifecycle_record.output_limit_exceeded\n            )));\n        }\n        let outcome = if output_limit_observed || lifecycle_record.output_limit_exceeded == 1 {\n            ChildOutcome::OutputLimitExceeded\n        } else {\n            match (lifecycle_record.timed_out, lifecycle_record.cancelled) {\n                (0, 0) => decode_wait_status(lifecycle_record.status)?,\n                (1, 0) => ChildOutcome::TimedOut,\n                (0, 1) => ChildOutcome::Cancelled,\n                (timed_out, cancelled) => {\n                    return Err(SandboxError::SetupFailed(format!(\n                        \"PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}\"\n                    )));\n                }\n            }\n        };",
    "linux decode output outcome",
)
# Replace capture reader with observed-total-budget semantics.
path = Path("src/platform/linux.rs")
text = path.read_text()
start = text.index("    fn read_capture(fd: RawFd, limit: usize) -> Result<CapturedOutput, SandboxError> {")
end = text.index("\n    fn cstring_bytes(", start)
new_reader = '''    fn read_capture(
        fd: RawFd,
        retain_limit: usize,
        total_limit: Option<u64>,
        output_limit_fd: RawFd,
    ) -> Result<(CapturedOutput, bool), SandboxError> {
        let mut bytes = Vec::with_capacity(retain_limit.min(8192));
        let mut truncated = false;
        let mut observed = 0u64;
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
            observed = observed.saturating_add(read as u64);
            let remaining = retain_limit.saturating_sub(bytes.len());
            let retained = remaining.min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            if retained < read {
                truncated = true;
            }

            if total_limit.is_some_and(|limit| observed > limit) {
                signal_output_limit(output_limit_fd)?;
                return Ok((CapturedOutput { bytes, truncated }, true));
            }
        }

        Ok((CapturedOutput { bytes, truncated }, false))
    }
'''
path.write_text(text[:start] + new_reader + text[end:])
replace_one(
    "src/platform/linux.rs",
    "            capture_write_fd,\n            wall_clock_milliseconds,\n        } = control;",
    "            capture_write_fd,\n            output_limit_fd,\n            wall_clock_milliseconds,\n        } = control;",
    "linux child destructure output fd",
)
replace_one(
    "src/platform/linux.rs",
    "            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),\n            TargetSupervisionPhases {",
    "            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),\n            output_limit_fd,\n            TargetSupervisionPhases {",
    "linux lifecycle output fd call",
)
replace_one(
    "src/platform/linux.rs",
    "                cancellation_poll: PHASE_CANCELLATION_POLL,\n                usage: PHASE_PROCESS_TREE_USAGE,",
    "                cancellation_poll: PHASE_CANCELLATION_POLL,\n                output_limit_pidfd: PHASE_OUTPUT_LIMIT_PIDFD,\n                output_limit_poll: PHASE_OUTPUT_LIMIT_POLL,\n                usage: PHASE_PROCESS_TREE_USAGE,",
    "linux lifecycle output phases init",
)
replace_one(
    "src/platform/linux.rs",
    "    fn ensure_supervision_support(\n        deadline: Option<u64>,\n        cancellable: bool,\n    ) -> Result<(), SandboxError> {\n        if deadline.is_none() && !cancellable {",
    "    fn ensure_supervision_support(\n        deadline: Option<u64>,\n        cancellable: bool,\n        output_limited: bool,\n    ) -> Result<(), SandboxError> {\n        if deadline.is_none() && !cancellable && !output_limited {",
    "linux supervision signature",
)
replace_one(
    "src/platform/linux.rs",
    "        let purpose = match (deadline.is_some(), cancellable) {\n            (true, true) => \"deadline/cancellation supervision\",\n            (true, false) => \"wall-clock deadline\",\n            (false, true) => \"external cancellation\",\n            (false, false) => unreachable!(),\n        };",
    "        let purpose = if output_limited {\n            \"stdout output-limit supervision\"\n        } else {\n            match (deadline.is_some(), cancellable) {\n                (true, true) => \"deadline/cancellation supervision\",\n                (true, false) => \"wall-clock deadline\",\n                (false, true) => \"external cancellation\",\n                (false, false) => unreachable!(),\n            }\n        };",
    "linux supervision purpose",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_LANDLOCK_NET_RULE => \"Landlock TCP port rule installation\",\n            PHASE_PROCESS_TREE_USAGE => \"process-tree resource usage collection\",",
    "            PHASE_LANDLOCK_NET_RULE => \"Landlock TCP port rule installation\",\n            PHASE_PROCESS_TREE_USAGE => \"process-tree resource usage collection\",\n            PHASE_OUTPUT_LIMIT_PIDFD => \"stdout output-limit pidfd supervision\",\n            PHASE_OUTPUT_LIMIT_POLL => \"stdout output-limit supervision poll\",",
    "linux output phase labels",
)

# Deterministic raw target: one paused descendant plus an unbounded stdout writer.
replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\n",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\n#   g fork a paused descendant and continuously emit stdout until launcher output budget terminates the tree\n",
    "fixture output mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $99, %al\n    je .cancellation_tree\n",
    "    cmp $99, %al\n    je .cancellation_tree\n    cmp $103, %al\n    je .stdout_output_budget_tree\n",
    "fixture output mode dispatch",
)
insert_before(
    "tests/fixtures/probe.S",
    ".cancellation_tree:\n",
    '''.stdout_output_budget_tree:
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail22
    jz .stdout_output_budget_descendant

.stdout_output_budget_write:
    mov $1, %eax
    mov $1, %edi
    lea capture_chunk(%rip), %rsi
    mov $64, %edx
    syscall
    cmp $64, %rax
    je .stdout_output_budget_write
.stdout_output_budget_parent_pause:
    mov $34, %eax
    syscall
    jmp .stdout_output_budget_parent_pause

.stdout_output_budget_descendant:
    mov $34, %eax
    syscall
    jmp .stdout_output_budget_descendant

''',
    "fixture output budget routine",
)

# Integration helper and executable evidence.
replace_one(
    "tests/sandbox.rs",
    "        stdout_capture_bytes: None,\n        wall_clock_milliseconds: None,",
    "        stdout_capture_bytes: None,\n        stdout_total_bytes: None,\n        wall_clock_milliseconds: None,",
    "sandbox helper stdout total",
)
insert_before(
    "tests/sandbox.rs",
    "#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n",
    '''#[test]
fn stdout_total_budget_owns_process_tree_teardown() {
    let mut limited = policy(
        "g",
        &[],
        &["execveat", "write", "fork", "pause", "exit"],
    );
    limited.stdio.stdout = StdioMode::Capture;
    limited.stdout_capture_bytes = Some(1024);
    limited.stdout_total_bytes = Some(4096);
    // Watchdog only bounds a broken regression; output-limit ownership should
    // win long before this timer becomes ready.
    limited.wall_clock_milliseconds = Some(5000);

    let report = run_report(&limited).expect("stdout-budget sandbox run failed");
    assert_eq!(report.outcome, ChildOutcome::OutputLimitExceeded);
    assert_eq!(report.reaped_descendants, 1);
    let captured = report.stdout.expect("capture result missing");
    assert_eq!(captured.bytes.len(), 1024);
    assert!(captured.truncated);
}

''',
    "sandbox output budget integration test",
)

# Existing capture test must remain an explicit backwards-compatibility oracle.
replace_one(
    "tests/sandbox.rs",
    "    captured.stdout_capture_bytes = Some(1024);\n",
    "    captured.stdout_capture_bytes = Some(1024);\n    assert_eq!(captured.stdout_total_bytes, None);\n",
    "sandbox unlimited capture compatibility",
)
