from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy model, validation, parser, and unit evidence.
replace_one(
    "src/policy.rs",
    "const MAX_STDOUT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;\nconst MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;",
    "const MAX_STDOUT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;\nconst MAX_TIME_OFFSET_SECONDS: u64 = 365 * 24 * 60 * 60;\nconst MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;",
    "time offset bound",
)
replace_one(
    "src/policy.rs",
    "    pub stdout_total_bytes: Option<u64>,\n    /// Optional launcher-owned wall-clock deadline measured from PID 1\n    /// beginning supervision of the direct target.\n    pub wall_clock_milliseconds: Option<u64>,",
    "    pub stdout_total_bytes: Option<u64>,\n    /// Optional nonnegative CLOCK_MONOTONIC/CLOCK_BOOTTIME offsets installed\n    /// for descendants in a dedicated Linux time namespace. The pair is\n    /// all-or-nothing and at least one offset must be non-zero.\n    pub time_monotonic_offset_seconds: Option<u64>,\n    pub time_boottime_offset_seconds: Option<u64>,\n    /// Optional launcher-owned wall-clock deadline measured from PID 1\n    /// beginning supervision of the direct target.\n    pub wall_clock_milliseconds: Option<u64>,",
    "policy time fields",
)
replace_one(
    "src/policy.rs",
    "        if let Some(milliseconds) = self.wall_clock_milliseconds {\n",
    "        match (\n            self.time_monotonic_offset_seconds,\n            self.time_boottime_offset_seconds,\n        ) {\n            (None, None) => {}\n            (Some(monotonic), Some(boottime)) => {\n                if monotonic > MAX_TIME_OFFSET_SECONDS || boottime > MAX_TIME_OFFSET_SECONDS {\n                    return Err(PolicyError::new(format!(\n                        \"time namespace offsets must be between 0 and {MAX_TIME_OFFSET_SECONDS} seconds\"\n                    )));\n                }\n                if monotonic == 0 && boottime == 0 {\n                    return Err(PolicyError::new(\n                        \"time namespace offsets must not both be zero\",\n                    ));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"time.monotonic_offset_seconds and time.boottime_offset_seconds must be specified together\",\n                ));\n            }\n        }\n\n        if let Some(milliseconds) = self.wall_clock_milliseconds {\n",
    "time offset validation",
)
replace_one(
    "src/policy.rs",
    "        let mut stdout_total_bytes = None;\n        let mut wall_clock_milliseconds = None;",
    "        let mut stdout_total_bytes = None;\n        let mut time_monotonic_offset_seconds = None;\n        let mut time_boottime_offset_seconds = None;\n        let mut wall_clock_milliseconds = None;",
    "parser time variables",
)
replace_one(
    "src/policy.rs",
    "                \"limit.stdout_total_bytes\" => set_once(\n                    &mut stdout_total_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"limit.wall_clock_milliseconds\" => set_once(",
    "                \"limit.stdout_total_bytes\" => set_once(\n                    &mut stdout_total_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"time.monotonic_offset_seconds\" => set_once(\n                    &mut time_monotonic_offset_seconds,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"time.boottime_offset_seconds\" => set_once(\n                    &mut time_boottime_offset_seconds,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"limit.wall_clock_milliseconds\" => set_once(",
    "parser time keys",
)
replace_one(
    "src/policy.rs",
    "            stdout_capture_bytes,\n            stdout_total_bytes,\n            wall_clock_milliseconds,",
    "            stdout_capture_bytes,\n            stdout_total_bytes,\n            time_monotonic_offset_seconds,\n            time_boottime_offset_seconds,\n            wall_clock_milliseconds,",
    "construct time fields",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.stdout_total_bytes, None);\n        assert_eq!(policy.wall_clock_milliseconds, None);",
    "        assert_eq!(policy.stdout_total_bytes, None);\n        assert_eq!(policy.time_monotonic_offset_seconds, None);\n        assert_eq!(policy.time_boottime_offset_seconds, None);\n        assert_eq!(policy.wall_clock_milliseconds, None);",
    "complete policy time defaults",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_landlock_read_execute_paths() {",
    "    #[test]\n    fn parses_time_namespace_offsets() {\n        let text = format!(\n            \"{VALID}\\ntime.monotonic_offset_seconds = 3600\\ntime.boottime_offset_seconds = 7200\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.time_monotonic_offset_seconds, Some(3600));\n        assert_eq!(policy.time_boottime_offset_seconds, Some(7200));\n    }\n\n    #[test]\n    fn rejects_incomplete_noop_or_oversized_time_namespace_offsets() {\n        for invalid in [\n            format!(\"{VALID}\\ntime.monotonic_offset_seconds = 3600\"),\n            format!(\"{VALID}\\ntime.boottime_offset_seconds = 7200\"),\n            format!(\"{VALID}\\ntime.monotonic_offset_seconds = 0\\ntime.boottime_offset_seconds = 0\"),\n            format!(\n                \"{VALID}\\ntime.monotonic_offset_seconds = {}\\ntime.boottime_offset_seconds = 0\",\n                MAX_TIME_OFFSET_SECONDS + 1\n            ),\n        ] {\n            assert!(invalid.parse::<SandboxPolicy>().is_err());\n        }\n    }\n\n    #[test]\n    fn parses_landlock_read_execute_paths() {",
    "time policy tests",
)

# Linux launcher: precompute offset records, create time namespace only when requested,
# install offsets after user/group mapping and before the first namespace child exists.
replace_one(
    "src/platform/linux.rs",
    "    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;\n",
    "    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;\n    const CLONE_NEWTIME: libc::c_int = 0x0000_0080;\n",
    "clone newtime constant",
)
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_OUTPUT_LIMIT_PIDFD: u32 = 54;\n    const PHASE_OUTPUT_LIMIT_POLL: u32 = 55;",
    "    const PHASE_OUTPUT_LIMIT_PIDFD: u32 = 54;\n    const PHASE_OUTPUT_LIMIT_POLL: u32 = 55;\n    const PHASE_TIME_OFFSETS: u32 = 56;",
    "time phase constant",
)
replace_one(
    "src/platform/linux.rs",
    "        gid_map: Vec<u8>,\n        hostname: Vec<u8>,\n        loopback_enabled: bool,",
    "        gid_map: Vec<u8>,\n        hostname: Vec<u8>,\n        time_monotonic_offset: Option<Vec<u8>>,\n        time_boottime_offset: Option<Vec<u8>>,\n        loopback_enabled: bool,",
    "prepared time fields",
)
replace_one(
    "src/platform/linux.rs",
    "            let hostname = policy.hostname.as_bytes().to_vec();\n\n            Ok(Self {",
    "            let hostname = policy.hostname.as_bytes().to_vec();\n            let (time_monotonic_offset, time_boottime_offset) = match (\n                policy.time_monotonic_offset_seconds,\n                policy.time_boottime_offset_seconds,\n            ) {\n                (Some(monotonic), Some(boottime)) => (\n                    Some(format!(\"monotonic {monotonic} 0\\n\").into_bytes()),\n                    Some(format!(\"boottime {boottime} 0\\n\").into_bytes()),\n                ),\n                (None, None) => (None, None),\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"time.monotonic_offset_seconds and time.boottime_offset_seconds must be specified together\",\n                    )));\n                }\n            };\n\n            Ok(Self {",
    "prepare time bytes",
)
replace_one(
    "src/platform/linux.rs",
    "                gid_map,\n                hostname,\n                loopback_enabled: policy.loopback_enabled,",
    "                gid_map,\n                hostname,\n                time_monotonic_offset,\n                time_boottime_offset,\n                loopback_enabled: policy.loopback_enabled,",
    "store time bytes",
)
replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(\n            libc::SYS_unshare,\n            libc::CLONE_NEWUSER\n                | libc::CLONE_NEWNS\n                | libc::CLONE_NEWPID\n                | libc::CLONE_NEWNET\n                | libc::CLONE_NEWIPC\n                | libc::CLONE_NEWUTS,\n        ) == -1\n",
    "        let mut namespace_flags = libc::CLONE_NEWUSER\n            | libc::CLONE_NEWNS\n            | libc::CLONE_NEWPID\n            | libc::CLONE_NEWNET\n            | libc::CLONE_NEWIPC\n            | libc::CLONE_NEWUTS;\n        if prepared.time_monotonic_offset.is_some() {\n            namespace_flags |= CLONE_NEWTIME;\n        }\n        if libc::syscall(libc::SYS_unshare, namespace_flags) == -1\n",
    "conditional time namespace",
)
replace_one(
    "src/platform/linux.rs",
    "        write_proc_file_or_fail(\n            b\"/proc/self/gid_map\\0\",\n            &prepared.gid_map,\n            launch_error,\n            PHASE_GID_MAP,\n            seccomp.error_exit_syscall,\n        );\n\n        if libc::syscall(\n",
    "        write_proc_file_or_fail(\n            b\"/proc/self/gid_map\\0\",\n            &prepared.gid_map,\n            launch_error,\n            PHASE_GID_MAP,\n            seccomp.error_exit_syscall,\n        );\n\n        if let (Some(monotonic), Some(boottime)) = (\n            &prepared.time_monotonic_offset,\n            &prepared.time_boottime_offset,\n        ) {\n            write_proc_file_or_fail(\n                b\"/proc/self/timens_offsets\\0\",\n                monotonic,\n                launch_error,\n                PHASE_TIME_OFFSETS,\n                seccomp.error_exit_syscall,\n            );\n            write_proc_file_or_fail(\n                b\"/proc/self/timens_offsets\\0\",\n                boottime,\n                launch_error,\n                PHASE_TIME_OFFSETS,\n                seccomp.error_exit_syscall,\n            );\n        }\n\n        if libc::syscall(\n",
    "install time offsets",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_OUTPUT_LIMIT_PIDFD => \"stdout output-limit pidfd supervision\",\n            PHASE_OUTPUT_LIMIT_POLL => \"stdout output-limit supervision poll\",\n            _ => \"unknown launch phase\",",
    "            PHASE_OUTPUT_LIMIT_PIDFD => \"stdout output-limit pidfd supervision\",\n            PHASE_OUTPUT_LIMIT_POLL => \"stdout output-limit supervision poll\",\n            PHASE_TIME_OFFSETS => \"time namespace offset installation\",\n            _ => \"unknown launch phase\",",
    "time phase name",
)

# Raw fixture mode `f`: emit binary timespecs for CLOCK_MONOTONIC and CLOCK_BOOTTIME.
replace_one(
    "tests/fixtures/probe.S",
    "#   g fork a paused descendant and continuously emit stdout until launcher output budget terminates the tree\n",
    "#   g fork a paused descendant and continuously emit stdout until launcher output budget terminates the tree\n#   f emit CLOCK_MONOTONIC and CLOCK_BOOTTIME timespecs for time-namespace evidence\n",
    "fixture time mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $103, %al\n    je .stdout_output_budget_tree\n    cmp $118, %al",
    "    cmp $103, %al\n    je .stdout_output_budget_tree\n    cmp $102, %al\n    je .time_namespace_clocks\n    cmp $118, %al",
    "fixture time dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".allowed:\n",
    ".time_namespace_clocks:\n    sub $32, %rsp\n\n    mov $228, %eax\n    mov $1, %edi\n    mov %rsp, %rsi\n    syscall\n    test %rax, %rax\n    js .fail29_time_stack\n\n    mov $228, %eax\n    mov $7, %edi\n    lea 16(%rsp), %rsi\n    syscall\n    test %rax, %rax\n    js .fail29_time_stack\n\n    mov $1, %eax\n    mov $1, %edi\n    mov %rsp, %rsi\n    mov $32, %edx\n    syscall\n    cmp $32, %rax\n    jne .fail29_time_stack\n    add $32, %rsp\n    xor %edi, %edi\n    jmp .exit\n\n.fail29_time_stack:\n    add $32, %rsp\n    jmp .fail29\n\n.allowed:\n",
    "fixture time oracle",
)

# Integration helper defaults and host/target clock oracle.
replace_one(
    "tests/sandbox.rs",
    "        stdout_capture_bytes: None,\n        stdout_total_bytes: None,\n        wall_clock_milliseconds: None,",
    "        stdout_capture_bytes: None,\n        stdout_total_bytes: None,\n        time_monotonic_offset_seconds: None,\n        time_boottime_offset_seconds: None,\n        wall_clock_milliseconds: None,",
    "integration policy time defaults",
)
replace_one(
    "tests/sandbox.rs",
    "fn assert_random_device_ioctl_available(path: &str) {",
    "fn clock_nanos(clock_id: libc::clockid_t) -> i128 {\n    let mut value = unsafe { std::mem::zeroed::<libc::timespec>() };\n    assert_eq!(\n        unsafe { libc::clock_gettime(clock_id, &mut value) },\n        0,\n        \"host clock_gettime failed: {}\",\n        std::io::Error::last_os_error()\n    );\n    i128::from(value.tv_sec) * 1_000_000_000 + i128::from(value.tv_nsec)\n}\n\nfn captured_timespec_nanos(bytes: &[u8], offset: usize) -> i128 {\n    let seconds = i64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());\n    let nanos = i64::from_ne_bytes(bytes[offset + 8..offset + 16].try_into().unwrap());\n    assert!((0..1_000_000_000).contains(&nanos));\n    i128::from(seconds) * 1_000_000_000 + i128::from(nanos)\n}\n\n#[test]\nfn policy_owned_time_namespace_offsets_descendant_clocks() {\n    const MONOTONIC_OFFSET_SECONDS: u64 = 3600;\n    const BOOTTIME_OFFSET_SECONDS: u64 = 7200;\n    const TOLERANCE_NANOS: i128 = 2_000_000_000;\n\n    let host_monotonic_before = clock_nanos(libc::CLOCK_MONOTONIC);\n    let host_boottime_before = clock_nanos(libc::CLOCK_BOOTTIME);\n\n    let mut timed = policy(\n        \"f\",\n        &[],\n        &[\"execveat\", \"clock_gettime\", \"write\", \"exit\"],\n    );\n    timed.time_monotonic_offset_seconds = Some(MONOTONIC_OFFSET_SECONDS);\n    timed.time_boottime_offset_seconds = Some(BOOTTIME_OFFSET_SECONDS);\n    timed.stdio.stdout = StdioMode::Capture;\n    timed.stdout_capture_bytes = Some(32);\n    timed.wall_clock_milliseconds = Some(5000);\n\n    let report = run_report(&timed).expect(\"time-namespace sandbox run failed\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    let captured = report.stdout.expect(\"time-namespace capture missing\");\n    assert!(!captured.truncated);\n    assert_eq!(captured.bytes.len(), 32);\n\n    let host_monotonic_after = clock_nanos(libc::CLOCK_MONOTONIC);\n    let host_boottime_after = clock_nanos(libc::CLOCK_BOOTTIME);\n    let target_monotonic = captured_timespec_nanos(&captured.bytes, 0);\n    let target_boottime = captured_timespec_nanos(&captured.bytes, 16);\n    let monotonic_offset = i128::from(MONOTONIC_OFFSET_SECONDS) * 1_000_000_000;\n    let boottime_offset = i128::from(BOOTTIME_OFFSET_SECONDS) * 1_000_000_000;\n\n    assert!(\n        target_monotonic >= host_monotonic_before + monotonic_offset - TOLERANCE_NANOS\n            && target_monotonic <= host_monotonic_after + monotonic_offset + TOLERANCE_NANOS,\n        \"target CLOCK_MONOTONIC did not reflect the configured time namespace offset\"\n    );\n    assert!(\n        target_boottime >= host_boottime_before + boottime_offset - TOLERANCE_NANOS\n            && target_boottime <= host_boottime_after + boottime_offset + TOLERANCE_NANOS,\n        \"target CLOCK_BOOTTIME did not reflect the configured time namespace offset\"\n    );\n    assert!(\n        host_monotonic_after - host_monotonic_before < 30_000_000_000,\n        \"host monotonic clock unexpectedly moved with the sandbox time namespace\"\n    );\n}\n\nfn assert_random_device_ioctl_available(path: &str) {",
    "time integration evidence",
)
