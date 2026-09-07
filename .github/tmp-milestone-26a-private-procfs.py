from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: explicit opt-in private procfs with overlap validation.
replace_one(
    "src/policy.rs",
    "    /// Whether the launcher activates `lo` inside the isolated network namespace.\n    /// This does not attach the namespace to any host or external network.\n    pub loopback_enabled: bool,\n    /// Optional launcher-brokered TCP connection to host 127.0.0.1.",
    "    /// Whether the launcher activates `lo` inside the isolated network namespace.\n    /// This does not attach the namespace to any host or external network.\n    pub loopback_enabled: bool,\n    /// Whether launcher-owned namespace PID 1 mounts a fresh procfs at `/proc`\n    /// after entering the sandbox PID namespace and before the direct target exists.\n    pub procfs_enabled: bool,\n    /// Optional launcher-brokered TCP connection to host 127.0.0.1.",
    "policy procfs field",
)
replace_one(
    "src/policy.rs",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if self.landlock_read_execute.len() > MAX_LANDLOCK_READ_EXECUTE_PATHS {",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if self.procfs_enabled {\n            let proc_path = Path::new(\"/proc\");\n            if self.executable.starts_with(proc_path) || self.working_dir.starts_with(proc_path) {\n                return Err(PolicyError::new(\n                    \"filesystem.proc must not hide the executable or working_dir\",\n                ));\n            }\n            for (path, label) in [\n                (&self.scratch_dir, \"filesystem.scratch\"),\n                (&self.readonly_volume_target, \"volume.readonly_target\"),\n                (&self.writable_volume_target, \"volume.writable_target\"),\n            ] {\n                if let Some(path) = path {\n                    if path.starts_with(proc_path) || proc_path.starts_with(path) {\n                        return Err(PolicyError::new(format!(\n                            \"filesystem.proc must not overlap {label}\"\n                        )));\n                    }\n                }\n            }\n        }\n\n        if self.landlock_read_execute.len() > MAX_LANDLOCK_READ_EXECUTE_PATHS {",
    "policy procfs validation",
)
replace_one(
    "src/policy.rs",
    "        let mut loopback_enabled = None;\n        let mut host_loopback_tcp_port = None;",
    "        let mut loopback_enabled = None;\n        let mut procfs_enabled = None;\n        let mut host_loopback_tcp_port = None;",
    "policy procfs parser state",
)
replace_one(
    "src/policy.rs",
    "                \"network.loopback\" => set_once(\n                    &mut loopback_enabled,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_port\" => set_once(",
    "                \"network.loopback\" => set_once(\n                    &mut loopback_enabled,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"filesystem.proc\" => set_once(\n                    &mut procfs_enabled,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_port\" => set_once(",
    "policy procfs parser key",
)
replace_one(
    "src/policy.rs",
    "            landlock_scope_signal: landlock_scope_signal.unwrap_or(false),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n            host_loopback_tcp_port,",
    "            landlock_scope_signal: landlock_scope_signal.unwrap_or(false),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n            procfs_enabled: procfs_enabled.unwrap_or(false),\n            host_loopback_tcp_port,",
    "policy procfs construction",
)
replace_one(
    "src/policy.rs",
    "        assert!(!policy.loopback_enabled);\n        assert_eq!(policy.host_loopback_tcp_port, None);",
    "        assert!(!policy.loopback_enabled);\n        assert!(!policy.procfs_enabled);\n        assert_eq!(policy.host_loopback_tcp_port, None);",
    "policy default procfs assertion",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_brokered_host_loopback_tcp_endpoint() {",
    "    #[test]\n    fn parses_private_procfs_mode() {\n        let enabled: SandboxPolicy = format!(\"{VALID}\\nfilesystem.proc = enabled\")\n            .parse()\n            .unwrap();\n        assert!(enabled.procfs_enabled);\n\n        let disabled: SandboxPolicy = format!(\"{VALID}\\nfilesystem.proc = disabled\")\n            .parse()\n            .unwrap();\n        assert!(!disabled.procfs_enabled);\n    }\n\n    #[test]\n    fn rejects_invalid_duplicate_or_overlapping_private_procfs() {\n        let invalid = format!(\"{VALID}\\nfilesystem.proc = host\");\n        assert!(invalid.parse::<SandboxPolicy>().is_err());\n\n        let duplicate = format!(\n            \"{VALID}\\nfilesystem.proc = enabled\\nfilesystem.proc = disabled\"\n        );\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n\n        let hides_cwd = VALID.replace(\"working_dir = /tmp\", \"working_dir = /proc/self\");\n        let hides_cwd = format!(\"{hides_cwd}\\nfilesystem.proc = enabled\");\n        assert!(hides_cwd.parse::<SandboxPolicy>().is_err());\n\n        let overlaps_scratch = VALID.replace(\"filesystem.scratch = /scratch\", \"filesystem.scratch = /proc\");\n        let overlaps_scratch = format!(\"{overlaps_scratch}\\nfilesystem.proc = enabled\");\n        assert!(overlaps_scratch.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_brokered_host_loopback_tcp_endpoint() {",
    "policy procfs tests",
)

# Public report surface: one real new enforcement stage.
replace_one(
    "src/report.rs",
    "    pub chroot: bool,\n    pub fd_sanitization: bool,\n    pub rlimits: bool,",
    "    pub chroot: bool,\n    pub fd_sanitization: bool,\n    /// A fresh procfs was mounted by launcher-owned namespace PID 1 after\n    /// entering the sandbox PID namespace and before the direct target fork.\n    pub private_procfs: bool,\n    pub rlimits: bool,",
    "report procfs receipt field",
)

# Linux runtime: validate the fixed mountpoint, mount only from namespace PID 1,
# and publish the receipt bit only after mount(2) succeeds.
replace_one(
    "src/platform/linux.rs",
    "    const ENFORCEMENT_LANDLOCK: u64 = 1 << 10;\n    const ENFORCEMENT_SECCOMP: u64 = 1 << 11;\n    const ENFORCEMENT_KNOWN: u64 = ENFORCEMENT_BASE_NAMESPACES",
    "    const ENFORCEMENT_LANDLOCK: u64 = 1 << 10;\n    const ENFORCEMENT_SECCOMP: u64 = 1 << 11;\n    const ENFORCEMENT_PRIVATE_PROCFS: u64 = 1 << 12;\n    const ENFORCEMENT_KNOWN: u64 = ENFORCEMENT_BASE_NAMESPACES",
    "runtime procfs receipt bit",
)
replace_one(
    "src/platform/linux.rs",
    "        | ENFORCEMENT_NO_NEW_PRIVS\n        | ENFORCEMENT_LANDLOCK\n        | ENFORCEMENT_SECCOMP;",
    "        | ENFORCEMENT_NO_NEW_PRIVS\n        | ENFORCEMENT_LANDLOCK\n        | ENFORCEMENT_SECCOMP\n        | ENFORCEMENT_PRIVATE_PROCFS;",
    "runtime procfs known mask",
)
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_TIME_OFFSETS: u32 = 56;\n",
    "    const PHASE_TIME_OFFSETS: u32 = 56;\n    const PHASE_PROCFS_MOUNT: u32 = 57;\n",
    "runtime procfs phase",
)
replace_one(
    "src/platform/linux.rs",
    "        time_boottime_offset: Option<Vec<u8>>,\n        loopback_enabled: bool,\n    }",
    "        time_boottime_offset: Option<Vec<u8>>,\n        loopback_enabled: bool,\n        procfs_enabled: bool,\n    }",
    "prepared procfs flag",
)
replace_one(
    "src/platform/linux.rs",
    "            let root_fd = open_root(&policy.root_dir)?;\n",
    "            let root_fd = open_root(&policy.root_dir)?;\n            if policy.procfs_enabled {\n                let proc_relative = sandbox_relative(Path::new(\"/proc\"))?;\n                let proc_how = OpenHow {\n                    flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n                    mode: 0,\n                    resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n                };\n                let proc_fd = unsafe {\n                    libc::syscall(\n                        libc::SYS_openat2,\n                        root_fd.raw(),\n                        proc_relative.as_ptr(),\n                        &proc_how as *const OpenHow,\n                        std::mem::size_of::<OpenHow>(),\n                    )\n                };\n                if proc_fd == -1 {\n                    return Err(SandboxError::SetupFailed(format!(\n                        \"cannot validate private procfs mountpoint beneath filesystem.root: {}\",\n                        io::Error::last_os_error()\n                    )));\n                }\n                drop(OwnedFd(proc_fd as RawFd));\n            }\n",
    "prepared procfs mountpoint validation",
)
replace_one(
    "src/platform/linux.rs",
    "                time_boottime_offset,\n                loopback_enabled: policy.loopback_enabled,\n            })",
    "                time_boottime_offset,\n                loopback_enabled: policy.loopback_enabled,\n                procfs_enabled: policy.procfs_enabled,\n            })",
    "prepared procfs construction",
)
replace_one(
    "src/platform/linux.rs",
    "        pid_lifecycle::become_pid_namespace_init_or_exit(\n            launch_error,\n            PHASE_PID_INIT_FORK,\n            PHASE_PID_INIT_WAIT,\n            PHASE_FD_SANITIZE,\n        );\n        pid_lifecycle::become_direct_target_or_reap(",
    "        pid_lifecycle::become_pid_namespace_init_or_exit(\n            launch_error,\n            PHASE_PID_INIT_FORK,\n            PHASE_PID_INIT_WAIT,\n            PHASE_FD_SANITIZE,\n        );\n        if prepared.procfs_enabled {\n            mount_private_procfs_or_fail(launch_error, seccomp.error_exit_syscall);\n        }\n        pid_lifecycle::become_direct_target_or_reap(",
    "PID1 procfs mount placement",
)
replace_one(
    "src/platform/linux.rs",
    "    unsafe fn enable_loopback_or_fail(\n        launch_error: *mut LaunchErrorRecord,",
    "    unsafe fn mount_private_procfs_or_fail(\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;\n        if libc::syscall(\n            libc::SYS_mount,\n            b\"proc\\0\".as_ptr().cast::<libc::c_char>(),\n            b\"/proc\\0\".as_ptr().cast::<libc::c_char>(),\n            b\"proc\\0\".as_ptr().cast::<libc::c_char>(),\n            flags,\n            ptr::null::<libc::c_void>(),\n        ) == -1\n        {\n            child_fail(launch_error, PHASE_PROCFS_MOUNT, error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_PRIVATE_PROCFS);\n    }\n\n    unsafe fn enable_loopback_or_fail(\n        launch_error: *mut LaunchErrorRecord,",
    "procfs mount helper",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_TIME_OFFSETS => \"time namespace offset installation\",\n            _ => \"unknown launch phase\",",
    "            PHASE_TIME_OFFSETS => \"time namespace offset installation\",\n            PHASE_PROCFS_MOUNT => \"private procfs mount in PID namespace\",\n            _ => \"unknown launch phase\",",
    "procfs phase label",
)

# Keep existing receipt tests source-compatible through a test-only wrapper, while
# production decoding receives the requested procfs state explicitly.
replace_one(
    "src/platform/linux.rs",
    "    fn enforcement_receipt_from_bits(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n    ) -> Result<EnforcementReceipt, SandboxError> {",
    "    #[cfg(test)]\n    fn enforcement_receipt_from_bits(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n    ) -> Result<EnforcementReceipt, SandboxError> {\n        enforcement_receipt_from_bits_for_policy(\n            bits,\n            time_namespace_requested,\n            landlock_requested,\n            false,\n        )\n    }\n\n    fn enforcement_receipt_from_bits_for_policy(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n        procfs_requested: bool,\n    ) -> Result<EnforcementReceipt, SandboxError> {",
    "procfs receipt decoder signature",
)
replace_one(
    "src/platform/linux.rs",
    "        require_predecessor(\n            ENFORCEMENT_FD_SANITIZATION,\n            ENFORCEMENT_CHROOT,\n            \"FD sanitization\",\n        )?;\n        require_predecessor(ENFORCEMENT_RLIMITS, ENFORCEMENT_FD_SANITIZATION, \"rlimits\")?;",
    "        require_predecessor(\n            ENFORCEMENT_FD_SANITIZATION,\n            ENFORCEMENT_CHROOT,\n            \"FD sanitization\",\n        )?;\n        require_predecessor(\n            ENFORCEMENT_PRIVATE_PROCFS,\n            ENFORCEMENT_FD_SANITIZATION,\n            \"private procfs\",\n        )?;\n        require_predecessor(ENFORCEMENT_RLIMITS, ENFORCEMENT_FD_SANITIZATION, \"rlimits\")?;",
    "procfs receipt predecessor",
)
replace_one(
    "src/platform/linux.rs",
    "        let landlock = observed(ENFORCEMENT_LANDLOCK);\n        if landlock && !landlock_requested {",
    "        let private_procfs = observed(ENFORCEMENT_PRIVATE_PROCFS);\n        if private_procfs && !procfs_requested {\n            return Err(SandboxError::SetupFailed(\n                \"runtime enforcement receipt observed unrequested private procfs\".to_owned(),\n            ));\n        }\n        if procfs_requested && observed(ENFORCEMENT_RLIMITS) && !private_procfs {\n            return Err(SandboxError::SetupFailed(\n                \"runtime enforcement receipt reached target rlimits without requested private procfs\"\n                    .to_owned(),\n            ));\n        }\n\n        let landlock = observed(ENFORCEMENT_LANDLOCK);\n        if landlock && !landlock_requested {",
    "procfs receipt conditional validation",
)
replace_one(
    "src/platform/linux.rs",
    "            chroot: bits & ENFORCEMENT_CHROOT != 0,\n            fd_sanitization: bits & ENFORCEMENT_FD_SANITIZATION != 0,\n            rlimits: bits & ENFORCEMENT_RLIMITS != 0,",
    "            chroot: bits & ENFORCEMENT_CHROOT != 0,\n            fd_sanitization: bits & ENFORCEMENT_FD_SANITIZATION != 0,\n            private_procfs,\n            rlimits: bits & ENFORCEMENT_RLIMITS != 0,",
    "procfs receipt construction",
)
replace_one(
    "src/platform/linux.rs",
    "        enforcement_receipt_from_bits(\n            bits,\n            policy.time_monotonic_offset_seconds.is_some(),\n            policy_requests_landlock(policy),\n        )",
    "        enforcement_receipt_from_bits_for_policy(\n            bits,\n            policy.time_monotonic_offset_seconds.is_some(),\n            policy_requests_landlock(policy),\n            policy.procfs_enabled,\n        )",
    "procfs receipt policy decoding",
)
replace_one(
    "src/platform/linux.rs",
    "        #[test]\n        fn early_control_termination_can_publish_a_valid_partial_receipt() {",
    "        #[test]\n        fn private_procfs_receipt_is_request_bound_and_ordered() {\n            let unrequested = enforcement_receipt_from_bits_for_policy(\n                ENFORCEMENT_BASE_NAMESPACES\n                    | ENFORCEMENT_HOSTNAME\n                    | ENFORCEMENT_PRIVATE_MOUNTS\n                    | ENFORCEMENT_READONLY_ROOT\n                    | ENFORCEMENT_CHROOT\n                    | ENFORCEMENT_FD_SANITIZATION\n                    | ENFORCEMENT_PRIVATE_PROCFS,\n                false,\n                false,\n                false,\n            );\n            assert!(unrequested.is_err());\n\n            let skipped = enforcement_receipt_from_bits_for_policy(\n                ENFORCEMENT_BASE_NAMESPACES\n                    | ENFORCEMENT_HOSTNAME\n                    | ENFORCEMENT_PRIVATE_MOUNTS\n                    | ENFORCEMENT_READONLY_ROOT\n                    | ENFORCEMENT_CHROOT\n                    | ENFORCEMENT_FD_SANITIZATION\n                    | ENFORCEMENT_RLIMITS,\n                false,\n                false,\n                true,\n            );\n            assert!(skipped.is_err());\n\n            let observed = enforcement_receipt_from_bits_for_policy(\n                ENFORCEMENT_BASE_NAMESPACES\n                    | ENFORCEMENT_HOSTNAME\n                    | ENFORCEMENT_PRIVATE_MOUNTS\n                    | ENFORCEMENT_READONLY_ROOT\n                    | ENFORCEMENT_CHROOT\n                    | ENFORCEMENT_FD_SANITIZATION\n                    | ENFORCEMENT_PRIVATE_PROCFS\n                    | ENFORCEMENT_RLIMITS,\n                false,\n                false,\n                true,\n            )\n            .expect(\"requested procfs progression should decode\");\n            assert!(observed.private_procfs);\n        }\n\n        #[test]\n        fn early_control_termination_can_publish_a_valid_partial_receipt() {",
    "procfs receipt tests",
)

# Deterministic JSON receipt surface.
replace_one(
    "src/cli_json.rs",
    "    output.push_str(\",\\\"fd_sanitization\\\":\");\n    push_bool(&mut output, report.enforcement.fd_sanitization);\n    output.push_str(\",\\\"rlimits\\\":\");",
    "    output.push_str(\",\\\"fd_sanitization\\\":\");\n    push_bool(&mut output, report.enforcement.fd_sanitization);\n    output.push_str(\",\\\"private_procfs\\\":\");\n    push_bool(&mut output, report.enforcement.private_procfs);\n    output.push_str(\",\\\"rlimits\\\":\");",
    "CLI procfs receipt field",
)
replace_one(
    "src/cli_json.rs",
    "\\\"chroot\\\":false,\\\"fd_sanitization\\\":false,\\\"rlimits\\\":false",
    "\\\"chroot\\\":false,\\\"fd_sanitization\\\":false,\\\"private_procfs\\\":false,\\\"rlimits\\\":false",
    "CLI unit expected procfs receipt",
)

# Static authority manifest: declaration only, no probing or launch.
replace_one(
    "src/authority_manifest.rs",
    "    output.push_str(\",\\\"host_filesystem\\\":{\\\"root\\\":\");\n    push_path(&mut output, &policy.root_dir);\n    output.push_str(\",\\\"scratch\\\":\");",
    "    output.push_str(\",\\\"host_filesystem\\\":{\\\"root\\\":\");\n    push_path(&mut output, &policy.root_dir);\n    output.push_str(\",\\\"private_procfs\\\":\");\n    push_bool(&mut output, policy.procfs_enabled);\n    output.push_str(\",\\\"scratch\\\":\");",
    "manifest procfs JSON",
)
replace_one(
    "src/authority_manifest.rs",
    "    writeln!(&mut output, \"root: {}\", policy.root_dir.display())\n        .expect(\"write to String cannot fail\");\n    writeln!(&mut output, \"executable: {}\", policy.executable.display())",
    "    writeln!(&mut output, \"root: {}\", policy.root_dir.display())\n        .expect(\"write to String cannot fail\");\n    writeln!(\n        &mut output,\n        \"private-procfs: {}\",\n        if policy.procfs_enabled { \"enabled\" } else { \"disabled\" }\n    )\n    .expect(\"write to String cannot fail\");\n    writeln!(&mut output, \"executable: {}\", policy.executable.display())",
    "manifest procfs human",
)

# Conservative preflight: requesting procfs stays unprobed without a real PID/mount
# namespace launch; it must never turn into a false green capability prediction.
replace_one(
    "src/policy_preflight.rs",
    "    stdout_output_limit: bool,\n    time_namespace: bool,\n}",
    "    stdout_output_limit: bool,\n    time_namespace: bool,\n    private_procfs: bool,\n}",
    "preflight procfs requirement field",
)
replace_one(
    "src/policy_preflight.rs",
    "            time_namespace: policy.time_monotonic_offset_seconds.is_some()\n                && policy.time_boottime_offset_seconds.is_some(),\n        }",
    "            time_namespace: policy.time_monotonic_offset_seconds.is_some()\n                && policy.time_boottime_offset_seconds.is_some(),\n            private_procfs: policy.procfs_enabled,\n        }",
    "preflight procfs requirement derive",
)
replace_one(
    "src/policy_preflight.rs",
    "    fn mandatory_launch_core_status(&self) -> RequirementStatus {",
    "    fn private_procfs_status(&self) -> RequirementStatus {\n        if self.requirements.private_procfs {\n            RequirementStatus::Unprobed\n        } else {\n            RequirementStatus::NotRequested\n        }\n    }\n\n    fn mandatory_launch_core_status(&self) -> RequirementStatus {",
    "preflight procfs status",
)
replace_one(
    "src/policy_preflight.rs",
    "        } else if self.mandatory_launch_core_status() == RequirementStatus::Unprobed\n            || self.time_namespace_status() == RequirementStatus::Unprobed\n        {",
    "        } else if self.mandatory_launch_core_status() == RequirementStatus::Unprobed\n            || self.time_namespace_status() == RequirementStatus::Unprobed\n            || self.private_procfs_status() == RequirementStatus::Unprobed\n        {",
    "preflight procfs verdict",
)
replace_one(
    "src/policy_preflight.rs",
    "        output.push_str(\"}}}\");\n        output\n    }\n\n    pub(crate) fn to_human(&self) -> String {",
    "        output.push_str(\"},\\\"private_procfs\\\":{\\\"status\\\":\\\"\");\n        output.push_str(self.private_procfs_status().as_str());\n        output.push_str(\"\\\",\\\"reason\\\":\");\n        if self.requirements.private_procfs {\n            output.push_str(\"\\\"pid_namespace_procfs_mount_requires_real_launch\\\"\");\n        } else {\n            output.push_str(\"null\");\n        }\n        output.push_str(\"}}}\");\n        output\n    }\n\n    pub(crate) fn to_human(&self) -> String {",
    "preflight procfs JSON",
)
replace_one(
    "src/policy_preflight.rs",
    "        output.push_str(\"time-namespace: \" );",
    "        output.push_str(\"time-namespace: \" );",
    "preflight human anchor sanity",
)
# The source has no space before the closing parenthesis in the actual line; do the
# human insertion using the stable newline after the time-namespace section.
replace_one(
    "src/policy_preflight.rs",
    "        if self.requirements.time_namespace {\n            output.push_str(\" (independent-safe-probe-not-implemented)\");\n        }\n        output.push('\\n');\n        output\n    }",
    "        if self.requirements.time_namespace {\n            output.push_str(\" (independent-safe-probe-not-implemented)\");\n        }\n        output.push('\\n');\n        output.push_str(\"private-procfs: \" );\n        output.push_str(self.private_procfs_status().as_str());\n        if self.requirements.private_procfs {\n            output.push_str(\" (pid-namespace-procfs-mount-requires-real-launch)\");\n        }\n        output.push('\\n');\n        output\n    }",
    "preflight procfs human",
)
replace_one(
    "src/policy_preflight.rs",
    "    #[test]\n    fn derives_highest_requested_landlock_abi_and_supervision_requirements() {",
    "    #[test]\n    fn private_procfs_remains_unprobed_without_real_namespace_mount() {\n        let policy = policy(\"filesystem.proc = enabled\");\n        let evaluated = evaluate_with_core(&policy, host(None), RequirementStatus::Supported);\n        assert_eq!(evaluated.private_procfs_status(), RequirementStatus::Unprobed);\n        assert_eq!(evaluated.verdict(), Verdict::Indeterminate);\n        assert!(evaluated\n            .to_json()\n            .contains(\"\\\"private_procfs\\\":{\\\"status\\\":\\\"unprobed\\\"\"));\n    }\n\n    #[test]\n    fn derives_highest_requested_landlock_abi_and_supervision_requirements() {",
    "preflight procfs unit test",
)

# Integration fixture root and policy defaults.
replace_one(
    "tests/sandbox.rs",
    "        std::fs::create_dir_all(root.join(\"work\")).expect(\"create sandbox work directory\");\n        std::fs::create_dir_all(root.join(\"scratch\")).expect(\"create sandbox scratch mountpoint\");",
    "        std::fs::create_dir_all(root.join(\"work\")).expect(\"create sandbox work directory\");\n        std::fs::create_dir_all(root.join(\"proc\")).expect(\"create sandbox procfs mountpoint\");\n        std::fs::create_dir_all(root.join(\"scratch\")).expect(\"create sandbox scratch mountpoint\");",
    "sandbox procfs mountpoint fixture",
)
replace_one(
    "tests/sandbox.rs",
    "        landlock_scope_signal: false,\n        loopback_enabled: false,\n        host_loopback_tcp_port: None,",
    "        landlock_scope_signal: false,\n        loopback_enabled: false,\n        procfs_enabled: false,\n        host_loopback_tcp_port: None,",
    "sandbox policy procfs default",
)
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {",
    "#[test]\nfn private_procfs_reflects_only_the_sandbox_pid_namespace() {\n    let proc_mountpoint = fixture_root().join(\"proc\");\n    assert_eq!(\n        std::fs::read_dir(&proc_mountpoint)\n            .expect(\"read empty procfs mountpoint before run\")\n            .count(),\n        0,\n        \"fixture proc mountpoint must begin empty\"\n    );\n\n    let host_pid = process::id();\n    assert!(host_pid > 2, \"host test process must not collide with namespace PID 1/2\");\n    let host_proc_path = format!(\"/proc/{host_pid}\");\n    let mut isolated = policy(\n        \"i\",\n        &[host_proc_path.as_str()],\n        &[\"execveat\", \"newfstatat\", \"exit\"],\n    );\n    isolated.procfs_enabled = true;\n\n    let report = run_report(&isolated).expect(\"private procfs sandbox run\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    assert!(\n        report.enforcement.private_procfs,\n        \"runtime receipt must positively observe the PID1 procfs mount\"\n    );\n    assert_eq!(\n        std::fs::read_dir(&proc_mountpoint)\n            .expect(\"read procfs mountpoint after run\")\n            .count(),\n        0,\n        \"private procfs mount must disappear with the sandbox mount namespace\"\n    );\n}\n\n#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {",
    "sandbox procfs integration test",
)

# Raw syscall oracle: PID 1 and PID 2 must exist in fresh procfs; a trusted host PID
# pathname must be absent. Seccomp explicitly allows newfstatat, so EPERM cannot fake it.
replace_one(
    "tests/fixtures/probe.S",
    "#   h prove Landlock narrows directory/symlink/reparent topology mutation\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "#   h prove Landlock narrows directory/symlink/reparent topology mutation\n#   i prove private procfs exposes namespace PID 1/2 while hiding a trusted host PID\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "probe procfs mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $104, %al\n    je .landlock_path_topology_mutation\n    cmp $115, %al",
    "    cmp $104, %al\n    je .landlock_path_topology_mutation\n    cmp $105, %al\n    je .private_procfs\n    cmp $115, %al",
    "probe procfs dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".selected_handle:\n",
    ".private_procfs:\n    mov 24(%rsp), %r12\n    test %r12, %r12\n    je .fail29\n    sub $160, %rsp\n\n    mov $262, %eax\n    mov $-100, %edi\n    lea proc_pid1_path(%rip), %rsi\n    mov %rsp, %rdx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .private_procfs_fail\n\n    mov $262, %eax\n    mov $-100, %edi\n    lea proc_pid2_path(%rip), %rsi\n    mov %rsp, %rdx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .private_procfs_fail\n\n    mov $262, %eax\n    mov $-100, %edi\n    mov %r12, %rsi\n    mov %rsp, %rdx\n    xor %r10d, %r10d\n    syscall\n    cmp $-2, %rax\n    jne .private_procfs_fail\n\n    add $160, %rsp\n    xor %edi, %edi\n    jmp .exit\n\n.private_procfs_fail:\n    add $160, %rsp\n    jmp .fail29\n\n.selected_handle:\n",
    "probe procfs implementation",
)
replace_one(
    "tests/fixtures/probe.S",
    "landlock_buffer:\n    .skip 32\n\n.section .note.GNU-stack,\"\",@progbits",
    "landlock_buffer:\n    .skip 32\nproc_pid1_path:\n    .asciz \"/proc/1\"\nproc_pid2_path:\n    .asciz \"/proc/2\"\n\n.section .note.GNU-stack,\"\",@progbits",
    "probe procfs paths",
)

# Existing CLI exact receipt contract gains the disabled default field.
replace_one(
    "tests/cli.rs",
    "\\\"chroot\\\":true,\\\"fd_sanitization\\\":true,\\\"rlimits\\\":true",
    "\\\"chroot\\\":true,\\\"fd_sanitization\\\":true,\\\"private_procfs\\\":false,\\\"rlimits\\\":true",
    "CLI integration procfs receipt",
)

# Manifest integration explicitly exercises the new declaration while proving static mode
# still does not materialize the nonexistent root.
replace_one(
    "tests/authority_manifest_cli.rs",
    "identity.hostname = manifest-test\nexecutable = /bin/probe",
    "identity.hostname = manifest-test\nfilesystem.proc = enabled\nexecutable = /bin/probe",
    "manifest procfs fixture",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\"\\\"argument_count\\\":1,\\\"environment_keys\\\":[\\\"SECRET_TOKEN\\\"]\"));",
    "    assert!(stdout.contains(\"\\\"argument_count\\\":1,\\\"environment_keys\\\":[\\\"SECRET_TOKEN\\\"]\"));\n    assert!(stdout.contains(\"\\\"private_procfs\\\":true\"));",
    "manifest procfs JSON assertion",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\"arguments: 1\\n\"));",
    "    assert!(stdout.contains(\"arguments: 1\\n\"));\n    assert!(stdout.contains(\"private-procfs: enabled\\n\"));",
    "manifest procfs human assertion",
)
