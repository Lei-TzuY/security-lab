from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Public report surface: runtime evidence is distinct from static policy authority.
replace_one(
    "src/report.rs",
    "/// Detailed result for callers that need launcher-owned captured output or process-tree lifecycle evidence.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct RunReport {",
    '''/// Kernel enforcement layers proven by this successful launcher-owned run.\n///\n/// Fields are published from the actual setup path after the corresponding\n/// kernel operation succeeds. Optional layers are false when they were not\n/// requested. `execveat` is confirmed by the host only after launch error state\n/// is clean and the PID-namespace lifecycle has converged.\n#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]\npub struct EnforcementReceipt {\n    pub base_namespaces: bool,\n    pub time_namespace_offsets: bool,\n    pub hostname: bool,\n    pub private_mount_propagation: bool,\n    pub readonly_root: bool,\n    pub chroot: bool,\n    pub fd_sanitization: bool,\n    pub rlimits: bool,\n    pub capabilities_reduced: bool,\n    pub no_new_privs: bool,\n    pub landlock: bool,\n    pub seccomp: bool,\n    pub execveat: bool,\n}\n\n/// Detailed result for callers that need launcher-owned captured output, process-tree lifecycle evidence, or a runtime enforcement receipt.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct RunReport {''',
    "report receipt type",
)
replace_one(
    "src/report.rs",
    "    /// Kernel resource telemetry collected by namespace PID 1 only after the sandbox tree converges.\n    pub process_tree_usage: ProcessTreeUsage,\n}",
    "    /// Kernel resource telemetry collected by namespace PID 1 only after the sandbox tree converges.\n    pub process_tree_usage: ProcessTreeUsage,\n    /// Runtime receipt for enforcement layers established by this successful launch.\n    pub enforcement: EnforcementReceipt,\n}",
    "report receipt field",
)
replace_one(
    "src/lib.rs",
    "pub use report::{CapturedOutput, ChildOutcome, ProcessTreeUsage, RunReport};",
    "pub use report::{CapturedOutput, ChildOutcome, EnforcementReceipt, ProcessTreeUsage, RunReport};",
    "lib receipt export",
)

# Shared launch record carries the setup evidence bitset along the existing
# bootstrap -> PID1 -> direct-target lineage.
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "pub(super) struct LaunchErrorRecord {\n    pub(super) errno: i32,\n    pub(super) phase: u32,\n}",
    "pub(super) struct LaunchErrorRecord {\n    pub(super) errno: i32,\n    pub(super) phase: u32,\n    pub(super) enforcement_bits: u64,\n}",
    "shared launch enforcement bits",
)

# Linux runtime implementation and fail-closed decoder.
replace_one(
    "src/platform/linux.rs",
    "        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ProcessTreeUsage,\n        ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n",
    "        CancellationToken, CapturedOutput, ChildOutcome, EnforcementReceipt, PolicyError,\n        ProcessTreeUsage, ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n",
    "linux receipt import",
)
replace_one(
    "src/platform/linux.rs",
    "    const CLONE_NEWTIME: libc::c_int = 0x0000_0080;\n",
    '''    const CLONE_NEWTIME: libc::c_int = 0x0000_0080;\n\n    const ENFORCEMENT_BASE_NAMESPACES: u64 = 1 << 0;\n    const ENFORCEMENT_TIME_NAMESPACE: u64 = 1 << 1;\n    const ENFORCEMENT_HOSTNAME: u64 = 1 << 2;\n    const ENFORCEMENT_PRIVATE_MOUNTS: u64 = 1 << 3;\n    const ENFORCEMENT_READONLY_ROOT: u64 = 1 << 4;\n    const ENFORCEMENT_CHROOT: u64 = 1 << 5;\n    const ENFORCEMENT_FD_SANITIZATION: u64 = 1 << 6;\n    const ENFORCEMENT_RLIMITS: u64 = 1 << 7;\n    const ENFORCEMENT_CAPABILITIES: u64 = 1 << 8;\n    const ENFORCEMENT_NO_NEW_PRIVS: u64 = 1 << 9;\n    const ENFORCEMENT_LANDLOCK: u64 = 1 << 10;\n    const ENFORCEMENT_SECCOMP: u64 = 1 << 11;\n    const ENFORCEMENT_MANDATORY: u64 = ENFORCEMENT_BASE_NAMESPACES\n        | ENFORCEMENT_HOSTNAME\n        | ENFORCEMENT_PRIVATE_MOUNTS\n        | ENFORCEMENT_READONLY_ROOT\n        | ENFORCEMENT_CHROOT\n        | ENFORCEMENT_FD_SANITIZATION\n        | ENFORCEMENT_RLIMITS\n        | ENFORCEMENT_CAPABILITIES\n        | ENFORCEMENT_NO_NEW_PRIVS\n        | ENFORCEMENT_SECCOMP;\n    const ENFORCEMENT_KNOWN: u64 =\n        ENFORCEMENT_MANDATORY | ENFORCEMENT_TIME_NAMESPACE | ENFORCEMENT_LANDLOCK;\n''',
    "enforcement bit constants",
)
replace_one(
    "src/platform/linux.rs",
    "                ptr::write_volatile(record, LaunchErrorRecord { errno: 0, phase: 0 });",
    "                ptr::write_volatile(\n                    record,\n                    LaunchErrorRecord {\n                        errno: 0,\n                        phase: 0,\n                        enforcement_bits: 0,\n                    },\n                );",
    "shared launch initialization",
)
replace_one(
    "src/platform/linux.rs",
    "    struct PreparedLandlock {\n",
    '''    unsafe fn mark_enforcement(launch_error: *mut LaunchErrorRecord, bit: u64) {\n        let current = ptr::read_volatile(ptr::addr_of!((*launch_error).enforcement_bits));\n        ptr::write_volatile(\n            ptr::addr_of_mut!((*launch_error).enforcement_bits),\n            current | bit,\n        );\n    }\n\n    fn policy_requests_landlock(policy: &SandboxPolicy) -> bool {\n        !policy.landlock_read_execute.is_empty()\n            || !policy.landlock_file_mutate.is_empty()\n            || !policy.landlock_path_topology_mutate.is_empty()\n            || !policy.landlock_device_ioctl.is_empty()\n            || !policy.landlock_tcp_bind_ports.is_empty()\n            || !policy.landlock_tcp_connect_ports.is_empty()\n            || policy.landlock_scope_abstract_unix_socket\n            || policy.landlock_scope_signal\n    }\n\n    fn enforcement_receipt_from_bits(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n    ) -> Result<EnforcementReceipt, SandboxError> {\n        let unknown = bits & !ENFORCEMENT_KNOWN;\n        if unknown != 0 {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt published unknown layer bits 0x{unknown:x}"\n            )));\n        }\n        let missing = ENFORCEMENT_MANDATORY & !bits;\n        if missing != 0 {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt is missing mandatory layer bits 0x{missing:x}"\n            )));\n        }\n\n        let time_namespace_offsets = bits & ENFORCEMENT_TIME_NAMESPACE != 0;\n        if time_namespace_offsets != time_namespace_requested {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt time-namespace mismatch: requested={time_namespace_requested} observed={time_namespace_offsets}"\n            )));\n        }\n        let landlock = bits & ENFORCEMENT_LANDLOCK != 0;\n        if landlock != landlock_requested {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt Landlock mismatch: requested={landlock_requested} observed={landlock}"\n            )));\n        }\n\n        Ok(EnforcementReceipt {\n            base_namespaces: bits & ENFORCEMENT_BASE_NAMESPACES != 0,\n            time_namespace_offsets,\n            hostname: bits & ENFORCEMENT_HOSTNAME != 0,\n            private_mount_propagation: bits & ENFORCEMENT_PRIVATE_MOUNTS != 0,\n            readonly_root: bits & ENFORCEMENT_READONLY_ROOT != 0,\n            chroot: bits & ENFORCEMENT_CHROOT != 0,\n            fd_sanitization: bits & ENFORCEMENT_FD_SANITIZATION != 0,\n            rlimits: bits & ENFORCEMENT_RLIMITS != 0,\n            capabilities_reduced: bits & ENFORCEMENT_CAPABILITIES != 0,\n            no_new_privs: bits & ENFORCEMENT_NO_NEW_PRIVS != 0,\n            landlock,\n            seccomp: bits & ENFORCEMENT_SECCOMP != 0,\n            // Successful exec cannot mark shared memory because execveat does not\n            // return. This decoder is invoked only after launch_error.phase == 0\n            // and PID1 publishes a complete target lifecycle; failed execveat\n            // writes PHASE_EXECVEAT and never reaches this path.\n            execveat: true,\n        })\n    }\n\n    fn decode_enforcement_receipt(\n        bits: u64,\n        policy: &SandboxPolicy,\n    ) -> Result<EnforcementReceipt, SandboxError> {\n        enforcement_receipt_from_bits(\n            bits,\n            policy.time_monotonic_offset_seconds.is_some(),\n            policy_requests_landlock(policy),\n        )\n    }\n\n    struct PreparedLandlock {\n''',
    "enforcement receipt helpers",
)

# Mark only after the corresponding kernel boundary succeeds.
replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(libc::SYS_unshare, namespace_flags) == -1 {\n            child_fail(launch_error, PHASE_NAMESPACE, seccomp.error_exit_syscall);\n        }\n\n        write_proc_file_or_fail(",
    "        if libc::syscall(libc::SYS_unshare, namespace_flags) == -1 {\n            child_fail(launch_error, PHASE_NAMESPACE, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_BASE_NAMESPACES);\n\n        write_proc_file_or_fail(",
    "mark base namespaces",
)
replace_one(
    "src/platform/linux.rs",
    "            write_proc_file_or_fail(\n                b\"/proc/self/timens_offsets\\0\",\n                boottime,\n                launch_error,\n                PHASE_TIME_OFFSETS,\n                seccomp.error_exit_syscall,\n            );\n        }\n\n        if libc::syscall(\n            libc::SYS_sethostname,",
    "            write_proc_file_or_fail(\n                b\"/proc/self/timens_offsets\\0\",\n                boottime,\n                launch_error,\n                PHASE_TIME_OFFSETS,\n                seccomp.error_exit_syscall,\n            );\n            mark_enforcement(launch_error, ENFORCEMENT_TIME_NAMESPACE);\n        }\n\n        if libc::syscall(\n            libc::SYS_sethostname,",
    "mark time namespace",
)
replace_one(
    "src/platform/linux.rs",
    "        {\n            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);\n        }\n\n        if prepared.loopback_enabled {",
    "        {\n            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_HOSTNAME);\n\n        if prepared.loopback_enabled {",
    "mark hostname",
)
replace_one(
    "src/platform/linux.rs",
    "        {\n            child_fail(\n                launch_error,\n                PHASE_MOUNT_PRIVATE,\n                seccomp.error_exit_syscall,\n            );\n        }\n\n        let current_root_how = OpenHow {",
    "        {\n            child_fail(\n                launch_error,\n                PHASE_MOUNT_PRIVATE,\n                seccomp.error_exit_syscall,\n            );\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_PRIVATE_MOUNTS);\n\n        let current_root_how = OpenHow {",
    "mark private mounts",
)
replace_one(
    "src/platform/linux.rs",
    "        {\n            child_fail(launch_error, PHASE_ROOT_ATTACH, seccomp.error_exit_syscall);\n        }\n\n        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {",
    "        {\n            child_fail(launch_error, PHASE_ROOT_ATTACH, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_READONLY_ROOT);\n\n        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {",
    "mark readonly root",
)
replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(libc::SYS_chroot, b\".\\0\".as_ptr().cast::<libc::c_char>()) == -1 {\n            child_fail(launch_error, PHASE_CHROOT, seccomp.error_exit_syscall);\n        }\n        if libc::syscall(libc::SYS_fchdir, cwd_fd) == -1 {",
    "        if libc::syscall(libc::SYS_chroot, b\".\\0\".as_ptr().cast::<libc::c_char>()) == -1 {\n            child_fail(launch_error, PHASE_CHROOT, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_CHROOT);\n        if libc::syscall(libc::SYS_fchdir, cwd_fd) == -1 {",
    "mark chroot",
)
replace_one(
    "src/platform/linux.rs",
    "        {\n            child_fail(launch_error, PHASE_FD_SANITIZE, seccomp.error_exit_syscall);\n        }\n\n        pid_lifecycle::become_pid_namespace_init_or_exit(",
    "        {\n            child_fail(launch_error, PHASE_FD_SANITIZE, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_FD_SANITIZATION);\n\n        pid_lifecycle::become_pid_namespace_init_or_exit(",
    "mark fd sanitization",
)
replace_one(
    "src/platform/linux.rs",
    "        set_limit_or_fail(\n            libc::RLIMIT_NOFILE,\n            limits.open_files,\n            launch_error,\n            PHASE_RLIMIT_NOFILE,\n            seccomp.error_exit_syscall,\n        );\n\n        drop_capabilities_or_fail(launch_error, seccomp.error_exit_syscall);\n\n        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {",
    "        set_limit_or_fail(\n            libc::RLIMIT_NOFILE,\n            limits.open_files,\n            launch_error,\n            PHASE_RLIMIT_NOFILE,\n            seccomp.error_exit_syscall,\n        );\n        mark_enforcement(launch_error, ENFORCEMENT_RLIMITS);\n\n        drop_capabilities_or_fail(launch_error, seccomp.error_exit_syscall);\n        mark_enforcement(launch_error, ENFORCEMENT_CAPABILITIES);\n\n        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {",
    "mark rlimits capabilities",
)
replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {\n            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);\n        }\n        restrict_landlock_or_fail(\n            landlock_ruleset_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        let program = libc::sock_fprog {",
    "        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {\n            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_NO_NEW_PRIVS);\n        let landlock_active = landlock_ruleset_fd >= 0;\n        restrict_landlock_or_fail(\n            landlock_ruleset_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n        if landlock_active {\n            mark_enforcement(launch_error, ENFORCEMENT_LANDLOCK);\n        }\n\n        let program = libc::sock_fprog {",
    "mark nnp landlock",
)
replace_one(
    "src/platform/linux.rs",
    "        {\n            child_fail(launch_error, PHASE_SECCOMP, seccomp.error_exit_syscall);\n        }\n\n        libc::syscall(\n            libc::SYS_execveat,",
    "        {\n            child_fail(launch_error, PHASE_SECCOMP, seccomp.error_exit_syscall);\n        }\n        mark_enforcement(launch_error, ENFORCEMENT_SECCOMP);\n\n        libc::syscall(\n            libc::SYS_execveat,",
    "mark seccomp",
)

# Host publishes a receipt only after launch state is clean and PID1 lifecycle is ready.
replace_one(
    "src/platform/linux.rs",
    "                reaped_descendants: 0,\n                process_tree_usage: ProcessTreeUsage::default(),\n            });",
    "                reaped_descendants: 0,\n                process_tree_usage: ProcessTreeUsage::default(),\n                enforcement: EnforcementReceipt::default(),\n            });",
    "error report receipt default",
)
replace_one(
    "src/platform/linux.rs",
    "        if lifecycle_record.ready != 1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"PID namespace lifecycle did not publish target status; bootstrap wait status 0x{bootstrap_status:x}\"\n            )));\n        }\n\n        let (stdout, output_limit_observed) = match capture_result {",
    "        if lifecycle_record.ready != 1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"PID namespace lifecycle did not publish target status; bootstrap wait status 0x{bootstrap_status:x}\"\n            )));\n        }\n        let enforcement = decode_enforcement_receipt(launch_error.enforcement_bits, policy)?;\n\n        let (stdout, output_limit_observed) = match capture_result {",
    "decode runtime receipt",
)
replace_one(
    "src/platform/linux.rs",
    "                max_child_rss_kib: lifecycle_record.max_child_rss_kib,\n            },\n        })",
    "                max_child_rss_kib: lifecycle_record.max_child_rss_kib,\n            },\n            enforcement,\n        })",
    "success report receipt",
)

# Deterministic fail-closed decoder tests do not require a sandbox launch.
replace_one(
    "src/platform/linux.rs",
    "    #[cfg(test)]\n    mod output_outcome_tests {",
    '''    #[cfg(test)]\n    mod enforcement_receipt_tests {\n        use super::*;\n\n        #[test]\n        fn mandatory_runtime_receipt_is_fail_closed() {\n            let missing_seccomp = ENFORCEMENT_MANDATORY & !ENFORCEMENT_SECCOMP;\n            let error = enforcement_receipt_from_bits(missing_seccomp, false, false)\n                .expect_err("missing mandatory enforcement must fail");\n            assert!(error.to_string().contains("missing mandatory layer bits"));\n        }\n\n        #[test]\n        fn optional_runtime_receipt_must_match_requested_layers() {\n            let base = ENFORCEMENT_MANDATORY;\n            assert!(enforcement_receipt_from_bits(base, true, false).is_err());\n            assert!(enforcement_receipt_from_bits(base | ENFORCEMENT_TIME_NAMESPACE, false, false)\n                .is_err());\n            assert!(enforcement_receipt_from_bits(base, false, true).is_err());\n            assert!(enforcement_receipt_from_bits(base | ENFORCEMENT_LANDLOCK, false, false)\n                .is_err());\n        }\n    }\n\n    #[cfg(test)]\n    mod output_outcome_tests {''',
    "receipt unit tests",
)

# Existing JSON format is intentionally untouched while 24B owns CLI surfaces;
# only update synthetic report literals so this independent core slice compiles.
replace_one(
    "src/cli_json.rs",
    "    use security_lab::{CapturedOutput, ProcessTreeUsage, RunReport};",
    "    use security_lab::{CapturedOutput, EnforcementReceipt, ProcessTreeUsage, RunReport};",
    "cli test receipt import",
)
replace_one(
    "src/cli_json.rs",
    "                max_child_rss_kib: 33,\n            },\n        };",
    "                max_child_rss_kib: 33,\n            },\n            enforcement: EnforcementReceipt::default(),\n        };",
    "cli binary fixture receipt",
)
replace_one(
    "src/cli_json.rs",
    "            reaped_descendants: 1,\n            process_tree_usage: ProcessTreeUsage::default(),\n        };",
    "            reaped_descendants: 1,\n            process_tree_usage: ProcessTreeUsage::default(),\n            enforcement: EnforcementReceipt::default(),\n        };",
    "cli output limit fixture receipt",
)

# Integration evidence: one baseline receipt and optional-layer positive evidence.
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn allowed_operation_succeeds() {\n    assert_eq!(\n        run(&policy(\"A\", &[], &[\"execveat\", \"write\", \"exit\"])).unwrap(),\n        ChildOutcome::Exited(0)\n    );\n}",
    '''#[test]\nfn allowed_operation_succeeds() {\n    let report = run_report(&policy("A", &[], &["execveat", "write", "exit"]))\n        .expect("allowed operation failed");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    let receipt = report.enforcement;\n    assert!(receipt.base_namespaces);\n    assert!(!receipt.time_namespace_offsets);\n    assert!(receipt.hostname);\n    assert!(receipt.private_mount_propagation);\n    assert!(receipt.readonly_root);\n    assert!(receipt.chroot);\n    assert!(receipt.fd_sanitization);\n    assert!(receipt.rlimits);\n    assert!(receipt.capabilities_reduced);\n    assert!(receipt.no_new_privs);\n    assert!(!receipt.landlock);\n    assert!(receipt.seccomp);\n    assert!(receipt.execveat);\n}''',
    "baseline runtime receipt evidence",
)
replace_one(
    "tests/sandbox.rs",
    "    let report = run_report(&timed).expect(\"time-namespace sandbox run failed\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    let captured = report.stdout.expect(\"time-namespace capture missing\");",
    "    let report = run_report(&timed).expect(\"time-namespace sandbox run failed\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    assert!(\n        report.enforcement.time_namespace_offsets,\n        \"runtime receipt did not record installed time namespace offsets\"\n    );\n    let captured = report.stdout.expect(\"time-namespace capture missing\");",
    "time namespace receipt evidence",
)
replace_one(
    "tests/sandbox.rs",
    "    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {",
    "    let report = run_report(&confined).expect(\"Landlock device sandbox failed\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    assert!(\n        report.enforcement.landlock,\n        \"runtime receipt did not record successful Landlock restriction\"\n    );\n}\n\n#[test]\nfn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {",
    "Landlock receipt evidence",
)
