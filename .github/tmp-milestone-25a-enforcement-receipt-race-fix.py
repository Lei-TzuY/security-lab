from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Receipt semantics must report only positively observed setup layers. A launcher
# control path can terminate the direct target before exec, so exec success is
# intentionally not inferred from lifecycle convergence.
replace_one(
    "src/report.rs",
    '''/// Kernel enforcement layers proven by this successful launcher-owned run.\n///\n/// Fields are published from the actual setup path after the corresponding\n/// kernel operation succeeds. Optional layers are false when they were not\n/// requested. `execveat` is confirmed by the host only after launch error state\n/// is clean and the PID-namespace lifecycle has converged.''',
    '''/// Kernel enforcement layers positively observed during this launcher-owned run.\n///\n/// Each field becomes true only after the corresponding kernel operation succeeds.\n/// A false field means that layer was not observed before termination; this can be\n/// expected when launcher-owned cancellation, deadline, or output-budget control\n/// wins while the direct target is still in setup. The receipt intentionally does\n/// not claim successful `execveat`, because a control-plane termination can race\n/// between the final pre-exec setup step and the non-returning exec syscall.''',
    "receipt semantics documentation",
)
replace_one(
    "src/report.rs",
    "    pub landlock: bool,\n    pub seccomp: bool,\n    pub execveat: bool,\n}",
    "    pub landlock: bool,\n    pub seccomp: bool,\n}",
    "remove unprovable exec receipt",
)
replace_one(
    "src/report.rs",
    "    /// Runtime receipt for enforcement layers established by this successful launch.\n    pub enforcement: EnforcementReceipt,",
    "    /// Runtime receipt for setup enforcement layers positively observed before termination.\n    pub enforcement: EnforcementReceipt,",
    "run report receipt wording",
)

# Replace completeness validation with monotonic progression validation. Later
# observed layers imply their earlier prerequisites; early control-plane
# termination is allowed to leave a valid partial receipt.
replace_one(
    "src/platform/linux.rs",
    '''    const ENFORCEMENT_MANDATORY: u64 = ENFORCEMENT_BASE_NAMESPACES\n        | ENFORCEMENT_HOSTNAME\n        | ENFORCEMENT_PRIVATE_MOUNTS\n        | ENFORCEMENT_READONLY_ROOT\n        | ENFORCEMENT_CHROOT\n        | ENFORCEMENT_FD_SANITIZATION\n        | ENFORCEMENT_RLIMITS\n        | ENFORCEMENT_CAPABILITIES\n        | ENFORCEMENT_NO_NEW_PRIVS\n        | ENFORCEMENT_SECCOMP;\n    const ENFORCEMENT_KNOWN: u64 =\n        ENFORCEMENT_MANDATORY | ENFORCEMENT_TIME_NAMESPACE | ENFORCEMENT_LANDLOCK;''',
    '''    const ENFORCEMENT_KNOWN: u64 = ENFORCEMENT_BASE_NAMESPACES\n        | ENFORCEMENT_TIME_NAMESPACE\n        | ENFORCEMENT_HOSTNAME\n        | ENFORCEMENT_PRIVATE_MOUNTS\n        | ENFORCEMENT_READONLY_ROOT\n        | ENFORCEMENT_CHROOT\n        | ENFORCEMENT_FD_SANITIZATION\n        | ENFORCEMENT_RLIMITS\n        | ENFORCEMENT_CAPABILITIES\n        | ENFORCEMENT_NO_NEW_PRIVS\n        | ENFORCEMENT_LANDLOCK\n        | ENFORCEMENT_SECCOMP;''',
    "receipt known bit mask",
)
replace_one(
    "src/platform/linux.rs",
    '''        let missing = ENFORCEMENT_MANDATORY & !bits;\n        if missing != 0 {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt is missing mandatory layer bits 0x{missing:x}"\n            )));\n        }\n\n        let time_namespace_offsets = bits & ENFORCEMENT_TIME_NAMESPACE != 0;\n        if time_namespace_offsets != time_namespace_requested {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt time-namespace mismatch: requested={time_namespace_requested} observed={time_namespace_offsets}"\n            )));\n        }\n        let landlock = bits & ENFORCEMENT_LANDLOCK != 0;\n        if landlock != landlock_requested {\n            return Err(SandboxError::SetupFailed(format!(\n                "runtime enforcement receipt Landlock mismatch: requested={landlock_requested} observed={landlock}"\n            )));\n        }''',
    '''        let observed = |bit| bits & bit != 0;\n        let require_predecessor = |later, earlier, label: &str| {\n            if observed(later) && !observed(earlier) {\n                Err(SandboxError::SetupFailed(format!(\n                    "runtime enforcement receipt published {label} without its required predecessor"\n                )))\n            } else {\n                Ok(())\n            }\n        };\n\n        require_predecessor(ENFORCEMENT_HOSTNAME, ENFORCEMENT_BASE_NAMESPACES, "hostname")?;\n        require_predecessor(\n            ENFORCEMENT_PRIVATE_MOUNTS,\n            ENFORCEMENT_HOSTNAME,\n            "private mount propagation",\n        )?;\n        require_predecessor(\n            ENFORCEMENT_READONLY_ROOT,\n            ENFORCEMENT_PRIVATE_MOUNTS,\n            "read-only root",\n        )?;\n        require_predecessor(ENFORCEMENT_CHROOT, ENFORCEMENT_READONLY_ROOT, "chroot")?;\n        require_predecessor(\n            ENFORCEMENT_FD_SANITIZATION,\n            ENFORCEMENT_CHROOT,\n            "FD sanitization",\n        )?;\n        require_predecessor(ENFORCEMENT_RLIMITS, ENFORCEMENT_FD_SANITIZATION, "rlimits")?;\n        require_predecessor(\n            ENFORCEMENT_CAPABILITIES,\n            ENFORCEMENT_RLIMITS,\n            "capability reduction",\n        )?;\n        require_predecessor(\n            ENFORCEMENT_NO_NEW_PRIVS,\n            ENFORCEMENT_CAPABILITIES,\n            "no_new_privs",\n        )?;\n        require_predecessor(ENFORCEMENT_LANDLOCK, ENFORCEMENT_NO_NEW_PRIVS, "Landlock")?;\n        require_predecessor(ENFORCEMENT_SECCOMP, ENFORCEMENT_NO_NEW_PRIVS, "seccomp")?;\n\n        let time_namespace_offsets = observed(ENFORCEMENT_TIME_NAMESPACE);\n        if time_namespace_offsets && !time_namespace_requested {\n            return Err(SandboxError::SetupFailed(\n                "runtime enforcement receipt observed unrequested time-namespace offsets".to_owned(),\n            ));\n        }\n        // Time offsets are installed before hostname. Reaching hostname with a\n        // requested time namespace but no time bit would be impossible without\n        // corrupted or incomplete receipt publication.\n        if time_namespace_requested\n            && observed(ENFORCEMENT_HOSTNAME)\n            && !time_namespace_offsets\n        {\n            return Err(SandboxError::SetupFailed(\n                "runtime enforcement receipt reached hostname without requested time-namespace offsets"\n                    .to_owned(),\n            ));\n        }\n\n        let landlock = observed(ENFORCEMENT_LANDLOCK);\n        if landlock && !landlock_requested {\n            return Err(SandboxError::SetupFailed(\n                "runtime enforcement receipt observed unrequested Landlock restriction".to_owned(),\n            ));\n        }\n        // Landlock restriction runs after no_new_privs and before seccomp. If\n        // seccomp was observed for a Landlock policy, Landlock must have been\n        // positively observed as well.\n        if landlock_requested && observed(ENFORCEMENT_SECCOMP) && !landlock {\n            return Err(SandboxError::SetupFailed(\n                "runtime enforcement receipt reached seccomp without requested Landlock restriction"\n                    .to_owned(),\n            ));\n        }''',
    "partial receipt progression validation",
)
replace_one(
    "src/platform/linux.rs",
    '''            landlock,\n            seccomp: bits & ENFORCEMENT_SECCOMP != 0,\n            // Successful exec cannot mark shared memory because execveat does not\n            // return. This decoder is invoked only after launch_error.phase == 0\n            // and PID1 publishes a complete target lifecycle; failed execveat\n            // writes PHASE_EXECVEAT and never reaches this path.\n            execveat: true,\n        })''',
    '''            landlock,\n            seccomp: bits & ENFORCEMENT_SECCOMP != 0,\n        })''',
    "remove exec receipt construction",
)

replace_one(
    "src/platform/linux.rs",
    '''        #[test]\n        fn mandatory_runtime_receipt_is_fail_closed() {\n            let missing_seccomp = ENFORCEMENT_MANDATORY & !ENFORCEMENT_SECCOMP;\n            let error = enforcement_receipt_from_bits(missing_seccomp, false, false)\n                .expect_err("missing mandatory enforcement must fail");\n            assert!(error.to_string().contains("missing mandatory layer bits"));\n        }\n\n        #[test]\n        fn optional_runtime_receipt_must_match_requested_layers() {\n            let base = ENFORCEMENT_MANDATORY;\n            assert!(enforcement_receipt_from_bits(base, true, false).is_err());\n            assert!(\n                enforcement_receipt_from_bits(base | ENFORCEMENT_TIME_NAMESPACE, false, false)\n                    .is_err()\n            );\n            assert!(enforcement_receipt_from_bits(base, false, true).is_err());\n            assert!(\n                enforcement_receipt_from_bits(base | ENFORCEMENT_LANDLOCK, false, false).is_err()\n            );\n        }''',
    '''        #[test]\n        fn impossible_runtime_receipt_progression_is_fail_closed() {\n            let unknown = enforcement_receipt_from_bits(1 << 63, false, false)\n                .expect_err("unknown receipt bits must fail");\n            assert!(unknown.to_string().contains("unknown layer bits"));\n\n            assert!(enforcement_receipt_from_bits(ENFORCEMENT_HOSTNAME, false, false).is_err());\n            assert!(enforcement_receipt_from_bits(\n                ENFORCEMENT_BASE_NAMESPACES | ENFORCEMENT_HOSTNAME,\n                true,\n                false,\n            )\n            .is_err());\n            assert!(enforcement_receipt_from_bits(\n                ENFORCEMENT_BASE_NAMESPACES | ENFORCEMENT_LANDLOCK,\n                false,\n                false,\n            )\n            .is_err());\n        }\n\n        #[test]\n        fn early_control_termination_can_publish_a_valid_partial_receipt() {\n            let receipt = enforcement_receipt_from_bits(\n                ENFORCEMENT_BASE_NAMESPACES,\n                true,\n                true,\n            )\n            .expect("early partial receipt should remain observable");\n            assert!(receipt.base_namespaces);\n            assert!(!receipt.time_namespace_offsets);\n            assert!(!receipt.hostname);\n            assert!(!receipt.landlock);\n            assert!(!receipt.seccomp);\n        }''',
    "receipt decoder regressions",
)

# Baseline completed target still proves the full generic setup sequence, but no
# exec claim is made by the receipt itself.
replace_one(
    "tests/sandbox.rs",
    "    assert!(!receipt.landlock);\n    assert!(receipt.seccomp);\n    assert!(receipt.execveat);",
    "    assert!(!receipt.landlock);\n    assert!(receipt.seccomp);",
    "baseline remove exec assertion",
)

# A token that is already ready before launch can win while the direct target is
# still in setup. This must remain Cancelled and return whatever setup layers were
# actually observed, rather than being converted to SetupFailed by receipt logic.
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn root_is_readonly_and_declared_scratch_is_writable() {",
    '''#[test]\nfn pre_cancelled_run_preserves_control_outcome_with_partial_receipt() {\n    let cancellation = CancellationToken::new().expect("create cancellation token");\n    cancellation.cancel().expect("pre-cancel token");\n    let mut cancellable = policy(\n        "Q",\n        &[],\n        &["execveat", "write", "fork", "nanosleep", "pause", "exit"],\n    );\n    cancellable.wall_clock_milliseconds = Some(5000);\n\n    let report = run_report_with_cancel(&cancellable, &cancellation)\n        .expect("pre-cancelled run should remain a valid controlled termination");\n    assert_eq!(report.outcome, ChildOutcome::Cancelled);\n    assert!(report.enforcement.base_namespaces);\n    assert!(report.enforcement.fd_sanitization);\n}\n\n#[test]\nfn root_is_readonly_and_declared_scratch_is_writable() {''',
    "pre-cancelled partial receipt regression",
)
