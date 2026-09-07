from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# The policy-specific preflight is deliberately not a launch dry-run.  The
# first 24B construction modeled requested optional mechanisms, but it could
# still call the overall policy/host pair `satisfied` while the mandatory
# launch core remained completely unprobed.  Make that missing evidence an
# explicit first-class requirement instead of allowing a false positive.
replace_one(
    "src/policy_preflight.rs",
    """pub(crate) struct PolicyPreflight {
    host: HostCapabilities,
    requirements: PolicyRequirements,
}

pub(crate) fn probe(policy: &SandboxPolicy) -> PolicyPreflight {
    evaluate(policy, host_capabilities::probe())
}

fn evaluate(policy: &SandboxPolicy, host: HostCapabilities) -> PolicyPreflight {
    PolicyPreflight {
        host,
        requirements: PolicyRequirements::from_policy(policy),
    }
}
""",
    """pub(crate) struct PolicyPreflight {
    host: HostCapabilities,
    requirements: PolicyRequirements,
    mandatory_launch_core: RequirementStatus,
}

pub(crate) fn probe(policy: &SandboxPolicy) -> PolicyPreflight {
    evaluate(policy, host_capabilities::probe())
}

fn evaluate(policy: &SandboxPolicy, host: HostCapabilities) -> PolicyPreflight {
    // We intentionally do not mutate host namespace/mount state or attempt a
    // sandbox launch merely to obtain a green preflight verdict.  Until the
    // mandatory launch core has a complete independent probe, the real CLI
    // result must remain indeterminate rather than claiming compatibility.
    evaluate_with_core(policy, host, RequirementStatus::Unprobed)
}

fn evaluate_with_core(
    policy: &SandboxPolicy,
    host: HostCapabilities,
    mandatory_launch_core: RequirementStatus,
) -> PolicyPreflight {
    PolicyPreflight {
        host,
        requirements: PolicyRequirements::from_policy(policy),
        mandatory_launch_core,
    }
}
""",
    "policy preflight mandatory core state",
)

replace_one(
    "src/policy_preflight.rs",
    """    fn time_namespace_status(&self) -> RequirementStatus {
        if self.requirements.time_namespace {
            RequirementStatus::Unprobed
        } else {
            RequirementStatus::NotRequested
        }
    }

    fn verdict(&self) -> Verdict {
        if !self.host.sandbox_target_supported
            || self.landlock_status() == RequirementStatus::Unsupported
            || self.deadline_status() == RequirementStatus::Unsupported
            || self.output_limit_status() == RequirementStatus::Unsupported
        {
            Verdict::Incompatible
        } else if self.time_namespace_status() == RequirementStatus::Unprobed {
            Verdict::Indeterminate
        } else {
            Verdict::Satisfied
        }
    }
""",
    """    fn time_namespace_status(&self) -> RequirementStatus {
        if self.requirements.time_namespace {
            RequirementStatus::Unprobed
        } else {
            RequirementStatus::NotRequested
        }
    }

    fn mandatory_launch_core_status(&self) -> RequirementStatus {
        self.mandatory_launch_core
    }

    fn mandatory_launch_core_reason(&self) -> Option<&'static str> {
        match self.mandatory_launch_core_status() {
            RequirementStatus::Unprobed => Some("mandatory_runtime_prerequisites_not_probed"),
            RequirementStatus::Unsupported => Some("mandatory_runtime_prerequisite_unavailable"),
            RequirementStatus::NotRequested | RequirementStatus::Supported => None,
        }
    }

    fn verdict(&self) -> Verdict {
        if !self.host.sandbox_target_supported
            || self.mandatory_launch_core_status() == RequirementStatus::Unsupported
            || self.landlock_status() == RequirementStatus::Unsupported
            || self.deadline_status() == RequirementStatus::Unsupported
            || self.output_limit_status() == RequirementStatus::Unsupported
        {
            Verdict::Incompatible
        } else if self.mandatory_launch_core_status() == RequirementStatus::Unprobed
            || self.time_namespace_status() == RequirementStatus::Unprobed
        {
            Verdict::Indeterminate
        } else {
            Verdict::Satisfied
        }
    }
""",
    "policy preflight verdict uses mandatory core",
)

replace_one(
    "src/policy_preflight.rs",
    """        output.push_str("\\\",\\\"target_arch\\\":\\\"");
        output.push_str(self.host.target_arch);
        output.push_str("\\\"},\\\"landlock\\\":{\\\"status\\\":\\\"");
""",
    """        output.push_str("\\\",\\\"target_arch\\\":\\\"");
        output.push_str(self.host.target_arch);
        output.push_str("\\\"},\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"");
        output.push_str(self.mandatory_launch_core_status().as_str());
        output.push_str("\\\",\\\"reason\\\":");
        if let Some(reason) = self.mandatory_launch_core_reason() {
            write!(&mut output, "\\\"{reason}\\\"").expect("write to String cannot fail");
        } else {
            output.push_str("null");
        }
        output.push_str("},\\\"landlock\\\":{\\\"status\\\":\\\"");
""",
    "policy preflight JSON mandatory core",
)

replace_one(
    "src/policy_preflight.rs",
    """        )
        .expect("write to String cannot fail");
        output.push_str("landlock: ");
""",
    """        )
        .expect("write to String cannot fail");
        output.push_str("mandatory-launch-core: ");
        output.push_str(self.mandatory_launch_core_status().as_str());
        if let Some(reason) = self.mandatory_launch_core_reason() {
            write!(&mut output, " ({reason})").expect("write to String cannot fail");
        }
        output.push('\\n');
        output.push_str("landlock: ");
""",
    "policy preflight human mandatory core",
)

# Preserve a deterministic `satisfied` evaluator path only when tests inject
# explicit complete mandatory-core evidence.  The real probe() never injects
# that evidence today, so production CLI output cannot take this branch.
replace_one(
    "src/policy_preflight.rs",
    "    fn exact_json_contract_reports_satisfied_known_requirements() {",
    "    fn exact_json_contract_requires_explicit_mandatory_core_evidence() {",
    "policy preflight satisfied test name",
)
replace_one(
    "src/policy_preflight.rs",
    """        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.exit_code(), 0);
""",
    """        let report = evaluate_with_core(
            &policy,
            host(Some(7)),
            RequirementStatus::Supported,
        );
        assert_eq!(report.exit_code(), 0);
""",
    "policy preflight satisfied test explicit core evidence",
)
replace_one(
    "src/policy_preflight.rs",
    "\\\"target_arch\\\":\\\"x86_64\\\"},\\\"landlock\\\":{",
    "\\\"target_arch\\\":\\\"x86_64\\\"},\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"supported\\\",\\\"reason\\\":null},\\\"landlock\\\":{",
    "policy preflight exact JSON mandatory core",
)

new_unit_tests = r'''
    #[test]
    fn unprobed_mandatory_launch_core_prevents_false_satisfaction() {
        let policy = policy(
            "landlock.scope_signal = enabled\nlimit.wall_clock_milliseconds = 1000\nlimit.stdout_total_bytes = 8192",
        );
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(
            report.mandatory_launch_core_status(),
            RequirementStatus::Unprobed
        );
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report.to_json().contains(
            "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
        ));
    }

    #[test]
    fn unavailable_mandatory_launch_core_is_incompatible() {
        let policy = policy("");
        let report = evaluate_with_core(
            &policy,
            host(Some(7)),
            RequirementStatus::Unsupported,
        );
        assert_eq!(
            report.mandatory_launch_core_status(),
            RequirementStatus::Unsupported
        );
        assert_eq!(report.verdict(), Verdict::Incompatible);
        assert_eq!(report.exit_code(), 3);
    }

'''
replace_one(
    "src/policy_preflight.rs",
    "    #[test]\n    fn known_incompatibility_wins_over_unprobed_requirement() {",
    new_unit_tests + "    #[test]\n    fn known_incompatibility_wins_over_unprobed_requirement() {",
    "policy preflight mandatory core regressions",
)

# The live CLI must reflect the incomplete mandatory-core evidence.  Optional
# probes may all be green, but that can only produce an indeterminate verdict
# until the core launch prerequisites are independently established.
replace_one(
    "tests/cli.rs",
    "fn preflight_json_matches_known_policy_requirements_without_launching() {",
    "fn preflight_json_remains_indeterminate_without_mandatory_core_probe() {",
    "CLI preflight false-positive regression name",
)
replace_one(
    "tests/cli.rs",
    """    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.starts_with(
        "{\\\"ok\\\":true,\\\"preflight\\\":{\\\"kind\\\":\\\"policy_host_capability_match\\\",\\\"policy_preflight\\\":true,\\\"launch_attempted\\\":false,\\\"launch_preflight_complete\\\":false,\\\"status\\\":\\\"satisfied\\\""
    ));
""",
    """    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.starts_with(
        "{\\\"ok\\\":true,\\\"preflight\\\":{\\\"kind\\\":\\\"policy_host_capability_match\\\",\\\"policy_preflight\\\":true,\\\"launch_attempted\\\":false,\\\"launch_preflight_complete\\\":false,\\\"status\\\":\\\"indeterminate\\\""
    ));
    assert!(stdout.contains(
        "\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"mandatory_runtime_prerequisites_not_probed\\\"}"
    ));
""",
    "CLI preflight known optional probes cannot satisfy core",
)

replace_one(
    "tests/cli.rs",
    """    assert!(stdout.contains("\\\"status\\\":\\\"indeterminate\\\""));
    assert!(stdout.contains(
        "\\\"time_namespace\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"independent_safe_probe_not_implemented\\\"}"
    ));
""",
    """    assert!(stdout.contains("\\\"status\\\":\\\"indeterminate\\\""));
    assert!(stdout.contains(
        "\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"mandatory_runtime_prerequisites_not_probed\\\"}"
    ));
    assert!(stdout.contains(
        "\\\"time_namespace\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"independent_safe_probe_not_implemented\\\"}"
    ));
""",
    "CLI time namespace also exposes mandatory core gap",
)

replace_one(
    "tests/cli.rs",
    """    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight human stdout is UTF-8");
    assert!(stdout.starts_with(
        "policy-host-preflight:\\nkind: policy-host-capability-match\\npolicy-preflight: true\\nlaunch-attempted: false\\nlaunch-preflight-complete: false\\nstatus: satisfied\\n"
    ));
    assert!(stdout.contains("time-namespace: not_requested\\n"));
""",
    """    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight human stdout is UTF-8");
    assert!(stdout.starts_with(
        "policy-host-preflight:\\nkind: policy-host-capability-match\\npolicy-preflight: true\\nlaunch-attempted: false\\nlaunch-preflight-complete: false\\nstatus: indeterminate\\n"
    ));
    assert!(stdout.contains(
        "mandatory-launch-core: unprobed (mandatory_runtime_prerequisites_not_probed)\\n"
    ));
    assert!(stdout.contains("time-namespace: not_requested\\n"));
""",
    "CLI human preflight exposes mandatory core gap",
)
