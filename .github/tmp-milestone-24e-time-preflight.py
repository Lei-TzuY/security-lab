from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    target = Path(path)
    text = target.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    target.write_text(text.replace(old, new, 1))


path = "src/policy_preflight.rs"

replace_one(
    path,
    "mod mandatory_core_probe;\n",
    "mod mandatory_core_probe;\nmod time_namespace_probe;\n",
    "module declaration",
)
replace_one(
    path,
    "use mandatory_core_probe::StagedCapabilityProbe;\n",
    "use mandatory_core_probe::StagedCapabilityProbe;\nuse time_namespace_probe::TimeNamespaceProbe;\n",
    "probe import",
)
replace_one(
    path,
    "    mandatory_namespace_mount_core: Option<StagedCapabilityProbe>,\n",
    "    mandatory_namespace_mount_core: Option<StagedCapabilityProbe>,\n    time_namespace_probe: Option<TimeNamespaceProbe>,\n",
    "preflight field",
)
replace_one(
    path,
    "    evaluated.mandatory_namespace_mount_core = Some(mandatory_core_probe::probe());\n    evaluated\n",
    """    evaluated.mandatory_namespace_mount_core = Some(mandatory_core_probe::probe());
    evaluated.time_namespace_probe = match (
        policy.time_monotonic_offset_seconds,
        policy.time_boottime_offset_seconds,
    ) {
        (Some(monotonic), Some(boottime)) => {
            Some(time_namespace_probe::probe(monotonic, boottime))
        }
        (None, None) => None,
        _ => unreachable!("validated time namespace policy must be all-or-nothing"),
    };
    evaluated
""",
    "probe integration",
)
replace_one(
    path,
    "        mandatory_namespace_mount_core: None,\n",
    "        mandatory_namespace_mount_core: None,\n        time_namespace_probe: None,\n",
    "evaluate initialization",
)
replace_one(
    path,
    """    fn time_namespace_status(&self) -> RequirementStatus {
        if self.requirements.time_namespace {
            RequirementStatus::Unprobed
        } else {
            RequirementStatus::NotRequested
        }
    }
""",
    """    fn time_namespace_status(&self) -> RequirementStatus {
        if !self.requirements.time_namespace {
            return RequirementStatus::NotRequested;
        }
        match self.time_namespace_probe {
            Some(probe) if probe.available => RequirementStatus::Supported,
            Some(_) => RequirementStatus::Unsupported,
            None => RequirementStatus::Unprobed,
        }
    }
""",
    "time namespace status",
)
replace_one(
    path,
    "            || self.output_limit_status() == RequirementStatus::Unsupported\n",
    "            || self.output_limit_status() == RequirementStatus::Unsupported\n            || self.time_namespace_status() == RequirementStatus::Unsupported\n",
    "unsupported verdict",
)
replace_one(
    path,
    """        output.push_str("},\\\"time_namespace\\\":{\\\"status\\\":\\\"");
        output.push_str(self.time_namespace_status().as_str());
        output.push_str("\\\",\\\"reason\\\":");
        if self.requirements.time_namespace {
            output.push_str("\\\"independent_safe_probe_not_implemented\\\"");
        } else {
            output.push_str("null");
        }
        output.push_str("},\\\"private_procfs\\\":{\\\"status\\\":\\\"");
""",
    """        output.push_str("},\\\"time_namespace\\\":");
        push_time_namespace_probe_json(
            &mut output,
            self.time_namespace_status(),
            self.requirements.time_namespace,
            self.time_namespace_probe,
        );
        output.push_str(",\\\"private_procfs\\\":{\\\"status\\\":\\\"");
""",
    "time namespace JSON",
)
replace_one(
    path,
    """        output.push_str("time-namespace: ");
        output.push_str(self.time_namespace_status().as_str());
        if self.requirements.time_namespace {
            output.push_str(" (independent-safe-probe-not-implemented)");
        }
        output.push('\\n');
""",
    """        output.push_str("time-namespace: ");
        output.push_str(self.time_namespace_status().as_str());
        if let Some(probe) = self.time_namespace_probe {
            write!(
                &mut output,
                " (stage={} isolated-helper=true configured-root-touched=false target-executed=false monotonic-offset-seconds={} boottime-offset-seconds={}",
                probe.stage,
                probe.monotonic_offset_seconds,
                probe.boottime_offset_seconds
            )
            .expect("write to String cannot fail");
            if let Some(errno) = probe.errno {
                write!(&mut output, " errno={errno}").expect("write to String cannot fail");
            }
            output.push(')');
        } else if self.requirements.time_namespace {
            output.push_str(" (independent-safe-probe-not-run)");
        }
        output.push('\\n');
""",
    "time namespace human",
)
replace_one(
    path,
    "fn push_probe_json(output: &mut String, probe: CapabilityProbe) {\n",
    """fn push_time_namespace_probe_json(
    output: &mut String,
    status: RequirementStatus,
    requested: bool,
    probe: Option<TimeNamespaceProbe>,
) {
    output.push_str("{\\\"status\\\":\\\"");
    output.push_str(status.as_str());
    output.push_str("\\\",\\\"reason\\\":");
    match status {
        RequirementStatus::Supported | RequirementStatus::NotRequested => output.push_str("null"),
        RequirementStatus::Unsupported => output.push_str("\\\"independent_safe_probe_failed\\\""),
        RequirementStatus::Unprobed if requested => {
            output.push_str("\\\"independent_safe_probe_not_run\\\"")
        }
        RequirementStatus::Unprobed => output.push_str("null"),
    }
    if let Some(probe) = probe {
        output.push_str(",\\\"probe\\\":{\\\"stage\\\":\\\"");
        output.push_str(probe.stage);
        output.push_str("\\\",\\\"errno\\\":");
        push_optional_i32(output, probe.errno);
        write!(
            output,
            ",\\\"isolated_helper\\\":true,\\\"configured_root_touched\\\":false,\\\"target_executed\\\":false,\\\"requested_monotonic_offset_seconds\\\":{},\\\"requested_boottime_offset_seconds\\\":{}",
            probe.monotonic_offset_seconds,
            probe.boottime_offset_seconds
        )
        .expect("write to String cannot fail");
        output.push('}');
    }
    output.push('}');
}

fn push_probe_json(output: &mut String, probe: CapabilityProbe) {
""",
    "time namespace JSON helper",
)
replace_one(
    path,
    """    #[test]
    fn requested_time_namespace_is_explicitly_indeterminate_until_probed() {
        let policy = policy("time.monotonic_offset_seconds = 1\\ntime.boottime_offset_seconds = 2");
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report
            .to_human()
            .contains("time-namespace: unprobed (independent-safe-probe-not-implemented)\\n"));
    }
""",
    """    #[test]
    fn requested_time_namespace_is_indeterminate_until_probe_runs() {
        let policy = policy("time.monotonic_offset_seconds = 1\\ntime.boottime_offset_seconds = 2");
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report
            .to_human()
            .contains("time-namespace: unprobed (independent-safe-probe-not-run)\\n"));
    }

    #[test]
    fn supported_time_namespace_probe_closes_optional_preflight_gap() {
        let policy = policy("time.monotonic_offset_seconds = 60\\ntime.boottime_offset_seconds = 120");
        let mut report =
            evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Supported);
        report.time_namespace_probe = Some(TimeNamespaceProbe::available(60, 120));
        assert_eq!(report.time_namespace_status(), RequirementStatus::Supported);
        assert_eq!(report.verdict(), Verdict::Satisfied);
        assert!(report.to_json().contains(
            "\\\"time_namespace\\\":{\\\"status\\\":\\\"supported\\\",\\\"reason\\\":null,\\\"probe\\\":{\\\"stage\\\":\\\"complete\\\",\\\"errno\\\":null,\\\"isolated_helper\\\":true,\\\"configured_root_touched\\\":false,\\\"target_executed\\\":false,\\\"requested_monotonic_offset_seconds\\\":60,\\\"requested_boottime_offset_seconds\\\":120}}"
        ));
    }

    #[test]
    fn unsupported_time_namespace_probe_is_incompatible() {
        let policy = policy("time.monotonic_offset_seconds = 60\\ntime.boottime_offset_seconds = 120");
        let mut report =
            evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Supported);
        report.time_namespace_probe = Some(TimeNamespaceProbe::unavailable(
            "timens_monotonic",
            Some(1),
            60,
            120,
        ));
        assert_eq!(report.time_namespace_status(), RequirementStatus::Unsupported);
        assert_eq!(report.verdict(), Verdict::Incompatible);
        assert_eq!(report.exit_code(), 3);
    }
""",
    "time namespace tests",
)
