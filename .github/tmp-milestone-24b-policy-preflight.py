from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Host capability snapshot: expose crate-private probe data and add the eventfd
# primitive required by the observed stdout-budget supervision path.
replace_one(
    "src/host_capabilities.rs",
    "struct CapabilityProbe {\n    available: bool,\n    errno: Option<i32>,\n}",
    "pub(crate) struct CapabilityProbe {\n    pub(crate) available: bool,\n    pub(crate) errno: Option<i32>,\n}",
    "capability probe visibility",
)
replace_one(
    "src/host_capabilities.rs",
    "    const fn available() -> Self {",
    "    pub(crate) const fn available() -> Self {",
    "capability available constructor",
)
replace_one(
    "src/host_capabilities.rs",
    "    const fn unavailable(errno: Option<i32>) -> Self {",
    "    pub(crate) const fn unavailable(errno: Option<i32>) -> Self {",
    "capability unavailable constructor",
)
replace_one(
    "src/host_capabilities.rs",
    "pub(crate) struct HostCapabilities {\n    target_os: &'static str,\n    target_arch: &'static str,\n    sandbox_target_supported: bool,\n    landlock_abi: Option<u32>,\n    landlock_errno: Option<i32>,\n    pidfd_open: CapabilityProbe,\n    timerfd_monotonic: CapabilityProbe,\n    cgroup_v2: bool,\n}",
    "pub(crate) struct HostCapabilities {\n    pub(crate) target_os: &'static str,\n    pub(crate) target_arch: &'static str,\n    pub(crate) sandbox_target_supported: bool,\n    pub(crate) landlock_abi: Option<u32>,\n    pub(crate) landlock_errno: Option<i32>,\n    pub(crate) pidfd_open: CapabilityProbe,\n    pub(crate) timerfd_monotonic: CapabilityProbe,\n    pub(crate) eventfd: CapabilityProbe,\n    pub(crate) cgroup_v2: bool,\n}",
    "host capability visibility and eventfd",
)
replace_one(
    "src/host_capabilities.rs",
    "    let (landlock_abi, landlock_errno, pidfd_open, timerfd_monotonic, cgroup_v2) =\n        platform_probes();",
    "    let (\n        landlock_abi,\n        landlock_errno,\n        pidfd_open,\n        timerfd_monotonic,\n        eventfd,\n        cgroup_v2,\n    ) = platform_probes();",
    "host probe tuple",
)
replace_one(
    "src/host_capabilities.rs",
    "        timerfd_monotonic,\n        cgroup_v2,",
    "        timerfd_monotonic,\n        eventfd,\n        cgroup_v2,",
    "host probe construction",
)
replace_one(
    "src/host_capabilities.rs",
    "        output.push_str(\",\\\"timerfd_monotonic\\\":\");\n        push_probe_json(&mut output, self.timerfd_monotonic);\n        output.push_str(\",\\\"cgroup_v2\\\":{\\\"present\\\":\");",
    "        output.push_str(\",\\\"timerfd_monotonic\\\":\");\n        push_probe_json(&mut output, self.timerfd_monotonic);\n        output.push_str(\",\\\"eventfd\\\":\");\n        push_probe_json(&mut output, self.eventfd);\n        output.push_str(\",\\\"cgroup_v2\\\":{\\\"present\\\":\");",
    "host JSON eventfd",
)
replace_one(
    "src/host_capabilities.rs",
    "        push_probe_human(&mut output, \"timerfd-monotonic\", self.timerfd_monotonic);\n        writeln!(",
    "        push_probe_human(&mut output, \"timerfd-monotonic\", self.timerfd_monotonic);\n        push_probe_human(&mut output, \"eventfd\", self.eventfd);\n        writeln!(",
    "host human eventfd",
)
replace_one(
    "src/host_capabilities.rs",
    "    CapabilityProbe,\n    CapabilityProbe,\n    bool,\n) {",
    "    CapabilityProbe,\n    CapabilityProbe,\n    CapabilityProbe,\n    bool,\n) {",
    "linux platform tuple signature",
)
# The same signature text occurs again for the non-Linux implementation after
# the first replacement, so replace it once more.
replace_one(
    "src/host_capabilities.rs",
    "    CapabilityProbe,\n    CapabilityProbe,\n    bool,\n) {",
    "    CapabilityProbe,\n    CapabilityProbe,\n    CapabilityProbe,\n    bool,\n) {",
    "non-linux platform tuple signature",
)
replace_one(
    "src/host_capabilities.rs",
    "    let timerfd_result = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };\n    let timerfd_monotonic = fd_probe(timerfd_result as libc::c_long);\n\n    (\n        landlock_abi,\n        landlock_errno,\n        pidfd_open,\n        timerfd_monotonic,\n        Path::new(\"/sys/fs/cgroup/cgroup.controllers\").is_file(),\n    )",
    "    let timerfd_result = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };\n    let timerfd_monotonic = fd_probe(timerfd_result as libc::c_long);\n\n    let eventfd_result = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };\n    let eventfd = fd_probe(eventfd_result as libc::c_long);\n\n    (\n        landlock_abi,\n        landlock_errno,\n        pidfd_open,\n        timerfd_monotonic,\n        eventfd,\n        Path::new(\"/sys/fs/cgroup/cgroup.controllers\").is_file(),\n    )",
    "linux eventfd probe",
)
replace_one(
    "src/host_capabilities.rs",
    "        CapabilityProbe::unavailable(None),\n        CapabilityProbe::unavailable(None),\n        false,\n    )",
    "        CapabilityProbe::unavailable(None),\n        CapabilityProbe::unavailable(None),\n        CapabilityProbe::unavailable(None),\n        false,\n    )",
    "non-linux eventfd probe",
)
replace_one(
    "src/host_capabilities.rs",
    "            timerfd_monotonic: CapabilityProbe::unavailable(Some(38)),\n            cgroup_v2: true,",
    "            timerfd_monotonic: CapabilityProbe::unavailable(Some(38)),\n            eventfd: CapabilityProbe::available(),\n            cgroup_v2: true,",
    "host unit fixture eventfd",
)
replace_one(
    "src/host_capabilities.rs",
    "\\\"timerfd_monotonic\\\":{\\\"available\\\":false,\\\"errno\\\":38},\\\"cgroup_v2\\\"",
    "\\\"timerfd_monotonic\\\":{\\\"available\\\":false,\\\"errno\\\":38},\\\"eventfd\\\":{\\\"available\\\":true,\\\"errno\\\":null},\\\"cgroup_v2\\\"",
    "host unit JSON eventfd",
)
replace_one(
    "src/host_capabilities.rs",
    "timerfd-monotonic: unavailable (errno=38)\\ncgroup-v2:",
    "timerfd-monotonic: unavailable (errno=38)\\neventfd: available\\ncgroup-v2:",
    "host unit human eventfd",
)

# New policy-specific host capability matcher. This is deliberately not a full
# launch dry-run: unsupported known requirements are authoritative, while
# requested mechanisms without an independent safe probe remain explicit
# `unprobed` and make the result indeterminate.
Path("src/policy_preflight.rs").write_text(r'''use crate::host_capabilities::{self, CapabilityProbe, HostCapabilities};
use security_lab::SandboxPolicy;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequirementStatus {
    NotRequested,
    Supported,
    Unsupported,
    Unprobed,
}

impl RequirementStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NotRequested => "not_requested",
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Unprobed => "unprobed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    Satisfied,
    Incompatible,
    Indeterminate,
}

impl Verdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Incompatible => "incompatible",
            Self::Indeterminate => "indeterminate",
        }
    }

    const fn exit_code(self) -> i32 {
        match self {
            Self::Satisfied => 0,
            Self::Incompatible => 3,
            Self::Indeterminate => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PolicyRequirements {
    landlock_abi: Option<u32>,
    deadline: bool,
    stdout_output_limit: bool,
    time_namespace: bool,
}

impl PolicyRequirements {
    fn from_policy(policy: &SandboxPolicy) -> Self {
        let mut landlock_abi = None;
        let any_landlock = !policy.landlock_read_execute.is_empty()
            || !policy.landlock_file_mutate.is_empty()
            || !policy.landlock_path_topology_mutate.is_empty()
            || !policy.landlock_device_ioctl.is_empty()
            || !policy.landlock_tcp_bind_ports.is_empty()
            || !policy.landlock_tcp_connect_ports.is_empty()
            || policy.landlock_scope_abstract_unix_socket
            || policy.landlock_scope_signal;
        if any_landlock {
            raise_abi(&mut landlock_abi, 1);
        }
        // File-mutation policy handles TRUNCATE; topology augmentation is only
        // valid alongside file-mutation policy and therefore inherits ABI 3.
        if !policy.landlock_file_mutate.is_empty()
            || !policy.landlock_path_topology_mutate.is_empty()
        {
            raise_abi(&mut landlock_abi, 3);
        }
        if !policy.landlock_tcp_bind_ports.is_empty()
            || !policy.landlock_tcp_connect_ports.is_empty()
        {
            raise_abi(&mut landlock_abi, 4);
        }
        if !policy.landlock_device_ioctl.is_empty() {
            raise_abi(&mut landlock_abi, 5);
        }
        if policy.landlock_scope_abstract_unix_socket || policy.landlock_scope_signal {
            raise_abi(&mut landlock_abi, 6);
        }

        Self {
            landlock_abi,
            deadline: policy.wall_clock_milliseconds.is_some(),
            stdout_output_limit: policy.stdout_total_bytes.is_some(),
            time_namespace: policy.time_monotonic_offset_seconds.is_some()
                && policy.time_boottime_offset_seconds.is_some(),
        }
    }
}

fn raise_abi(current: &mut Option<u32>, required: u32) {
    match current {
        Some(value) if *value >= required => {}
        _ => *current = Some(required),
    }
}

pub(crate) struct PolicyPreflight {
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

impl PolicyPreflight {
    fn landlock_status(&self) -> RequirementStatus {
        let Some(required) = self.requirements.landlock_abi else {
            return RequirementStatus::NotRequested;
        };
        match self.host.landlock_abi {
            Some(observed) if observed >= required => RequirementStatus::Supported,
            _ => RequirementStatus::Unsupported,
        }
    }

    fn deadline_status(&self) -> RequirementStatus {
        probe_pair_status(
            self.requirements.deadline,
            self.host.pidfd_open,
            self.host.timerfd_monotonic,
        )
    }

    fn output_limit_status(&self) -> RequirementStatus {
        probe_pair_status(
            self.requirements.stdout_output_limit,
            self.host.pidfd_open,
            self.host.eventfd,
        )
    }

    fn time_namespace_status(&self) -> RequirementStatus {
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

    pub(crate) fn exit_code(&self) -> i32 {
        self.verdict().exit_code()
    }

    pub(crate) fn to_json(&self) -> String {
        let mut output = String::from(
            "{\"ok\":true,\"preflight\":{\"kind\":\"policy_host_capability_match\",\"policy_preflight\":true,\"launch_attempted\":false,\"launch_preflight_complete\":false,\"status\":\"",
        );
        output.push_str(self.verdict().as_str());
        output.push_str("\",\"sandbox_target\":{\"status\":\"");
        output.push_str(if self.host.sandbox_target_supported {
            "supported"
        } else {
            "unsupported"
        });
        output.push_str("\",\"target_os\":\"");
        output.push_str(self.host.target_os);
        output.push_str("\",\"target_arch\":\"");
        output.push_str(self.host.target_arch);
        output.push_str("\"},\"landlock\":{\"status\":\"");
        output.push_str(self.landlock_status().as_str());
        output.push_str("\",\"required_abi\":");
        push_optional_u32(&mut output, self.requirements.landlock_abi);
        output.push_str(",\"observed_abi\":");
        push_optional_u32(&mut output, self.host.landlock_abi);
        output.push_str(",\"errno\":");
        push_optional_i32(&mut output, self.host.landlock_errno);
        output.push_str("},\"deadline\":{\"status\":\"");
        output.push_str(self.deadline_status().as_str());
        output.push_str("\",\"pidfd_open\":");
        push_probe_json(&mut output, self.host.pidfd_open);
        output.push_str(",\"timerfd_monotonic\":");
        push_probe_json(&mut output, self.host.timerfd_monotonic);
        output.push_str("},\"stdout_output_limit\":{\"status\":\"");
        output.push_str(self.output_limit_status().as_str());
        output.push_str("\",\"pidfd_open\":");
        push_probe_json(&mut output, self.host.pidfd_open);
        output.push_str(",\"eventfd\":");
        push_probe_json(&mut output, self.host.eventfd);
        output.push_str("},\"time_namespace\":{\"status\":\"");
        output.push_str(self.time_namespace_status().as_str());
        output.push_str("\",\"reason\":");
        if self.requirements.time_namespace {
            output.push_str("\"independent_safe_probe_not_implemented\"");
        } else {
            output.push_str("null");
        }
        output.push_str("}}}");
        output
    }

    pub(crate) fn to_human(&self) -> String {
        let mut output = String::from(
            "policy-host-preflight:\nkind: policy-host-capability-match\npolicy-preflight: true\nlaunch-attempted: false\nlaunch-preflight-complete: false\n",
        );
        writeln!(&mut output, "status: {}", self.verdict().as_str())
            .expect("write to String cannot fail");
        writeln!(
            &mut output,
            "sandbox-target: {} ({}/{})",
            if self.host.sandbox_target_supported {
                "supported"
            } else {
                "unsupported"
            },
            self.host.target_os,
            self.host.target_arch
        )
        .expect("write to String cannot fail");
        output.push_str("landlock: ");
        output.push_str(self.landlock_status().as_str());
        output.push_str(" (required-abi=");
        push_optional_u32_human(&mut output, self.requirements.landlock_abi);
        output.push_str(" observed-abi=");
        push_optional_u32_human(&mut output, self.host.landlock_abi);
        if let Some(errno) = self.host.landlock_errno {
            write!(&mut output, " errno={errno}").expect("write to String cannot fail");
        }
        output.push_str(")\n");
        push_pair_human(
            &mut output,
            "deadline",
            self.deadline_status(),
            "pidfd-open",
            self.host.pidfd_open,
            "timerfd-monotonic",
            self.host.timerfd_monotonic,
        );
        push_pair_human(
            &mut output,
            "stdout-output-limit",
            self.output_limit_status(),
            "pidfd-open",
            self.host.pidfd_open,
            "eventfd",
            self.host.eventfd,
        );
        output.push_str("time-namespace: ");
        output.push_str(self.time_namespace_status().as_str());
        if self.requirements.time_namespace {
            output.push_str(" (independent-safe-probe-not-implemented)");
        }
        output.push('\n');
        output
    }
}

fn probe_pair_status(
    requested: bool,
    first: CapabilityProbe,
    second: CapabilityProbe,
) -> RequirementStatus {
    if !requested {
        RequirementStatus::NotRequested
    } else if first.available && second.available {
        RequirementStatus::Supported
    } else {
        RequirementStatus::Unsupported
    }
}

fn push_probe_json(output: &mut String, probe: CapabilityProbe) {
    output.push_str("{\"available\":");
    output.push_str(if probe.available { "true" } else { "false" });
    output.push_str(",\"errno\":");
    push_optional_i32(output, probe.errno);
    output.push('}');
}

fn push_optional_u32(output: &mut String, value: Option<u32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("null"),
    }
}

fn push_optional_i32(output: &mut String, value: Option<i32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("null"),
    }
}

fn push_optional_u32_human(output: &mut String, value: Option<u32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("none"),
    }
}

fn push_pair_human(
    output: &mut String,
    label: &str,
    status: RequirementStatus,
    first_label: &str,
    first: CapabilityProbe,
    second_label: &str,
    second: CapabilityProbe,
) {
    write!(output, "{label}: {}", status.as_str()).expect("write to String cannot fail");
    if status != RequirementStatus::NotRequested {
        write!(
            output,
            " ({first_label}={} {second_label}={})",
            probe_human(first),
            probe_human(second)
        )
        .expect("write to String cannot fail");
    }
    output.push('\n');
}

fn probe_human(probe: CapabilityProbe) -> String {
    if probe.available {
        "available".to_owned()
    } else if let Some(errno) = probe.errno {
        format!("unavailable(errno={errno})")
    } else {
        "unavailable".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
filesystem.root = /
identity.hostname = preflight
executable = /bin/true
working_dir = /
stdio.stdin = closed
stdio.stdout = capture
stdio.stdout_capture_bytes = 4096
stdio.stderr = closed
limit.cpu_seconds = 1
limit.address_space_bytes = 67108864
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,exit
"#;

    fn policy(extra: &str) -> SandboxPolicy {
        format!("{BASE}\n{extra}\n").parse().expect("valid preflight policy")
    }

    fn host(abi: Option<u32>) -> HostCapabilities {
        HostCapabilities {
            target_os: "linux",
            target_arch: "x86_64",
            sandbox_target_supported: true,
            landlock_abi: abi,
            landlock_errno: None,
            pidfd_open: CapabilityProbe::available(),
            timerfd_monotonic: CapabilityProbe::available(),
            eventfd: CapabilityProbe::available(),
            cgroup_v2: true,
        }
    }

    #[test]
    fn derives_highest_requested_landlock_abi_and_supervision_requirements() {
        let policy = policy(
            "landlock.scope_signal = enabled\nlimit.wall_clock_milliseconds = 1000\nlimit.stdout_total_bytes = 8192",
        );
        assert_eq!(
            PolicyRequirements::from_policy(&policy),
            PolicyRequirements {
                landlock_abi: Some(6),
                deadline: true,
                stdout_output_limit: true,
                time_namespace: false,
            }
        );
    }

    #[test]
    fn exact_json_contract_reports_satisfied_known_requirements() {
        let policy = policy(
            "landlock.scope_signal = enabled\nlimit.wall_clock_milliseconds = 1000\nlimit.stdout_total_bytes = 8192",
        );
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.exit_code(), 0);
        assert_eq!(
            report.to_json(),
            "{\"ok\":true,\"preflight\":{\"kind\":\"policy_host_capability_match\",\"policy_preflight\":true,\"launch_attempted\":false,\"launch_preflight_complete\":false,\"status\":\"satisfied\",\"sandbox_target\":{\"status\":\"supported\",\"target_os\":\"linux\",\"target_arch\":\"x86_64\"},\"landlock\":{\"status\":\"supported\",\"required_abi\":6,\"observed_abi\":7,\"errno\":null},\"deadline\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"timerfd_monotonic\":{\"available\":true,\"errno\":null}},\"stdout_output_limit\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"eventfd\":{\"available\":true,\"errno\":null}},\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null}}}"
        );
    }

    #[test]
    fn known_incompatibility_wins_over_unprobed_requirement() {
        let policy = policy(
            "landlock.scope_signal = enabled\ntime.monotonic_offset_seconds = 1\ntime.boottime_offset_seconds = 2",
        );
        let mut fixture = host(Some(5));
        fixture.timerfd_monotonic = CapabilityProbe::unavailable(Some(38));
        let report = evaluate(&policy, fixture);
        assert_eq!(report.verdict(), Verdict::Incompatible);
        assert_eq!(report.exit_code(), 3);
        assert_eq!(report.landlock_status(), RequirementStatus::Unsupported);
        assert_eq!(report.time_namespace_status(), RequirementStatus::Unprobed);
    }

    #[test]
    fn requested_time_namespace_is_explicitly_indeterminate_until_probed() {
        let policy = policy(
            "time.monotonic_offset_seconds = 1\ntime.boottime_offset_seconds = 2",
        );
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report.to_human().contains(
            "time-namespace: unprobed (independent-safe-probe-not-implemented)\n"
        ));
    }
}
''')

# Wire the new policy-specific command without changing run/check/manifest/host
# semantics.
replace_one(
    "src/main.rs",
    "mod host_capabilities;\n",
    "mod host_capabilities;\nmod policy_preflight;\n",
    "main preflight module",
)
replace_one(
    "src/main.rs",
    "    let host_json_requested = command.as_deref() == Some(OsStr::new(\"host-json\"));\n    let host_requested = command.as_deref() == Some(OsStr::new(\"host\"));",
    "    let host_json_requested = command.as_deref() == Some(OsStr::new(\"host-json\"));\n    let host_requested = command.as_deref() == Some(OsStr::new(\"host\"));\n    let preflight_json_requested = command.as_deref() == Some(OsStr::new(\"preflight-json\"));\n    let preflight_requested = command.as_deref() == Some(OsStr::new(\"preflight\"));",
    "main preflight command flags",
)
replace_one(
    "src/main.rs",
    "        || manifest_json_requested\n        || host_json_requested;",
    "        || manifest_json_requested\n        || host_json_requested\n        || preflight_json_requested;",
    "main machine preflight",
)
replace_one(
    "src/main.rs",
    "        || manifest_requested\n        || host_json_requested\n        || host_requested;",
    "        || manifest_requested\n        || host_json_requested\n        || host_requested\n        || preflight_json_requested\n        || preflight_requested;",
    "main recognized preflight",
)
replace_one(
    "src/main.rs",
    "            \"usage: {display_program} <run|run-json|check|check-json|manifest|manifest-json> <policy-file> | {display_program} <host|host-json>\"",
    "            \"usage: {display_program} <run|run-json|check|check-json|manifest|manifest-json|preflight|preflight-json> <policy-file> | {display_program} <host|host-json>\"",
    "main usage preflight",
)
replace_one(
    "src/main.rs",
    "    if manifest_json_requested {\n        println!(\"{}\", authority_manifest::to_json(&policy));",
    "    if preflight_json_requested {\n        let report = policy_preflight::probe(&policy);\n        println!(\"{}\", report.to_json());\n        process::exit(report.exit_code());\n    }\n    if preflight_requested {\n        let report = policy_preflight::probe(&policy);\n        print!(\"{}\", report.to_human());\n        process::exit(report.exit_code());\n    }\n    if manifest_json_requested {\n        println!(\"{}\", authority_manifest::to_json(&policy));",
    "main preflight execution",
)

# CLI regressions: known feature matching must work without materializing the
# deliberately missing root, while a requested time namespace must remain
# explicit indeterminate rather than being falsely accepted.
replace_one(
    "tests/cli.rs",
    "    assert!(stdout.contains(\"\\\"timerfd_monotonic\\\":{\\\"available\\\":true,\\\"errno\\\":null}\"));\n    assert!(stdout.contains(\"\\\"cgroup_v2\\\":{\\\"present\\\":true}\"));",
    "    assert!(stdout.contains(\"\\\"timerfd_monotonic\\\":{\\\"available\\\":true,\\\"errno\\\":null}\"));\n    assert!(stdout.contains(\"\\\"eventfd\\\":{\\\"available\\\":true,\\\"errno\\\":null}\"));\n    assert!(stdout.contains(\"\\\"cgroup_v2\\\":{\\\"present\\\":true}\"));",
    "CLI host JSON eventfd",
)
replace_one(
    "tests/cli.rs",
    "    assert!(stdout.contains(\"timerfd-monotonic: available\\n\"));\n    assert!(stdout.contains(\"cgroup-v2: present\\n\"));",
    "    assert!(stdout.contains(\"timerfd-monotonic: available\\n\"));\n    assert!(stdout.contains(\"eventfd: available\\n\"));\n    assert!(stdout.contains(\"cgroup-v2: present\\n\"));",
    "CLI host human eventfd",
)
insert = r'''

#[test]
fn preflight_json_matches_known_policy_requirements_without_launching() {
    let (policy, missing_root) = static_only_policy();
    let policy = format!(
        "{policy}\nlandlock.scope_signal = enabled\nlimit.wall_clock_milliseconds = 5000\nlimit.stdout_total_bytes = 8192\n"
    );
    let path = write_policy("preflight-known", &policy);
    let output = Command::new(binary())
        .args(["preflight-json", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run policy preflight JSON CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":true,\"preflight\":{\"kind\":\"policy_host_capability_match\",\"policy_preflight\":true,\"launch_attempted\":false,\"launch_preflight_complete\":false,\"status\":\"satisfied\""
    ));
    assert!(stdout.contains("\"landlock\":{\"status\":\"supported\",\"required_abi\":6,"));
    assert!(stdout.contains("\"deadline\":{\"status\":\"supported\""));
    assert!(stdout.contains("\"stdout_output_limit\":{\"status\":\"supported\""));
    assert!(stdout.contains("\"eventfd\":{\"available\":true,\"errno\":null}"));
    assert!(stdout.contains("\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null}"));
    assert!(!missing_root.exists(), "preflight must not materialize runtime root state");
}

#[test]
fn preflight_json_marks_requested_time_namespace_unprobed() {
    let (policy, missing_root) = static_only_policy();
    let policy = format!(
        "{policy}\ntime.monotonic_offset_seconds = 1\ntime.boottime_offset_seconds = 2\n"
    );
    let path = write_policy("preflight-time-unprobed", &policy);
    let output = Command::new(binary())
        .args(["preflight-json", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run time namespace preflight JSON CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.contains("\"status\":\"indeterminate\""));
    assert!(stdout.contains(
        "\"time_namespace\":{\"status\":\"unprobed\",\"reason\":\"independent_safe_probe_not_implemented\"}"
    ));
    assert!(!missing_root.exists(), "indeterminate preflight must not launch the sandbox");
}

#[test]
fn preflight_human_report_exposes_partial_scope() {
    let (policy, missing_root) = static_only_policy();
    let path = write_policy("preflight-human", &policy);
    let output = Command::new(binary())
        .args(["preflight", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run policy preflight human CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight human stdout is UTF-8");
    assert!(stdout.starts_with(
        "policy-host-preflight:\nkind: policy-host-capability-match\npolicy-preflight: true\nlaunch-attempted: false\nlaunch-preflight-complete: false\nstatus: satisfied\n"
    ));
    assert!(stdout.contains("time-namespace: not_requested\n"));
    assert!(!missing_root.exists());
}
'''
replace_one(
    "tests/cli.rs",
    "\n#[test]\nfn host_json_reports_runtime_capabilities_without_reading_policy() {",
    insert + "\n#[test]\nfn host_json_reports_runtime_capabilities_without_reading_policy() {",
    "CLI preflight regressions",
)
