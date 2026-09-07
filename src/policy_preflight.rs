use crate::host_capabilities::{self, CapabilityProbe, HostCapabilities};
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
        output.push_str("\"},\"mandatory_launch_core\":{\"status\":\"");
        output.push_str(self.mandatory_launch_core_status().as_str());
        output.push_str("\",\"reason\":");
        if let Some(reason) = self.mandatory_launch_core_reason() {
            write!(&mut output, "\"{reason}\"").expect("write to String cannot fail");
        } else {
            output.push_str("null");
        }
        output.push_str("},\"landlock\":{\"status\":\"");
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
        output.push_str("mandatory-launch-core: ");
        output.push_str(self.mandatory_launch_core_status().as_str());
        if let Some(reason) = self.mandatory_launch_core_reason() {
            write!(&mut output, " ({reason})").expect("write to String cannot fail");
        }
        output.push('\n');
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
        format!("{BASE}\n{extra}\n")
            .parse()
            .expect("valid preflight policy")
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
    fn exact_json_contract_requires_explicit_mandatory_core_evidence() {
        let policy = policy(
            "landlock.scope_signal = enabled\nlimit.wall_clock_milliseconds = 1000\nlimit.stdout_total_bytes = 8192",
        );
        let report = evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Supported);
        assert_eq!(report.exit_code(), 0);
        assert_eq!(
            report.to_json(),
            "{\"ok\":true,\"preflight\":{\"kind\":\"policy_host_capability_match\",\"policy_preflight\":true,\"launch_attempted\":false,\"launch_preflight_complete\":false,\"status\":\"satisfied\",\"sandbox_target\":{\"status\":\"supported\",\"target_os\":\"linux\",\"target_arch\":\"x86_64\"},\"mandatory_launch_core\":{\"status\":\"supported\",\"reason\":null},\"landlock\":{\"status\":\"supported\",\"required_abi\":6,\"observed_abi\":7,\"errno\":null},\"deadline\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"timerfd_monotonic\":{\"available\":true,\"errno\":null}},\"stdout_output_limit\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"eventfd\":{\"available\":true,\"errno\":null}},\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null}}}"
        );
    }

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
        let report = evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Unsupported);
        assert_eq!(
            report.mandatory_launch_core_status(),
            RequirementStatus::Unsupported
        );
        assert_eq!(report.verdict(), Verdict::Incompatible);
        assert_eq!(report.exit_code(), 3);
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
        let policy = policy("time.monotonic_offset_seconds = 1\ntime.boottime_offset_seconds = 2");
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report
            .to_human()
            .contains("time-namespace: unprobed (independent-safe-probe-not-implemented)\n"));
    }
}
