mod configured_filesystem_probe;
mod mandatory_core_probe;
mod time_namespace_probe;

use crate::host_capabilities::{self, CapabilityProbe, HostCapabilities};
use configured_filesystem_probe::ConfiguredFilesystemProbe;
use mandatory_core_probe::StagedCapabilityProbe;
use security_lab::SandboxPolicy;
use std::fmt::Write as _;
use time_namespace_probe::TimeNamespaceProbe;

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
    private_procfs: bool,
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
            private_procfs: policy.procfs_enabled,
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
    configured_filesystem: Option<ConfiguredFilesystemProbe>,
    mandatory_namespace_mount_core: Option<StagedCapabilityProbe>,
    time_namespace_probe: Option<TimeNamespaceProbe>,
}

pub(crate) fn probe(policy: &SandboxPolicy) -> PolicyPreflight {
    let mut evaluated = evaluate(policy, host_capabilities::probe());
    evaluated.configured_filesystem = Some(configured_filesystem_probe::probe(policy));
    evaluated.mandatory_namespace_mount_core = Some(mandatory_core_probe::probe());
    evaluated.time_namespace_probe = match (
        policy.time_monotonic_offset_seconds,
        policy.time_boottime_offset_seconds,
    ) {
        (Some(monotonic), Some(boottime)) => Some(time_namespace_probe::probe(monotonic, boottime)),
        (None, None) => None,
        _ => unreachable!("validated time namespace policy must be all-or-nothing"),
    };
    evaluated
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
        configured_filesystem: None,
        mandatory_namespace_mount_core: None,
        time_namespace_probe: None,
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
        if !self.requirements.time_namespace {
            return RequirementStatus::NotRequested;
        }
        match self.time_namespace_probe {
            Some(probe) if probe.available => RequirementStatus::Supported,
            Some(_) => RequirementStatus::Unsupported,
            None => RequirementStatus::Unprobed,
        }
    }

    fn private_procfs_status(&self) -> RequirementStatus {
        if self.requirements.private_procfs {
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
            || matches!(self.configured_filesystem, Some(probe) if !probe.available)
            || self.landlock_status() == RequirementStatus::Unsupported
            || self.deadline_status() == RequirementStatus::Unsupported
            || self.output_limit_status() == RequirementStatus::Unsupported
            || self.time_namespace_status() == RequirementStatus::Unsupported
        {
            Verdict::Incompatible
        } else if self.mandatory_launch_core_status() == RequirementStatus::Unprobed
            || self.time_namespace_status() == RequirementStatus::Unprobed
            || self.private_procfs_status() == RequirementStatus::Unprobed
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
        output.push('}');
        if let Some(probe) = self.configured_filesystem {
            output.push_str(",\"configured_filesystem_probe\":");
            push_configured_filesystem_probe_json(&mut output, probe);
        }
        if let Some(probe) = self.mandatory_namespace_mount_core {
            output.push_str(",\"mandatory_namespace_mount_core_probe\":");
            push_staged_probe_json(&mut output, probe);
        }
        output.push_str(",\"landlock\":{\"status\":\"");
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
        output.push_str("},\"time_namespace\":");
        push_time_namespace_probe_json(
            &mut output,
            self.time_namespace_status(),
            self.requirements.time_namespace,
            self.time_namespace_probe,
        );
        output.push_str(",\"private_procfs\":{\"status\":\"");
        output.push_str(self.private_procfs_status().as_str());
        output.push_str("\",\"reason\":");
        if self.requirements.private_procfs {
            output.push_str("\"pid_namespace_procfs_mount_requires_real_launch\"");
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
        if let Some(probe) = self.configured_filesystem {
            output.push_str("configured-filesystem-probe: ");
            if probe.available {
                writeln!(
                    &mut output,
                    "supported (stage={} read-only=true namespaces-created=false target-executed=false)",
                    probe.stage
                )
                .expect("write to String cannot fail");
            } else {
                write!(
                    &mut output,
                    "unsupported (stage={} read-only=true namespaces-created=false target-executed=false",
                    probe.stage
                )
                .expect("write to String cannot fail");
                if let Some(errno) = probe.errno {
                    write!(&mut output, " errno={errno}").expect("write to String cannot fail");
                }
                output.push_str(")\n");
            }
        }
        if let Some(probe) = self.mandatory_namespace_mount_core {
            output.push_str("mandatory-namespace-mount-core-probe: ");
            if probe.available {
                writeln!(&mut output, "supported (stage={})", probe.stage)
                    .expect("write to String cannot fail");
            } else {
                write!(&mut output, "unsupported (stage={}", probe.stage)
                    .expect("write to String cannot fail");
                if let Some(errno) = probe.errno {
                    write!(&mut output, " errno={errno}").expect("write to String cannot fail");
                }
                output.push_str(")\n");
            }
        }
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
        output.push('\n');
        output.push_str("private-procfs: ");
        output.push_str(self.private_procfs_status().as_str());
        if self.requirements.private_procfs {
            output.push_str(" (pid-namespace-procfs-mount-requires-real-launch)");
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

fn push_configured_filesystem_probe_json(output: &mut String, probe: ConfiguredFilesystemProbe) {
    output.push_str("{\"status\":\"");
    output.push_str(if probe.available {
        "supported"
    } else {
        "unsupported"
    });
    output.push_str("\",\"stage\":\"");
    output.push_str(probe.stage);
    output.push_str("\",\"errno\":");
    push_optional_i32(output, probe.errno);
    output.push_str(",\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}");
}

fn push_staged_probe_json(output: &mut String, probe: StagedCapabilityProbe) {
    output.push_str("{\"status\":\"");
    output.push_str(if probe.available {
        "supported"
    } else {
        "unsupported"
    });
    output.push_str("\",\"stage\":\"");
    output.push_str(probe.stage);
    output.push_str("\",\"errno\":");
    push_optional_i32(output, probe.errno);
    output.push_str(
        ",\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}",
    );
}

fn push_time_namespace_probe_json(
    output: &mut String,
    status: RequirementStatus,
    requested: bool,
    probe: Option<TimeNamespaceProbe>,
) {
    output.push_str("{\"status\":\"");
    output.push_str(status.as_str());
    output.push_str("\",\"reason\":");
    match status {
        RequirementStatus::Supported | RequirementStatus::NotRequested => output.push_str("null"),
        RequirementStatus::Unsupported => output.push_str("\"independent_safe_probe_failed\""),
        RequirementStatus::Unprobed if requested => {
            output.push_str("\"independent_safe_probe_not_run\"")
        }
        RequirementStatus::Unprobed => output.push_str("null"),
    }
    if let Some(probe) = probe {
        output.push_str(",\"probe\":{\"stage\":\"");
        output.push_str(probe.stage);
        output.push_str("\",\"errno\":");
        push_optional_i32(output, probe.errno);
        write!(
            output,
            ",\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false,\"requested_monotonic_offset_seconds\":{},\"requested_boottime_offset_seconds\":{}",
            probe.monotonic_offset_seconds,
            probe.boottime_offset_seconds
        )
        .expect("write to String cannot fail");
        output.push('}');
    }
    output.push('}');
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
    fn private_procfs_remains_unprobed_without_real_namespace_mount() {
        let policy = policy("filesystem.proc = enabled");
        let evaluated = evaluate_with_core(&policy, host(None), RequirementStatus::Supported);
        assert_eq!(
            evaluated.private_procfs_status(),
            RequirementStatus::Unprobed
        );
        assert_eq!(evaluated.verdict(), Verdict::Indeterminate);
        assert!(evaluated
            .to_json()
            .contains("\"private_procfs\":{\"status\":\"unprobed\""));
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
                private_procfs: false,
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
            "{\"ok\":true,\"preflight\":{\"kind\":\"policy_host_capability_match\",\"policy_preflight\":true,\"launch_attempted\":false,\"launch_preflight_complete\":false,\"status\":\"satisfied\",\"sandbox_target\":{\"status\":\"supported\",\"target_os\":\"linux\",\"target_arch\":\"x86_64\"},\"mandatory_launch_core\":{\"status\":\"supported\",\"reason\":null},\"landlock\":{\"status\":\"supported\",\"required_abi\":6,\"observed_abi\":7,\"errno\":null},\"deadline\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"timerfd_monotonic\":{\"available\":true,\"errno\":null}},\"stdout_output_limit\":{\"status\":\"supported\",\"pidfd_open\":{\"available\":true,\"errno\":null},\"eventfd\":{\"available\":true,\"errno\":null}},\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null},\"private_procfs\":{\"status\":\"not_requested\",\"reason\":null}}}"
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
    fn requested_time_namespace_is_indeterminate_until_probe_runs() {
        let policy = policy("time.monotonic_offset_seconds = 1\ntime.boottime_offset_seconds = 2");
        let report = evaluate(&policy, host(Some(7)));
        assert_eq!(report.verdict(), Verdict::Indeterminate);
        assert_eq!(report.exit_code(), 4);
        assert!(report
            .to_human()
            .contains("time-namespace: unprobed (independent-safe-probe-not-run)\n"));
    }

    #[test]
    fn supported_time_namespace_probe_closes_optional_preflight_gap() {
        let policy =
            policy("time.monotonic_offset_seconds = 60\ntime.boottime_offset_seconds = 120");
        let mut report = evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Supported);
        report.time_namespace_probe = Some(TimeNamespaceProbe::available(60, 120));
        assert_eq!(report.time_namespace_status(), RequirementStatus::Supported);
        assert_eq!(report.verdict(), Verdict::Satisfied);
        assert!(report.to_json().contains(
            "\"time_namespace\":{\"status\":\"supported\",\"reason\":null,\"probe\":{\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false,\"requested_monotonic_offset_seconds\":60,\"requested_boottime_offset_seconds\":120}}"
        ));
    }

    #[test]
    fn unsupported_time_namespace_probe_is_incompatible() {
        let policy =
            policy("time.monotonic_offset_seconds = 60\ntime.boottime_offset_seconds = 120");
        let mut report = evaluate_with_core(&policy, host(Some(7)), RequirementStatus::Supported);
        report.time_namespace_probe = Some(TimeNamespaceProbe::unavailable(
            "timens_monotonic",
            Some(1),
            60,
            120,
        ));
        assert_eq!(
            report.time_namespace_status(),
            RequirementStatus::Unsupported
        );
        assert_eq!(report.verdict(), Verdict::Incompatible);
        assert_eq!(report.exit_code(), 3);
    }
}
