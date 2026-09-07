use security_lab::{SandboxPolicy, StdioMode};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeltaClass {
    Unchanged,
    Widened,
    Reduced,
    Incomparable,
}

impl DeltaClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Widened => "widened",
            Self::Reduced => "reduced",
            Self::Incomparable => "incomparable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Change {
    field: &'static str,
    class: DeltaClass,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AuthorityDelta {
    status: DeltaClass,
    changes: Vec<Change>,
}

impl AuthorityDelta {
    pub(crate) const fn exit_code(&self) -> i32 {
        match self.status {
            DeltaClass::Unchanged | DeltaClass::Reduced => 0,
            DeltaClass::Widened => 5,
            DeltaClass::Incomparable => 6,
        }
    }

    pub(crate) fn to_json(&self) -> String {
        let widening_detected = self
            .changes
            .iter()
            .any(|change| change.class == DeltaClass::Widened);
        let mut output = String::from(
            "{\"ok\":true,\"authority_delta\":{\"kind\":\"static_policy_authority_delta\",\"kernel_effective_state\":false,\"filesystem_alias_proof\":false,\"status\":\"",
        );
        output.push_str(self.status.as_str());
        output.push_str("\",\"static_non_widening\":");
        output.push_str(
            if matches!(self.status, DeltaClass::Unchanged | DeltaClass::Reduced) {
                "true"
            } else {
                "false"
            },
        );
        output.push_str(",\"widening_detected\":");
        output.push_str(if widening_detected { "true" } else { "false" });
        output.push_str(",\"changes\":[");
        for (index, change) in self.changes.iter().enumerate() {
            if index != 0 {
                output.push(',');
            }
            output.push_str("{\"field\":");
            push_json_string(&mut output, change.field);
            output.push_str(",\"class\":\"");
            output.push_str(change.class.as_str());
            output.push_str("\"}");
        }
        output.push_str("]}}");
        output
    }

    pub(crate) fn to_human(&self) -> String {
        let mut output = String::from(
            "policy-authority-delta:\nkind: static-policy-authority-delta\nkernel-effective-state: false\nfilesystem-alias-proof: false\n",
        );
        writeln!(&mut output, "status: {}", self.status.as_str())
            .expect("write to String cannot fail");
        writeln!(
            &mut output,
            "static-non-widening: {}",
            if matches!(self.status, DeltaClass::Unchanged | DeltaClass::Reduced) {
                "true"
            } else {
                "false"
            }
        )
        .expect("write to String cannot fail");
        if self.changes.is_empty() {
            output.push_str("changes: none\n");
        } else {
            for change in &self.changes {
                writeln!(
                    &mut output,
                    "change: {} {}",
                    change.field,
                    change.class.as_str()
                )
                .expect("write to String cannot fail");
            }
        }
        output
    }
}

pub(crate) fn compare(baseline: &SandboxPolicy, candidate: &SandboxPolicy) -> AuthorityDelta {
    let mut changes = Vec::new();

    compare_exact_incomparable(
        "filesystem.root",
        &baseline.root_dir,
        &candidate.root_dir,
        &mut changes,
    );
    compare_exact_incomparable(
        "identity.hostname",
        &baseline.hostname,
        &candidate.hostname,
        &mut changes,
    );
    compare_exact_incomparable(
        "execution.executable",
        &baseline.executable,
        &candidate.executable,
        &mut changes,
    );
    compare_exact_incomparable(
        "execution.arguments",
        &baseline.args,
        &candidate.args,
        &mut changes,
    );
    compare_exact_incomparable(
        "execution.environment",
        &baseline.environment,
        &candidate.environment,
        &mut changes,
    );
    compare_exact_incomparable(
        "execution.working_dir",
        &baseline.working_dir,
        &candidate.working_dir,
        &mut changes,
    );

    compare_exact_incomparable(
        "filesystem.private_procfs",
        &baseline.procfs_enabled,
        &candidate.procfs_enabled,
        &mut changes,
    );
    compare_scratch(baseline, candidate, &mut changes);
    compare_optional_capability(
        "filesystem.read_only_volume",
        baseline
            .readonly_volume_source
            .as_ref()
            .zip(baseline.readonly_volume_target.as_ref()),
        candidate
            .readonly_volume_source
            .as_ref()
            .zip(candidate.readonly_volume_target.as_ref()),
        &mut changes,
    );
    compare_optional_capability(
        "filesystem.writable_volume",
        baseline
            .writable_volume_source
            .as_ref()
            .zip(baseline.writable_volume_target.as_ref()),
        candidate
            .writable_volume_source
            .as_ref()
            .zip(candidate.writable_volume_target.as_ref()),
        &mut changes,
    );

    push_change(
        "filesystem.persistent_volumes",
        subset_relation(
            map_is_subset(&baseline.persistent_volumes, &candidate.persistent_volumes),
            map_is_subset(&candidate.persistent_volumes, &baseline.persistent_volumes),
            true,
        ),
        &mut changes,
    );

    compare_positive_bool(
        "network.isolated_loopback_enabled",
        baseline.loopback_enabled,
        candidate.loopback_enabled,
        &mut changes,
    );
    compare_optional_capability(
        "network.host_loopback_tcp",
        baseline
            .host_loopback_tcp_port
            .zip(baseline.host_loopback_tcp_target_fd),
        candidate
            .host_loopback_tcp_port
            .zip(candidate.host_loopback_tcp_target_fd),
        &mut changes,
    );
    compare_optional_capability(
        "network.host_ipv4_tcp",
        triple(
            baseline.host_ipv4_tcp_address,
            baseline.host_ipv4_tcp_port,
            baseline.host_ipv4_tcp_target_fd,
        ),
        triple(
            candidate.host_ipv4_tcp_address,
            candidate.host_ipv4_tcp_port,
            candidate.host_ipv4_tcp_target_fd,
        ),
        &mut changes,
    );
    compare_optional_capability(
        "network.host_ipv4_udp",
        triple(
            baseline.host_ipv4_udp_address,
            baseline.host_ipv4_udp_port,
            baseline.host_ipv4_udp_target_fd,
        ),
        triple(
            candidate.host_ipv4_udp_address,
            candidate.host_ipv4_udp_port,
            candidate.host_ipv4_udp_target_fd,
        ),
        &mut changes,
    );
    compare_optional_capability(
        "network.host_loopback_tcp_listener",
        baseline
            .host_loopback_tcp_listen_port
            .zip(baseline.host_loopback_tcp_listen_target_fd),
        candidate
            .host_loopback_tcp_listen_port
            .zip(candidate.host_loopback_tcp_listen_target_fd),
        &mut changes,
    );
    compare_optional_capability(
        "host_ipc.unix_stream",
        baseline
            .host_unix_stream_path
            .as_ref()
            .zip(baseline.host_unix_stream_target_fd),
        candidate
            .host_unix_stream_path
            .as_ref()
            .zip(candidate.host_unix_stream_target_fd),
        &mut changes,
    );
    compare_optional_restriction(
        "host_ipc.unix_stream_peer_credentials",
        baseline
            .host_unix_stream_peer_uid
            .zip(baseline.host_unix_stream_peer_gid),
        candidate
            .host_unix_stream_peer_uid
            .zip(candidate.host_unix_stream_peer_gid),
        &mut changes,
    );

    compare_stdio(
        "descriptors.stdin",
        baseline.stdio.stdin,
        candidate.stdio.stdin,
        &mut changes,
    );
    compare_stdio(
        "descriptors.stdout",
        baseline.stdio.stdout,
        candidate.stdio.stdout,
        &mut changes,
    );
    compare_stdio(
        "descriptors.stderr",
        baseline.stdio.stderr,
        candidate.stdio.stderr,
        &mut changes,
    );
    compare_selected_handles(
        &baseline.selected_handles,
        &candidate.selected_handles,
        &mut changes,
    );
    if baseline.stdio.stdout == StdioMode::Redirect && candidate.stdio.stdout == StdioMode::Redirect
    {
        compare_exact_incomparable(
            "descriptors.stdout_redirect_path",
            &baseline.stdout_redirect,
            &candidate.stdout_redirect,
            &mut changes,
        );
    }
    if baseline.stdio.stdout == StdioMode::Capture && candidate.stdio.stdout == StdioMode::Capture {
        if let (Some(base), Some(new)) = (
            baseline.stdout_capture_bytes,
            candidate.stdout_capture_bytes,
        ) {
            push_change(
                "controls.stdout_capture_bytes",
                classify_allowance(base, new),
                &mut changes,
            );
        }
    }

    compare_restriction_allowlist(
        "landlock.read_execute",
        &baseline.landlock_read_execute,
        &candidate.landlock_read_execute,
        &mut changes,
    );
    compare_restriction_allowlist(
        "landlock.file_mutate",
        &baseline.landlock_file_mutate,
        &candidate.landlock_file_mutate,
        &mut changes,
    );
    compare_positive_allowlist(
        "landlock.path_topology_mutate",
        &baseline.landlock_path_topology_mutate,
        &candidate.landlock_path_topology_mutate,
        &mut changes,
    );
    compare_restriction_allowlist(
        "landlock.device_ioctl",
        &baseline.landlock_device_ioctl,
        &candidate.landlock_device_ioctl,
        &mut changes,
    );
    compare_restriction_allowlist(
        "landlock.tcp_bind_ports",
        &baseline.landlock_tcp_bind_ports,
        &candidate.landlock_tcp_bind_ports,
        &mut changes,
    );
    compare_restriction_allowlist(
        "landlock.tcp_connect_ports",
        &baseline.landlock_tcp_connect_ports,
        &candidate.landlock_tcp_connect_ports,
        &mut changes,
    );
    compare_restrictive_bool(
        "landlock.scope_abstract_unix_socket",
        baseline.landlock_scope_abstract_unix_socket,
        candidate.landlock_scope_abstract_unix_socket,
        &mut changes,
    );
    compare_restrictive_bool(
        "landlock.scope_signal",
        baseline.landlock_scope_signal,
        candidate.landlock_scope_signal,
        &mut changes,
    );

    push_change(
        "controls.cpu_seconds",
        classify_allowance(baseline.limits.cpu_seconds, candidate.limits.cpu_seconds),
        &mut changes,
    );
    push_change(
        "controls.address_space_bytes",
        classify_allowance(
            baseline.limits.address_space_bytes,
            candidate.limits.address_space_bytes,
        ),
        &mut changes,
    );
    push_change(
        "controls.file_size_bytes",
        classify_allowance(
            baseline.limits.file_size_bytes,
            candidate.limits.file_size_bytes,
        ),
        &mut changes,
    );
    push_change(
        "controls.open_files",
        classify_allowance(baseline.limits.open_files, candidate.limits.open_files),
        &mut changes,
    );
    compare_optional_ceiling(
        "controls.wall_clock_milliseconds",
        baseline.wall_clock_milliseconds,
        candidate.wall_clock_milliseconds,
        &mut changes,
    );
    compare_optional_ceiling(
        "controls.stdout_total_bytes",
        baseline.stdout_total_bytes,
        candidate.stdout_total_bytes,
        &mut changes,
    );
    compare_exact_incomparable(
        "controls.time_namespace_offsets",
        &baseline
            .time_monotonic_offset_seconds
            .zip(baseline.time_boottime_offset_seconds),
        &candidate
            .time_monotonic_offset_seconds
            .zip(candidate.time_boottime_offset_seconds),
        &mut changes,
    );

    compare_seccomp(baseline, candidate, &mut changes);

    let saw_widen = changes
        .iter()
        .any(|change| change.class == DeltaClass::Widened);
    let saw_reduce = changes
        .iter()
        .any(|change| change.class == DeltaClass::Reduced);
    let saw_incomparable = changes
        .iter()
        .any(|change| change.class == DeltaClass::Incomparable);
    let status = if saw_incomparable || (saw_widen && saw_reduce) {
        DeltaClass::Incomparable
    } else if saw_widen {
        DeltaClass::Widened
    } else if saw_reduce {
        DeltaClass::Reduced
    } else {
        DeltaClass::Unchanged
    };

    AuthorityDelta { status, changes }
}

fn compare_scratch(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {
    match (
        (&baseline.scratch_dir, baseline.scratch_bytes),
        (&candidate.scratch_dir, candidate.scratch_bytes),
    ) {
        ((None, None), (None, None)) => {}
        ((None, None), (Some(_), Some(_))) => {
            push_change("filesystem.private_scratch", DeltaClass::Widened, changes)
        }
        ((Some(_), Some(_)), (None, None)) => {
            push_change("filesystem.private_scratch", DeltaClass::Reduced, changes)
        }
        ((Some(base_path), Some(base_bytes)), (Some(new_path), Some(new_bytes))) => {
            if base_path != new_path {
                push_change(
                    "filesystem.private_scratch",
                    DeltaClass::Incomparable,
                    changes,
                );
            } else {
                push_change(
                    "filesystem.private_scratch_bytes",
                    classify_allowance(base_bytes, new_bytes),
                    changes,
                );
            }
        }
        _ => push_change(
            "filesystem.private_scratch",
            DeltaClass::Incomparable,
            changes,
        ),
    }
}

fn compare_stdio(
    field: &'static str,
    baseline: StdioMode,
    candidate: StdioMode,
    changes: &mut Vec<Change>,
) {
    let class = if baseline == candidate {
        DeltaClass::Unchanged
    } else if baseline == StdioMode::Closed {
        DeltaClass::Widened
    } else if candidate == StdioMode::Closed {
        DeltaClass::Reduced
    } else {
        DeltaClass::Incomparable
    };
    push_change(field, class, changes);
}

fn compare_selected_handles(
    baseline: &BTreeMap<u32, u32>,
    candidate: &BTreeMap<u32, u32>,
    changes: &mut Vec<Change>,
) {
    let baseline_subset = map_is_subset(baseline, candidate);
    let candidate_subset = map_is_subset(candidate, baseline);
    let class = subset_relation(baseline_subset, candidate_subset, true);
    push_change("descriptors.selected_handles", class, changes);
}

fn compare_seccomp(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {
    let baseline_allowed = &baseline.seccomp.allowed_syscalls;
    let candidate_allowed = &candidate.seccomp.allowed_syscalls;
    push_change(
        "seccomp.allow",
        subset_relation(
            baseline_allowed.is_subset(candidate_allowed),
            candidate_allowed.is_subset(baseline_allowed),
            true,
        ),
        changes,
    );

    let mut masked = DeltaClass::Unchanged;
    let mut ranges = DeltaClass::Unchanged;
    for syscall in baseline_allowed.intersection(candidate_allowed) {
        masked = combine_classes(
            masked,
            compare_rule_map(
                baseline.seccomp.argument_rules.get(syscall),
                candidate.seccomp.argument_rules.get(syscall),
            ),
        );
        ranges = combine_classes(
            ranges,
            compare_rule_map(
                baseline.seccomp.argument_range_rules.get(syscall),
                candidate.seccomp.argument_range_rules.get(syscall),
            ),
        );
    }
    push_change("seccomp.masked_arguments", masked, changes);
    push_change("seccomp.argument_ranges", ranges, changes);
}

fn compare_rule_map<V: PartialEq>(
    baseline: Option<&BTreeMap<u8, V>>,
    candidate: Option<&BTreeMap<u8, V>>,
) -> DeltaClass {
    let baseline_subset = optional_map_is_subset(baseline, candidate);
    let candidate_subset = optional_map_is_subset(candidate, baseline);
    // Additional exact constraints narrow an already-allowed syscall.
    subset_relation(baseline_subset, candidate_subset, false)
}

fn compare_positive_allowlist<T: Ord>(
    field: &'static str,
    baseline: &[T],
    candidate: &[T],
    changes: &mut Vec<Change>,
) {
    let baseline = baseline.iter().collect::<BTreeSet<_>>();
    let candidate = candidate.iter().collect::<BTreeSet<_>>();
    push_change(
        field,
        subset_relation(
            baseline.is_subset(&candidate),
            candidate.is_subset(&baseline),
            true,
        ),
        changes,
    );
}

fn compare_restriction_allowlist<T: Ord>(
    field: &'static str,
    baseline: &[T],
    candidate: &[T],
    changes: &mut Vec<Change>,
) {
    let baseline = baseline.iter().collect::<BTreeSet<_>>();
    let candidate = candidate.iter().collect::<BTreeSet<_>>();
    let class = if baseline == candidate {
        DeltaClass::Unchanged
    } else if baseline.is_empty() {
        // These Landlock lists are restriction allowlists: empty means the
        // corresponding Landlock restriction is not installed.
        DeltaClass::Reduced
    } else if candidate.is_empty() {
        DeltaClass::Widened
    } else {
        subset_relation(
            baseline.is_subset(&candidate),
            candidate.is_subset(&baseline),
            true,
        )
    };
    push_change(field, class, changes);
}

fn compare_positive_bool(
    field: &'static str,
    baseline: bool,
    candidate: bool,
    changes: &mut Vec<Change>,
) {
    let class = match (baseline, candidate) {
        (false, true) => DeltaClass::Widened,
        (true, false) => DeltaClass::Reduced,
        _ => DeltaClass::Unchanged,
    };
    push_change(field, class, changes);
}

fn compare_restrictive_bool(
    field: &'static str,
    baseline: bool,
    candidate: bool,
    changes: &mut Vec<Change>,
) {
    let class = match (baseline, candidate) {
        (false, true) => DeltaClass::Reduced,
        (true, false) => DeltaClass::Widened,
        _ => DeltaClass::Unchanged,
    };
    push_change(field, class, changes);
}

fn compare_optional_capability<T: PartialEq>(
    field: &'static str,
    baseline: Option<T>,
    candidate: Option<T>,
    changes: &mut Vec<Change>,
) {
    let class = match (baseline, candidate) {
        (None, None) => DeltaClass::Unchanged,
        (None, Some(_)) => DeltaClass::Widened,
        (Some(_), None) => DeltaClass::Reduced,
        (Some(base), Some(new)) if base == new => DeltaClass::Unchanged,
        (Some(_), Some(_)) => DeltaClass::Incomparable,
    };
    push_change(field, class, changes);
}

fn compare_optional_restriction<T: PartialEq>(
    field: &'static str,
    baseline: Option<T>,
    candidate: Option<T>,
    changes: &mut Vec<Change>,
) {
    let class = match (baseline, candidate) {
        (None, None) => DeltaClass::Unchanged,
        (None, Some(_)) => DeltaClass::Reduced,
        (Some(_), None) => DeltaClass::Widened,
        (Some(base), Some(new)) if base == new => DeltaClass::Unchanged,
        (Some(_), Some(_)) => DeltaClass::Incomparable,
    };
    push_change(field, class, changes);
}

fn compare_optional_ceiling(
    field: &'static str,
    baseline: Option<u64>,
    candidate: Option<u64>,
    changes: &mut Vec<Change>,
) {
    let class = match (baseline, candidate) {
        (None, None) => DeltaClass::Unchanged,
        (None, Some(_)) => DeltaClass::Reduced,
        (Some(_), None) => DeltaClass::Widened,
        (Some(base), Some(new)) => classify_allowance(base, new),
    };
    push_change(field, class, changes);
}

fn compare_exact_incomparable<T: PartialEq>(
    field: &'static str,
    baseline: &T,
    candidate: &T,
    changes: &mut Vec<Change>,
) {
    if baseline != candidate {
        push_change(field, DeltaClass::Incomparable, changes);
    }
}

fn classify_allowance(baseline: u64, candidate: u64) -> DeltaClass {
    if candidate > baseline {
        DeltaClass::Widened
    } else if candidate < baseline {
        DeltaClass::Reduced
    } else {
        DeltaClass::Unchanged
    }
}

fn subset_relation(
    baseline_subset_candidate: bool,
    candidate_subset_baseline: bool,
    added_is_widening: bool,
) -> DeltaClass {
    match (baseline_subset_candidate, candidate_subset_baseline) {
        (true, true) => DeltaClass::Unchanged,
        (true, false) if added_is_widening => DeltaClass::Widened,
        (true, false) => DeltaClass::Reduced,
        (false, true) if added_is_widening => DeltaClass::Reduced,
        (false, true) => DeltaClass::Widened,
        (false, false) => DeltaClass::Incomparable,
    }
}

fn combine_classes(left: DeltaClass, right: DeltaClass) -> DeltaClass {
    match (left, right) {
        (DeltaClass::Unchanged, other) | (other, DeltaClass::Unchanged) => other,
        (left, right) if left == right => left,
        _ => DeltaClass::Incomparable,
    }
}

fn map_is_subset<K: Ord, V: PartialEq>(
    baseline: &BTreeMap<K, V>,
    candidate: &BTreeMap<K, V>,
) -> bool {
    baseline
        .iter()
        .all(|(key, value)| candidate.get(key) == Some(value))
}

fn optional_map_is_subset<V: PartialEq>(
    baseline: Option<&BTreeMap<u8, V>>,
    candidate: Option<&BTreeMap<u8, V>>,
) -> bool {
    match baseline {
        None => true,
        Some(baseline) => baseline
            .iter()
            .all(|(key, value)| candidate.and_then(|candidate| candidate.get(key)) == Some(value)),
    }
}

fn triple<A, B, C>(first: Option<A>, second: Option<B>, third: Option<C>) -> Option<(A, B, C)> {
    match (first, second, third) {
        (Some(first), Some(second), Some(third)) => Some((first, second, third)),
        _ => None,
    }
}

fn push_change(field: &'static str, class: DeltaClass, changes: &mut Vec<Change>) {
    if class != DeltaClass::Unchanged {
        changes.push(Change { field, class });
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", character as u32).expect("write to String cannot fail");
            }
            character => output.push(character),
        }
    }
    output.push('"');
}
