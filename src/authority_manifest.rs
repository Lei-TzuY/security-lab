use security_lab::{SandboxPolicy, StdioMode};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

pub(crate) fn to_json(policy: &SandboxPolicy) -> String {
    let mut output = String::from(
        "{\"ok\":true,\"manifest\":{\"kind\":\"static_authority\",\"runtime_preflight\":false",
    );

    output.push_str(",\"identity\":{\"hostname\":");
    push_json_string(&mut output, &policy.hostname);
    output.push_str(",\"executable\":");
    push_path(&mut output, &policy.executable);
    output.push_str(",\"working_dir\":");
    push_path(&mut output, &policy.working_dir);
    output.push_str(",\"argument_count\":");
    write!(&mut output, "{}", policy.args.len()).expect("write to String cannot fail");
    output.push_str(",\"environment_keys\":");
    let environment_keys = policy.environment.keys().cloned().collect::<Vec<_>>();
    push_string_array(&mut output, &environment_keys);
    output.push('}');

    output.push_str(",\"host_filesystem\":{\"root\":");
    push_path(&mut output, &policy.root_dir);
    output.push_str(",\"scratch\":");
    match (&policy.scratch_dir, policy.scratch_bytes) {
        (Some(path), Some(bytes)) => {
            output.push_str("{\"target\":");
            push_path(&mut output, path);
            output.push_str(",\"bytes\":");
            write!(&mut output, "{bytes}").expect("write to String cannot fail");
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push_str(",\"read_only_volume\":");
    push_volume(
        &mut output,
        policy.readonly_volume_source.as_deref(),
        policy.readonly_volume_target.as_deref(),
        "read_only",
    );
    output.push_str(",\"writable_volume\":");
    push_volume(
        &mut output,
        policy.writable_volume_source.as_deref(),
        policy.writable_volume_target.as_deref(),
        "writable",
    );
    output.push('}');

    output.push_str(",\"network\":{\"isolated_loopback_enabled\":");
    push_bool(&mut output, policy.loopback_enabled);
    output.push_str(",\"host_loopback_tcp\":");
    match (
        policy.host_loopback_tcp_port,
        policy.host_loopback_tcp_target_fd,
    ) {
        (Some(port), Some(target_fd)) => {
            output.push_str("{\"address\":\"127.0.0.1\",\"port\":");
            write!(&mut output, "{port}").expect("write to String cannot fail");
            output.push_str(",\"target_fd\":");
            write!(&mut output, "{target_fd}").expect("write to String cannot fail");
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push_str(",\"host_ipv4_tcp\":");
    match (
        policy.host_ipv4_tcp_address,
        policy.host_ipv4_tcp_port,
        policy.host_ipv4_tcp_target_fd,
    ) {
        (Some(address), Some(port), Some(target_fd)) => {
            output.push_str("{\"address\":");
            push_json_string(&mut output, &address.to_string());
            output.push_str(",\"port\":");
            write!(&mut output, "{port}").expect("write to String cannot fail");
            output.push_str(",\"target_fd\":");
            write!(&mut output, "{target_fd}").expect("write to String cannot fail");
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push_str(",\"host_ipv4_udp\":");
    match (
        policy.host_ipv4_udp_address,
        policy.host_ipv4_udp_port,
        policy.host_ipv4_udp_target_fd,
    ) {
        (Some(address), Some(port), Some(target_fd)) => {
            output.push_str("{\"address\":");
            push_json_string(&mut output, &address.to_string());
            output.push_str(",\"port\":");
            write!(&mut output, "{port}").expect("write to String cannot fail");
            output.push_str(",\"target_fd\":");
            write!(&mut output, "{target_fd}").expect("write to String cannot fail");
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push_str(",\"host_loopback_tcp_listener\":");
    match (
        policy.host_loopback_tcp_listen_port,
        policy.host_loopback_tcp_listen_target_fd,
    ) {
        (Some(port), Some(target_fd)) => {
            output.push_str("{\"address\":\"127.0.0.1\",\"port\":");
            write!(&mut output, "{port}").expect("write to String cannot fail");
            output.push_str(",\"target_fd\":");
            write!(&mut output, "{target_fd}").expect("write to String cannot fail");
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push_str(",\"target_bind_ports\":");
    push_sorted_u16_array(&mut output, &policy.landlock_tcp_bind_ports);
    output.push_str(",\"target_connect_ports\":");
    push_sorted_u16_array(&mut output, &policy.landlock_tcp_connect_ports);
    output.push('}');

    output.push_str(",\"host_ipc\":{\"unix_stream\":");
    match (
        policy.host_unix_stream_path.as_deref(),
        policy.host_unix_stream_target_fd,
    ) {
        (Some(path), Some(target_fd)) => {
            output.push_str("{\"path\":");
            push_path(&mut output, path);
            output.push_str(",\"target_fd\":");
            write!(&mut output, "{target_fd}").expect("write to String cannot fail");
            output.push_str(",\"peer_credentials\":");
            match (
                policy.host_unix_stream_peer_uid,
                policy.host_unix_stream_peer_gid,
            ) {
                (Some(uid), Some(gid)) => {
                    output.push_str("{\"uid\":");
                    write!(&mut output, "{uid}").expect("write to String cannot fail");
                    output.push_str(",\"gid\":");
                    write!(&mut output, "{gid}").expect("write to String cannot fail");
                    output.push('}');
                }
                _ => output.push_str("null"),
            }
            output.push('}');
        }
        _ => output.push_str("null"),
    }
    output.push('}');

    output.push_str(",\"descriptors\":{\"stdio\":{\"stdin\":");
    push_json_string(&mut output, stdio_mode_name(policy.stdio.stdin));
    output.push_str(",\"stdout\":");
    push_json_string(&mut output, stdio_mode_name(policy.stdio.stdout));
    output.push_str(",\"stderr\":");
    push_json_string(&mut output, stdio_mode_name(policy.stdio.stderr));
    output.push_str("},\"selected\":[");
    let mut first = true;
    for (target_fd, source_fd) in &policy.selected_handles {
        if !first {
            output.push(',');
        }
        first = false;
        output.push_str("{\"target_fd\":");
        write!(&mut output, "{target_fd}").expect("write to String cannot fail");
        output.push_str(",\"source_fd\":");
        write!(&mut output, "{source_fd}").expect("write to String cannot fail");
        output.push('}');
    }
    output.push_str("]}");

    output.push_str(",\"landlock\":{\"read_execute\":");
    push_sorted_path_array(&mut output, &policy.landlock_read_execute);
    output.push_str(",\"file_mutate\":");
    push_sorted_path_array(&mut output, &policy.landlock_file_mutate);
    output.push_str(",\"path_topology_mutate\":");
    push_sorted_path_array(&mut output, &policy.landlock_path_topology_mutate);
    output.push_str(",\"device_ioctl\":");
    push_sorted_path_array(&mut output, &policy.landlock_device_ioctl);
    output.push_str(",\"scope_signal\":");
    push_bool(&mut output, policy.landlock_scope_signal);
    output.push_str(",\"scope_abstract_unix_socket\":");
    push_bool(&mut output, policy.landlock_scope_abstract_unix_socket);
    output.push('}');

    output.push_str(",\"controls\":{\"cpu_seconds\":");
    write!(&mut output, "{}", policy.limits.cpu_seconds).expect("write to String cannot fail");
    output.push_str(",\"address_space_bytes\":");
    write!(&mut output, "{}", policy.limits.address_space_bytes)
        .expect("write to String cannot fail");
    output.push_str(",\"file_size_bytes\":");
    write!(&mut output, "{}", policy.limits.file_size_bytes).expect("write to String cannot fail");
    output.push_str(",\"open_files\":");
    write!(&mut output, "{}", policy.limits.open_files).expect("write to String cannot fail");
    output.push_str(",\"wall_clock_milliseconds\":");
    push_optional_u64(&mut output, policy.wall_clock_milliseconds);
    output.push_str(",\"stdout_capture_bytes\":");
    push_optional_u64(&mut output, policy.stdout_capture_bytes);
    output.push_str(",\"stdout_total_bytes\":");
    push_optional_u64(&mut output, policy.stdout_total_bytes);
    output.push('}');

    output.push_str(",\"seccomp\":{\"allow\":[");
    let mut first = true;
    for syscall in &policy.seccomp.allowed_syscalls {
        if !first {
            output.push(',');
        }
        first = false;
        push_json_string(&mut output, syscall);
    }
    output.push_str("],\"masked\":[");
    first = true;
    for (syscall, rules) in &policy.seccomp.argument_rules {
        for (argument, rule) in rules {
            if !first {
                output.push(',');
            }
            first = false;
            output.push_str("{\"syscall\":");
            push_json_string(&mut output, syscall);
            output.push_str(",\"argument\":");
            write!(&mut output, "{argument}").expect("write to String cannot fail");
            output.push_str(",\"mask\":");
            push_hex_u64(&mut output, rule.mask);
            output.push_str(",\"value\":");
            push_hex_u64(&mut output, rule.value);
            output.push('}');
        }
    }
    output.push_str("],\"ranges\":[");
    first = true;
    for (syscall, rules) in &policy.seccomp.argument_range_rules {
        for (argument, rule) in rules {
            if !first {
                output.push(',');
            }
            first = false;
            output.push_str("{\"syscall\":");
            push_json_string(&mut output, syscall);
            output.push_str(",\"argument\":");
            write!(&mut output, "{argument}").expect("write to String cannot fail");
            output.push_str(",\"minimum\":");
            push_hex_u64(&mut output, rule.minimum);
            output.push_str(",\"maximum\":");
            push_hex_u64(&mut output, rule.maximum);
            output.push('}');
        }
    }
    output.push_str("]}}");

    output.push('}');
    output
}

pub(crate) fn to_human(policy: &SandboxPolicy) -> String {
    let mut output = String::new();
    writeln!(&mut output, "policy-authority-manifest:").expect("write to String cannot fail");
    writeln!(&mut output, "runtime-preflight: false").expect("write to String cannot fail");
    writeln!(&mut output, "root: {}", policy.root_dir.display())
        .expect("write to String cannot fail");
    writeln!(&mut output, "executable: {}", policy.executable.display())
        .expect("write to String cannot fail");
    writeln!(&mut output, "working-dir: {}", policy.working_dir.display())
        .expect("write to String cannot fail");
    writeln!(&mut output, "hostname: {}", policy.hostname).expect("write to String cannot fail");
    writeln!(&mut output, "arguments: {}", policy.args.len()).expect("write to String cannot fail");
    let environment_keys = policy.environment.keys().cloned().collect::<Vec<_>>();
    writeln!(
        &mut output,
        "environment-keys: {}",
        if environment_keys.is_empty() {
            "none".to_owned()
        } else {
            environment_keys.join(",")
        }
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "stdio: stdin={} stdout={} stderr={}",
        stdio_mode_name(policy.stdio.stdin),
        stdio_mode_name(policy.stdio.stdout),
        stdio_mode_name(policy.stdio.stderr)
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "selected-handles: {}",
        policy.selected_handles.len()
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "host-filesystem-volumes: read-only={} writable={}",
        policy.readonly_volume_source.is_some() as u8,
        policy.writable_volume_source.is_some() as u8
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "host-network-brokers: {}",
        host_network_broker_count(policy)
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "host-unix-stream-broker: {}",
        if policy.host_unix_stream_path.is_some() {
            "present"
        } else {
            "none"
        }
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "landlock-rules: read-execute={} file-mutate={} topology-mutate={} device-ioctl={} bind-ports={} connect-ports={} signal-scope={} abstract-unix-scope={}",
        policy.landlock_read_execute.len(),
        policy.landlock_file_mutate.len(),
        policy.landlock_path_topology_mutate.len(),
        policy.landlock_device_ioctl.len(),
        policy.landlock_tcp_bind_ports.len(),
        policy.landlock_tcp_connect_ports.len(),
        policy.landlock_scope_signal,
        policy.landlock_scope_abstract_unix_socket
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "seccomp: allow={} masked={} ranges={}",
        policy.seccomp.allowed_syscalls.len(),
        policy
            .seccomp
            .argument_rules
            .values()
            .map(|rules| rules.len())
            .sum::<usize>(),
        policy
            .seccomp
            .argument_range_rules
            .values()
            .map(|rules| rules.len())
            .sum::<usize>()
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "controls: cpu-seconds={} address-space-bytes={} file-size-bytes={} open-files={} wall-clock-ms={} stdout-capture-bytes={} stdout-total-bytes={}",
        policy.limits.cpu_seconds,
        policy.limits.address_space_bytes,
        policy.limits.file_size_bytes,
        policy.limits.open_files,
        display_optional_u64(policy.wall_clock_milliseconds),
        display_optional_u64(policy.stdout_capture_bytes),
        display_optional_u64(policy.stdout_total_bytes)
    )
    .expect("write to String cannot fail");
    output
}

fn host_network_broker_count(policy: &SandboxPolicy) -> usize {
    [
        policy.host_loopback_tcp_port.is_some(),
        policy.host_ipv4_tcp_address.is_some(),
        policy.host_ipv4_udp_address.is_some(),
        policy.host_loopback_tcp_listen_port.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count()
}

fn display_optional_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "none".to_owned())
}

fn stdio_mode_name(mode: StdioMode) -> &'static str {
    match mode {
        StdioMode::Inherit => "inherit",
        StdioMode::Closed => "closed",
        StdioMode::Redirect => "redirect",
        StdioMode::Capture => "capture",
    }
}

fn push_volume(output: &mut String, source: Option<&Path>, target: Option<&Path>, access: &str) {
    match (source, target) {
        (Some(source), Some(target)) => {
            output.push_str("{\"access\":");
            push_json_string(output, access);
            output.push_str(",\"source\":");
            push_path(output, source);
            output.push_str(",\"target\":");
            push_path(output, target);
            output.push('}');
        }
        _ => output.push_str("null"),
    }
}

fn push_sorted_path_array(output: &mut String, paths: &[PathBuf]) {
    let mut values = paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    values.sort();
    push_string_array(output, &values);
}

fn push_sorted_u16_array(output: &mut String, values: &[u16]) {
    let mut values = values.to_vec();
    values.sort_unstable();
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        write!(output, "{value}").expect("write to String cannot fail");
    }
    output.push(']');
}

fn push_string_array(output: &mut String, values: &[String]) {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        push_json_string(output, value);
    }
    output.push(']');
}

fn push_optional_u64(output: &mut String, value: Option<u64>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("null"),
    }
}

fn push_hex_u64(output: &mut String, value: u64) {
    output.push('"');
    write!(output, "0x{value:016x}").expect("write to String cannot fail");
    output.push('"');
}

fn push_bool(output: &mut String, value: bool) {
    output.push_str(if value { "true" } else { "false" });
}

fn push_path(output: &mut String, path: &Path) {
    push_json_string(output, path.to_string_lossy().as_ref());
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
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
