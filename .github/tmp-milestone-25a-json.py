from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/cli_json.rs",
    '''    write!(
        &mut output,
        "{}",
        report.process_tree_usage.max_child_rss_kib
    )
    .expect("write to String cannot fail");
    output.push_str("}}");
    output
}
''',
    '''    write!(
        &mut output,
        "{}",
        report.process_tree_usage.max_child_rss_kib
    )
    .expect("write to String cannot fail");
    output.push_str("},\\\"enforcement\\\":{\\\"base_namespaces\\\":");
    push_bool(&mut output, report.enforcement.base_namespaces);
    output.push_str(",\\\"time_namespace_offsets\\\":");
    push_bool(&mut output, report.enforcement.time_namespace_offsets);
    output.push_str(",\\\"hostname\\\":");
    push_bool(&mut output, report.enforcement.hostname);
    output.push_str(",\\\"private_mount_propagation\\\":");
    push_bool(&mut output, report.enforcement.private_mount_propagation);
    output.push_str(",\\\"readonly_root\\\":");
    push_bool(&mut output, report.enforcement.readonly_root);
    output.push_str(",\\\"chroot\\\":");
    push_bool(&mut output, report.enforcement.chroot);
    output.push_str(",\\\"fd_sanitization\\\":");
    push_bool(&mut output, report.enforcement.fd_sanitization);
    output.push_str(",\\\"rlimits\\\":");
    push_bool(&mut output, report.enforcement.rlimits);
    output.push_str(",\\\"capabilities_reduced\\\":");
    push_bool(&mut output, report.enforcement.capabilities_reduced);
    output.push_str(",\\\"no_new_privs\\\":");
    push_bool(&mut output, report.enforcement.no_new_privs);
    output.push_str(",\\\"landlock\\\":");
    push_bool(&mut output, report.enforcement.landlock);
    output.push_str(",\\\"seccomp\\\":");
    push_bool(&mut output, report.enforcement.seccomp);
    output.push_str("}}");
    output
}
''',
    "serialize enforcement receipt",
)

replace_one(
    "src/cli_json.rs",
    '''fn push_outcome(output: &mut String, outcome: ChildOutcome) {
''',
    '''fn push_bool(output: &mut String, value: bool) {
    output.push_str(if value { "true" } else { "false" });
}

fn push_outcome(output: &mut String, outcome: ChildOutcome) {
''',
    "insert bool serializer",
)

replace_one(
    "src/cli_json.rs",
    '''            "{\\\"ok\\\":true,\\\"outcome\\\":{\\\"kind\\\":\\\"exited\\\",\\\"code\\\":7},\\\"stdout\\\":{\\\"encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"0022ff\\\",\\\"truncated\\\":true},\\\"reaped_descendants\\\":3,\\\"process_tree_usage\\\":{\\\"user_cpu_micros\\\":11,\\\"system_cpu_micros\\\":22,\\\"max_child_rss_kib\\\":33}}"
''',
    '''            "{\\\"ok\\\":true,\\\"outcome\\\":{\\\"kind\\\":\\\"exited\\\",\\\"code\\\":7},\\\"stdout\\\":{\\\"encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"0022ff\\\",\\\"truncated\\\":true},\\\"reaped_descendants\\\":3,\\\"process_tree_usage\\\":{\\\"user_cpu_micros\\\":11,\\\"system_cpu_micros\\\":22,\\\"max_child_rss_kib\\\":33},\\\"enforcement\\\":{\\\"base_namespaces\\\":false,\\\"time_namespace_offsets\\\":false,\\\"hostname\\\":false,\\\"private_mount_propagation\\\":false,\\\"readonly_root\\\":false,\\\"chroot\\\":false,\\\"fd_sanitization\\\":false,\\\"rlimits\\\":false,\\\"capabilities_reduced\\\":false,\\\"no_new_privs\\\":false,\\\"landlock\\\":false,\\\"seccomp\\\":false}}"
''',
    "update JSON unit contract",
)

replace_one(
    "tests/cli.rs",
    '''    let max_rss = usage
        .strip_suffix("}}\\n")
        .unwrap_or_else(|| panic!("unexpected JSON telemetry suffix: {stdout}"));
    for (label, value) in [
        ("user_cpu_micros", user_cpu),
        ("system_cpu_micros", system_cpu),
        ("max_child_rss_kib", max_rss),
    ] {
        assert!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "{label} must be an unsigned decimal integer, got {value:?} in {stdout}"
        );
    }
''',
    '''    let (max_rss, enforcement) = usage
        .split_once("},\\\"enforcement\\\":")
        .unwrap_or_else(|| panic!("missing runtime enforcement receipt: {stdout}"));
    for (label, value) in [
        ("user_cpu_micros", user_cpu),
        ("system_cpu_micros", system_cpu),
        ("max_child_rss_kib", max_rss),
    ] {
        assert!(
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
            "{label} must be an unsigned decimal integer, got {value:?} in {stdout}"
        );
    }
    assert_eq!(
        enforcement,
        "{\\\"base_namespaces\\\":true,\\\"time_namespace_offsets\\\":false,\\\"hostname\\\":true,\\\"private_mount_propagation\\\":true,\\\"readonly_root\\\":true,\\\"chroot\\\":true,\\\"fd_sanitization\\\":true,\\\"rlimits\\\":true,\\\"capabilities_reduced\\\":true,\\\"no_new_privs\\\":true,\\\"landlock\\\":false,\\\"seccomp\\\":true}}\\n"
    );
''',
    "assert live enforcement JSON contract",
)
