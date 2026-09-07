from pathlib import Path

path = Path("tests/cli.rs")
text = path.read_text()
old = '''#[test]
fn preflight_json_marks_requested_time_namespace_unprobed() {
    let (policy, root) = preflight_policy("preflight_json_marks_requested_time_namespace_unprobed");
    let policy =
        format!("{policy}\\ntime.monotonic_offset_seconds = 1\\ntime.boottime_offset_seconds = 2\\n");
    let path = write_policy("preflight-time-unprobed", &policy);
    let output = Command::new(binary())
        .args([
            "preflight-json",
            path.to_str().expect("UTF-8 temp policy path"),
        ])
        .output()
        .expect("run time namespace preflight JSON CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.contains("\\\"status\\\":\\\"indeterminate\\\""));
    assert!(stdout.contains(
        "\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"mandatory_runtime_prerequisites_not_probed\\\"}"
    ));
    assert!(stdout.contains(
        "\\\"time_namespace\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"independent_safe_probe_not_implemented\\\"}"
    ));
    assert_eq!(
        fs::read(root.join("bin/probe")).expect("read time-preflight executable after probe"),
        b"preflight-only-not-executed\\n"
    );
    let _ = fs::remove_dir_all(root);
}
'''
new = '''#[test]
fn preflight_json_positively_probes_requested_time_namespace() {
    let (policy, root) = preflight_policy("preflight_json_positively_probes_requested_time_namespace");
    let policy =
        format!("{policy}\\ntime.monotonic_offset_seconds = 1\\ntime.boottime_offset_seconds = 2\\n");
    let path = write_policy("preflight-time-probed", &policy);
    let output = Command::new(binary())
        .args([
            "preflight-json",
            path.to_str().expect("UTF-8 temp policy path"),
        ])
        .output()
        .expect("run time namespace preflight JSON CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON stdout is UTF-8");
    assert!(stdout.contains("\\\"status\\\":\\\"indeterminate\\\""));
    assert!(stdout.contains(
        "\\\"mandatory_launch_core\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"mandatory_runtime_prerequisites_not_probed\\\"}"
    ));
    assert!(stdout.contains(
        "\\\"time_namespace\\\":{\\\"status\\\":\\\"supported\\\",\\\"reason\\\":null,\\\"probe\\\":{\\\"stage\\\":\\\"complete\\\",\\\"errno\\\":null,\\\"isolated_helper\\\":true,\\\"configured_root_touched\\\":false,\\\"target_executed\\\":false,\\\"requested_monotonic_offset_seconds\\\":1,\\\"requested_boottime_offset_seconds\\\":2}}"
    ));
    assert_eq!(
        fs::read(root.join("bin/probe")).expect("read time-preflight executable after probe"),
        b"preflight-only-not-executed\\n"
    );
    let _ = fs::remove_dir_all(root);
}
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"CLI time namespace regression: expected exactly one match, got {count}")
path.write_text(text.replace(old, new, 1))
