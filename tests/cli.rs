#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

fn policy_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("security-lab-cli-{}-{label}.conf", process::id()))
}

fn write_policy(label: &str, text: &str) -> PathBuf {
    let path = policy_path(label);
    let _ = fs::remove_file(&path);
    fs::write(&path, text).expect("write CLI policy fixture");
    path
}

fn captured_echo_policy() -> String {
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/policies/echo.conf");
    let text = fs::read_to_string(example).expect("read example echo policy");
    let needle = "stdio.stdout = inherit";
    assert_eq!(
        text.matches(needle).count(),
        1,
        "example policy should contain one stdout inheritance declaration"
    );
    text.replace(
        needle,
        "stdio.stdout = capture\nstdio.stdout_capture_bytes = 4096",
    )
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

#[test]
fn run_json_emits_deterministic_machine_report() {
    let path = write_policy("json-success", &captured_echo_policy());
    let output = Command::new(binary())
        .args(["run-json", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run JSON CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "unexpected stderr bytes: {:?}", output.stderr);
    assert_eq!(
        String::from_utf8(output.stdout).expect("JSON CLI stdout is UTF-8"),
        "{\"ok\":true,\"outcome\":{\"kind\":\"exited\",\"code\":0},\"stdout\":{\"encoding\":\"hex\",\"data\":\"68656c6c6f2066726f6d2073656375726974792d6c61620a\",\"truncated\":false},\"reaped_descendants\":0}\n"
    );
}

#[test]
fn run_command_keeps_human_readable_status_contract() {
    let path = write_policy("human-success", &captured_echo_policy());
    let output = Command::new(binary())
        .args(["run", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run human CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty(), "unexpected stderr bytes: {:?}", output.stderr);
    assert_eq!(output.stdout, b"sandbox-result: exited code=0\n");
}

#[test]
fn run_json_reports_policy_errors_as_json() {
    let path = write_policy("json-policy-error", "unknown.field = value\n");
    let output = Command::new(binary())
        .args(["run-json", path.to_str().expect("UTF-8 temp policy path")])
        .output()
        .expect("run invalid JSON CLI policy");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty(), "unexpected stderr bytes: {:?}", output.stderr);
    let stdout = String::from_utf8(output.stdout).expect("JSON CLI stdout is UTF-8");
    assert!(
        stdout.starts_with("{\"ok\":false,\"error\":{\"kind\":\"policy_rejected\",\"message\":"),
        "unexpected JSON error prefix: {stdout}"
    );
    assert!(stdout.ends_with("}}\n"), "unexpected JSON error suffix: {stdout}");
}
