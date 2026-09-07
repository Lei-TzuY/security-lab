#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

fn policy_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-lab-authority-manifest-{}-{label}.conf",
        process::id()
    ))
}

fn root_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-lab-authority-manifest-root-{}-{label}",
        process::id()
    ))
}

fn write_policy(label: &str, text: &str) -> PathBuf {
    let path = policy_path(label);
    let _ = fs::remove_file(&path);
    fs::write(&path, text).expect("write manifest CLI policy fixture");
    path
}

fn manifest_policy(root: &Path) -> String {
    format!(
        r#"filesystem.root = {}
identity.hostname = manifest-test
executable = /bin/probe
arg = super-secret-argument
env.SECRET_TOKEN = top-secret-value
working_dir = /work
stdio.stdin = closed
stdio.stdout = capture
stdio.stdout_capture_bytes = 1024
stdio.stdout_total_bytes = 4096
stdio.stderr = inherit
handle.9 = 200
limit.cpu_seconds = 2
limit.address_space_bytes = 134217728
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,lseek,read,write,exit
seccomp.arg.lseek.1 = 0x1:0x0
seccomp.range.lseek.1 = 4:16
"#,
        root.display()
    )
}

#[test]
fn manifest_json_is_deterministic_redacted_and_static() {
    let root = root_path("json");
    let _ = fs::remove_dir_all(&root);
    assert!(!root.exists());
    let path = write_policy("json", &manifest_policy(&root));

    let first = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run manifest JSON CLI");
    let second = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run manifest JSON CLI twice");
    let _ = fs::remove_file(path);

    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert!(first.stderr.is_empty());
    assert!(second.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout, "manifest output must be deterministic");

    let stdout = String::from_utf8(first.stdout).expect("manifest JSON is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":true,\"manifest\":{\"kind\":\"static_authority\",\"runtime_preflight\":false,\"identity\":{\"hostname\":\"manifest-test\""
    ));
    assert!(stdout.contains("\"argument_count\":1,\"environment_keys\":[\"SECRET_TOKEN\"]"));
    assert!(stdout.contains("\"selected\":[{\"target_fd\":9,\"source_fd\":200}]"));
    assert!(stdout.contains(
        "\"masked\":[{\"syscall\":\"lseek\",\"argument\":1,\"mask\":\"0x0000000000000001\",\"value\":\"0x0000000000000000\"}]"
    ));
    assert!(stdout.contains(
        "\"ranges\":[{\"syscall\":\"lseek\",\"argument\":1,\"minimum\":\"0x0000000000000004\",\"maximum\":\"0x0000000000000010\"}]"
    ));
    assert!(stdout.contains("\"stdout_capture_bytes\":1024,\"stdout_total_bytes\":4096"));
    assert!(!stdout.contains("super-secret-argument"));
    assert!(!stdout.contains("top-secret-value"));
    assert!(
        !root.exists(),
        "static authority manifest must not materialize the runtime filesystem root"
    );
}

#[test]
fn manifest_human_summarizes_authority_without_secret_values() {
    let root = root_path("human");
    let _ = fs::remove_dir_all(&root);
    let path = write_policy("human", &manifest_policy(&root));

    let output = Command::new(binary())
        .args(["manifest", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run manifest human CLI");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("manifest human output is UTF-8");
    assert!(stdout.starts_with("policy-authority-manifest:\nruntime-preflight: false\n"));
    assert!(stdout.contains("arguments: 1\n"));
    assert!(stdout.contains("environment-keys: SECRET_TOKEN\n"));
    assert!(stdout.contains("stdio: stdin=closed stdout=capture stderr=inherit\n"));
    assert!(stdout.contains("selected-handles: 1\n"));
    assert!(stdout.contains("seccomp: allow=5 masked=1 ranges=1\n"));
    assert!(stdout.contains("stdout-capture-bytes=1024 stdout-total-bytes=4096\n"));
    assert!(!stdout.contains("super-secret-argument"));
    assert!(!stdout.contains("top-secret-value"));
    assert!(!root.exists());
}

#[test]
fn manifest_json_rejects_invalid_policy_fail_closed() {
    let path = write_policy("invalid", "unknown.field = value\n");
    let output = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run invalid manifest JSON policy");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("manifest error JSON is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":false,\"error\":{\"kind\":\"policy_rejected\",\"message\":"
    ));
    assert!(stdout.ends_with("}}\n"));
}

#[test]
fn manifest_json_requires_exactly_one_policy_argument() {
    let output = Command::new(binary())
        .arg("manifest-json")
        .output()
        .expect("run malformed manifest JSON invocation");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("manifest usage JSON is UTF-8");
    assert!(stdout.starts_with("{\"ok\":false,\"error\":{\"kind\":\"usage\",\"message\":"));
    assert!(stdout.contains("manifest|manifest-json"));
    assert!(stdout.ends_with("}}\n"));
}
