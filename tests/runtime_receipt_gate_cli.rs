#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::path::{Path, PathBuf};
use std::process::{self, Command};

struct TempRoot {
    root: PathBuf,
    policy: PathBuf,
}

impl TempRoot {
    fn new(label: &str, policy_body: impl FnOnce(&Path) -> String) -> Self {
        let root = std::env::temp_dir().join(format!(
            "security-lab-receipt-gate-{label}-{}",
            process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("work")).expect("create work directory");

        let probe = root.join("probe");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.S");
        let status = Command::new("cc")
            .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
            .arg(&probe)
            .arg(&source)
            .status()
            .expect("Linux x86_64 integration tests require cc");
        assert!(status.success(), "failed to build raw-syscall fixture");

        let policy = root.join("policy.conf");
        std::fs::write(&policy, policy_body(&root)).expect("write policy fixture");
        Self { root, policy }
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab-runtime-receipt-gate")
}

fn valid_policy(root: &Path) -> String {
    format!(
        "filesystem.root = {}\n\
         identity.hostname = receipt-gate\n\
         executable = /probe\n\
         arg = X\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.cpu_seconds = 1\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,exit\n",
        root.display()
    )
}

#[test]
fn real_run_proves_receipt_gate_is_independent_of_target_exit_zero() {
    let fixture = TempRoot::new("complete", valid_policy);
    let output = Command::new(binary())
        .arg("check-json")
        .arg(&fixture.policy)
        .output()
        .expect("run receipt gate");

    assert!(
        output.status.success(),
        "receipt gate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("JSON output is UTF-8");
    assert!(stdout.contains("\"kind\":\"runtime_receipt_gate\""));
    assert!(stdout.contains("\"receipt_complete\":true"));
    assert!(stdout.contains("\"full_policy_attestation\":false"));
    assert!(stdout.contains("\"exec_success_proof\":false"));
    assert!(stdout.contains("\"target_outcome\":\"exited code=42\""));
    assert!(stdout.contains("\"missing\":[]"));
    assert!(stdout.contains("\"unexpected\":[]"));
}

#[test]
fn invalid_policy_is_rejected_before_launch_with_machine_error() {
    let fixture = TempRoot::new("invalid", |root| {
        format!(
            "filesystem.root = {}\nidentity.hostname = receipt-gate\nexecutable = relative\n",
            root.display()
        )
    });
    let output = Command::new(binary())
        .arg("check-json")
        .arg(&fixture.policy)
        .output()
        .expect("run receipt gate");

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).expect("JSON error is UTF-8");
    assert!(stdout.contains("\"ok\":false"));
    assert!(stdout.contains("\"kind\":\"policy_rejected\""));
    assert!(stdout.contains("\"full_policy_attestation\":false"));
    assert!(stdout.contains("\"exec_success_proof\":false"));
}
