use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);

struct TempPolicy(PathBuf);

impl TempPolicy {
    fn new(label: &str, contents: &str) -> Self {
        let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-authority-delta-{}-{sequence}-{label}.conf",
            process::id()
        ));
        fs::write(&path, contents).expect("write temporary policy");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempPolicy {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn base_policy(root: &Path) -> String {
    format!(
        "filesystem.root = {}\n\
identity.hostname = authority-delta\n\
executable = /bin/true\n\
working_dir = /\n\
stdio.stdin = closed\n\
stdio.stdout = closed\n\
stdio.stderr = closed\n\
limit.cpu_seconds = 2\n\
limit.address_space_bytes = 67108864\n\
limit.file_size_bytes = 1048576\n\
limit.open_files = 32\n\
seccomp.allow = execveat,exit\n",
        root.display()
    )
}

fn run_json(baseline: &TempPolicy, candidate: &TempPolicy) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_security-lab-authority-delta"))
        .arg("compare-json")
        .arg(baseline.path())
        .arg(candidate.path())
        .output()
        .expect("run authority delta binary")
}

#[test]
fn identical_policy_is_unchanged_and_static() {
    let root = unique_absent_root("unchanged");
    let text = base_policy(&root);
    let baseline = TempPolicy::new("baseline", &text);
    let candidate = TempPolicy::new("candidate", &text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"unchanged\""));
    assert!(stdout.contains("\"kernel_effective_state\":false"));
    assert!(stdout.contains("\"filesystem_alias_proof\":false"));
    assert!(stdout.contains("\"static_non_widening\":true"));
    assert!(
        !root.exists(),
        "static comparison must not materialize the root"
    );
}

#[test]
fn added_syscall_is_detected_as_authority_widening() {
    let root = unique_absent_root("widen");
    let baseline_text = base_policy(&root);
    let candidate_text = baseline_text.replace(
        "seccomp.allow = execveat,exit",
        "seccomp.allow = execveat,getpid,exit",
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(5));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"widened\""));
    assert!(stdout.contains("\"field\":\"seccomp.allow\",\"class\":\"widened\""));
    assert!(stdout.contains("\"widening_detected\":true"));
    assert!(stdout.contains("\"static_non_widening\":false"));
}

#[test]
fn lower_resource_ceiling_is_detected_as_reduction() {
    let root = unique_absent_root("reduce");
    let baseline_text = base_policy(&root);
    let candidate_text = baseline_text.replace("limit.cpu_seconds = 2", "limit.cpu_seconds = 1");
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"reduced\""));
    assert!(stdout.contains("\"field\":\"controls.cpu_seconds\",\"class\":\"reduced\""));
    assert!(stdout.contains("\"static_non_widening\":true"));
}

#[test]
fn activating_landlock_read_envelope_is_detected_as_reduction() {
    let root = unique_absent_root("landlock");
    let baseline_text = base_policy(&root);
    let candidate_text = format!("{baseline_text}landlock.read_execute = /bin\n");
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"reduced\""));
    assert!(stdout.contains("\"field\":\"landlock.read_execute\",\"class\":\"reduced\""));
}

#[test]
fn execution_identity_change_is_incomparable() {
    let root = unique_absent_root("incomparable");
    let baseline_text = base_policy(&root);
    let candidate_text = baseline_text.replace("executable = /bin/true", "executable = /bin/false");
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(6));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"incomparable\""));
    assert!(stdout.contains("\"field\":\"execution.executable\",\"class\":\"incomparable\""));
}

#[test]
fn mixed_widening_and_reduction_is_incomparable() {
    let root = unique_absent_root("mixed");
    let baseline_text = base_policy(&root);
    let candidate_text = baseline_text
        .replace("limit.cpu_seconds = 2", "limit.cpu_seconds = 1")
        .replace(
            "seccomp.allow = execveat,exit",
            "seccomp.allow = execveat,getpid,exit",
        );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(6));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"incomparable\""));
    assert!(stdout.contains("\"widening_detected\":true"));
    assert!(stdout.contains("\"static_non_widening\":false"));
}

#[test]
fn invalid_candidate_fails_closed_before_comparison() {
    let root = unique_absent_root("invalid");
    let baseline_text = base_policy(&root);
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", "this is not a policy\n");

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"ok\":false"));
    assert!(stdout.contains("\"kind\":\"candidate_policy_rejected\""));
    assert!(
        !root.exists(),
        "rejected comparison must not launch the sandbox"
    );
}

fn unique_absent_root(label: &str) -> PathBuf {
    let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "security-lab-authority-delta-root-{}-{sequence}-{label}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    root
}
