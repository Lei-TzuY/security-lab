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
filesystem.proc = enabled
executable = /bin/probe
executable.sha256 = 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
arg = super-secret-argument
env.SECRET_TOKEN = top-secret-value
working_dir = /work
time.monotonic_offset_seconds = 3600
time.boottime_offset_seconds = 7200
stdio.stdin = closed
stdio.stdout = capture
stdio.stdout_capture_bytes = 1024
limit.stdout_total_bytes = 4096
stdio.stderr = inherit
handle.9 = 200
limit.cpu_seconds = 2
limit.address_space_bytes = 134217728
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,lseek,read,write,exit
seccomp.arg.lseek.1 = 0x1:0x0
seccomp.range.lseek.1 = 4:16
seccomp.deny_mask.lseek.2 = 0x6:0x6
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
    assert_eq!(
        first.stdout, second.stdout,
        "manifest output must be deterministic"
    );

    let stdout = String::from_utf8(first.stdout).expect("manifest JSON is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":true,\"manifest\":{\"kind\":\"static_authority\",\"runtime_preflight\":false,\"identity\":{\"hostname\":\"manifest-test\""
    ));
    assert!(stdout.contains("\"executable_sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\""));
    assert!(stdout.contains("\"executable_interpreter\":null"));
    assert!(stdout.contains("\"executable_interpreter_sha256\":null"));
    assert!(stdout.contains("\"executable_needed\":null"));
    assert!(stdout.contains("\"executable_needed_sha256\":null"));
    assert!(stdout.contains("\"executable_needed_bindings\":[]"));
    assert!(stdout.contains("\"argument_count\":1,\"environment_keys\":[\"SECRET_TOKEN\"]"));
    assert!(stdout.contains("\"private_procfs\":true"));
    assert!(stdout.contains("\"selected\":[{\"target_fd\":9,\"source_fd\":200}]"));
    assert!(stdout.contains(
        "\"masked\":[{\"syscall\":\"lseek\",\"argument\":1,\"mask\":\"0x0000000000000001\",\"value\":\"0x0000000000000000\"}]"
    ));
    assert!(stdout.contains(
        "\"ranges\":[{\"syscall\":\"lseek\",\"argument\":1,\"minimum\":\"0x0000000000000004\",\"maximum\":\"0x0000000000000010\"}]"
    ));
    assert!(stdout.contains(
        "\"deny_mask\":[{\"syscall\":\"lseek\",\"argument\":2,\"mask\":\"0x0000000000000006\",\"value\":\"0x0000000000000006\"}]"
    ));
    assert!(stdout.contains("\"stdout_capture_bytes\":1024,\"stdout_total_bytes\":4096,\"time_namespace\":{\"monotonic_offset_seconds\":3600,\"boottime_offset_seconds\":7200}"));
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
    assert!(stdout.contains(
        "executable-sha256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n"
    ));
    assert!(stdout.contains("executable-needed-bindings: none\n"));
    assert!(stdout.contains("arguments: 1\n"));
    assert!(stdout.contains("private-procfs: enabled\n"));
    assert!(stdout.contains("environment-keys: SECRET_TOKEN\n"));
    assert!(stdout.contains("stdio: stdin=closed stdout=capture stderr=inherit\n"));
    assert!(stdout.contains("selected-handles: 1\n"));
    assert!(stdout.contains("seccomp: allow=5 masked=1 ranges=1 deny-mask=1\n"));
    assert!(stdout
        .contains("time-namespace: monotonic-offset-seconds=3600 boottime-offset-seconds=7200\n"));
    assert!(stdout.contains("stdout-capture-bytes=1024 stdout-total-bytes=4096\n"));
    assert!(!stdout.contains("super-secret-argument"));
    assert!(!stdout.contains("top-secret-value"));
    assert!(!root.exists());
}

#[test]
fn manifest_json_canonicalizes_bounded_needed_binding_set() {
    let root = root_path("needed-set");
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let second = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let text = format!(
        "{}executable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}\nexecutable.needed = /z-dependency\nexecutable.needed = /a-dependency\nexecutable.needed_sha256 = {second}\nexecutable.needed_sha256 = {digest}\n",
        manifest_policy(&root)
    );
    let path = write_policy("needed-set", &text);
    let output = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run needed-set manifest JSON");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("manifest JSON is UTF-8");
    assert!(stdout.contains(
        "\"executable_needed_bindings\":[{\"path\":\"/a-dependency\",\"sha256\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"},{\"path\":\"/z-dependency\",\"sha256\":\"1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}]"
    ));
}

#[test]
fn manifest_reports_canonical_bounded_persistent_volume_sets() {
    let root = root_path("volume-set");
    let text = format!(
        "{}volume.readonly_source = /srv/z-read
volume.readonly_source = /srv/a-read
volume.readonly_target = /z-data
volume.readonly_target = /a-data
volume.writable_source = /srv/z-write
volume.writable_source = /srv/a-write
volume.writable_target = /z-persist
volume.writable_target = /a-persist
volume.cow_source = /srv/z-cow
volume.cow_source = /srv/a-cow
volume.cow_target = /z-cow-data
volume.cow_target = /a-cow-data
volume.cow_bytes = 2097152
volume.cow_bytes = 1048576
volume.cow_diff_bytes = 8192
volume.cow_diff_bytes = 4096
volume.cow_base_identity_bytes = 2097152
volume.cow_base_identity_bytes = 1048576
volume.cow_base_identity_nodes = 200
volume.cow_base_identity_nodes = 100
",
        manifest_policy(&root)
    );
    let path = write_policy("volume-set", &text);

    let json = Command::new(binary())
        .args(["manifest-json", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run volume-set manifest JSON");
    let human = Command::new(binary())
        .args(["manifest", path.to_str().expect("UTF-8 policy path")])
        .output()
        .expect("run volume-set human manifest");
    let _ = fs::remove_file(path);

    assert_eq!(json.status.code(), Some(0));
    let stdout = String::from_utf8(json.stdout).expect("manifest JSON is UTF-8");
    assert!(stdout.contains(
        "\"read_only_volumes\":[{\"access\":\"read_only\",\"source\":\"/srv/a-read\",\"target\":\"/a-data\"},{\"access\":\"read_only\",\"source\":\"/srv/z-read\",\"target\":\"/z-data\"}]"
    ));
    assert!(stdout.contains(
        "\"writable_volumes\":[{\"access\":\"writable\",\"source\":\"/srv/a-write\",\"target\":\"/a-persist\"},{\"access\":\"writable\",\"source\":\"/srv/z-write\",\"target\":\"/z-persist\"}]"
    ));
    assert!(stdout.contains(
        "\"copy_on_write_volumes\":[{\"access\":\"copy_on_write\",\"source\":\"/srv/a-cow\",\"target\":\"/a-cow-data\",\"bytes\":1048576,\"diff_bytes\":4096,\"base_identity_bytes\":1048576,\"base_identity_nodes\":100},{\"access\":\"copy_on_write\",\"source\":\"/srv/z-cow\",\"target\":\"/z-cow-data\",\"bytes\":2097152,\"diff_bytes\":8192,\"base_identity_bytes\":2097152,\"base_identity_nodes\":200}]"
    ));

    assert_eq!(human.status.code(), Some(0));
    let stdout = String::from_utf8(human.stdout).expect("human manifest is UTF-8");
    assert!(stdout.contains("host-filesystem-volumes: read-only=2 writable=2 copy-on-write=2\n"));
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
    assert!(
        stdout.starts_with("{\"ok\":false,\"error\":{\"kind\":\"policy_rejected\",\"message\":")
    );
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
