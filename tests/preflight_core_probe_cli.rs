#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

#[test]
fn preflight_positively_probes_isolated_namespace_mount_core_without_touching_policy_root() {
    let missing_root = std::env::temp_dir().join(format!(
        "security-lab-preflight-core-missing-root-{}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&missing_root);
    let policy_path: PathBuf = std::env::temp_dir().join(format!(
        "security-lab-preflight-core-policy-{}.conf",
        process::id()
    ));
    let _ = fs::remove_file(&policy_path);
    let policy = format!(
        "filesystem.root = {}\nidentity.hostname = preflight-core\nexecutable = /bin/true\nworking_dir = /\nstdio.stdin = closed\nstdio.stdout = closed\nstdio.stderr = closed\nlimit.cpu_seconds = 1\nlimit.address_space_bytes = 67108864\nlimit.file_size_bytes = 1048576\nlimit.open_files = 32\nseccomp.allow = execveat,exit\n",
        missing_root.display()
    );
    fs::write(&policy_path, policy).expect("write preflight policy");

    let output = Command::new(binary())
        .args([
            "preflight-json",
            policy_path.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run preflight core probe");
    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"mandatory_namespace_mount_core_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}"
    ));
    assert!(
        !missing_root.exists(),
        "isolated core probe must not materialize or inspect the configured policy root"
    );
}
