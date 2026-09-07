#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{self, Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

fn policy_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-lab-time-preflight-policy-{}.conf",
        process::id()
    ))
}

#[test]
fn configured_time_namespace_offsets_are_positively_probed_without_launch() {
    let root = std::env::temp_dir().join(format!(
        "security-lab-time-preflight-root-{}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("bin")).expect("create executable parent");
    fs::create_dir_all(root.join("work")).expect("create working directory");

    let executable = root.join("bin/probe");
    fs::write(&executable, b"time-preflight-executable-not-run\n")
        .expect("write executable anchor");
    let mut permissions = fs::metadata(&executable)
        .expect("stat executable anchor")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("chmod executable anchor");

    let policy_path = policy_path();
    let _ = fs::remove_file(&policy_path);
    let policy = format!(
        "filesystem.root = {}\nidentity.hostname = time-preflight\nexecutable = /bin/probe\nworking_dir = /work\nstdio.stdin = closed\nstdio.stdout = closed\nstdio.stderr = closed\nlimit.cpu_seconds = 1\nlimit.address_space_bytes = 67108864\nlimit.file_size_bytes = 1048576\nlimit.open_files = 32\ntime.monotonic_offset_seconds = 60\ntime.boottime_offset_seconds = 120\nseccomp.allow = execveat,exit\n",
        root.display()
    );
    fs::write(&policy_path, policy).expect("write time preflight policy");

    let output = Command::new(binary())
        .args([
            "preflight-json",
            policy_path.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run time namespace preflight");

    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains("\"status\":\"indeterminate\""));
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"configured_filesystem_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}"
    ));
    assert!(stdout.contains(
        "\"time_namespace\":{\"status\":\"supported\",\"reason\":null,\"probe\":{\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false,\"requested_monotonic_offset_seconds\":60,\"requested_boottime_offset_seconds\":120}}"
    ));
    assert!(stdout.contains("\"launch_attempted\":false"));
    assert!(stdout.contains("\"launch_preflight_complete\":false"));
    assert_eq!(
        fs::read(&executable).expect("read executable after preflight"),
        b"time-preflight-executable-not-run\n"
    );

    let _ = fs::remove_dir_all(&root);
}
