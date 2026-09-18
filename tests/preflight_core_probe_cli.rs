#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{self, Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

fn policy_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-lab-preflight-core-policy-{}-{label}.conf",
        process::id()
    ))
}

#[test]
fn missing_configured_root_is_known_incompatible_without_materialization() {
    let missing_root = std::env::temp_dir().join(format!(
        "security-lab-preflight-core-missing-root-{}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&missing_root);
    let policy_path = policy_path("missing-root");
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
        .expect("run configured filesystem preflight");
    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains("\"status\":\"incompatible\""));
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"configured_filesystem_probe\":{\"status\":\"unsupported\",\"stage\":\"root_open\",\"errno\":2,\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}"
    ));
    assert!(stdout.contains(
        "\"mandatory_namespace_mount_core_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}"
    ));
    assert!(
        !missing_root.exists(),
        "configured filesystem preflight may inspect but must never materialize a missing root"
    );
}

#[test]
fn configured_filesystem_anchors_are_positively_probed_without_launch() {
    let root = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-root-{}",
        process::id()
    ));
    let readonly_source = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-readonly-{}",
        process::id()
    ));
    let writable_source = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-writable-{}",
        process::id()
    ));
    for path in [&root, &readonly_source, &writable_source] {
        let _ = fs::remove_dir_all(path);
    }
    for relative in ["bin", "work", "scratch", "proc", "data", "persist"] {
        fs::create_dir_all(root.join(relative)).expect("create configured filesystem anchor");
    }
    fs::create_dir_all(&readonly_source).expect("create read-only volume source");
    fs::create_dir_all(&writable_source).expect("create writable volume source");
    fs::write(readonly_source.join("marker"), b"readonly-marker\n")
        .expect("write read-only source marker");
    fs::write(writable_source.join("marker"), b"writable-marker\n")
        .expect("write writable source marker");

    let executable = root.join("bin/probe");
    fs::write(&executable, b"preflight-executable-not-run\n").expect("write executable anchor");
    let mut permissions = fs::metadata(&executable)
        .expect("stat executable anchor")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("chmod executable anchor");

    let policy_path = policy_path("positive-filesystem");
    let _ = fs::remove_file(&policy_path);
    let policy = format!(
        "filesystem.root = {}\nidentity.hostname = preflight-filesystem\nfilesystem.scratch = /scratch\nfilesystem.scratch_bytes = 4096\nfilesystem.proc = enabled\nvolume.readonly_source = {}\nvolume.readonly_target = /data\nvolume.writable_source = {}\nvolume.writable_target = /persist\nexecutable = /bin/probe\nworking_dir = /work\nstdio.stdin = closed\nstdio.stdout = closed\nstdio.stderr = closed\nlimit.cpu_seconds = 1\nlimit.address_space_bytes = 67108864\nlimit.file_size_bytes = 1048576\nlimit.open_files = 32\nseccomp.allow = execveat,exit\n",
        root.display(),
        readonly_source.display(),
        writable_source.display(),
    );
    fs::write(&policy_path, policy).expect("write positive filesystem preflight policy");

    let output = Command::new(binary())
        .args([
            "preflight-json",
            policy_path.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run positive configured filesystem preflight");
    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains("\"status\":\"indeterminate\""));
    assert!(stdout.contains(
        "\"configured_filesystem_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}"
    ));
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"mandatory_namespace_mount_core_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}"
    ));
    assert_eq!(
        fs::read(&executable).expect("read executable after preflight"),
        b"preflight-executable-not-run\n"
    );
    assert_eq!(
        fs::read(readonly_source.join("marker")).expect("read read-only marker after preflight"),
        b"readonly-marker\n"
    );
    assert_eq!(
        fs::read(writable_source.join("marker")).expect("read writable marker after preflight"),
        b"writable-marker\n"
    );
    assert!(
        fs::read_dir(root.join("persist"))
            .expect("read persist target after preflight")
            .next()
            .is_none(),
        "preflight must not mount or write into the configured writable target"
    );

    for path in [&root, &readonly_source, &writable_source] {
        let _ = fs::remove_dir_all(path);
    }
}
