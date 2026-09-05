#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{run, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy, SeccompPolicy};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::OnceLock;

fn fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("security-lab-fixture-{}", process::id()));
            std::fs::create_dir_all(&dir).expect("create fixture build directory");
            let output = dir.join("probe");
            let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.S");
            let status = Command::new("cc")
                .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
                .arg(&output)
                .arg(&source)
                .status()
                .expect("Linux x86_64 integration tests require a C toolchain with cc");
            assert!(status.success(), "failed to assemble raw-syscall fixture");
            output
        })
        .as_path()
}

fn syscall_set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

fn policy(mode: &str, extra_args: &[&str], syscalls: &[&str]) -> SandboxPolicy {
    let mut args = vec![mode.to_owned()];
    args.extend(extra_args.iter().map(|arg| (*arg).to_owned()));
    SandboxPolicy {
        executable: fixture().to_path_buf(),
        args,
        environment: BTreeMap::new(),
        working_dir: PathBuf::from("/tmp"),
        limits: ResourceLimits {
            cpu_seconds: 2,
            address_space_bytes: 128 * 1024 * 1024,
            file_size_bytes: 1024 * 1024,
            open_files: 32,
        },
        seccomp: SeccompPolicy {
            allowed_syscalls: syscall_set(syscalls),
        },
    }
}

#[test]
fn allowed_operation_succeeds() {
    assert_eq!(
        run(&policy("A", &[], &["execve", "write", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn forbidden_syscall_is_denied_with_eperm() {
    assert_eq!(
        run(&policy("F", &[], &["execve", "exit"])).unwrap(),
        ChildOutcome::Exited(77)
    );
}

#[test]
fn malformed_policy_is_rejected() {
    let malformed = r#"
        executable = /bin/true
        working_dir = /tmp
        limit.cpu_seconds = 1
        limit.address_space_bytes = 100000000
        limit.file_size_bytes = 1000000
        limit.open_files = 16
        seccomp.allow = execve,exit
        silently_disable_seccomp = true
    "#;
    assert!(malformed.parse::<SandboxPolicy>().is_err());
}

#[test]
fn unknown_syscall_is_rejected_before_execution() {
    let invalid = policy("A", &[], &["execve", "not_a_real_syscall"]);
    assert!(matches!(run(&invalid), Err(SandboxError::InvalidPolicy(_))));
}

#[test]
fn setup_failure_never_falls_back_to_execution() {
    let marker = std::env::temp_dir().join(format!(
        "security-lab-marker-{}-{}",
        process::id(),
        unique_suffix()
    ));
    let _ = std::fs::remove_file(&marker);
    let marker_text = marker.to_string_lossy().into_owned();
    let mut failing = policy("W", &[&marker_text], &["execve", "openat", "exit"]);
    failing.working_dir = PathBuf::from("/definitely/does/not/exist/security-lab");

    let error = run(&failing).unwrap_err();
    assert!(matches!(error, SandboxError::SetupFailed(_)));
    assert!(!marker.exists(), "child ran despite setup failure");
}

#[test]
fn inherited_non_stdio_descriptor_does_not_survive_exec() {
    let source = unsafe {
        libc::open(
            b"/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY,
        )
    };
    assert!(source >= 0, "open /dev/null failed");
    let inherited = unsafe { libc::fcntl(source, libc::F_DUPFD, 200) };
    unsafe {
        libc::close(source);
    }
    assert!(
        inherited >= 200,
        "failed to create inheritable high descriptor"
    );

    let flags = unsafe { libc::fcntl(inherited, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        flags & libc::FD_CLOEXEC,
        0,
        "test descriptor must start inheritable"
    );

    let descriptor = inherited.to_string();
    let result = run(&policy("D", &[&descriptor], &["execve", "fcntl", "exit"]));
    unsafe {
        libc::close(inherited);
    }

    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn exec_failure_is_reported_after_descriptor_sanitization() {
    let script = std::env::temp_dir().join(format!(
        "security-lab-missing-interpreter-{}-{}",
        process::id(),
        unique_suffix()
    ));
    std::fs::write(&script, b"#!/definitely/missing/security-lab-interpreter\n")
        .expect("write executable fixture");
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let mut failing = policy("A", &[], &["execve", "write", "exit", "exit_group"]);
    failing.executable = script.clone();
    let result = run(&failing);
    let _ = std::fs::remove_file(&script);

    assert!(matches!(result, Err(SandboxError::SetupFailed(_))));
}

#[test]
fn child_exit_code_is_surfaced() {
    assert_eq!(
        run(&policy("X", &[], &["execve", "exit"])).unwrap(),
        ChildOutcome::Exited(42)
    );
}

#[test]
fn child_signal_is_surfaced() {
    assert_eq!(
        run(&policy(
            "S",
            &[],
            &["execve", "getpid", "gettid", "tgkill", "exit"]
        ))
        .unwrap(),
        ChildOutcome::Signaled(libc::SIGTERM)
    );
}

#[test]
fn environment_is_cleared_then_explicitly_rebuilt() {
    let mut env_policy = policy("E", &[], &["execve", "exit"]);
    env_policy
        .environment
        .insert("SANDBOX_ALLOWED".to_owned(), "yes".to_owned());
    assert_eq!(run(&env_policy).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn working_directory_is_controlled() {
    assert_eq!(
        run(&policy("C", &["/tmp"], &["execve", "getcwd", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn all_configured_resource_limits_are_observable() {
    assert_eq!(
        run(&policy("R", &[], &["execve", "prlimit64", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn open_file_limit_is_enforced() {
    let mut limited = policy("N", &[], &["execve", "openat", "exit"]);
    limited.limits.open_files = 16;
    assert_eq!(run(&limited).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn no_new_privs_is_observable_in_child() {
    assert_eq!(
        run(&policy("P", &[], &["execve", "prctl", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

fn unique_suffix() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
