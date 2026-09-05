#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{run, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy, SeccompPolicy};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process;

const FIXTURE: &str = env!("CARGO_BIN_EXE_fixture-probe");

fn runtime_syscalls(extra: &[&str]) -> BTreeSet<String> {
    let baseline = [
        "read",
        "write",
        "close",
        "fstat",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "pread64",
        "access",
        "mremap",
        "madvise",
        "sched_yield",
        "nanosleep",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "fcntl",
        "getcwd",
        "readlink",
        "sigaltstack",
        "arch_prctl",
        "futex",
        "sched_getaffinity",
        "set_tid_address",
        "exit",
        "openat",
        "newfstatat",
        "set_robust_list",
        "prlimit64",
        "getrandom",
        "execve",
        "exit_group",
        "statx",
        "rseq",
        "clock_gettime",
        "uname",
        "readlinkat",
    ];
    baseline
        .into_iter()
        .chain(extra.iter().copied())
        .map(str::to_owned)
        .collect()
}

fn policy(mode: &str, extra_args: &[&str], extra_syscalls: &[&str]) -> SandboxPolicy {
    let mut args = vec![mode.to_owned()];
    args.extend(extra_args.iter().map(|arg| (*arg).to_owned()));
    SandboxPolicy {
        executable: PathBuf::from(FIXTURE),
        args,
        environment: BTreeMap::new(),
        working_dir: std::env::temp_dir(),
        limits: ResourceLimits {
            cpu_seconds: 2,
            address_space_bytes: 512 * 1024 * 1024,
            file_size_bytes: 1024 * 1024,
            open_files: 32,
        },
        seccomp: SeccompPolicy {
            allowed_syscalls: runtime_syscalls(extra_syscalls),
        },
    }
}

#[test]
fn allowed_operation_succeeds() {
    assert_eq!(
        run(&policy("allowed", &[], &[])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn forbidden_syscall_is_denied_with_eperm() {
    assert_eq!(
        run(&policy("forbidden-getpid", &[], &[])).unwrap(),
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
        seccomp.allow = execve,exit_group
        silently_disable_seccomp = true
    "#;
    assert!(malformed.parse::<SandboxPolicy>().is_err());
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
    let mut failing = policy("write-marker", &[&marker_text], &[]);
    failing.working_dir = PathBuf::from("/definitely/does/not/exist/security-lab");

    let error = run(&failing).unwrap_err();
    assert!(matches!(error, SandboxError::SetupFailed(_)));
    assert!(!marker.exists(), "child ran despite setup failure");
}

#[test]
fn child_exit_code_is_surfaced() {
    assert_eq!(
        run(&policy("exit", &["42"], &[])).unwrap(),
        ChildOutcome::Exited(42)
    );
}

#[test]
fn child_signal_is_surfaced() {
    assert_eq!(
        run(&policy("signal-term", &[], &["getpid", "gettid", "tgkill"])).unwrap(),
        ChildOutcome::Signaled(libc::SIGTERM)
    );
}

#[test]
fn environment_is_cleared_then_explicitly_rebuilt() {
    let mut env_policy = policy("expect-env", &["SANDBOX_ALLOWED", "yes"], &[]);
    env_policy
        .environment
        .insert("SANDBOX_ALLOWED".to_owned(), "yes".to_owned());
    assert_eq!(run(&env_policy).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn working_directory_is_controlled() {
    let cwd = std::env::temp_dir();
    let cwd_text = cwd.to_string_lossy().into_owned();
    assert_eq!(
        run(&policy("expect-cwd", &[&cwd_text], &[])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn open_file_limit_is_enforced() {
    let mut limited = policy("nofile", &[], &[]);
    limited.limits.open_files = 16;
    assert_eq!(run(&limited).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn no_new_privs_is_observable_in_child() {
    assert_eq!(
        run(&policy("no-new-privs", &[], &["prctl"])).unwrap(),
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
