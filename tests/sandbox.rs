#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{
    run, run_report, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy, SeccompArgRule,
    SeccompPolicy, StdioMode, StdioPolicy,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::OnceLock;

const SCRATCH_BYTES: u64 = 16 * 1024 * 1024;

struct TestFd(RawFd);

impl TestFd {
    fn raw(&self) -> RawFd {
        self.0
    }
}

impl Drop for TestFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

fn duplicate_fd_at_least(fd: RawFd, minimum: RawFd, label: &str) -> TestFd {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(
        duplicated >= minimum,
        "failed to duplicate {label} at or above {minimum}: {}",
        std::io::Error::last_os_error()
    );
    TestFd(duplicated)
}

fn fixture_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("security-lab-root-{}", process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("work")).expect("create sandbox work directory");
        std::fs::create_dir_all(root.join("scratch")).expect("create sandbox scratch mountpoint");

        let output = root.join("probe");
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.S");
        let status = Command::new("cc")
            .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
            .arg(&output)
            .arg(&source)
            .status()
            .expect("Linux x86_64 integration tests require a C toolchain with cc");
        assert!(status.success(), "failed to assemble raw-syscall fixture");
        root
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
        root_dir: fixture_root().to_path_buf(),
        hostname: "security-lab".to_owned(),
        executable: PathBuf::from("/probe"),
        args,
        environment: BTreeMap::new(),
        working_dir: PathBuf::from("/work"),
        scratch_dir: Some(PathBuf::from("/scratch")),
        scratch_bytes: Some(SCRATCH_BYTES),
        stdio: StdioPolicy {
            stdin: StdioMode::Inherit,
            stdout: StdioMode::Inherit,
            stderr: StdioMode::Inherit,
        },
        selected_handles: BTreeMap::new(),
        stdout_redirect: None,
        stdout_capture_bytes: None,
        wall_clock_milliseconds: None,
        limits: ResourceLimits {
            cpu_seconds: 2,
            address_space_bytes: 128 * 1024 * 1024,
            file_size_bytes: 1024 * 1024,
            open_files: 32,
        },
        seccomp: SeccompPolicy {
            allowed_syscalls: syscall_set(syscalls),
            argument_rules: BTreeMap::new(),
        },
    }
}

#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "create selected-handle pipe"
    );
    let read_end = TestFd(pipe[0]);
    let write_end = TestFd(pipe[1]);
    let source = duplicate_fd_at_least(read_end.raw(), 200, "selected source");
    drop(read_end);

    let marker = b"selected-handle-ok";
    let written = unsafe {
        libc::write(
            write_end.raw(),
            marker.as_ptr().cast::<libc::c_void>(),
            marker.len(),
        )
    };
    assert_eq!(written, marker.len() as isize, "write selected marker");
    drop(write_end);

    let null_path = CString::new("/dev/null").unwrap();
    let null_fd = unsafe { libc::open(null_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(null_fd >= 0, "open undeclared descriptor fixture");
    let null_fd = TestFd(null_fd);
    let undeclared = duplicate_fd_at_least(null_fd.raw(), 220, "undeclared descriptor");
    drop(null_fd);

    let source_text = source.raw().to_string();
    let undeclared_text = undeclared.raw().to_string();
    let mut selected = policy(
        "G",
        &[source_text.as_str(), undeclared_text.as_str()],
        &["execveat", "read", "fcntl", "exit"],
    );
    selected.selected_handles.insert(9, source.raw() as u32);

    assert_eq!(run(&selected).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn selected_handle_rejects_directory_source() {
    let directory = std::fs::File::open(fixture_root()).expect("open directory descriptor");
    let mut selected = policy("A", &[], &["execveat", "write", "exit"]);
    selected
        .selected_handles
        .insert(9, directory.as_raw_fd() as u32);

    match run(&selected).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error.to_string().contains("directory descriptor"));
        }
        other => panic!("unexpected directory-source result: {other}"),
    }
}

#[test]
fn network_namespace_cannot_reach_host_loopback_listener() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind host loopback listener");
    let address = listener.local_addr().expect("read host listener address");

    // Prove the host-side endpoint is genuinely reachable before using it
    // as the cross-namespace isolation oracle.
    let host_client =
        TcpStream::connect(address).expect("host loopback listener must be reachable");
    let (host_peer, _) = listener.accept().expect("accept host reachability probe");
    drop(host_peer);
    drop(host_client);

    let port = address.port().to_string();
    let mut isolated = policy(
        "K",
        &[port.as_str()],
        &["execveat", "socket", "connect", "close", "exit"],
    );
    isolated.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn ipc_namespace_cannot_observe_host_sysv_message_queue() {
    let base_key = 0x534c_0000_i32.wrapping_add(((process::id() & 0x0fff) as i32) << 4);
    let mut created = None;
    for offset in 0..16_i32 {
        let key = base_key.wrapping_add(offset) as libc::key_t;
        let queue_id = unsafe { libc::msgget(key, libc::IPC_CREAT | libc::IPC_EXCL | 0o600) };
        if queue_id >= 0 {
            created = Some((key, queue_id));
            break;
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(
            error.raw_os_error(),
            Some(libc::EEXIST),
            "host msgget failed before finding a free key: {error}"
        );
    }

    let (key, queue_id) = created.expect("create host SysV message queue");
    let host_lookup = unsafe { libc::msgget(key, 0) };
    assert_eq!(
        host_lookup, queue_id,
        "host must observe the queue before it is used as an IPC namespace oracle"
    );

    let key_text = (key as i64).to_string();
    let result = run(&policy(
        "L",
        &[key_text.as_str()],
        &["execveat", "msgget", "exit"],
    ));

    let removed = unsafe { libc::msgctl(queue_id, libc::IPC_RMID, std::ptr::null_mut()) };
    assert_eq!(removed, 0, "remove host SysV message queue");
    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn uts_namespace_uses_policy_hostname_without_changing_host() {
    let host_before = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read host hostname before sandbox");
    let sandbox_hostname = format!("security-lab-{}", process::id());
    let mut identity = policy(
        "J",
        &[sandbox_hostname.as_str()],
        &["execveat", "uname", "exit"],
    );
    identity.hostname = sandbox_hostname;

    let result = run(&identity);
    let host_after = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .expect("read host hostname after sandbox");
    assert_eq!(
        host_after, host_before,
        "sandbox UTS hostname changed host hostname"
    );
    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn seccomp_argument_filter_checks_full_64_bit_masked_value() {
    let mut filtered = policy("B", &[], &["execveat", "openat", "lseek", "close", "exit"]);
    let mut lseek_rules = BTreeMap::new();
    lseek_rules.insert(
        1,
        SeccompArgRule {
            mask: 0xffff_ffff_0000_000f,
            value: 0x0000_0001_0000_0008,
        },
    );
    filtered
        .seccomp
        .argument_rules
        .insert("lseek".to_owned(), lseek_rules);

    assert_eq!(run(&filtered).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn allowed_operation_succeeds() {
    assert_eq!(
        run(&policy("A", &[], &["execveat", "write", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn root_is_readonly_and_declared_scratch_is_writable() {
    let forbidden_host = fixture_root().join("root-write-must-fail");
    let scratch_host = fixture_root().join("scratch/allowed");
    let _ = std::fs::remove_file(&forbidden_host);
    let _ = std::fs::remove_file(&scratch_host);

    assert_eq!(
        run(&policy(
            "M",
            &[],
            &["execveat", "openat", "write", "close", "exit"]
        ))
        .unwrap(),
        ChildOutcome::Exited(0)
    );

    assert!(
        !forbidden_host.exists(),
        "read-only root write leaked into the host root"
    );
    assert!(
        !scratch_host.exists(),
        "scratch tmpfs write escaped its private mount namespace"
    );
}

#[test]
fn owned_stdout_redirect_is_usable_and_private() {
    let host_redirect = fixture_root().join("scratch/stdout.log");
    let _ = std::fs::remove_file(&host_redirect);

    let mut redirected = policy(
        "U",
        &[],
        &["execveat", "write", "openat", "read", "close", "exit"],
    );
    redirected.stdio.stdout = StdioMode::Redirect;
    redirected.stdout_redirect = Some(PathBuf::from("/scratch/stdout.log"));

    assert_eq!(run(&redirected).unwrap(), ChildOutcome::Exited(0));
    assert!(
        !host_redirect.exists(),
        "owned stdout redirection leaked into the host scratch directory"
    );
}

#[test]
fn owned_stdout_capture_returns_exact_bytes() {
    let mut captured = policy("A", &[], &["execveat", "write", "exit"]);
    captured.stdio.stdout = StdioMode::Capture;
    captured.stdout_capture_bytes = Some(4096);

    let report = run_report(&captured).unwrap();
    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    let stdout = report.stdout.expect("capture result must be present");
    assert_eq!(stdout.bytes, b"allowed operation succeeded\n");
    assert!(!stdout.truncated);
}

#[test]
fn bounded_stdout_capture_drains_excess_without_deadlock() {
    let mut captured = policy("V", &[], &["execveat", "write", "exit"]);
    captured.stdio.stdout = StdioMode::Capture;
    captured.stdout_capture_bytes = Some(1024);

    let report = run_report(&captured).unwrap();
    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    let stdout = report.stdout.expect("capture result must be present");
    assert_eq!(stdout.bytes.len(), 1024);
    assert!(stdout.bytes.iter().all(|byte| *byte == b'C'));
    assert!(stdout.truncated);
}

#[test]
fn direct_target_is_pid2_under_launcher_owned_namespace_init() {
    let report = run_report(&policy(
        "Y",
        &[],
        &["execveat", "getpid", "getppid", "exit"],
    ))
    .unwrap();

    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    assert_eq!(report.reaped_descendants, 0);
}

#[test]
fn namespace_init_kills_reaps_live_descendant_and_releases_capture() {
    let mut tree = policy("Z", &[], &["execveat", "fork", "pause", "exit"]);
    tree.stdio.stdout = StdioMode::Capture;
    tree.stdout_capture_bytes = Some(1024);

    let report = run_report(&tree).unwrap();
    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    assert_eq!(report.reaped_descendants, 1);
    let stdout = report.stdout.expect("capture result must be present");
    assert!(stdout.bytes.is_empty());
    assert!(!stdout.truncated);
}

#[test]
fn wall_clock_deadline_terminates_process_tree_and_releases_capture() {
    let mut deadline = policy(
        "Q",
        &[],
        &["execveat", "write", "fork", "nanosleep", "pause", "exit"],
    );
    deadline.wall_clock_milliseconds = Some(1000);
    deadline.stdio.stdout = StdioMode::Capture;
    deadline.stdout_capture_bytes = Some(4096);

    let report = run_report(&deadline).unwrap();
    assert_eq!(report.outcome, ChildOutcome::TimedOut);
    assert_eq!(report.reaped_descendants, 1);
    let stdout = report.stdout.expect("capture result must be present");
    assert_eq!(stdout.bytes, b"deadline target started\n");
    assert!(!stdout.truncated);
}

#[test]
fn natural_target_exit_wins_before_wall_clock_deadline() {
    let mut natural = policy("X", &[], &["execveat", "exit"]);
    natural.wall_clock_milliseconds = Some(5000);
    assert_eq!(run(&natural).unwrap(), ChildOutcome::Exited(42));
}

#[test]
fn forbidden_syscall_is_denied_with_eperm() {
    assert_eq!(
        run(&policy("F", &[], &["execveat", "exit"])).unwrap(),
        ChildOutcome::Exited(77)
    );
}

#[test]
fn malformed_policy_is_rejected() {
    let malformed = r#"
        filesystem.root = /
        identity.hostname = malformed-policy
        executable = /bin/true
        working_dir = /tmp
        stdio.stdin = closed
        stdio.stdout = inherit
        stdio.stderr = inherit
        limit.cpu_seconds = 1
        limit.address_space_bytes = 100000000
        limit.file_size_bytes = 1000000
        limit.open_files = 16
        seccomp.allow = execveat,exit
        silently_disable_seccomp = true
    "#;
    assert!(malformed.parse::<SandboxPolicy>().is_err());
}

#[test]
fn unknown_syscall_is_rejected_before_execution() {
    let invalid = policy("A", &[], &["execveat", "not_a_real_syscall"]);
    assert!(matches!(run(&invalid), Err(SandboxError::InvalidPolicy(_))));
}

#[test]
fn launch_requires_policy_authorized_termination_syscall() {
    let invalid = policy("A", &[], &["execveat"]);
    let error = run(&invalid).unwrap_err();
    assert!(matches!(error, SandboxError::InvalidPolicy(_)));
    assert!(error.to_string().contains("exit or exit_group"));
}

#[test]
fn setup_failure_never_falls_back_to_execution() {
    let mut failing = policy("X", &[], &["execveat", "exit"]);
    failing.working_dir = PathBuf::from("/definitely/missing");

    let error = run(&failing).unwrap_err();
    assert!(matches!(error, SandboxError::SetupFailed(_)));
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
    let result = run(&policy("D", &[&descriptor], &["execveat", "fcntl", "exit"]));
    unsafe {
        libc::close(inherited);
    }

    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn explicitly_closed_stdio_is_unusable_after_exec() {
    let mut closed = policy("O", &[], &["execveat", "fcntl", "exit"]);
    closed.stdio = StdioPolicy {
        stdin: StdioMode::Closed,
        stdout: StdioMode::Closed,
        stderr: StdioMode::Closed,
    };

    assert_eq!(run(&closed).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn selective_stdout_inheritance_matches_policy() {
    let mut selective = policy("T", &[], &["execveat", "fcntl", "write", "exit"]);
    selective.stdio = StdioPolicy {
        stdin: StdioMode::Closed,
        stdout: StdioMode::Inherit,
        stderr: StdioMode::Closed,
    };

    assert_eq!(run(&selective).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn exec_failure_is_reported_without_target_write_permission() {
    let name = format!("missing-interpreter-{}-{}", process::id(), unique_suffix());
    let host_path = fixture_root().join(&name);
    std::fs::write(
        &host_path,
        b"#!/definitely/missing/security-lab-interpreter\n",
    )
    .expect("write executable fixture");
    let mut permissions = std::fs::metadata(&host_path).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&host_path, permissions).unwrap();

    let mut failing = policy("A", &[], &["execveat", "exit"]);
    failing.executable = PathBuf::from(format!("/{name}"));
    let result = run(&failing);
    let _ = std::fs::remove_file(&host_path);

    match result {
        Err(SandboxError::SetupFailed(message)) => {
            assert!(
                message.contains("execveat"),
                "unexpected launch error: {message}"
            );
        }
        other => panic!("expected precise execveat setup failure, got {other:?}"),
    }
}

#[test]
fn executable_symlink_escape_is_rejected_before_execution() {
    let name = format!("escape-{}-{}", process::id(), unique_suffix());
    let host_link = fixture_root().join(&name);
    symlink("/bin/true", &host_link).expect("create escape symlink");

    let mut escaping = policy("A", &[], &["execveat", "exit"]);
    escaping.executable = PathBuf::from(format!("/{name}"));
    let result = run(&escaping);
    let _ = std::fs::remove_file(&host_link);

    assert!(matches!(result, Err(SandboxError::SetupFailed(_))));
}

#[test]
fn host_path_outside_root_is_not_visible_to_target() {
    let host_secret = std::env::temp_dir().join(format!(
        "security-lab-host-secret-{}-{}",
        process::id(),
        unique_suffix()
    ));
    std::fs::write(&host_secret, b"outside sandbox root").expect("write host-only fixture");
    let host_secret_text = host_secret.to_string_lossy().into_owned();

    let result = run(&policy(
        "H",
        &[&host_secret_text],
        &["execveat", "openat", "exit"],
    ));
    let _ = std::fs::remove_file(&host_secret);

    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn namespace_identity_and_capabilities_are_reduced() {
    assert_eq!(
        run(&policy(
            "I",
            &[],
            &["execveat", "getuid", "getgid", "capget", "prctl", "exit"]
        ))
        .unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn child_exit_code_is_surfaced() {
    assert_eq!(
        run(&policy("X", &[], &["execveat", "exit"])).unwrap(),
        ChildOutcome::Exited(42)
    );
}

#[test]
fn child_signal_is_surfaced() {
    assert_eq!(
        run(&policy(
            "S",
            &[],
            &["execveat", "getpid", "gettid", "tgkill", "exit"]
        ))
        .unwrap(),
        ChildOutcome::Signaled(libc::SIGTERM)
    );
}

#[test]
fn environment_is_cleared_then_explicitly_rebuilt() {
    let mut env_policy = policy("E", &[], &["execveat", "exit"]);
    env_policy
        .environment
        .insert("SANDBOX_ALLOWED".to_owned(), "yes".to_owned());
    assert_eq!(run(&env_policy).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn working_directory_is_controlled_inside_root() {
    assert_eq!(
        run(&policy("C", &["/work"], &["execveat", "getcwd", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn all_configured_resource_limits_are_observable() {
    assert_eq!(
        run(&policy("R", &[], &["execveat", "prlimit64", "exit"])).unwrap(),
        ChildOutcome::Exited(0)
    );
}

#[test]
fn open_file_limit_is_enforced() {
    let mut limited = policy("N", &[], &["execveat", "openat", "exit"]);
    limited.limits.open_files = 16;
    assert_eq!(run(&limited).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn no_new_privs_is_observable_in_child() {
    assert_eq!(
        run(&policy("P", &[], &["execveat", "prctl", "exit"])).unwrap(),
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
