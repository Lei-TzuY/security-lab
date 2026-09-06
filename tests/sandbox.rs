#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{
    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, ResourceLimits,
    SandboxError, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,
};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

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

fn abstract_unix_address(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    assert!(
        !name.is_empty(),
        "abstract UNIX socket name must not be empty"
    );
    assert!(
        name.len() < 108,
        "abstract UNIX socket name exceeds sockaddr_un.sun_path"
    );
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in name.iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
    (address, length)
}

fn abstract_unix_stream_listener(name: &[u8]) -> TestFd {
    let listener = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    assert!(
        listener >= 0,
        "create abstract UNIX listener failed: {}",
        std::io::Error::last_os_error()
    );
    let listener = TestFd(listener);
    let (address, length) = abstract_unix_address(name);
    let bound = unsafe {
        libc::bind(
            listener.raw(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            length,
        )
    };
    assert_eq!(
        bound,
        0,
        "bind abstract UNIX listener failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        unsafe { libc::listen(listener.raw(), 4) },
        0,
        "listen on abstract UNIX socket failed: {}",
        std::io::Error::last_os_error()
    );
    listener
}

fn unix_stream_client() -> TestFd {
    let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        client >= 0,
        "create abstract UNIX client failed: {}",
        std::io::Error::last_os_error()
    );
    TestFd(client)
}

fn write_all_fd(fd: RawFd, buffer: &[u8]) {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let written = unsafe {
            libc::write(
                fd,
                buffer[offset..].as_ptr().cast::<libc::c_void>(),
                buffer.len() - offset,
            )
        };
        if written == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("fd write failed: {error}");
        }
        assert!(written > 0, "fd write made no progress");
        offset += written as usize;
    }
}

fn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let read = unsafe {
            libc::read(
                fd,
                buffer[offset..].as_mut_ptr().cast::<libc::c_void>(),
                buffer.len() - offset,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("ready-handshake read failed: {error}");
        }
        assert!(read > 0, "ready-handshake pipe reached EOF early");
        offset += read as usize;
    }
}

fn try_read_exact_fd(fd: RawFd, buffer: &mut [u8]) -> std::io::Result<bool> {
    let mut offset = 0usize;
    while offset < buffer.len() {
        let read = unsafe {
            libc::read(
                fd,
                buffer[offset..].as_mut_ptr().cast::<libc::c_void>(),
                buffer.len() - offset,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(error);
        }
        if read == 0 {
            return Ok(false);
        }
        offset += read as usize;
    }
    Ok(true)
}

fn fixture_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::temp_dir().join(format!("security-lab-root-{}", process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("work")).expect("create sandbox work directory");
        std::fs::create_dir_all(root.join("scratch")).expect("create sandbox scratch mountpoint");
        std::fs::create_dir_all(root.join("data")).expect("create sandbox volume mountpoint");
        std::fs::create_dir_all(root.join("persist"))
            .expect("create sandbox writable-volume mountpoint");
        std::fs::create_dir_all(root.join("devices"))
            .expect("create sandbox device-volume mountpoint");
        std::fs::create_dir_all(root.join("landlock-allowed"))
            .expect("create Landlock allowed directory");
        std::fs::create_dir_all(root.join("landlock-denied"))
            .expect("create Landlock denied directory");
        std::fs::write(root.join("landlock-allowed/marker"), b"landlock-allowed\n")
            .expect("write Landlock allowed marker");
        std::fs::write(root.join("landlock-denied/secret"), b"landlock-secret\n")
            .expect("write Landlock denied secret");

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

fn readonly_volume_source() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source =
                std::env::temp_dir().join(format!("security-lab-volume-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(&source).expect("create persistent volume source");
            std::fs::write(source.join("marker"), b"volume-marker\n")
                .expect("write persistent volume marker");
            source
        })
        .as_path()
}

fn writable_volume_source() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source = std::env::temp_dir()
                .join(format!("security-lab-writable-volume-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(&source).expect("create writable persistent volume source");
            source
        })
        .as_path()
}

fn landlock_topology_source() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source = std::env::temp_dir()
                .join(format!("security-lab-landlock-topology-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(source.join("allowed/from"))
                .expect("create Landlock topology source directory");
            std::fs::create_dir_all(source.join("allowed/to"))
                .expect("create Landlock topology destination directory");
            std::fs::create_dir_all(source.join("denied"))
                .expect("create Landlock topology denied directory");
            std::fs::write(
                source.join("allowed/from/item"),
                b"landlock-topology-item\n",
            )
            .expect("seed Landlock topology rename fixture");
            source
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
        landlock_read_execute: Vec::new(),
        landlock_file_mutate: Vec::new(),
        landlock_path_topology_mutate: Vec::new(),
        landlock_device_ioctl: Vec::new(),
        landlock_tcp_bind_ports: Vec::new(),
        landlock_tcp_connect_ports: Vec::new(),
        landlock_scope_abstract_unix_socket: false,
        landlock_scope_signal: false,
        loopback_enabled: false,
        host_loopback_tcp_port: None,
        host_loopback_tcp_target_fd: None,
        host_ipv4_tcp_address: None,
        host_ipv4_tcp_port: None,
        host_ipv4_tcp_target_fd: None,
        host_ipv4_udp_address: None,
        host_ipv4_udp_port: None,
        host_ipv4_udp_target_fd: None,
        host_unix_stream_path: None,
        host_unix_stream_target_fd: None,
        host_unix_stream_peer_uid: None,
        host_unix_stream_peer_gid: None,
        host_loopback_tcp_listen_port: None,
        host_loopback_tcp_listen_target_fd: None,
        readonly_volume_source: None,
        readonly_volume_target: None,
        writable_volume_source: None,
        writable_volume_target: None,
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

fn assert_random_device_ioctl_available(path: &str) {
    const RNDGETENTCNT: libc::c_ulong = 0x80045200;
    let device = std::fs::File::open(path).expect("open host random device");
    let mut entropy_bits: libc::c_int = 0;
    assert_eq!(
        unsafe { libc::ioctl(device.as_raw_fd(), RNDGETENTCNT, &mut entropy_bits) },
        0,
        "host random-device ioctl baseline failed for {path}: {}",
        std::io::Error::last_os_error()
    );
}

#[test]
fn brokered_host_unix_stream_is_usable_while_host_path_stays_hidden() {
    let socket_path =
        std::env::temp_dir().join(format!("security-lab-host-unix-{}.sock", process::id()));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind host UNIX stream endpoint");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept brokered UNIX connection");
        let expected = b"brokered-host-unix-ok";
        let mut request = vec![0u8; expected.len()];
        read_exact_fd(stream.as_raw_fd(), &mut request);
        assert_eq!(&request, expected);
        write_all_fd(stream.as_raw_fd(), b"host-unix-reply");
    });

    let socket_argument = socket_path.to_string_lossy().into_owned();
    let mut brokered = policy(
        "b",
        &[socket_argument.as_str()],
        &[
            "execveat", "read", "write", "close", "socket", "connect", "exit",
        ],
    );
    brokered.host_unix_stream_path = Some(socket_path.clone());
    brokered.host_unix_stream_target_fd = Some(10);
    brokered.host_unix_stream_peer_uid = Some(unsafe { libc::geteuid() });
    brokered.host_unix_stream_peer_gid = Some(unsafe { libc::getegid() });
    brokered.wall_clock_milliseconds = Some(2000);

    let result = run(&brokered);
    server.join().expect("host UNIX server thread failed");
    let _ = std::fs::remove_file(&socket_path);
    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn brokered_host_unix_stream_rejects_wrong_peer_credentials_before_target_exec() {
    let socket_path = std::env::temp_dir().join(format!(
        "security-lab-host-unix-peer-mismatch-{}.sock",
        process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind peer-credential test endpoint");

    let actual_uid = unsafe { libc::geteuid() };
    let actual_gid = unsafe { libc::getegid() };
    let wrong_uid = actual_uid.wrapping_add(1);
    assert_ne!(wrong_uid, actual_uid);

    let mut brokered = policy("A", &[], &["execveat", "write", "exit"]);
    brokered.host_unix_stream_path = Some(socket_path.clone());
    brokered.host_unix_stream_target_fd = Some(10);
    brokered.host_unix_stream_peer_uid = Some(wrong_uid);
    brokered.host_unix_stream_peer_gid = Some(actual_gid);

    let result = run(&brokered);
    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
    match result.unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains("peer credentials mismatch"));
        }
        other => panic!("unexpected peer-credential mismatch result: {other}"),
    }
}

#[test]
fn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {
    const PORT_ACQUIRE_ATTEMPTS: usize = 32;
    let mut endpoints = None;
    for _ in 0..PORT_ACQUIRE_ATTEMPTS {
        let other = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 0))
            .expect("bind first address-aware UDP broker endpoint");
        let port = other
            .local_addr()
            .expect("read first UDP broker endpoint")
            .port();
        match UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), port)) {
            Ok(selected) => {
                endpoints = Some((other, selected, port));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind selected UDP broker endpoint failed: {error}"),
        }
    }
    let (other, selected, port) = endpoints.expect("acquire shared UDP port across 127/8");
    selected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set selected UDP receive timeout");

    let port_text = port.to_string();
    let mut brokered = policy(
        "e",
        &[port_text.as_str()],
        &["execveat", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_ipv4_udp_address = Some(Ipv4Addr::new(127, 0, 0, 2));
    brokered.host_ipv4_udp_port = Some(port);
    brokered.host_ipv4_udp_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));

    let mut datagram = [0u8; 64];
    let (received, _) = selected
        .recv_from(&mut datagram)
        .expect("selected UDP endpoint did not receive brokered datagram");
    assert_eq!(&datagram[..received], b"brokered-host-udp-ok");

    selected
        .set_nonblocking(true)
        .expect("make selected UDP endpoint nonblocking");
    match selected.recv_from(&mut datagram) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((received, peer)) => panic!(
            "isolated target unexpectedly delivered a second UDP datagram from {peer}: {:?}",
            &datagram[..received]
        ),
        Err(error) => panic!("unexpected selected UDP receive error: {error}"),
    }

    other
        .set_nonblocking(true)
        .expect("make non-selected UDP endpoint nonblocking");
    match other.recv_from(&mut datagram) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((received, peer)) => panic!(
            "UDP broker selected the wrong same-port address; received from {peer}: {:?}",
            &datagram[..received]
        ),
        Err(error) => panic!("unexpected non-selected UDP receive error: {error}"),
    }
}

#[test]
fn landlock_device_ioctl_envelope_binds_rights_at_post_restriction_open() {
    assert_random_device_ioctl_available("/dev/urandom");
    assert_random_device_ioctl_available("/dev/random");

    let mut confined = policy("d", &[], &["execveat", "openat", "ioctl", "close", "exit"]);
    confined.readonly_volume_source = Some(PathBuf::from("/dev"));
    confined.readonly_volume_target = Some(PathBuf::from("/devices"));
    confined.landlock_device_ioctl = vec![PathBuf::from("/devices/urandom")];

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {
    let name = format!("security-lab-landlock-abstract-{}", process::id());
    let listener = abstract_unix_stream_listener(name.as_bytes());

    let unscoped_client = unix_stream_client();
    let mut unscoped = policy("a", &[name.as_str()], &["execveat", "connect", "exit"]);
    unscoped
        .selected_handles
        .insert(9, unscoped_client.raw() as u32);
    assert_eq!(run(&unscoped).unwrap(), ChildOutcome::Exited(0));

    let accepted = unsafe {
        libc::accept4(
            listener.raw(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert!(
        accepted >= 0,
        "unscoped target did not reach host-domain abstract listener: {}",
        std::io::Error::last_os_error()
    );
    drop(TestFd(accepted));
    drop(unscoped_client);

    let scoped_client = unix_stream_client();
    let mut scoped = policy("a", &[name.as_str()], &["execveat", "connect", "exit"]);
    scoped
        .selected_handles
        .insert(9, scoped_client.raw() as u32);
    scoped.landlock_scope_abstract_unix_socket = true;
    assert_eq!(
        run(&scoped).unwrap(),
        ChildOutcome::Exited(libc::EPERM),
        "Landlock abstract UNIX scope must deny connect with exact EPERM"
    );

    let unexpected = unsafe {
        libc::accept4(
            listener.raw(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert_eq!(
        unexpected, -1,
        "scoped target unexpectedly queued a connection"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN),
        "scoped target changed listener state without an accepted connection"
    );
}

#[test]
fn landlock_signal_scope_attenuates_namespace_init_signal_permission() {
    let unscoped = policy(
        "t",
        &[],
        &["execveat", "pidfd_open", "pidfd_send_signal", "exit"],
    );
    assert_eq!(run(&unscoped).unwrap(), ChildOutcome::Exited(0));

    let mut scoped = policy(
        "u",
        &[],
        &["execveat", "pidfd_open", "pidfd_send_signal", "exit"],
    );
    scoped.landlock_scope_signal = true;
    assert_eq!(run(&scoped).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn landlock_read_execute_envelope_denies_visible_undeclared_path() {
    let mut confined = policy("r", &[], &["execveat", "openat", "read", "close", "exit"]);
    confined.landlock_read_execute =
        vec![PathBuf::from("/probe"), PathBuf::from("/landlock-allowed")];

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn landlock_file_mutation_envelope_narrows_existing_writable_surfaces() {
    let source = writable_volume_source().to_path_buf();
    let allowed = source.join("allowed");
    let denied = source.join("denied");
    std::fs::create_dir_all(&allowed).expect("create Landlock mutation allowed directory");
    std::fs::create_dir_all(&denied).expect("create Landlock mutation denied directory");
    std::fs::write(allowed.join("existing"), b"stale\n")
        .expect("seed Landlock mutation truncate fixture");
    std::fs::write(allowed.join("remove-me"), b"remove-me\n")
        .expect("seed Landlock mutation remove fixture");
    std::fs::write(denied.join("blocked"), b"blocked\n")
        .expect("seed Landlock mutation denied remove fixture");
    let denied_created = denied.join("created");
    let _ = std::fs::remove_file(&denied_created);

    let mut confined = policy(
        "m",
        &[],
        &[
            "execveat", "openat", "truncate", "write", "close", "unlink", "exit",
        ],
    );
    confined.landlock_read_execute = vec![PathBuf::from("/probe")];
    confined.landlock_file_mutate =
        vec![PathBuf::from("/scratch"), PathBuf::from("/persist/allowed")];
    confined.writable_volume_source = Some(source.clone());
    confined.writable_volume_target = Some(PathBuf::from("/persist"));

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(allowed.join("existing")).expect("read Landlock-mutated host file"),
        b"landlock-persistent-write\n",
    );
    assert!(
        !allowed.join("remove-me").exists(),
        "declared mutation envelope did not allow REMOVE_FILE"
    );
    assert_eq!(
        std::fs::read(denied.join("blocked")).expect("read denied mutation sentinel"),
        b"blocked\n",
    );
    assert!(
        !denied_created.exists(),
        "Landlock mutation escaped its declared persistent subtree"
    );
}

#[test]
fn landlock_path_topology_mutation_is_scoped_to_declared_directory() {
    let source = landlock_topology_source().to_path_buf();
    let allowed = source.join("allowed");
    let denied = source.join("denied");

    let mut confined = policy(
        "h",
        &[],
        &["execveat", "mkdir", "rmdir", "symlink", "rename", "exit"],
    );
    confined.landlock_read_execute = vec![PathBuf::from("/probe")];
    confined.landlock_file_mutate = vec![PathBuf::from("/persist/allowed")];
    confined.landlock_path_topology_mutate = vec![PathBuf::from("/persist/allowed")];
    confined.writable_volume_source = Some(source.clone());
    confined.writable_volume_target = Some(PathBuf::from("/persist"));

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(allowed.join("to/item")).expect("read renamed topology fixture"),
        b"landlock-topology-item\n",
    );
    assert!(!allowed.join("from/item").exists());
    assert_eq!(
        std::fs::read_link(allowed.join("newlink")).expect("read allowed topology symlink"),
        PathBuf::from("topology-target"),
    );
    assert!(!allowed.join("newdir").exists());
    for denied_path in ["newdir", "newlink", "item"] {
        assert!(
            !denied.join(denied_path).exists(),
            "Landlock topology mutation escaped to denied path {denied_path}"
        );
    }
}

#[test]
fn landlock_file_mutation_requires_existing_writable_surface() {
    let mut confined = policy("X", &[], &["execveat", "exit"]);
    confined.landlock_file_mutate = vec![PathBuf::from("/work")];
    match run(&confined).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error.to_string().contains(
                "landlock.file_mutate must be within filesystem.scratch or volume.writable_target"
            ));
        }
        other => panic!("unexpected Landlock mutation policy result: {other}"),
    }
}

#[test]
fn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {
    let source = readonly_volume_source().to_path_buf();
    let forbidden_write = source.join("write-must-fail");
    let _ = std::fs::remove_file(&forbidden_write);
    let marker_before = std::fs::read(source.join("marker")).expect("read host volume marker");
    let source_argument = source.to_string_lossy().into_owned();

    let mut mounted = policy(
        "v",
        &[source_argument.as_str()],
        &["execveat", "openat", "read", "close", "exit"],
    );
    mounted.readonly_volume_source = Some(source.clone());
    mounted.readonly_volume_target = Some(PathBuf::from("/data"));

    assert_eq!(run(&mounted).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(source.join("marker")).expect("read host volume marker after run"),
        marker_before,
        "sandbox changed persistent volume marker"
    );
    assert!(
        !forbidden_write.exists(),
        "sandbox write escaped the read-only persistent volume"
    );
}

#[test]
fn writable_persistent_volume_mutates_only_declared_host_tree() {
    let source = writable_volume_source().to_path_buf();
    let persisted = source.join("persisted");
    let _ = std::fs::remove_file(&persisted);
    let root_forbidden = fixture_root().join("root-write-must-fail");
    let _ = std::fs::remove_file(&root_forbidden);
    let source_argument = source.to_string_lossy().into_owned();

    let mut mounted = policy(
        "w",
        &[source_argument.as_str()],
        &["execveat", "openat", "write", "close", "exit"],
    );
    mounted.writable_volume_source = Some(source.clone());
    mounted.writable_volume_target = Some(PathBuf::from("/persist"));

    assert_eq!(run(&mounted).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(&persisted).expect("read persisted host volume output"),
        b"persistent-write\n",
    );
    assert!(
        !root_forbidden.exists(),
        "writable volume reopened mutation outside its declared target"
    );
}

#[test]
fn persistent_volume_source_cannot_overlap_sandbox_root() {
    let mut writable = policy("X", &[], &["execveat", "exit"]);
    writable.writable_volume_source = Some(fixture_root().join("persist"));
    writable.writable_volume_target = Some(PathBuf::from("/persist"));
    match run(&writable).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error
                .to_string()
                .contains("must not overlap filesystem.root"));
        }
        other => panic!("unexpected writable root-overlap result: {other}"),
    }

    let mut readonly = policy("X", &[], &["execveat", "exit"]);
    readonly.readonly_volume_source = Some(
        fixture_root()
            .parent()
            .expect("fixture root has a parent")
            .to_path_buf(),
    );
    readonly.readonly_volume_target = Some(PathBuf::from("/data"));
    match run(&readonly).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error
                .to_string()
                .contains("must not overlap filesystem.root"));
        }
        other => panic!("unexpected read-only root-overlap result: {other}"),
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
fn external_cancellation_owns_process_tree_after_ready_handshake() {
    let mut pipe = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0,
        "create cancellation readiness pipe"
    );
    let read_end = TestFd(pipe[0]);
    let write_end = TestFd(pipe[1]);
    let cancellation = CancellationToken::new().expect("create cancellation token");
    let runner_token = cancellation.clone();

    let runner = thread::spawn(move || {
        let mut cancellable = policy("c", &[], &["execveat", "write", "fork", "pause", "exit"]);
        cancellable
            .selected_handles
            .insert(9, write_end.raw() as u32);
        // A watchdog makes a broken cancellation path fail as TimedOut rather
        // than hanging CI; the ready handshake ensures cancellation itself is
        // never timing-based.
        cancellable.wall_clock_milliseconds = Some(5000);
        run_report_with_cancel(&cancellable, &runner_token)
    });

    let mut marker = [0u8; 26];
    read_exact_fd(read_end.raw(), &mut marker);
    assert_eq!(
        &marker,
        b"cancellation-target-ready
"
    );
    cancellation.cancel().expect("signal cancellation");

    let report = runner
        .join()
        .expect("cancellable sandbox thread panicked")
        .expect("cancellable sandbox run failed");
    assert_eq!(report.outcome, ChildOutcome::Cancelled);
    assert_eq!(report.reaped_descendants, 1);
}

#[test]
fn uncancelled_token_preserves_natural_completion() {
    let cancellation = CancellationToken::new().expect("create cancellation token");
    let report = run_report_with_cancel(&policy("X", &[], &["execveat", "exit"]), &cancellation)
        .expect("uncancelled run failed");
    assert_eq!(report.outcome, ChildOutcome::Exited(42));
    assert_eq!(report.reaped_descendants, 0);
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
    isolated.loopback_enabled = true;
    isolated.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&isolated).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn brokered_host_loopback_tcp_exposes_one_endpoint_without_rejoining_host_network() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind brokered host listener");
    let address = listener
        .local_addr()
        .expect("read brokered host listener address");
    let port = address.port().to_string();

    let mut brokered = policy(
        "p",
        &[port.as_str()],
        &["execveat", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_loopback_tcp_port = Some(address.port());
    brokered.host_loopback_tcp_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));
    let (peer, _) = listener
        .accept()
        .expect("accept brokered target connection");
    let mut marker = [0u8; 25];
    read_exact_fd(peer.as_raw_fd(), &mut marker);
    assert_eq!(&marker, b"brokered-host-loopback-ok");
}

#[test]
fn brokered_host_ipv4_tcp_selects_exact_address_on_shared_port() {
    const PORT_ACQUIRE_ATTEMPTS: usize = 32;
    let mut listeners = None;
    for _ in 0..PORT_ACQUIRE_ATTEMPTS {
        let other =
            TcpListener::bind(("127.0.0.1", 0)).expect("bind first address-aware broker listener");
        let port = other
            .local_addr()
            .expect("read address-aware broker port")
            .port();
        match TcpListener::bind(("127.0.0.2", port)) {
            Ok(selected) => {
                listeners = Some((other, selected, port));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind selected address-aware broker listener: {error}"),
        }
    }
    let (other, selected, port) =
        listeners.expect("acquire one port on two host loopback addresses");
    other
        .set_nonblocking(true)
        .expect("set other address listener nonblocking");
    selected
        .set_nonblocking(true)
        .expect("set selected address listener nonblocking");

    let port_text = port.to_string();
    let mut brokered = policy(
        "p",
        &[port_text.as_str()],
        &["execveat", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_ipv4_tcp_address = Some(Ipv4Addr::new(127, 0, 0, 2));
    brokered.host_ipv4_tcp_port = Some(port);
    brokered.host_ipv4_tcp_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));

    let (peer, _) = selected
        .accept()
        .expect("selected host IPv4 listener must receive brokered connection");
    let mut marker = [0u8; 25];
    read_exact_fd(peer.as_raw_fd(), &mut marker);
    assert_eq!(&marker, b"brokered-host-loopback-ok");

    match other.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected other-address accept error: {error}"),
        Ok(_) => panic!("brokered connection reached the wrong host IPv4 address"),
    }
}

#[test]
fn brokered_host_loopback_tcp_listener_accepts_one_host_ingress_capability() {
    const PORT_ACQUIRE_ATTEMPTS: usize = 16;
    let mut last_bind_contention = None;

    for attempt in 0..PORT_ACQUIRE_ATTEMPTS {
        let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve ingress host port");
        let port = reservation
            .local_addr()
            .expect("read reserved ingress port")
            .port();
        drop(reservation);

        let mut pipe = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create ingress readiness pipe"
        );
        let read_end = TestFd(pipe[0]);
        let write_end = TestFd(pipe[1]);

        let runner = thread::spawn(move || {
            let mut ingress = policy(
                "q",
                &[],
                &["execveat", "write", "accept", "read", "close", "exit"],
            );
            ingress.selected_handles.insert(9, write_end.raw() as u32);
            ingress.host_loopback_tcp_listen_port = Some(port);
            ingress.host_loopback_tcp_listen_target_fd = Some(10);
            ingress.wall_clock_milliseconds = Some(5000);
            run(&ingress)
        });

        let mut ready = [0u8; 28];
        match try_read_exact_fd(read_end.raw(), &mut ready) {
            Ok(true) => {}
            Ok(false) => {
                let result = runner.join().expect("ingress sandbox thread panicked");
                match result {
                    Err(SandboxError::SetupFailed(message))
                        if message.contains("cannot bind brokered host-loopback TCP listener") =>
                    {
                        last_bind_contention = Some(message);
                        if attempt + 1 < PORT_ACQUIRE_ATTEMPTS {
                            continue;
                        }
                    }
                    other => panic!(
                        "ingress target closed readiness before marker with unexpected result: {other:?}"
                    ),
                }
                break;
            }
            Err(error) => panic!("ingress readiness read failed: {error}"),
        }
        assert_eq!(&ready, b"brokered-host-ingress-ready\n");

        let client = TcpStream::connect(("127.0.0.1", port))
            .expect("connect to launcher-brokered host-loopback listener");
        write_all_fd(client.as_raw_fd(), b"brokered-host-ingress-request");
        let mut reply = [0u8; 24];
        read_exact_fd(client.as_raw_fd(), &mut reply);
        assert_eq!(&reply, b"brokered-host-ingress-ok");
        drop(client);

        assert_eq!(
            runner
                .join()
                .expect("ingress sandbox thread panicked")
                .expect("ingress sandbox run failed"),
            ChildOutcome::Exited(0)
        );
        return;
    }

    panic!(
        "could not reacquire an ingress host port after {PORT_ACQUIRE_ATTEMPTS} attempts; last bind contention: {}",
        last_bind_contention.as_deref().unwrap_or("none recorded")
    );
}

#[test]
fn brokered_host_loopback_tcp_listener_bind_failure_is_fail_closed() {
    let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied ingress port");
    let port = occupied
        .local_addr()
        .expect("read occupied ingress port")
        .port();
    let mut ingress = policy("X", &[], &["execveat", "exit"]);
    ingress.host_loopback_tcp_listen_port = Some(port);
    ingress.host_loopback_tcp_listen_target_fd = Some(10);

    match run(&ingress).unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains("cannot bind brokered host-loopback TCP listener"));
        }
        other => panic!("unexpected occupied-ingress result: {other}"),
    }
}

#[test]
fn loopback_is_down_unless_policy_enables_it() {
    let disabled = policy("o", &[], &["execveat", "socket", "ioctl", "close", "exit"]);
    assert_eq!(run(&disabled).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn enabled_loopback_supports_intra_sandbox_tcp() {
    let mut local = policy(
        "n",
        &[],
        &[
            "execveat", "socket", "bind", "listen", "fork", "connect", "accept", "read", "write",
            "close", "exit",
        ],
    );
    local.loopback_enabled = true;
    local.wall_clock_milliseconds = Some(2000);
    assert_eq!(run(&local).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn landlock_tcp_port_envelope_allows_declared_loopback_endpoint_and_denies_other_ports() {
    let mut confined = policy(
        "s",
        &[],
        &[
            "execveat", "socket", "bind", "listen", "fork", "connect", "accept", "read", "write",
            "close", "exit",
        ],
    );
    confined.loopback_enabled = true;
    confined.landlock_tcp_bind_ports = vec![42421];
    confined.landlock_tcp_connect_ports = vec![42421];
    confined.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
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
fn process_tree_resource_usage_reports_kernel_accounting() {
    let report = run_report(&policy("x", &[], &["execveat", "mmap", "exit"])).unwrap();

    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    assert_eq!(report.reaped_descendants, 0);
    assert!(
        report.process_tree_usage.max_child_rss_kib >= 4096,
        "8 MiB touched mapping should produce at least 4 MiB max-child RSS, got {} KiB",
        report.process_tree_usage.max_child_rss_kib
    );
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
