#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{
    run, ChildOutcome, RuntimeFdBroker, RuntimeFdBrokerError, SandboxPolicy,
    MAX_RUNTIME_SEALED_BUNDLE_BYTES, MAX_RUNTIME_SEALED_BUNDLE_ITEMS,
    MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

static NEXT_PATH: AtomicU64 = AtomicU64::new(1);

fn unique_path(label: &str) -> PathBuf {
    let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("security-lab-{label}-{}-{sequence}", process::id()))
}

struct TestFd(RawFd);

impl Drop for TestFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl TestFd {
    fn raw(&self) -> RawFd {
        self.0
    }
}

#[repr(C, align(8))]
struct OneFdControl([u8; 24]);

fn receive_one_fd(stream: &UnixStream) -> TestFd {
    let mut payload = [0u8; 1];
    let mut iovec = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = OneFdControl([0; 24]);
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control.0.len();

    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert_eq!(
        received,
        1,
        "receive one broker grant failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&payload, b"F");
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    assert!(
        message.msg_controllen
            >= std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>()
    );

    let header = control.0.as_ptr().cast::<libc::cmsghdr>();
    unsafe {
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!(
            (*header).cmsg_len,
            std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>()
        );
        let fd = control
            .0
            .as_ptr()
            .add(std::mem::size_of::<libc::cmsghdr>())
            .cast::<RawFd>()
            .read();
        assert!(fd >= 0);
        TestFd(fd)
    }
}

#[repr(C, align(8))]
struct BundleFdControl([u8; 48]);

fn receive_bundle_fds(stream: &UnixStream, expected_count: usize) -> Vec<TestFd> {
    assert!((2..=MAX_RUNTIME_SEALED_BUNDLE_ITEMS).contains(&expected_count));
    let mut payload = [0u8; 1];
    let mut iovec = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = BundleFdControl([0; 48]);
    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control.0.len();

    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert_eq!(
        received,
        1,
        "receive broker bundle failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&payload, b"B");
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);

    let header = control.0.as_ptr().cast::<libc::cmsghdr>();
    unsafe {
        assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
        assert_eq!(
            (*header).cmsg_len,
            std::mem::size_of::<libc::cmsghdr>() + expected_count * std::mem::size_of::<RawFd>()
        );
        let data = control
            .0
            .as_ptr()
            .add(std::mem::size_of::<libc::cmsghdr>())
            .cast::<RawFd>();
        (0..expected_count)
            .map(|index| {
                let fd = data.add(index).read();
                assert!(fd >= 0);
                TestFd(fd)
            })
            .collect()
    }
}

fn read_exact_fd(fd: RawFd, expected_len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; expected_len];
    let mut offset = 0usize;
    while offset < bytes.len() {
        let read = unsafe {
            libc::read(
                fd,
                bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                bytes.len() - offset,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("read brokered descriptor failed: {error}");
        }
        assert!(read > 0, "brokered descriptor reached EOF early");
        offset += read as usize;
    }
    bytes
}

#[test]
fn broker_attenuates_rw_regular_file_to_readonly_independent_description() {
    let socket_path = unique_path("runtime-rights-local.sock");
    let file_path = unique_path("runtime-rights-source");
    let directory_path = unique_path("runtime-rights-directory");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&file_path);
    let _ = std::fs::remove_dir_all(&directory_path);
    std::fs::write(&file_path, b"broker-rights-marker\n").expect("seed broker source");
    std::fs::create_dir(&directory_path).expect("create broker directory source");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind runtime FD broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect local broker client");
    let mut session = broker.accept().expect("accept local broker client");

    let source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open read-write broker source");
    let premature_grant = RuntimeFdBroker::prepare_readonly_regular_file(&source)
        .expect("prepare pre-readiness grant");
    assert!(matches!(
        session.send_readonly_regular_file(premature_grant),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("readiness")
    ));

    client
        .write_all(b"R")
        .expect("publish local broker readiness");
    session
        .wait_for_ready(b'R')
        .expect("consume exact local broker readiness");
    assert!(matches!(
        session.wait_for_ready(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly once")
    ));

    let grant = RuntimeFdBroker::prepare_readonly_regular_file(&source)
        .expect("attenuate read-write regular file");
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "pre-transfer source offset changed during preparation"
    );

    session
        .send_readonly_regular_file(grant)
        .expect("send attenuated grant");
    let received = receive_one_fd(&client);
    let flags = unsafe { libc::fcntl(received.raw(), libc::F_GETFL) };
    assert!(flags >= 0, "inspect received flags");
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    assert_eq!(flags & libc::O_PATH, 0);

    let byte = b"x";
    assert_eq!(
        unsafe {
            libc::write(
                received.raw(),
                byte.as_ptr().cast::<libc::c_void>(),
                byte.len(),
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(
        read_exact_fd(received.raw(), b"broker-rights-marker\n".len()),
        b"broker-rights-marker\n"
    );
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "target-side read description must not share caller source offset"
    );

    let second_grant =
        RuntimeFdBroker::prepare_readonly_regular_file(&source).expect("prepare second grant");
    assert!(matches!(
        session.send_readonly_regular_file(second_grant),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    let write_only = OpenOptions::new()
        .write(true)
        .open(&file_path)
        .expect("open write-only broker source");
    assert!(matches!(
        RuntimeFdBroker::prepare_readonly_regular_file(&write_only),
        Err(RuntimeFdBrokerError::SourceNotReadable)
    ));

    let directory = File::open(&directory_path).expect("open broker directory source");
    assert!(matches!(
        RuntimeFdBroker::prepare_readonly_regular_file(&directory),
        Err(RuntimeFdBrokerError::SourceNotRegular)
    ));

    let c_path = CString::new(file_path.as_os_str().as_bytes()).unwrap();
    let path_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    assert!(path_fd >= 0, "open O_PATH broker source");
    let path_only = unsafe { File::from_raw_fd(path_fd) };
    assert!(matches!(
        RuntimeFdBroker::prepare_readonly_regular_file(&path_only),
        Err(RuntimeFdBrokerError::SourcePathOnly)
    ));

    drop(session);
    drop(client);
    drop(broker);
    assert!(
        !socket_path.exists(),
        "broker drop must remove its own socket inode"
    );
    std::fs::remove_file(&file_path).expect("remove broker source");
    std::fs::remove_dir(&directory_path).expect("remove broker source directory");
}

fn build_probe_root() -> PathBuf {
    let root = unique_path("runtime-rights-root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work")).expect("create sandbox work directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/probe.S");
    let output = root.join("probe");
    let status = Command::new("cc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&output)
        .arg(&source)
        .status()
        .expect("Linux x86_64 integration tests require cc");
    assert!(status.success(), "failed to assemble runtime broker probe");
    root
}

#[test]
fn mediated_grant_arrives_only_after_exec_and_host_path_stays_hidden() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-rights-sandbox.sock");
    let marker_path = unique_path("runtime-rights-marker");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);
    std::fs::write(&marker_path, b"runtime-fd-handoff-ok\n").expect("seed runtime handoff marker");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind runtime FD broker");
    let marker_argument = marker_path.to_string_lossy();
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 0\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,read,close,openat,exit\n",
        root.display(),
        marker_argument
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse runtime broker policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure runtime broker policy");

    let source = File::open(&marker_path).expect("open runtime broker marker");
    let grant = RuntimeFdBroker::prepare_readonly_regular_file(&source)
        .expect("prepare runtime broker marker grant");
    let runner = thread::spawn(move || run(&policy));

    let mut session = broker.accept().expect("accept launcher broker connection");
    session
        .wait_for_ready(b'R')
        .expect("target must publish post-exec readiness");
    session
        .send_readonly_regular_file(grant)
        .expect("send mediated runtime grant");

    let outcome = runner
        .join()
        .expect("runtime broker runner panicked")
        .expect("runtime broker sandbox failed");
    assert_eq!(outcome, ChildOutcome::Exited(0));
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "sandbox read must not mutate caller source offset"
    );

    drop(session);
    drop(broker);
    std::fs::remove_file(&marker_path).expect("remove runtime broker marker");
    std::fs::remove_dir_all(&root).expect("remove runtime broker root");
}

#[test]
fn broker_configuration_is_fail_closed_and_non_overwriting() {
    let socket_path = unique_path("runtime-rights-policy.sock");
    let root = build_probe_root();
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind runtime FD broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = X\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,exit\n",
        root.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse broker policy");

    let before_missing_recvmsg = policy.clone();
    match broker.configure_policy(&mut policy, 10) {
        Err(RuntimeFdBrokerError::InvalidConfiguration(message)) => {
            assert!(message.contains("explicitly allow recvmsg"));
        }
        other => panic!("unexpected missing-recvmsg broker result: {other:?}"),
    }
    assert_eq!(
        policy, before_missing_recvmsg,
        "missing recvmsg must not partially mutate policy"
    );

    policy.seccomp.allowed_syscalls.insert("recvmsg".to_owned());
    policy.host_unix_stream_path = Some(unique_path("already-configured.sock"));
    let before_existing_broker = policy.clone();
    assert!(matches!(
        broker.configure_policy(&mut policy, 10),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert_eq!(
        policy, before_existing_broker,
        "failed broker configuration must not overwrite existing broker policy"
    );

    drop(broker);
    std::fs::remove_dir_all(&root).expect("remove broker policy root");
}

#[test]
fn sealed_runtime_snapshot_freezes_bounded_bytes_after_preparation() {
    let socket_path = unique_path("runtime-sealed-local.sock");
    let file_path = unique_path("runtime-sealed-source");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&file_path);
    let frozen = b"runtime-fd-handoff-ok\n";
    let mutated = b"host-mutated-after-snapshot\n";
    std::fs::write(&file_path, frozen).expect("seed sealed runtime source");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind sealed runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect sealed runtime client");
    let mut session = broker.accept().expect("accept sealed runtime client");
    let source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open sealed runtime source");

    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&source, 0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_regular_file_snapshot(
            &source,
            MAX_RUNTIME_SEALED_SNAPSHOT_BYTES + 1,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&source, 4),
        Err(RuntimeFdBrokerError::SourceSnapshotTooLarge { max_bytes: 4 })
    ));

    let grant = RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&source, 4096)
        .expect("prepare sealed runtime snapshot");
    assert_eq!(grant.len(), frozen.len() as u64);
    assert!(!grant.is_empty());
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "sealed preparation must not share caller offset"
    );

    std::fs::write(&file_path, mutated).expect("mutate host source after sealed preparation");
    assert_eq!(
        std::fs::read(&file_path).expect("read mutated host source"),
        mutated
    );

    client
        .write_all(b"R")
        .expect("publish sealed runtime readiness");
    session
        .wait_for_ready(b'R')
        .expect("consume sealed runtime readiness");
    session
        .send_sealed_regular_file_snapshot(grant)
        .expect("send sealed runtime snapshot");
    let received = receive_one_fd(&client);

    let flags = unsafe { libc::fcntl(received.raw(), libc::F_GETFL) };
    assert!(flags >= 0, "inspect sealed snapshot flags");
    assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
    let seals = unsafe { libc::fcntl(received.raw(), libc::F_GET_SEALS) };
    assert!(seals >= 0, "inspect sealed snapshot seals");
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    assert_eq!(seals & required, required);
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    assert_eq!(unsafe { libc::fstat(received.raw(), &mut stat) }, 0);
    assert_eq!(stat.st_mode & 0o777, 0o400);

    assert_eq!(
        unsafe { libc::write(received.raw(), b"x".as_ptr().cast::<libc::c_void>(), 1) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(read_exact_fd(received.raw(), frozen.len()), frozen);
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "sealed target read must not share caller offset"
    );

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
    std::fs::remove_file(&file_path).expect("remove sealed runtime source");
}

#[test]
fn sealed_runtime_snapshot_reaches_real_target_with_frozen_preparation_bytes() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-sealed-sandbox.sock");
    let marker_path = unique_path("runtime-sealed-marker");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&marker_path);
    let frozen = b"runtime-fd-handoff-ok\n";
    let mutated = b"host-mutated-after-snapshot\n";
    std::fs::write(&marker_path, frozen).expect("seed sealed runtime marker");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind sealed runtime broker");
    let marker_argument = marker_path.to_string_lossy();
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 0\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,read,close,openat,exit\n",
        root.display(),
        marker_argument
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse sealed runtime policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure sealed runtime broker");

    let source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&marker_path)
        .expect("open sealed runtime marker");
    let grant = RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&source, 4096)
        .expect("prepare sealed runtime marker snapshot");
    std::fs::write(&marker_path, mutated).expect("mutate host marker after preparation");

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker
        .accept()
        .expect("accept launcher sealed broker connection");
    session
        .wait_for_ready(b'R')
        .expect("target must publish post-exec readiness");
    session
        .send_sealed_regular_file_snapshot(grant)
        .expect("send sealed runtime grant");

    let outcome = runner
        .join()
        .expect("sealed runtime runner panicked")
        .expect("sealed runtime sandbox failed");
    assert_eq!(outcome, ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(&marker_path).expect("read mutated host marker"),
        mutated
    );
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "sealed sandbox read must not share caller source offset"
    );

    drop(session);
    drop(broker);
    std::fs::remove_file(&marker_path).expect("remove sealed runtime marker");
    std::fs::remove_dir_all(&root).expect("remove sealed runtime root");
}

#[test]
fn sealed_snapshot_bundle_is_bounded_ordered_and_one_shot() {
    let socket_path = unique_path("runtime-bundle-local.sock");
    let first_path = unique_path("runtime-bundle-first");
    let second_path = unique_path("runtime-bundle-second");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&first_path);
    let _ = std::fs::remove_file(&second_path);
    let first_marker = b"runtime-bundle-first\n";
    let second_marker = b"runtime-bundle-second\n";
    std::fs::write(&first_path, first_marker).expect("seed first bundle source");
    std::fs::write(&second_path, second_marker).expect("seed second bundle source");

    let first = File::open(&first_path).expect("open first bundle source");
    let second = File::open(&second_path).expect("open second bundle source");
    let make_first = || {
        RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&first, 4096)
            .expect("prepare first sealed snapshot")
    };
    let make_second = || {
        RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&second, 4096)
            .expect("prepare second sealed snapshot")
    };

    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(vec![make_first()], 4096),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    let too_many = (0..=MAX_RUNTIME_SEALED_BUNDLE_ITEMS)
        .map(|_| make_first())
        .collect();
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(too_many, 4096),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(vec![make_first(), make_second()], 0,),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(
            vec![make_first(), make_second()],
            MAX_RUNTIME_SEALED_BUNDLE_BYTES + 1,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(
            vec![make_first(), make_second()],
            (first_marker.len() + second_marker.len() - 1) as u64,
        ),
        Err(RuntimeFdBrokerError::SnapshotBundleTooLarge { .. })
    ));

    let bundle =
        RuntimeFdBroker::prepare_sealed_snapshot_bundle(vec![make_first(), make_second()], 4096)
            .expect("prepare sealed snapshot bundle");
    assert_eq!(bundle.item_count(), 2);
    assert_eq!(
        bundle.total_len(),
        (first_marker.len() + second_marker.len()) as u64
    );

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind bundle broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect bundle client");
    let mut session = broker.accept().expect("accept bundle client");
    client.write_all(b"R").expect("publish bundle readiness");
    session
        .wait_for_ready(b'R')
        .expect("consume bundle readiness");
    session
        .send_sealed_snapshot_bundle(bundle)
        .expect("send sealed snapshot bundle");

    let received = receive_bundle_fds(&client, 2);
    assert_eq!(
        read_exact_fd(received[0].raw(), first_marker.len()),
        first_marker
    );
    assert_eq!(
        read_exact_fd(received[1].raw(), second_marker.len()),
        second_marker
    );
    for fd in &received {
        let flags = unsafe { libc::fcntl(fd.raw(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
        let seals = unsafe { libc::fcntl(fd.raw(), libc::F_GET_SEALS) };
        let required =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        assert_eq!(seals & required, required);
    }

    let after_bundle = make_first();
    assert!(matches!(
        session.send_sealed_regular_file_snapshot(after_bundle),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
    std::fs::remove_file(&first_path).expect("remove first bundle source");
    std::fs::remove_file(&second_path).expect("remove second bundle source");
}

#[test]
fn failed_bundle_send_poison_session_against_retry() {
    let socket_path = unique_path("runtime-bundle-failure.sock");
    let first_path = unique_path("runtime-bundle-failure-first");
    let second_path = unique_path("runtime-bundle-failure-second");
    let _ = std::fs::remove_file(&socket_path);
    std::fs::write(&first_path, b"first\n").expect("seed first failure source");
    std::fs::write(&second_path, b"second\n").expect("seed second failure source");
    let first = File::open(&first_path).expect("open first failure source");
    let second = File::open(&second_path).expect("open second failure source");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind failure broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect failure client");
    let mut session = broker.accept().expect("accept failure client");
    client.write_all(b"R").expect("publish failure readiness");
    session
        .wait_for_ready(b'R')
        .expect("consume failure readiness");
    drop(client);

    let bundle = RuntimeFdBroker::prepare_sealed_snapshot_bundle(
        vec![
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&first, 4096).unwrap(),
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&second, 4096).unwrap(),
        ],
        4096,
    )
    .unwrap();
    assert!(matches!(
        session.send_sealed_snapshot_bundle(bundle),
        Err(RuntimeFdBrokerError::Io { .. })
    ));

    let retry = RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&first, 4096).unwrap();
    assert!(matches!(
        session.send_sealed_regular_file_snapshot(retry),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(session);
    drop(broker);
    std::fs::remove_file(&first_path).expect("remove first failure source");
    std::fs::remove_file(&second_path).expect("remove second failure source");
}

#[test]
fn sealed_snapshot_bundle_reaches_real_target_in_order() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-bundle-sandbox.sock");
    let first_path = unique_path("runtime-bundle-sandbox-first");
    let second_path = unique_path("runtime-bundle-sandbox-second");
    let _ = std::fs::remove_file(&socket_path);
    let first_marker = b"runtime-bundle-first\n";
    let second_marker = b"runtime-bundle-second\n";
    std::fs::write(&first_path, first_marker).expect("seed first sandbox bundle source");
    std::fs::write(&second_path, second_marker).expect("seed second sandbox bundle source");

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind sandbox bundle broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 3\n\
         arg = {}\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,read,close,openat,exit\n",
        root.display(),
        first_path.display(),
        second_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse sandbox bundle policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure sandbox bundle broker");

    let first = File::open(&first_path).expect("open first sandbox bundle source");
    let second = File::open(&second_path).expect("open second sandbox bundle source");
    let bundle = RuntimeFdBroker::prepare_sealed_snapshot_bundle(
        vec![
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&first, 4096).unwrap(),
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&second, 4096).unwrap(),
        ],
        4096,
    )
    .expect("prepare sandbox bundle");
    std::fs::write(&first_path, b"host-mutated-first\n").expect("mutate first host source");
    std::fs::write(&second_path, b"host-mutated-second\n").expect("mutate second host source");

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker.accept().expect("accept sandbox bundle connection");
    session
        .wait_for_ready(b'R')
        .expect("bundle target must publish post-exec readiness");
    session
        .send_sealed_snapshot_bundle(bundle)
        .expect("send sandbox sealed bundle");
    assert_eq!(
        runner
            .join()
            .expect("sandbox bundle runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );

    drop(session);
    drop(broker);
    std::fs::remove_file(&first_path).expect("remove first sandbox bundle source");
    std::fs::remove_file(&second_path).expect("remove second sandbox bundle source");
    std::fs::remove_dir_all(&root).expect("remove sandbox bundle root");
}

#[test]
fn sealed_snapshot_bundle_target_rejects_truncated_control() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-bundle-truncated.sock");
    let first_path = unique_path("runtime-bundle-truncated-first");
    let second_path = unique_path("runtime-bundle-truncated-second");
    let third_path = unique_path("runtime-bundle-truncated-third");
    std::fs::write(&first_path, b"runtime-bundle-first\n").unwrap();
    std::fs::write(&second_path, b"runtime-bundle-second\n").unwrap();
    std::fs::write(&third_path, b"runtime-bundle-third\n").unwrap();

    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind truncated bundle broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 3\n\
         arg = {}\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,read,close,openat,exit\n",
        root.display(),
        first_path.display(),
        second_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse truncated bundle policy");
    broker.configure_policy(&mut policy, 10).unwrap();

    let first = File::open(&first_path).unwrap();
    let second = File::open(&second_path).unwrap();
    let third = File::open(&third_path).unwrap();
    let bundle = RuntimeFdBroker::prepare_sealed_snapshot_bundle(
        vec![
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&first, 4096).unwrap(),
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&second, 4096).unwrap(),
            RuntimeFdBroker::prepare_sealed_regular_file_snapshot(&third, 4096).unwrap(),
        ],
        4096,
    )
    .unwrap();

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker.accept().unwrap();
    session.wait_for_ready(b'R').unwrap();
    session.send_sealed_snapshot_bundle(bundle).unwrap();
    assert_eq!(
        runner
            .join()
            .expect("truncated bundle runner panicked")
            .unwrap(),
        ChildOutcome::Exited(29)
    );

    drop(session);
    drop(broker);
    std::fs::remove_file(&first_path).unwrap();
    std::fs::remove_file(&second_path).unwrap();
    std::fs::remove_file(&third_path).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}
