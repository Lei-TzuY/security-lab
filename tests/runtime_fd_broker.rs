#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use security_lab::{
    run, ChildOutcome, RuntimeFdBroker, RuntimeFdBrokerError, SandboxPolicy,
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
    std::env::temp_dir().join(format!(
        "security-lab-{label}-{}-{sequence}",
        process::id()
    ))
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

    let received = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    assert_eq!(
        received,
        1,
        "receive one broker grant failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(&payload, b"F");
    assert_eq!(message.msg_flags & libc::MSG_CTRUNC, 0);
    assert!(
        message.msg_controllen >= std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>()
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
    let client = UnixStream::connect(broker.path()).expect("connect local broker client");
    let mut session = broker.accept().expect("accept local broker client");

    let source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&file_path)
        .expect("open read-write broker source");
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
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    assert_eq!(
        read_exact_fd(received.raw(), b"broker-rights-marker\n".len()),
        b"broker-rights-marker\n"
    );
    assert_eq!(
        unsafe { libc::lseek(source.as_raw_fd(), 0, libc::SEEK_CUR) },
        0,
        "target-side read description must not share caller source offset"
    );

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
    assert!(!socket_path.exists(), "broker drop must remove its own socket inode");
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
    policy.host_unix_stream_path = Some(unique_path("already-configured.sock"));
    let before = policy.clone();
    assert!(matches!(
        broker.configure_policy(&mut policy, 10),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert_eq!(policy, before, "failed broker configuration must not partially mutate policy");

    drop(broker);
    std::fs::remove_dir_all(&root).expect("remove broker policy root");
}
