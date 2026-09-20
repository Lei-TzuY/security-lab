#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use hmac::{Hmac, Mac};
use security_lab::{
    run, ChildOutcome, RuntimeFdBroker, RuntimeFdBrokerError, RuntimeHostUnixRoute, SandboxPolicy,
    MAX_RUNTIME_CORRELATED_IN_FLIGHT, MAX_RUNTIME_CORRELATED_REQUESTS, MAX_RUNTIME_MESSAGE_BYTES,
    MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS, MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS,
    MAX_RUNTIME_MULTI_MESSAGE_ROUNDS, MAX_RUNTIME_MULTI_MESSAGE_SESSION_MILLISECONDS,
    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,
    MAX_RUNTIME_SEALED_BUNDLE_ITEMS, MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
    MIN_RUNTIME_CORRELATED_IN_FLIGHT, MIN_RUNTIME_CORRELATED_REQUESTS,
    MIN_RUNTIME_MULTI_MESSAGE_ROUNDS, RUNTIME_AUTH_CHALLENGE_BYTES, RUNTIME_AUTH_KEY_BYTES,
    RUNTIME_AUTH_TAG_BYTES,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
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

struct SeqpacketListener {
    fd: RawFd,
    path: PathBuf,
}

impl SeqpacketListener {
    fn bind(path: &Path) -> Self {
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() <= 107);
        assert!(!bytes.contains(&0));
        let fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0, "create AF_UNIX SOCK_SEQPACKET listener");

        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in bytes.iter().enumerate() {
            address.sun_path[index] = *byte as libc::c_char;
        }
        let address_len =
            (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::bind(
                    fd,
                    (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                    address_len,
                )
            },
            0,
            "bind AF_UNIX SOCK_SEQPACKET listener"
        );
        assert_eq!(
            unsafe { libc::listen(fd, 8) },
            0,
            "listen on seqpacket socket"
        );
        Self {
            fd,
            path: path.to_path_buf(),
        }
    }

    fn accept(&self) -> TestFd {
        let fd = unsafe {
            libc::accept4(
                self.fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        assert!(fd >= 0, "accept AF_UNIX SOCK_SEQPACKET connection");
        TestFd(fd)
    }
}

impl Drop for SeqpacketListener {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

fn recv_packet(fd: RawFd) -> Vec<u8> {
    let mut buffer = [0u8; 256];
    let read = unsafe {
        libc::recv(
            fd,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
        )
    };
    assert!(read > 0, "receive AF_UNIX SOCK_SEQPACKET packet");
    buffer[..read as usize].to_vec()
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

fn send_correlated_packet(fd: RawFd, request_id: u64, payload: &[u8]) {
    assert!(!payload.is_empty());
    let mut frame = Vec::with_capacity(8 + payload.len());
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(payload);
    assert_eq!(
        unsafe {
            libc::send(
                fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        frame.len() as isize,
        "send correlated packet failed: {}",
        std::io::Error::last_os_error()
    );
}

fn receive_correlated_packet(fd: RawFd) -> (u64, Vec<u8>) {
    let mut frame = vec![0u8; MAX_RUNTIME_MESSAGE_BYTES as usize + 8];
    let received = unsafe {
        libc::recv(
            fd,
            frame.as_mut_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
        )
    };
    assert!(
        received >= 9,
        "receive correlated packet failed or malformed: received={received}, error={}",
        std::io::Error::last_os_error()
    );
    frame.truncate(received as usize);
    let mut request_id_bytes = [0u8; 8];
    request_id_bytes.copy_from_slice(&frame[..8]);
    (u64::from_le_bytes(request_id_bytes), frame[8..].to_vec())
}

const TEST_RUNTIME_AUTH_VERSION: u8 = 1;
const TEST_RUNTIME_AUTH_CHALLENGE_KIND: u8 = b'C';
const TEST_RUNTIME_AUTH_REQUEST_KIND: u8 = b'Q';
const TEST_RUNTIME_AUTH_RESPONSE_KIND: u8 = b'S';
const TEST_RUNTIME_AUTH_ACKNOWLEDGMENT_KIND: u8 = b'A';
const TEST_RUNTIME_AUTH_DOMAIN: &[u8] = b"security-lab-runtime-correlated-hmac-sha256-v1\0";

type TestRuntimeHmacSha256 = Hmac<Sha256>;

fn test_runtime_auth_mac(
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
    kind: u8,
    request_id: u64,
    payload: &[u8],
) -> TestRuntimeHmacSha256 {
    let mut mac = TestRuntimeHmacSha256::new_from_slice(key).unwrap();
    mac.update(TEST_RUNTIME_AUTH_DOMAIN);
    mac.update(challenge);
    mac.update(&[kind, TEST_RUNTIME_AUTH_VERSION]);
    mac.update(&request_id.to_le_bytes());
    mac.update(&(payload.len() as u64).to_le_bytes());
    mac.update(payload);
    mac
}

fn test_runtime_auth_tag(
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
    kind: u8,
    request_id: u64,
    payload: &[u8],
) -> [u8; RUNTIME_AUTH_TAG_BYTES] {
    let mut tag = [0u8; RUNTIME_AUTH_TAG_BYTES];
    tag.copy_from_slice(
        &test_runtime_auth_mac(key, challenge, kind, request_id, payload)
            .finalize()
            .into_bytes(),
    );
    tag
}

fn receive_runtime_auth_challenge(fd: RawFd) -> [u8; RUNTIME_AUTH_CHALLENGE_BYTES] {
    let mut frame = [0u8; 2 + RUNTIME_AUTH_CHALLENGE_BYTES];
    let received = unsafe {
        libc::recv(
            fd,
            frame.as_mut_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
        )
    };
    assert_eq!(
        received,
        frame.len() as isize,
        "receive authenticated runtime challenge failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(frame[0], TEST_RUNTIME_AUTH_CHALLENGE_KIND);
    assert_eq!(frame[1], TEST_RUNTIME_AUTH_VERSION);
    let mut challenge = [0u8; RUNTIME_AUTH_CHALLENGE_BYTES];
    challenge.copy_from_slice(&frame[2..]);
    challenge
}

fn send_authenticated_runtime_request(
    fd: RawFd,
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
    request_id: u64,
    payload: &[u8],
) {
    assert!(!payload.is_empty());
    let tag = test_runtime_auth_tag(
        key,
        challenge,
        TEST_RUNTIME_AUTH_REQUEST_KIND,
        request_id,
        payload,
    );
    let mut frame = Vec::with_capacity(2 + 8 + payload.len() + tag.len());
    frame.push(TEST_RUNTIME_AUTH_REQUEST_KIND);
    frame.push(TEST_RUNTIME_AUTH_VERSION);
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&tag);
    assert_eq!(
        unsafe {
            libc::send(
                fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        frame.len() as isize,
        "send authenticated runtime request failed: {}",
        std::io::Error::last_os_error()
    );
}

fn receive_authenticated_runtime_response(
    fd: RawFd,
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
) -> (u64, Vec<u8>) {
    let mut frame = vec![0u8; MAX_RUNTIME_MESSAGE_BYTES as usize + 2 + 8 + RUNTIME_AUTH_TAG_BYTES];
    let received = unsafe {
        libc::recv(
            fd,
            frame.as_mut_ptr().cast::<libc::c_void>(),
            frame.len(),
            0,
        )
    };
    assert!(
        received > (2 + 8 + RUNTIME_AUTH_TAG_BYTES) as isize,
        "receive authenticated runtime response failed or malformed: received={received}, error={}",
        std::io::Error::last_os_error()
    );
    frame.truncate(received as usize);
    assert_eq!(frame[0], TEST_RUNTIME_AUTH_RESPONSE_KIND);
    assert_eq!(frame[1], TEST_RUNTIME_AUTH_VERSION);
    let mut request_id_bytes = [0u8; 8];
    request_id_bytes.copy_from_slice(&frame[2..10]);
    let request_id = u64::from_le_bytes(request_id_bytes);
    let payload_end = frame.len() - RUNTIME_AUTH_TAG_BYTES;
    let payload = frame[10..payload_end].to_vec();
    let tag = &frame[payload_end..];
    test_runtime_auth_mac(
        key,
        challenge,
        TEST_RUNTIME_AUTH_RESPONSE_KIND,
        request_id,
        &payload,
    )
    .verify_slice(tag)
    .expect("authenticated runtime response tag must verify");
    (request_id, payload)
}

fn test_runtime_response_sha256(payload: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(payload);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn send_authenticated_runtime_acknowledgment_digest(
    fd: RawFd,
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
    request_id: u64,
    response_sha256: &[u8; 32],
) {
    let tag = test_runtime_auth_tag(
        key,
        challenge,
        TEST_RUNTIME_AUTH_ACKNOWLEDGMENT_KIND,
        request_id,
        response_sha256,
    );
    let mut frame = Vec::with_capacity(2 + 8 + response_sha256.len() + tag.len());
    frame.push(TEST_RUNTIME_AUTH_ACKNOWLEDGMENT_KIND);
    frame.push(TEST_RUNTIME_AUTH_VERSION);
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(response_sha256);
    frame.extend_from_slice(&tag);
    assert_eq!(
        unsafe {
            libc::send(
                fd,
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        frame.len() as isize,
        "send authenticated response acknowledgment failed: {}",
        std::io::Error::last_os_error()
    );
}

fn send_authenticated_runtime_acknowledgment(
    fd: RawFd,
    key: &[u8; RUNTIME_AUTH_KEY_BYTES],
    challenge: &[u8; RUNTIME_AUTH_CHALLENGE_BYTES],
    request_id: u64,
    response_payload: &[u8],
) {
    let response_sha256 = test_runtime_response_sha256(response_payload);
    send_authenticated_runtime_acknowledgment_digest(
        fd,
        key,
        challenge,
        request_id,
        &response_sha256,
    );
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

#[test]
fn prepared_host_unix_stream_connects_exact_peer_and_reuses_one_shot_grant_state() {
    let service_path = unique_path("runtime-host-unix-local-service.sock");
    let broker_path = unique_path("runtime-host-unix-local-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = UnixListener::bind(&service_path).expect("bind host UNIX service");
    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let grant = RuntimeFdBroker::prepare_host_unix_stream(
        &service_path,
        Some((expected_uid, expected_gid)),
    )
    .expect("prepare exact host UNIX stream");
    assert_eq!(grant.peer_uid(), expected_uid);
    assert_eq!(grant.peer_gid(), expected_gid);
    assert!(grant.peer_pid() > 0);

    let (mut service, _) = listener.accept().expect("accept prepared host UNIX stream");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect runtime broker");
    let mut session = broker.accept().expect("accept runtime broker");
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();
    session
        .send_host_unix_stream(grant)
        .expect("send prepared host UNIX stream");
    let received = receive_one_fd(&client);

    let request = b"runtime-host-unix-request\n";
    assert_eq!(
        unsafe {
            libc::write(
                received.raw(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
            )
        },
        request.len() as isize
    );
    let mut observed = vec![0u8; request.len()];
    service.read_exact(&mut observed).unwrap();
    assert_eq!(observed, request);
    service.write_all(b"runtime-host-unix-ok\n").unwrap();
    assert_eq!(
        read_exact_fd(received.raw(), b"runtime-host-unix-ok\n".len()),
        b"runtime-host-unix-ok\n"
    );

    let second_listener_path = unique_path("runtime-host-unix-local-second.sock");
    let _ = std::fs::remove_file(&second_listener_path);
    let second_listener = UnixListener::bind(&second_listener_path).unwrap();
    let second_grant =
        RuntimeFdBroker::prepare_host_unix_stream(&second_listener_path, None).unwrap();
    let _second_service = second_listener.accept().unwrap();
    assert!(matches!(
        session.send_host_unix_stream(second_grant),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    let wrong_uid = expected_uid.wrapping_add(1);
    assert!(matches!(
        RuntimeFdBroker::prepare_host_unix_stream(
            &service_path,
            Some((wrong_uid, expected_gid))
        ),
        Err(RuntimeFdBrokerError::HostUnixPeerCredentialMismatch {
            expected_uid: uid,
            expected_gid: gid,
            ..
        }) if uid == wrong_uid && gid == expected_gid
    ));

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
    drop(service);
    drop(listener);
    drop(second_listener);
    std::fs::remove_file(&service_path).unwrap();
    std::fs::remove_file(&second_listener_path).unwrap();
}

#[test]
fn prepared_host_unix_seqpacket_preserves_packet_boundaries_after_transfer() {
    let service_path = unique_path("runtime-host-unix-seqpacket-local-service.sock");
    let broker_path = unique_path("runtime-host-unix-seqpacket-local-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = SeqpacketListener::bind(&service_path);
    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let grant = RuntimeFdBroker::prepare_host_unix_seqpacket(
        &service_path,
        Some((expected_uid, expected_gid)),
    )
    .expect("prepare exact host UNIX seqpacket");
    assert_eq!(grant.peer_uid(), expected_uid);
    assert_eq!(grant.peer_gid(), expected_gid);
    assert!(grant.peer_pid() > 0);
    let service = listener.accept();

    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind seqpacket runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect seqpacket runtime broker");
    let mut session = broker.accept().expect("accept seqpacket runtime broker");
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();
    session
        .send_host_unix_seqpacket(grant)
        .expect("send prepared host UNIX seqpacket");
    let received = receive_one_fd(&client);

    for packet in [b"packet-one".as_slice(), b"packet-two-longer".as_slice()] {
        assert_eq!(
            unsafe {
                libc::send(
                    received.raw(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            packet.len() as isize
        );
    }
    assert_eq!(recv_packet(service.raw()), b"packet-one");
    assert_eq!(recv_packet(service.raw()), b"packet-two-longer");

    for packet in [b"reply-a".as_slice(), b"reply-b-different".as_slice()] {
        assert_eq!(
            unsafe {
                libc::send(
                    service.raw(),
                    packet.as_ptr().cast::<libc::c_void>(),
                    packet.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            packet.len() as isize
        );
    }
    assert_eq!(recv_packet(received.raw()), b"reply-a");
    assert_eq!(recv_packet(received.raw()), b"reply-b-different");

    let wrong_uid = expected_uid.wrapping_add(1);
    assert!(matches!(
        RuntimeFdBroker::prepare_host_unix_seqpacket(
            &service_path,
            Some((wrong_uid, expected_gid))
        ),
        Err(RuntimeFdBrokerError::HostUnixPeerCredentialMismatch {
            expected_uid: uid,
            expected_gid: gid,
            ..
        }) if uid == wrong_uid && gid == expected_gid
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_host_unix_seqpacket("relative.sock", None),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
    drop(service);
    drop(listener);
}

#[test]
fn transferred_host_unix_stream_can_be_revoked_after_grant() {
    let service_path = unique_path("runtime-host-unix-revocable-service.sock");
    let broker_path = unique_path("runtime-host-unix-revocable-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = UnixListener::bind(&service_path).expect("bind revocable host UNIX service");
    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let grant = RuntimeFdBroker::prepare_host_unix_stream(
        &service_path,
        Some((expected_uid, expected_gid)),
    )
    .expect("prepare revocable host UNIX stream");
    let (mut service, _) = listener
        .accept()
        .expect("accept revocable host UNIX stream");

    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind revocable runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect revocable runtime broker");
    let mut session = broker.accept().expect("accept revocable runtime broker");
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();
    let mut controller = session
        .send_revocable_host_unix_stream(grant)
        .expect("transfer revocable host UNIX stream");
    let received = receive_one_fd(&client);

    let credentials = controller.peer_credentials();
    assert!(credentials.pid() > 0);
    assert_eq!(credentials.uid(), expected_uid);
    assert_eq!(credentials.gid(), expected_gid);
    assert!(!controller.is_revoked());
    assert!(!controller.is_failed());

    let request = b"before-host-revoke\n";
    assert_eq!(
        unsafe {
            libc::send(
                received.raw(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        request.len() as isize
    );
    let mut observed = vec![0u8; request.len()];
    service.read_exact(&mut observed).unwrap();
    assert_eq!(observed, request);
    service.write_all(b"before-host-revoke-ok\n").unwrap();
    assert_eq!(
        read_exact_fd(received.raw(), b"before-host-revoke-ok\n".len()),
        b"before-host-revoke-ok\n"
    );

    controller
        .revoke()
        .expect("revoke transferred host UNIX stream");
    assert!(controller.is_revoked());
    assert!(!controller.is_failed());

    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::read(
                received.raw(),
                byte.as_mut_ptr().cast::<libc::c_void>(),
                byte.len(),
            )
        },
        0,
        "target descriptor did not observe EOF after trusted shutdown"
    );
    assert_eq!(
        unsafe {
            libc::send(
                received.raw(),
                b"x".as_ptr().cast::<libc::c_void>(),
                1,
                libc::MSG_NOSIGNAL,
            )
        },
        -1,
        "target descriptor unexpectedly retained send authority after revocation"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPIPE)
    );
    assert!(matches!(
        controller.revoke(),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("revoked exactly once")
    ));

    let second_path = unique_path("runtime-host-unix-revocable-second.sock");
    let _ = std::fs::remove_file(&second_path);
    let second_listener = UnixListener::bind(&second_path).unwrap();
    let second_grant = RuntimeFdBroker::prepare_host_unix_stream(&second_path, None).unwrap();
    let _second_service = second_listener.accept().unwrap();
    assert!(matches!(
        session.send_host_unix_stream(second_grant),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    drop(received);
    drop(controller);
    drop(session);
    drop(client);
    drop(broker);
    drop(service);
    drop(listener);
    drop(second_listener);
    std::fs::remove_file(&service_path).unwrap();
    std::fs::remove_file(&second_path).unwrap();
}

#[test]
fn dropping_active_host_unix_revocation_controller_fails_closed() {
    let service_path = unique_path("runtime-host-unix-drop-revoke-service.sock");
    let broker_path = unique_path("runtime-host-unix-drop-revoke-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = UnixListener::bind(&service_path).expect("bind drop-revoke host UNIX service");
    let grant = RuntimeFdBroker::prepare_host_unix_stream(&service_path, None)
        .expect("prepare drop-revoke host UNIX stream");
    let (_service, _) = listener
        .accept()
        .expect("accept drop-revoke host UNIX stream");

    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind drop-revoke runtime broker");
    let mut client =
        UnixStream::connect(broker.path()).expect("connect drop-revoke runtime broker");
    let mut session = broker.accept().expect("accept drop-revoke runtime broker");
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let controller = session
        .send_revocable_host_unix_stream(grant)
        .expect("transfer drop-revoke host UNIX stream");
    let received = receive_one_fd(&client);
    drop(controller);

    let mut byte = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::read(
                received.raw(),
                byte.as_mut_ptr().cast::<libc::c_void>(),
                byte.len(),
            )
        },
        0,
        "dropping active revocation controller did not shut down target receive authority"
    );
    assert_eq!(
        unsafe {
            libc::send(
                received.raw(),
                b"x".as_ptr().cast::<libc::c_void>(),
                1,
                libc::MSG_NOSIGNAL,
            )
        },
        -1,
        "dropping active revocation controller left target send authority active"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPIPE)
    );

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
    drop(listener);
    std::fs::remove_file(&service_path).unwrap();
}

#[test]
fn host_unix_router_routes_target_selection_and_enforces_route_bounds() {
    let service_a_path = unique_path("runtime-host-unix-router-a.sock");
    let service_b_path = unique_path("runtime-host-unix-router-b.sock");
    let broker_path = unique_path("runtime-host-unix-router-broker.sock");
    for path in [&service_a_path, &service_b_path, &broker_path] {
        let _ = std::fs::remove_file(path);
    }

    let listener_a = UnixListener::bind(&service_a_path).expect("bind router service A");
    let listener_b = UnixListener::bind(&service_b_path).expect("bind router service B");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind router runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect router runtime broker");
    let expected_peer = Some((unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
    let mut controller = broker
        .accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, expected_peer, 1),
            RuntimeHostUnixRoute::new(&service_b_path, expected_peer, 2),
        ])
        .expect("accept bounded router controller");

    assert_eq!(controller.route_count(), 2);
    assert_eq!(controller.max_connections(0), Some(1));
    assert_eq!(controller.max_connections(1), Some(2));
    assert_eq!(controller.total_granted_connections(), 0);

    for (route_index, listener, request, reply) in [
        (0u8, &listener_a, b"a-one".as_slice(), b"a-ok".as_slice()),
        (1u8, &listener_b, b"b-one".as_slice(), b"b1-ok".as_slice()),
        (1u8, &listener_b, b"b-two".as_slice(), b"b2-ok".as_slice()),
    ] {
        client.write_all(&[b'R', route_index]).unwrap();
        let grant = controller
            .grant_next(b'R')
            .expect("grant selected host UNIX route");
        assert_eq!(grant.route_index(), route_index as usize);
        assert_eq!(grant.credentials().uid(), unsafe { libc::geteuid() });
        assert_eq!(grant.credentials().gid(), unsafe { libc::getegid() });
        assert!(grant.credentials().pid() > 0);

        let (mut service, _) = listener.accept().expect("accept selected route connection");
        let received = receive_one_fd(&client);
        assert_eq!(
            unsafe {
                libc::write(
                    received.raw(),
                    request.as_ptr().cast::<libc::c_void>(),
                    request.len(),
                )
            },
            request.len() as isize
        );
        let mut observed = vec![0u8; request.len()];
        service.read_exact(&mut observed).unwrap();
        assert_eq!(observed, request);
        service.write_all(reply).unwrap();
        assert_eq!(read_exact_fd(received.raw(), reply.len()), reply);
    }

    assert_eq!(controller.granted_connections(0), Some(1));
    assert_eq!(controller.granted_connections(1), Some(2));
    assert_eq!(controller.total_granted_connections(), 3);
    assert!(controller.is_complete());
    assert!(!controller.is_failed());
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("exhausted all route bounds")
    ));

    drop(controller);
    drop(client);
    drop(broker);
    drop(listener_a);
    drop(listener_b);
    for path in [service_a_path, service_b_path] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn host_unix_router_rejects_invalid_configuration_before_accepting_channel() {
    let service_a_path = unique_path("runtime-host-unix-router-invalid-a.sock");
    let service_b_path = unique_path("runtime-host-unix-router-invalid-b.sock");
    let broker_path = unique_path("runtime-host-unix-router-invalid-broker.sock");
    for path in [&service_a_path, &service_b_path, &broker_path] {
        let _ = std::fs::remove_file(path);
    }

    let _listener_a = UnixListener::bind(&service_a_path).unwrap();
    let _listener_b = UnixListener::bind(&service_b_path).unwrap();
    let broker = RuntimeFdBroker::bind(&broker_path).unwrap();

    assert!(matches!(
        broker.accept_host_unix_router_controller(vec![RuntimeHostUnixRoute::new(
            &service_a_path,
            None,
            1
        )]),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("service count must be between")
    ));
    assert!(matches!(
        broker.accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, None, 1),
            RuntimeHostUnixRoute::new(&service_a_path, None, 1),
        ]),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("service paths must be unique")
    ));
    assert!(matches!(
        broker.accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, None, 0),
            RuntimeHostUnixRoute::new(&service_b_path, None, 1),
        ]),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("per-route connection bound must be between")
    ));

    drop(broker);
    for path in [service_a_path, service_b_path] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn host_unix_router_unknown_or_exhausted_selection_is_terminal() {
    let service_a_path = unique_path("runtime-host-unix-router-terminal-a.sock");
    let service_b_path = unique_path("runtime-host-unix-router-terminal-b.sock");
    let broker_path = unique_path("runtime-host-unix-router-terminal-broker.sock");
    for path in [&service_a_path, &service_b_path, &broker_path] {
        let _ = std::fs::remove_file(path);
    }

    let listener_a = UnixListener::bind(&service_a_path).unwrap();
    let listener_b = UnixListener::bind(&service_b_path).unwrap();
    listener_b.set_nonblocking(true).unwrap();
    let broker = RuntimeFdBroker::bind(&broker_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut controller = broker
        .accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, None, 1),
            RuntimeHostUnixRoute::new(&service_b_path, None, 1),
        ])
        .unwrap();

    client.write_all(&[b'R', 0]).unwrap();
    controller.grant_next(b'R').unwrap();
    let (_service, _) = listener_a.accept().unwrap();
    let _received = receive_one_fd(&client);

    client.write_all(&[b'R', 0]).unwrap();
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("route 0 exhausted its connection bound")
    ));
    assert!(controller.is_failed());
    assert_eq!(controller.granted_connections(0), Some(1));
    assert_eq!(controller.granted_connections(1), Some(0));
    assert!(matches!(
        listener_b.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    drop(controller);
    drop(client);
    drop(broker);
    drop(listener_a);
    drop(listener_b);
    for path in [service_a_path, service_b_path] {
        std::fs::remove_file(path).unwrap();
    }

    let service_a_path = unique_path("runtime-host-unix-router-unknown-a.sock");
    let service_b_path = unique_path("runtime-host-unix-router-unknown-b.sock");
    let broker_path = unique_path("runtime-host-unix-router-unknown-broker.sock");
    for path in [&service_a_path, &service_b_path, &broker_path] {
        let _ = std::fs::remove_file(path);
    }
    let listener_a = UnixListener::bind(&service_a_path).unwrap();
    let listener_b = UnixListener::bind(&service_b_path).unwrap();
    listener_a.set_nonblocking(true).unwrap();
    listener_b.set_nonblocking(true).unwrap();
    let broker = RuntimeFdBroker::bind(&broker_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut controller = broker
        .accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, None, 1),
            RuntimeHostUnixRoute::new(&service_b_path, None, 1),
        ])
        .unwrap();

    client.write_all(&[b'R', 7]).unwrap();
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("unknown route index 7")
    ));
    assert!(controller.is_failed());
    for listener in [&listener_a, &listener_b] {
        assert!(matches!(
            listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    drop(controller);
    drop(client);
    drop(broker);
    drop(listener_a);
    drop(listener_b);
    for path in [service_a_path, service_b_path] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn host_unix_reconnect_controller_grants_two_fresh_connections_and_exhausts_bound() {
    let service_path = unique_path("runtime-host-unix-reconnect-service.sock");
    let broker_path = unique_path("runtime-host-unix-reconnect-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = UnixListener::bind(&service_path).expect("bind reconnect host UNIX service");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind reconnect runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect reconnect runtime broker");
    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let mut controller = broker
        .accept_host_unix_reconnect_controller(&service_path, Some((expected_uid, expected_gid)), 2)
        .expect("accept bounded reconnect controller");

    assert_eq!(controller.max_connections(), 2);
    assert_eq!(controller.granted_connections(), 0);
    assert!(!controller.is_complete());
    assert!(!controller.is_failed());

    for (round, request, reply) in [
        (
            1u8,
            b"reconnect-one\n".as_slice(),
            b"reconnect-one-ok\n".as_slice(),
        ),
        (
            2u8,
            b"reconnect-two\n".as_slice(),
            b"reconnect-two-ok\n".as_slice(),
        ),
    ] {
        client.write_all(b"R").unwrap();
        let credentials = controller
            .grant_next(b'R')
            .expect("grant fresh reconnect stream");
        assert!(credentials.pid() > 0);
        assert_eq!(credentials.uid(), expected_uid);
        assert_eq!(credentials.gid(), expected_gid);
        assert_eq!(controller.granted_connections(), round as u32);

        let (mut service, _) = listener.accept().expect("accept fresh service connection");
        let received = receive_one_fd(&client);

        assert_eq!(
            unsafe {
                libc::write(
                    received.raw(),
                    request.as_ptr().cast::<libc::c_void>(),
                    request.len(),
                )
            },
            request.len() as isize
        );
        let mut observed = vec![0u8; request.len()];
        service.read_exact(&mut observed).unwrap();
        assert_eq!(observed, request);
        service.write_all(reply).unwrap();
        assert_eq!(read_exact_fd(received.raw(), reply.len()), reply);
    }

    assert!(controller.is_complete());
    assert!(!controller.is_failed());
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("exhausted its connection bound")
    ));

    drop(controller);
    drop(client);
    drop(broker);
    drop(listener);
    std::fs::remove_file(&service_path).unwrap();
}

#[test]
fn host_unix_reconnect_controller_requires_readiness_before_connect_and_fails_terminally() {
    let service_path = unique_path("runtime-host-unix-reconnect-ordering.sock");
    let broker_path = unique_path("runtime-host-unix-reconnect-ordering-broker.sock");
    let _ = std::fs::remove_file(&service_path);
    let _ = std::fs::remove_file(&broker_path);

    let listener = UnixListener::bind(&service_path).expect("bind ordering host UNIX service");
    listener
        .set_nonblocking(true)
        .expect("make ordering listener nonblocking");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind ordering runtime broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect ordering runtime broker");
    let mut controller = broker
        .accept_host_unix_reconnect_controller(&service_path, None, 2)
        .expect("accept ordering reconnect controller");

    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));

    client.write_all(b"X").unwrap();
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("expected reconnect readiness byte")
    ));
    assert!(controller.is_failed());
    assert_eq!(controller.granted_connections(), 0);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    assert!(matches!(
        controller.grant_next(b'R'),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("closed after a failed round")
    ));

    assert!(matches!(
        broker.accept_host_unix_reconnect_controller(&service_path, None, 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("connection bound must be between")
    ));

    drop(controller);
    drop(client);
    drop(broker);
    drop(listener);
    std::fs::remove_file(&service_path).unwrap();
}

fn build_revocable_host_unix_probe_root() -> PathBuf {
    let root = unique_path("runtime-host-unix-revocable-root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work")).expect("create revocable host UNIX work directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_host_unix_revocable_probe.S");
    let output = root.join("revocable-probe");
    let status = Command::new("cc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&output)
        .arg(&source)
        .status()
        .expect("Linux x86_64 revocable host UNIX integration requires cc");
    assert!(
        status.success(),
        "failed to assemble revocable host UNIX target fixture"
    );
    root
}

fn build_reconnect_probe_root() -> PathBuf {
    let root = unique_path("runtime-host-unix-reconnect-root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work")).expect("create reconnect work directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_host_unix_reconnect_probe.S");
    let output = root.join("reconnect-probe");
    let status = Command::new("cc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&output)
        .arg(&source)
        .status()
        .expect("Linux x86_64 reconnect integration requires cc");
    assert!(
        status.success(),
        "failed to assemble runtime host UNIX reconnect fixture"
    );
    root
}

fn build_seqpacket_probe_root() -> PathBuf {
    let root = unique_path("runtime-host-unix-seqpacket-root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work")).expect("create seqpacket work directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_host_unix_seqpacket_probe.S");
    let output = root.join("seqpacket-probe");
    let status = Command::new("cc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&output)
        .arg(&source)
        .status()
        .expect("Linux x86_64 seqpacket integration requires cc");
    assert!(
        status.success(),
        "failed to assemble runtime host UNIX seqpacket fixture"
    );
    root
}

fn build_router_probe_root() -> PathBuf {
    let root = unique_path("runtime-host-unix-router-root");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("work")).expect("create router work directory");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/runtime_host_unix_router_probe.S");
    let output = root.join("router-probe");
    let status = Command::new("cc")
        .args(["-nostdlib", "-static", "-Wl,--build-id=none", "-o"])
        .arg(&output)
        .arg(&source)
        .status()
        .expect("Linux x86_64 router integration requires cc");
    assert!(
        status.success(),
        "failed to assemble runtime host UNIX router fixture"
    );
    root
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
fn post_launch_host_unix_stream_grant_reaches_target_without_path_authority() {
    let root = build_probe_root();
    let broker_path = unique_path("runtime-host-unix-sandbox-broker.sock");
    let service_path = unique_path("runtime-host-unix-sandbox-service.sock");
    let _ = std::fs::remove_file(&broker_path);
    let _ = std::fs::remove_file(&service_path);

    let listener = UnixListener::bind(&service_path).expect("bind sandbox host UNIX service");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind sandbox runtime broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 6\n\
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
         seccomp.allow = write,recvmsg,read,close,openat,exit\n",
        root.display(),
        service_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse host UNIX grant policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure runtime broker policy");
    for syscall in ["socket", "connect", "execveat"] {
        assert!(
            !policy.seccomp.allowed_syscalls.contains(syscall),
            "host UNIX object grant must not require target {syscall} authority"
        );
    }

    let grant = RuntimeFdBroker::prepare_host_unix_stream(
        &service_path,
        Some((unsafe { libc::geteuid() }, unsafe { libc::getegid() })),
    )
    .expect("prepare sandbox host UNIX stream");
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept target host UNIX grant");
        let mut request = vec![0u8; b"runtime-host-unix-request\n".len()];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, b"runtime-host-unix-request\n");
        stream.write_all(b"runtime-host-unix-ok\n").unwrap();
    });

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker.accept().expect("accept sandbox runtime connection");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner.join().expect("host UNIX target runner panicked");
        panic!(
            "host UNIX grant target failed before readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    session
        .send_host_unix_stream(grant)
        .expect("transfer host UNIX stream grant");

    assert_eq!(
        runner.join().expect("host UNIX runner panicked").unwrap(),
        ChildOutcome::Exited(0)
    );
    peer.join().expect("host UNIX service thread panicked");

    drop(session);
    drop(broker);
    std::fs::remove_file(&service_path).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn post_launch_host_unix_seqpacket_preserves_packets_without_target_connect_authority() {
    let root = build_seqpacket_probe_root();
    let broker_path = unique_path("runtime-host-unix-seqpacket-sandbox-broker.sock");
    let service_path = unique_path("runtime-host-unix-seqpacket-sandbox-service.sock");
    let _ = std::fs::remove_file(&broker_path);
    let _ = std::fs::remove_file(&service_path);

    let listener = SeqpacketListener::bind(&service_path);
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind seqpacket sandbox broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /seqpacket-probe\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 5000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = write,recvmsg,read,close,openat,exit\n",
        root.display(),
        service_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse seqpacket sandbox policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure seqpacket runtime broker policy");
    for syscall in ["socket", "connect", "execveat"] {
        assert!(
            !policy.seccomp.allowed_syscalls.contains(syscall),
            "host UNIX seqpacket grant must not require target {syscall} authority"
        );
    }

    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let grant = RuntimeFdBroker::prepare_host_unix_seqpacket(
        &service_path,
        Some((expected_uid, expected_gid)),
    )
    .expect("prepare sandbox host UNIX seqpacket");
    assert_eq!(grant.peer_uid(), expected_uid);
    assert_eq!(grant.peer_gid(), expected_gid);

    let peer = thread::spawn(move || {
        let service = listener.accept();
        assert_eq!(recv_packet(service.raw()), b"seq-one");
        assert_eq!(recv_packet(service.raw()), b"seq-two-long");
        for packet in [b"reply-a".as_slice(), b"reply-b-longer".as_slice()] {
            assert_eq!(
                unsafe {
                    libc::send(
                        service.raw(),
                        packet.as_ptr().cast::<libc::c_void>(),
                        packet.len(),
                        libc::MSG_NOSIGNAL,
                    )
                },
                packet.len() as isize
            );
        }
    });

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker
        .accept()
        .expect("accept seqpacket sandbox broker connection");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner
            .join()
            .expect("seqpacket sandbox target runner panicked");
        panic!(
            "seqpacket target failed before readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    session
        .send_host_unix_seqpacket(grant)
        .expect("transfer sandbox host UNIX seqpacket");

    assert_eq!(
        runner
            .join()
            .expect("seqpacket sandbox runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );
    peer.join().expect("seqpacket host service thread panicked");

    drop(session);
    drop(broker);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn post_launch_host_unix_stream_revocation_wakes_target_to_eof() {
    let root = build_revocable_host_unix_probe_root();
    let broker_path = unique_path("runtime-host-unix-revocable-sandbox-broker.sock");
    let service_path = unique_path("runtime-host-unix-revocable-sandbox-service.sock");
    let _ = std::fs::remove_file(&broker_path);
    let _ = std::fs::remove_file(&service_path);

    let listener = UnixListener::bind(&service_path).expect("bind revocable sandbox service");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind revocable sandbox broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /revocable-probe\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 5000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = write,recvmsg,read,close,openat,exit\n",
        root.display(),
        service_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse revocable host UNIX policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure revocable host UNIX broker policy");
    for syscall in ["socket", "connect", "execveat"] {
        assert!(
            !policy.seccomp.allowed_syscalls.contains(syscall),
            "revocable host UNIX grant must not require target {syscall} authority"
        );
    }

    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let grant = RuntimeFdBroker::prepare_host_unix_stream(
        &service_path,
        Some((expected_uid, expected_gid)),
    )
    .expect("prepare revocable sandbox host UNIX stream");

    let (marker_tx, marker_rx) = mpsc::channel();
    let peer = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept revocable sandbox service");
        let expected = b"before-host-revoke\n";
        let mut request = vec![0u8; expected.len()];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, expected);
        marker_tx
            .send(())
            .expect("publish pre-revocation service marker");

        let mut eof = [0u8; 1];
        assert_eq!(
            stream
                .read(&mut eof)
                .expect("read service EOF after revocation"),
            0,
            "service peer did not observe EOF after trusted shutdown"
        );
    });

    let runner = thread::spawn(move || run(&policy));
    let mut session = broker
        .accept()
        .expect("accept revocable sandbox broker connection");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner
            .join()
            .expect("revocable host UNIX target runner panicked");
        panic!(
            "revocable host UNIX target failed before readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    let mut controller = session
        .send_revocable_host_unix_stream(grant)
        .expect("transfer revocable sandbox host UNIX stream");
    assert_eq!(controller.peer_credentials().uid(), expected_uid);
    assert_eq!(controller.peer_credentials().gid(), expected_gid);

    marker_rx
        .recv()
        .expect("target never reached pre-revocation service exchange");
    controller
        .revoke()
        .expect("revoke transferred sandbox host UNIX stream");
    assert!(controller.is_revoked());

    assert_eq!(
        runner
            .join()
            .expect("revocable host UNIX runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );
    peer.join()
        .expect("revocable host UNIX service thread panicked");

    drop(controller);
    drop(session);
    drop(broker);
    std::fs::remove_file(&service_path).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn post_launch_host_unix_reconnects_twice_without_target_connect_authority() {
    let root = build_reconnect_probe_root();
    let broker_path = unique_path("runtime-host-unix-reconnect-sandbox-broker.sock");
    let service_path = unique_path("runtime-host-unix-reconnect-sandbox-service.sock");
    let _ = std::fs::remove_file(&broker_path);
    let _ = std::fs::remove_file(&service_path);

    let listener = UnixListener::bind(&service_path).expect("bind reconnect sandbox service");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind reconnect sandbox broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /reconnect-probe\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 5000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = write,recvmsg,read,close,openat,exit\n",
        root.display(),
        service_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse reconnect sandbox policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure reconnect runtime broker policy");
    for syscall in ["socket", "connect", "execveat"] {
        assert!(
            !policy.seccomp.allowed_syscalls.contains(syscall),
            "bounded reconnect must not require target {syscall} authority"
        );
    }

    let peer = thread::spawn(move || {
        for (expected_request, reply) in [
            (
                b"runtime-reconnect-one\n".as_slice(),
                b"runtime-reconnect-one-ok\n".as_slice(),
            ),
            (
                b"runtime-reconnect-two\n".as_slice(),
                b"runtime-reconnect-two-ok\n".as_slice(),
            ),
        ] {
            let (mut stream, _) = listener.accept().expect("accept reconnect service round");
            let mut request = vec![0u8; expected_request.len()];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, expected_request);
            stream.write_all(reply).unwrap();
        }
    });

    let runner = thread::spawn(move || run(&policy));
    let expected_uid = unsafe { libc::geteuid() };
    let expected_gid = unsafe { libc::getegid() };
    let mut controller = broker
        .accept_host_unix_reconnect_controller(&service_path, Some((expected_uid, expected_gid)), 2)
        .expect("accept sandbox reconnect controller");

    for round in 1..=2 {
        let credentials = match controller.grant_next(b'R') {
            Ok(credentials) => credentials,
            Err(error) => {
                let runner_result = runner.join().expect("reconnect target runner panicked");
                panic!(
                    "reconnect round {round} failed before grant: {error}; runner result: {runner_result:?}"
                );
            }
        };
        assert_eq!(credentials.uid(), expected_uid);
        assert_eq!(credentials.gid(), expected_gid);
        assert!(credentials.pid() > 0);
        assert_eq!(controller.granted_connections(), round);
    }
    assert!(controller.is_complete());
    assert!(!controller.is_failed());

    assert_eq!(
        runner.join().expect("reconnect runner panicked").unwrap(),
        ChildOutcome::Exited(0)
    );
    peer.join().expect("reconnect service thread panicked");

    drop(controller);
    drop(broker);
    std::fs::remove_file(&service_path).unwrap();
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn post_launch_host_unix_router_selects_two_services_without_target_connect_authority() {
    let root = build_router_probe_root();
    let broker_path = unique_path("runtime-host-unix-router-sandbox-broker.sock");
    let service_a_path = unique_path("runtime-host-unix-router-sandbox-a.sock");
    let service_b_path = unique_path("runtime-host-unix-router-sandbox-b.sock");
    for path in [&broker_path, &service_a_path, &service_b_path] {
        let _ = std::fs::remove_file(path);
    }

    let listener_a = UnixListener::bind(&service_a_path).expect("bind router sandbox service A");
    let listener_b = UnixListener::bind(&service_b_path).expect("bind router sandbox service B");
    let broker = RuntimeFdBroker::bind(&broker_path).expect("bind router sandbox broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /router-probe\n\
         arg = {}\n\
         arg = {}\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 5000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = write,recvmsg,read,close,openat,exit\n",
        root.display(),
        service_a_path.display(),
        service_b_path.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse router sandbox policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure router runtime broker policy");
    for syscall in ["socket", "connect", "execveat"] {
        assert!(
            !policy.seccomp.allowed_syscalls.contains(syscall),
            "bounded router must not require target {syscall} authority"
        );
    }

    let peer_a = thread::spawn(move || {
        let (mut stream, _) = listener_a.accept().expect("accept router service A");
        let mut request = vec![0u8; b"runtime-router-a\n".len()];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, b"runtime-router-a\n");
        stream.write_all(b"runtime-router-a-ok\n").unwrap();
    });
    let peer_b = thread::spawn(move || {
        let (mut stream, _) = listener_b.accept().expect("accept router service B");
        let mut request = vec![0u8; b"runtime-router-b\n".len()];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(request, b"runtime-router-b\n");
        stream.write_all(b"runtime-router-b-ok\n").unwrap();
    });

    let runner = thread::spawn(move || run(&policy));
    let expected_peer = Some((unsafe { libc::geteuid() }, unsafe { libc::getegid() }));
    let mut controller = broker
        .accept_host_unix_router_controller(vec![
            RuntimeHostUnixRoute::new(&service_a_path, expected_peer, 1),
            RuntimeHostUnixRoute::new(&service_b_path, expected_peer, 1),
        ])
        .expect("accept sandbox router controller");

    for expected_route in 0..=1 {
        let grant = match controller.grant_next(b'R') {
            Ok(grant) => grant,
            Err(error) => {
                let runner_result = runner.join().expect("router target runner panicked");
                panic!(
                    "router round {expected_route} failed before grant: {error}; runner result: {runner_result:?}"
                );
            }
        };
        assert_eq!(grant.route_index(), expected_route);
        assert_eq!(grant.credentials().uid(), unsafe { libc::geteuid() });
        assert_eq!(grant.credentials().gid(), unsafe { libc::getegid() });
        assert!(grant.credentials().pid() > 0);
    }
    assert!(controller.is_complete());
    assert_eq!(controller.total_granted_connections(), 2);

    assert_eq!(
        runner.join().expect("router runner panicked").unwrap(),
        ChildOutcome::Exited(0)
    );
    peer_a.join().expect("router service A thread panicked");
    peer_b.join().expect("router service B thread panicked");

    drop(controller);
    drop(broker);
    for path in [service_a_path, service_b_path] {
        std::fs::remove_file(path).unwrap();
    }
    std::fs::remove_dir_all(&root).unwrap();
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
    client
        .shutdown(std::net::Shutdown::Read)
        .expect("explicit bundle peer read shutdown");

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
    drop(client);
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

#[test]
fn bounded_runtime_message_exchange_is_one_shot_and_message_preserving() {
    let socket_path = unique_path("runtime-message-local.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind runtime message broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect runtime message client");
    let mut session = broker.accept().expect("accept runtime message client");
    client
        .write_all(b"R")
        .expect("publish runtime message readiness");
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(64, 64).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    let request = b"runtime-request\n";
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        request.len() as isize
    );
    assert_eq!(controller.receive_request().unwrap(), request);

    let response = b"runtime-response\n";
    controller.send_response(response).unwrap();
    assert!(controller.is_complete());

    let mut received = [0u8; 64];
    let count = unsafe {
        libc::recv(
            endpoint.raw(),
            received.as_mut_ptr().cast::<libc::c_void>(),
            received.len(),
            0,
        )
    };
    assert_eq!(count, response.len() as isize);
    assert_eq!(&received[..count as usize], response);

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));
    assert!(matches!(
        controller.send_response(b"second"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_message_request_deadline_times_out_and_poison_exchange() {
    let socket_path = unique_path("runtime-message-deadline-timeout.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(16, 16).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert!(matches!(
        controller.receive_request_with_deadline(1),
        Err(RuntimeFdBrokerError::RuntimeRequestTimedOut {
            wait_milliseconds: 1
        })
    ));
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(matches!(
        controller.send_response(b"late"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_message_request_deadline_validates_bounds_without_consuming_ready_request() {
    let socket_path = unique_path("runtime-message-deadline-ready.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(64, 64).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert!(matches!(
        controller.receive_request_with_deadline(0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        controller.receive_request_with_deadline(MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS + 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    let request = b"queued-before-deadline
";
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                request.as_ptr().cast::<libc::c_void>(),
                request.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        request.len() as isize
    );
    assert_eq!(
        controller.receive_request_with_deadline(1).unwrap(),
        request
    );
    controller.send_response(b"ok").unwrap();

    let mut response = [0u8; 8];
    let received = unsafe {
        libc::recv(
            endpoint.raw(),
            response.as_mut_ptr().cast::<libc::c_void>(),
            response.len(),
            0,
        )
    };
    assert_eq!(received, 2);
    assert_eq!(&response[..2], b"ok");

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_message_exchange_rejects_invalid_bounds_and_oversized_request() {
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_message_exchange(0, 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_message_exchange(1, MAX_RUNTIME_MESSAGE_BYTES + 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    let socket_path = unique_path("runtime-message-request-too-large.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) = RuntimeFdBroker::prepare_runtime_message_exchange(4, 4).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"12345".as_ptr().cast::<libc::c_void>(),
                5,
                libc::MSG_NOSIGNAL,
            )
        },
        5
    );
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeRequestTooLarge { max_bytes }) if max_bytes == 4
    ));
    assert!(matches!(
        controller.send_response(b"ok"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_message_exchange_poisoning_is_fail_closed_for_response_and_io_failure() {
    let socket_path = unique_path("runtime-message-response-too-large.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) = RuntimeFdBroker::prepare_runtime_message_exchange(16, 4).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"request".as_ptr().cast::<libc::c_void>(),
                7,
                libc::MSG_NOSIGNAL,
            )
        },
        7
    );
    assert_eq!(controller.receive_request().unwrap(), b"request");
    assert!(matches!(
        controller.send_response(b"12345"),
        Err(RuntimeFdBrokerError::RuntimeResponseTooLarge { max_bytes }) if max_bytes == 4
    ));
    assert!(matches!(
        controller.send_response(b"ok"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);

    let socket_path = unique_path("runtime-message-io-failure.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(16, 16).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"request".as_ptr().cast::<libc::c_void>(),
                7,
                libc::MSG_NOSIGNAL,
            )
        },
        7
    );
    assert_eq!(controller.receive_request().unwrap(), b"request");
    assert_eq!(unsafe { libc::shutdown(endpoint.raw(), libc::SHUT_RD) }, 0);
    assert!(matches!(
        controller.send_response(b"response"),
        Err(RuntimeFdBrokerError::Io { .. })
    ));
    assert!(matches!(
        controller.send_response(b"retry"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn revocable_runtime_stream_is_receive_only_bounded_and_revokes_to_eof() {
    let socket_path = unique_path("runtime-revocable-local.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind revocable stream broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect revocable stream client");
    let mut session = broker.accept().expect("accept revocable stream client");
    client
        .write_all(b"R")
        .expect("publish revocable stream readiness");
    session
        .wait_for_ready(b'R')
        .expect("consume revocable stream readiness");

    let marker = b"runtime-revocable-stream\n";
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_revocable_byte_stream(marker.len() as u64)
            .expect("prepare revocable byte stream");
    session
        .send_revocable_byte_stream(grant)
        .expect("transfer revocable stream endpoint");
    let received = receive_one_fd(&client);

    let byte = b"x";
    assert_eq!(
        unsafe {
            libc::send(
                received.raw(),
                byte.as_ptr().cast::<libc::c_void>(),
                byte.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        -1,
        "target endpoint unexpectedly retained send authority"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EPIPE)
    );

    let mut over_budget = marker.to_vec();
    over_budget.push(b'!');
    assert!(matches!(
        controller.send_all(&over_budget),
        Err(RuntimeFdBrokerError::RuntimeStreamBudgetExceeded { max_bytes })
            if max_bytes == marker.len() as u64
    ));
    assert_eq!(controller.sent_bytes(), 0);

    controller
        .send_all(marker)
        .expect("send bounded revocable stream marker");
    assert_eq!(controller.sent_bytes(), marker.len() as u64);
    assert_eq!(read_exact_fd(received.raw(), marker.len()), marker);

    controller.revoke().expect("revoke future stream bytes");
    assert!(controller.is_revoked());
    let mut eof = [0u8; 1];
    assert_eq!(
        unsafe {
            libc::read(
                received.raw(),
                eof.as_mut_ptr().cast::<libc::c_void>(),
                eof.len(),
            )
        },
        0,
        "target did not observe EOF after queued bytes drained"
    );
    assert!(matches!(
        controller.send_all(b"late"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("revocation")
    ));
    assert!(matches!(
        controller.revoke(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly once")
    ));

    let (second_grant, _second_controller) =
        RuntimeFdBroker::prepare_revocable_byte_stream(16).unwrap();
    assert!(matches!(
        session.send_revocable_byte_stream(second_grant),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    drop(received);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn revocable_runtime_stream_rejects_invalid_ceiling_and_poisoned_send_retry() {
    assert!(matches!(
        RuntimeFdBroker::prepare_revocable_byte_stream(0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_revocable_byte_stream(MAX_RUNTIME_REVOCABLE_STREAM_BYTES + 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    let socket_path = unique_path("runtime-revocable-failure.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind stream failure broker");
    let mut client = UnixStream::connect(broker.path()).expect("connect stream failure client");
    let mut session = broker.accept().expect("accept stream failure client");
    client
        .write_all(b"R")
        .expect("publish stream failure readiness");
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) = RuntimeFdBroker::prepare_revocable_byte_stream(64).unwrap();
    session.send_revocable_byte_stream(grant).unwrap();
    let received = receive_one_fd(&client);
    assert_eq!(
        unsafe { libc::shutdown(received.raw(), libc::SHUT_RD) },
        0,
        "explicit peer read shutdown must make controller send failure deterministic"
    );

    assert!(matches!(
        controller.send_all(b"will-fail"),
        Err(RuntimeFdBrokerError::Io { .. })
    ));
    drop(received);
    assert!(matches!(
        controller.send_all(b"retry"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(matches!(
        controller.revoke(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_message_response_deadline_validates_bounds_without_consuming_request() {
    let socket_path = unique_path("runtime-message-response-deadline-ready.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(16, 16).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"request".as_ptr().cast::<libc::c_void>(),
                7,
                libc::MSG_NOSIGNAL,
            )
        },
        7
    );
    assert_eq!(controller.receive_request().unwrap(), b"request");

    assert!(matches!(
        controller.send_response_with_deadline(b"ok", 0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        controller
            .send_response_with_deadline(b"ok", MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS + 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    controller.send_response_with_deadline(b"ok", 1000).unwrap();
    let mut response = [0u8; 8];
    assert_eq!(
        unsafe {
            libc::recv(
                endpoint.raw(),
                response.as_mut_ptr().cast::<libc::c_void>(),
                response.len(),
                0,
            )
        },
        2
    );
    assert_eq!(&response[..2], b"ok");
}

#[test]
fn runtime_multi_message_response_deadline_closes_on_real_backpressure() {
    let socket_path = unique_path("runtime-multi-response-backpressure.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) = RuntimeFdBroker::prepare_runtime_multi_message_exchange(
        1,
        MAX_RUNTIME_MESSAGE_BYTES,
        MAX_RUNTIME_MULTI_MESSAGE_ROUNDS,
    )
    .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    let response = vec![0x5au8; MAX_RUNTIME_MESSAGE_BYTES as usize];

    let mut timed_out = None;
    for round in 0..MAX_RUNTIME_MULTI_MESSAGE_ROUNDS {
        assert_eq!(
            unsafe {
                libc::send(
                    endpoint.raw(),
                    b"x".as_ptr().cast::<libc::c_void>(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            },
            1
        );
        assert_eq!(
            controller.receive_request_with_deadline(1000).unwrap(),
            b"x"
        );

        match controller.send_response_with_deadline(&response, 10) {
            Ok(()) => {}
            Err(RuntimeFdBrokerError::RuntimeResponseTimedOut { wait_milliseconds }) => {
                assert_eq!(wait_milliseconds, 10);
                timed_out = Some(round);
                break;
            }
            Err(other) => panic!("unexpected response publication result: {other}"),
        }
    }

    let timed_out_round = timed_out.expect(
        "32 maximum-size unread response packets must create deterministic socket backpressure",
    );
    assert!(timed_out_round > 0);
    assert!(controller.completed_rounds() < MAX_RUNTIME_MULTI_MESSAGE_ROUNDS);
    assert!(!controller.is_complete());
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn runtime_multi_message_session_deadline_is_nonresettable_and_excludes_per_operation_deadlines() {
    let socket_path = unique_path("runtime-multi-session-deadline-config.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(16, 16, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert!(matches!(
        controller.start_session_deadline(0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        controller.start_session_deadline(MAX_RUNTIME_MULTI_MESSAGE_SESSION_MILLISECONDS + 1),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    controller.start_session_deadline(1000).unwrap();
    assert!(matches!(
        controller.start_session_deadline(1000),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message)) if message.contains("cannot be reset")
    ));

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"one".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert!(matches!(
        controller.receive_request_with_deadline(1000),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message)) if message.contains("cannot be combined")
    ));
    assert_eq!(controller.receive_request().unwrap(), b"one");
    assert!(matches!(
        controller.send_response_with_deadline(b"ONE", 1000),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message)) if message.contains("cannot be combined")
    ));
    controller.send_response(b"ONE").unwrap();

    let mut response = [0u8; 8];
    assert_eq!(
        unsafe {
            libc::recv(
                endpoint.raw(),
                response.as_mut_ptr().cast::<libc::c_void>(),
                response.len(),
                0,
            )
        },
        3
    );
    assert_eq!(&response[..3], b"ONE");
    assert_eq!(controller.completed_rounds(), 1);
}

#[test]
fn runtime_multi_message_session_deadline_spans_rounds_and_beats_queued_request() {
    let socket_path = unique_path("runtime-multi-session-deadline-rounds.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(16, 16, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.start_session_deadline(50).unwrap();

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"one".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert_eq!(controller.receive_request().unwrap(), b"one");
    controller.send_response(b"ONE").unwrap();
    let mut response = [0u8; 8];
    assert_eq!(
        unsafe {
            libc::recv(
                endpoint.raw(),
                response.as_mut_ptr().cast::<libc::c_void>(),
                response.len(),
                0,
            )
        },
        3
    );

    std::thread::sleep(std::time::Duration::from_millis(150));
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"two".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeSessionTimedOut { limit_milliseconds }) if limit_milliseconds == 50
    ));
    assert_eq!(controller.completed_rounds(), 1);
    assert!(!controller.is_complete());
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(matches!(
        controller.receive_request_with_deadline(1000),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn runtime_multi_message_session_deadline_also_bounds_response_publication() {
    let socket_path = unique_path("runtime-multi-session-deadline-response.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(16, 16, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.start_session_deadline(50).unwrap();

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"one".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert_eq!(controller.receive_request().unwrap(), b"one");

    std::thread::sleep(std::time::Duration::from_millis(150));
    assert!(matches!(
        controller.send_response(b"late"),
        Err(RuntimeFdBrokerError::RuntimeSessionTimedOut { limit_milliseconds }) if limit_milliseconds == 50
    ));
    assert_eq!(controller.completed_rounds(), 0);
    assert!(!controller.is_complete());
    assert!(matches!(
        controller.send_response(b"retry"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(matches!(
        controller.send_response_with_deadline(b"retry", 1000),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn acknowledged_correlated_runtime_exchange_requires_exact_response_ack() {
    let socket_path = unique_path("runtime-auth-ack-success.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0x6cu8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_acknowledged_correlated_exchange(16, 16, 3, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.publish_challenge().unwrap();
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 41, b"one");
    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 42, b"two");
    assert_eq!(controller.receive_request().unwrap().request_id(), 41);
    assert_eq!(controller.receive_request().unwrap().request_id(), 42);

    controller.send_response(42, b"TWO").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (42, b"TWO".to_vec())
    );
    assert_eq!(controller.published_responses(), 1);
    assert_eq!(controller.acknowledged_responses(), 0);
    assert_eq!(controller.awaiting_acknowledgment_request_id(), Some(42));
    assert!(!controller.is_complete());

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("outstanding response acknowledgment")
    ));
    assert!(matches!(
        controller.send_response(41, b"ONE"),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("one published response")
    ));

    send_authenticated_runtime_acknowledgment(endpoint.raw(), &key, &challenge, 42, b"TWO");
    assert_eq!(controller.receive_acknowledgment().unwrap(), 42);
    assert_eq!(controller.acknowledged_responses(), 1);
    assert_eq!(controller.awaiting_acknowledgment_request_id(), None);

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 43, b"three");
    let third = controller.receive_request().unwrap();
    assert_eq!(third.request_id(), 43);
    assert_eq!(third.payload(), b"three");

    controller.send_response(43, b"THREE").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (43, b"THREE".to_vec())
    );
    send_authenticated_runtime_acknowledgment(endpoint.raw(), &key, &challenge, 43, b"THREE");
    assert_eq!(controller.receive_acknowledgment().unwrap(), 43);

    controller.send_response(41, b"ONE").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (41, b"ONE".to_vec())
    );
    send_authenticated_runtime_acknowledgment(endpoint.raw(), &key, &challenge, 41, b"ONE");
    assert_eq!(controller.receive_acknowledgment().unwrap(), 41);

    assert_eq!(controller.received_requests(), 3);
    assert_eq!(controller.published_responses(), 3);
    assert_eq!(controller.acknowledged_responses(), 3);
    assert_eq!(controller.pending_requests(), 0);
    assert_eq!(controller.max_requests(), 3);
    assert_eq!(controller.max_in_flight(), 2);
    assert!(controller.challenge_published());
    assert!(controller.is_complete());
}

#[test]
fn acknowledged_correlated_runtime_exchange_rejects_request_before_ack_terminally() {
    let socket_path = unique_path("runtime-auth-ack-ordering.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0x44u8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_acknowledged_correlated_exchange(16, 16, 2, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.publish_challenge().unwrap();
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 11, b"one");
    assert_eq!(controller.receive_request().unwrap().request_id(), 11);
    controller.send_response(11, b"ONE").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (11, b"ONE".to_vec())
    );

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 12, b"too-early");
    assert!(matches!(
        controller.receive_acknowledgment(),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("must be the peer's next packet")
    ));
    assert_eq!(controller.acknowledged_responses(), 0);
    assert!(!controller.is_complete());
    assert!(matches!(
        controller.receive_acknowledgment(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn acknowledged_correlated_runtime_exchange_rejects_wrong_response_digest_terminally() {
    let socket_path = unique_path("runtime-auth-ack-mismatch.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0x91u8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_acknowledged_correlated_exchange(16, 16, 2, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.publish_challenge().unwrap();
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 7, b"request");
    assert_eq!(controller.receive_request().unwrap().request_id(), 7);
    controller.send_response(7, b"OK").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (7, b"OK".to_vec())
    );

    let wrong_digest = test_runtime_response_sha256(b"WRONG");
    send_authenticated_runtime_acknowledgment_digest(
        endpoint.raw(),
        &key,
        &challenge,
        7,
        &wrong_digest,
    );
    assert!(matches!(
        controller.receive_acknowledgment(),
        Err(RuntimeFdBrokerError::RuntimeAcknowledgmentMismatch { request_id }) if request_id == 7
    ));
    assert_eq!(controller.acknowledged_responses(), 0);
    assert!(!controller.is_complete());
    assert!(matches!(
        controller.receive_acknowledgment(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn authenticated_correlated_runtime_exchange_authenticates_and_correlates() {
    let socket_path = unique_path("runtime-auth-correlated-success.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0x5au8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_authenticated_correlated_exchange(16, 16, 3, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("challenge")
    ));
    controller.publish_challenge().unwrap();
    assert!(controller.challenge_published());
    assert!(matches!(
        controller.publish_challenge(),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("exactly once")
    ));
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 41, b"one");
    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 42, b"two");

    let first = controller.receive_request().unwrap();
    assert_eq!(first.request_id(), 41);
    assert_eq!(first.payload(), b"one");
    let second = controller.receive_request().unwrap();
    assert_eq!(second.request_id(), 42);
    assert_eq!(second.payload(), b"two");
    assert_eq!(controller.pending_requests(), 2);
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("in-flight request limit")
    ));

    controller.send_response(42, b"TWO").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (42, b"TWO".to_vec())
    );

    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 43, b"three");
    let third = controller.receive_request().unwrap();
    assert_eq!(third.request_id(), 43);
    assert_eq!(third.payload(), b"three");

    controller.send_response(43, b"THREE").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (43, b"THREE".to_vec())
    );
    controller.send_response(41, b"ONE").unwrap();
    assert_eq!(
        receive_authenticated_runtime_response(endpoint.raw(), &key, &challenge),
        (41, b"ONE".to_vec())
    );

    assert_eq!(controller.received_requests(), 3);
    assert_eq!(controller.completed_responses(), 3);
    assert_eq!(controller.pending_requests(), 0);
    assert_eq!(controller.max_requests(), 3);
    assert_eq!(controller.max_in_flight(), 2);
    assert!(controller.is_complete());
}

#[test]
fn authenticated_correlated_runtime_exchange_rejects_bad_mac_terminally() {
    let socket_path = unique_path("runtime-auth-correlated-bad-mac.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0x33u8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_authenticated_correlated_exchange(16, 16, 2, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.publish_challenge().unwrap();
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    let request_id = 7u64;
    let payload = b"tamper";
    let mut tag = test_runtime_auth_tag(
        &key,
        &challenge,
        TEST_RUNTIME_AUTH_REQUEST_KIND,
        request_id,
        payload,
    );
    tag[0] ^= 0x80;
    let mut frame = Vec::new();
    frame.push(TEST_RUNTIME_AUTH_REQUEST_KIND);
    frame.push(TEST_RUNTIME_AUTH_VERSION);
    frame.extend_from_slice(&request_id.to_le_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&tag);
    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                frame.as_ptr().cast::<libc::c_void>(),
                frame.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        frame.len() as isize
    );

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeAuthenticationFailed)
    ));
    send_authenticated_runtime_request(endpoint.raw(), &key, &challenge, 8, b"valid");
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
}

#[test]
fn authenticated_correlated_runtime_exchange_binds_session_challenge() {
    let socket_path = unique_path("runtime-auth-correlated-replay.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let key = [0xa5u8; RUNTIME_AUTH_KEY_BYTES];
    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_authenticated_correlated_exchange(16, 16, 2, 2, key)
            .unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);
    controller.publish_challenge().unwrap();
    let challenge = receive_runtime_auth_challenge(endpoint.raw());

    let mut stale_challenge = challenge;
    stale_challenge[0] ^= 0x01;
    send_authenticated_runtime_request(endpoint.raw(), &key, &stale_challenge, 9, b"replay");

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeAuthenticationFailed)
    ));
    assert_eq!(controller.received_requests(), 0);
    assert_eq!(controller.pending_requests(), 0);
}

#[test]
fn correlated_runtime_exchange_tracks_multiple_inflight_and_out_of_order_responses() {
    let socket_path = unique_path("runtime-correlated-out-of-order.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_correlated_exchange(16, 16, 3, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    send_correlated_packet(endpoint.raw(), 41, b"one");
    send_correlated_packet(endpoint.raw(), 42, b"two");

    let first = controller.receive_request().unwrap();
    assert_eq!(first.request_id(), 41);
    assert_eq!(first.payload(), b"one");
    let second = controller.receive_request().unwrap();
    assert_eq!(second.request_id(), 42);
    assert_eq!(second.payload(), b"two");
    assert_eq!(controller.pending_requests(), 2);
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::InvalidConfiguration(message))
            if message.contains("in-flight request limit")
    ));

    controller.send_response(42, b"TWO").unwrap();
    assert_eq!(
        receive_correlated_packet(endpoint.raw()),
        (42, b"TWO".to_vec())
    );
    assert_eq!(controller.pending_requests(), 1);

    send_correlated_packet(endpoint.raw(), 43, b"three");
    let third = controller.receive_request().unwrap();
    assert_eq!(third.request_id(), 43);
    assert_eq!(third.into_payload(), b"three");
    assert_eq!(controller.received_requests(), 3);
    assert_eq!(controller.pending_requests(), 2);

    controller.send_response(43, b"THREE").unwrap();
    assert_eq!(
        receive_correlated_packet(endpoint.raw()),
        (43, b"THREE".to_vec())
    );
    controller.send_response(41, b"ONE").unwrap();
    assert_eq!(
        receive_correlated_packet(endpoint.raw()),
        (41, b"ONE".to_vec())
    );

    assert_eq!(controller.completed_responses(), 3);
    assert_eq!(controller.pending_requests(), 0);
    assert_eq!(controller.max_requests(), 3);
    assert_eq!(controller.max_in_flight(), 2);
    assert!(controller.is_complete());
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("request limit")
    ));
}

#[test]
fn correlated_runtime_exchange_rejects_duplicate_request_id_terminally() {
    let socket_path = unique_path("runtime-correlated-duplicate.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_correlated_exchange(16, 16, 3, 3).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    send_correlated_packet(endpoint.raw(), 7, b"first");
    send_correlated_packet(endpoint.raw(), 7, b"duplicate");
    assert_eq!(controller.receive_request().unwrap().request_id(), 7);
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeDuplicateRequestId { request_id }) if request_id == 7
    ));
    assert!(matches!(
        controller.send_response(7, b"FIRST"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(!controller.is_complete());
}

#[test]
fn correlated_runtime_exchange_rejects_unknown_response_id_terminally() {
    let socket_path = unique_path("runtime-correlated-unknown-response.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_correlated_exchange(16, 16, 2, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    send_correlated_packet(endpoint.raw(), 9, b"request");
    assert_eq!(controller.receive_request().unwrap().request_id(), 9);
    assert!(matches!(
        controller.send_response(10, b"wrong"),
        Err(RuntimeFdBrokerError::RuntimeUnknownRequestId { request_id }) if request_id == 10
    ));
    assert!(matches!(
        controller.send_response(9, b"correct"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(!controller.is_complete());
}

#[test]
fn correlated_runtime_exchange_rejects_unsafe_bounds_without_creating_a_session() {
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_correlated_exchange(
            16,
            16,
            MIN_RUNTIME_CORRELATED_REQUESTS - 1,
            MIN_RUNTIME_CORRELATED_IN_FLIGHT,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_correlated_exchange(
            16,
            16,
            MAX_RUNTIME_CORRELATED_REQUESTS + 1,
            MIN_RUNTIME_CORRELATED_IN_FLIGHT,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_correlated_exchange(
            16,
            16,
            2,
            MIN_RUNTIME_CORRELATED_IN_FLIGHT - 1,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_correlated_exchange(
            16,
            16,
            MAX_RUNTIME_CORRELATED_IN_FLIGHT,
            MAX_RUNTIME_CORRELATED_IN_FLIGHT + 1,
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_correlated_exchange(16, 16, 2, 3),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
}

#[test]
fn bounded_runtime_multi_message_exchange_completes_exact_round_limit() {
    let socket_path = unique_path("runtime-multi-message.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(16, 16, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    for (request, response, round) in [
        (b"one".as_slice(), b"ONE".as_slice(), 1u32),
        (b"two".as_slice(), b"TWO".as_slice(), 2u32),
    ] {
        assert_eq!(
            unsafe {
                libc::send(
                    endpoint.raw(),
                    request.as_ptr().cast::<libc::c_void>(),
                    request.len(),
                    libc::MSG_NOSIGNAL,
                )
            },
            request.len() as isize
        );
        assert_eq!(
            controller.receive_request_with_deadline(1000).unwrap(),
            request
        );
        controller.send_response(response).unwrap();

        let mut received = [0u8; 16];
        let count = unsafe {
            libc::recv(
                endpoint.raw(),
                received.as_mut_ptr().cast::<libc::c_void>(),
                received.len(),
                0,
            )
        };
        assert_eq!(count, response.len() as isize);
        assert_eq!(&received[..response.len()], response);
        assert_eq!(controller.completed_rounds(), round);
        assert_eq!(controller.max_rounds(), 2);
        assert_eq!(controller.is_complete(), round == 2);
    }

    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("round limit")
    ));
}

#[test]
fn runtime_multi_message_exchange_rejects_invalid_round_bounds() {
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(
            1,
            1,
            MIN_RUNTIME_MULTI_MESSAGE_ROUNDS - 1
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(
            1,
            1,
            MAX_RUNTIME_MULTI_MESSAGE_ROUNDS + 1
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
}

#[test]
fn runtime_multi_message_exchange_second_round_oversize_is_terminal() {
    let socket_path = unique_path("runtime-multi-message-oversize.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(4, 4, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"one".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert_eq!(controller.receive_request().unwrap(), b"one");
    controller.send_response(b"ok").unwrap();
    let mut response = [0u8; 4];
    assert_eq!(
        unsafe {
            libc::recv(
                endpoint.raw(),
                response.as_mut_ptr().cast::<libc::c_void>(),
                response.len(),
                0,
            )
        },
        2
    );

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"12345".as_ptr().cast::<libc::c_void>(),
                5,
                libc::MSG_NOSIGNAL,
            )
        },
        5
    );
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::RuntimeRequestTooLarge { max_bytes }) if max_bytes == 4
    ));
    assert!(matches!(
        controller.receive_request(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(!controller.is_complete());
    assert_eq!(controller.completed_rounds(), 1);
}

#[test]
fn runtime_multi_message_exchange_second_round_timeout_is_terminal() {
    let socket_path = unique_path("runtime-multi-message-timeout.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_multi_message_exchange(16, 16, 2).unwrap();
    session.send_runtime_message_channel(grant).unwrap();
    let endpoint = receive_one_fd(&client);

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"one".as_ptr().cast::<libc::c_void>(),
                3,
                libc::MSG_NOSIGNAL,
            )
        },
        3
    );
    assert_eq!(controller.receive_request().unwrap(), b"one");
    controller.send_response(b"ok").unwrap();
    let mut response = [0u8; 4];
    assert_eq!(
        unsafe {
            libc::recv(
                endpoint.raw(),
                response.as_mut_ptr().cast::<libc::c_void>(),
                response.len(),
                0,
            )
        },
        2
    );

    assert!(matches!(
        controller.receive_request_with_deadline(1),
        Err(RuntimeFdBrokerError::RuntimeRequestTimedOut { wait_milliseconds }) if wait_milliseconds == 1
    ));
    assert!(matches!(
        controller.send_response(b"retry"),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));
    assert!(!controller.is_complete());
    assert_eq!(controller.completed_rounds(), 1);
}

#[test]
fn bounded_runtime_message_exchange_reaches_real_target() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-message-sandbox.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind sandbox runtime message broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 5\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,sendmsg,close,exit\n",
        root.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse runtime message policy");
    broker.configure_policy(&mut policy, 10).unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_message_exchange(4096, 4096).unwrap();
    let runner = thread::spawn(move || run(&policy));
    let mut session = broker.accept().expect("accept runtime message target");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner.join().expect("runtime message runner panicked");
        panic!(
            "runtime message target failed before readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    session.send_runtime_message_channel(grant).unwrap();

    assert_eq!(
        controller.receive_request_with_deadline(1000).unwrap(),
        b"runtime-request\n"
    );
    controller
        .send_response(b"runtime-response\n")
        .expect("send bounded runtime response");
    assert!(controller.is_complete());

    assert_eq!(
        runner
            .join()
            .expect("runtime message runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );

    drop(session);
    drop(broker);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn revocable_runtime_stream_reaches_real_target_and_revokes_future_bytes() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-revocable-sandbox.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).expect("bind sandbox revocable broker");
    let text = format!(
        "filesystem.root = {}\n\
         identity.hostname = security-lab\n\
         executable = /probe\n\
         arg = 4\n\
         working_dir = /work\n\
         stdio.stdin = closed\n\
         stdio.stdout = closed\n\
         stdio.stderr = closed\n\
         limit.wall_clock_milliseconds = 3000\n\
         limit.cpu_seconds = 2\n\
         limit.address_space_bytes = 134217728\n\
         limit.file_size_bytes = 1048576\n\
         limit.open_files = 32\n\
         seccomp.allow = execveat,write,recvmsg,sendmsg,read,close,exit\n",
        root.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse revocable stream policy");
    broker
        .configure_policy(&mut policy, 10)
        .expect("configure revocable stream broker");

    let marker = b"runtime-revocable-stream\n";
    let (grant, mut controller) = RuntimeFdBroker::prepare_revocable_byte_stream(4096)
        .expect("prepare sandbox revocable stream");
    let runner = thread::spawn(move || run(&policy));
    let mut session = broker
        .accept()
        .expect("accept sandbox revocable connection");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner
            .join()
            .expect("revocable stream runner panicked before readiness");
        panic!(
            "revocable target failed before post-exec readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    session
        .send_revocable_byte_stream(grant)
        .expect("transfer sandbox revocable stream");
    controller
        .send_all(marker)
        .expect("send sandbox revocable bytes");
    controller
        .revoke()
        .expect("revoke sandbox future byte supply");

    assert_eq!(
        runner
            .join()
            .expect("revocable stream runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );
    assert_eq!(controller.sent_bytes(), marker.len() as u64);
    assert!(controller.is_revoked());

    drop(session);
    drop(broker);
    std::fs::remove_dir_all(&root).expect("remove revocable stream sandbox root");
}
