use crate::{PolicyError, SandboxPolicy};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

pub const MAX_RUNTIME_SEALED_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_RUNTIME_SEALED_BUNDLE_ITEMS: usize = 2;
pub const MAX_RUNTIME_SEALED_BUNDLE_ITEMS: usize = 8;
pub const MAX_RUNTIME_SEALED_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RUNTIME_REVOCABLE_STREAM_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RUNTIME_MESSAGE_BYTES: u64 = 64 * 1024;
pub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;
pub const MIN_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 2;
pub const MAX_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 32;

#[derive(Debug)]
pub enum RuntimeFdBrokerError {
    UnsupportedPlatform(String),
    InvalidConfiguration(String),
    Policy(PolicyError),
    SourceNotRegular,
    SourceNotReadable,
    SourcePathOnly,
    SourceSnapshotTooLarge {
        max_bytes: u64,
    },
    SnapshotBundleTooLarge {
        max_bytes: u64,
    },
    RuntimeStreamBudgetExceeded {
        max_bytes: u64,
    },
    RuntimeRequestTooLarge {
        max_bytes: u64,
    },
    RuntimeResponseTooLarge {
        max_bytes: u64,
    },
    RuntimeRequestTimedOut {
        wait_milliseconds: u64,
    },
    UnexpectedPeer {
        expected_pid: i32,
        expected_uid: u32,
        expected_gid: u32,
        actual_pid: i32,
        actual_uid: u32,
        actual_gid: u32,
    },
    Protocol(String),
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl RuntimeFdBrokerError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for RuntimeFdBrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(message) => f.write_str(message),
            Self::InvalidConfiguration(message) => write!(f, "invalid broker configuration: {message}"),
            Self::Policy(error) => write!(f, "broker policy integration failed: {error}"),
            Self::SourceNotRegular => f.write_str("runtime FD broker source must be a regular file"),
            Self::SourceNotReadable => {
                f.write_str("runtime FD broker source must already carry read authority")
            }
            Self::SourcePathOnly => {
                f.write_str("runtime FD broker does not accept O_PATH-only sources")
            }
            Self::SourceSnapshotTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker source exceeds sealed snapshot byte ceiling of {max_bytes}"
            ),
            Self::SnapshotBundleTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker sealed snapshot bundle exceeds aggregate byte ceiling of {max_bytes}"
            ),
            Self::RuntimeStreamBudgetExceeded { max_bytes } => write!(
                f,
                "runtime FD broker stream exceeds total byte ceiling of {max_bytes}"
            ),
            Self::RuntimeRequestTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker request exceeds message byte ceiling of {max_bytes}"
            ),
            Self::RuntimeResponseTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker response exceeds message byte ceiling of {max_bytes}"
            ),
            Self::RuntimeRequestTimedOut { wait_milliseconds } => write!(
                f,
                "runtime FD broker request wait exceeded {wait_milliseconds} ms"
            ),
            Self::UnexpectedPeer {
                expected_pid,
                expected_uid,
                expected_gid,
                actual_pid,
                actual_uid,
                actual_gid,
            } => write!(
                f,
                "runtime FD broker peer mismatch: expected pid/uid/gid {expected_pid}/{expected_uid}/{expected_gid}, got {actual_pid}/{actual_uid}/{actual_gid}"
            ),
            Self::Protocol(message) => write!(f, "runtime FD broker protocol error: {message}"),
            Self::Io { operation, source } => write!(f, "{operation}: {source}"),
        }
    }
}

impl Error for RuntimeFdBrokerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Component, PathBuf};

    const MAX_UNIX_PATH_BYTES: usize = 107;
    const MFD_CLOEXEC: libc::c_uint = 0x0001;
    const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;

    #[derive(Debug)]
    pub struct PreparedReadOnlyRegularFile {
        fd: RawFd,
    }

    impl Drop for PreparedReadOnlyRegularFile {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct PreparedSealedRegularFileSnapshot {
        fd: RawFd,
        len: u64,
    }

    impl PreparedSealedRegularFileSnapshot {
        pub fn len(&self) -> u64 {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    impl Drop for PreparedSealedRegularFileSnapshot {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct PreparedSealedSnapshotBundle {
        grants: Vec<PreparedSealedRegularFileSnapshot>,
        total_len: u64,
    }

    impl PreparedSealedSnapshotBundle {
        pub fn item_count(&self) -> usize {
            self.grants.len()
        }

        pub fn total_len(&self) -> u64 {
            self.total_len
        }
    }

    #[derive(Debug)]
    pub struct PreparedRevocableByteStream {
        fd: RawFd,
    }

    impl Drop for PreparedRevocableByteStream {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RevocableByteStreamState {
        Active,
        Revoked,
        Failed,
    }

    #[derive(Debug)]
    pub struct RevocableByteStreamController {
        fd: RawFd,
        max_bytes: u64,
        sent_bytes: u64,
        state: RevocableByteStreamState,
    }

    impl Drop for RevocableByteStreamController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl RevocableByteStreamController {
        pub fn sent_bytes(&self) -> u64 {
            self.sent_bytes
        }

        pub fn is_revoked(&self) -> bool {
            self.state == RevocableByteStreamState::Revoked
        }

        /// Send bytes while the stream is active.
        ///
        /// The complete slice is budget-checked before any byte is sent. Once
        /// an I/O/protocol failure occurs the controller becomes terminally
        /// failed so callers never retry an ambiguous partial send.
        pub fn send_all(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RevocableByteStreamState::Active {
                let message = match self.state {
                    RevocableByteStreamState::Revoked => {
                        "revocable runtime stream is closed after revocation"
                    }
                    RevocableByteStreamState::Failed => {
                        "revocable runtime stream is closed after an I/O or protocol failure"
                    }
                    RevocableByteStreamState::Active => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            let requested = u64::try_from(bytes.len()).map_err(|_| {
                RuntimeFdBrokerError::RuntimeStreamBudgetExceeded {
                    max_bytes: self.max_bytes,
                }
            })?;
            let projected = self.sent_bytes.checked_add(requested).ok_or(
                RuntimeFdBrokerError::RuntimeStreamBudgetExceeded {
                    max_bytes: self.max_bytes,
                },
            )?;
            if projected > self.max_bytes {
                return Err(RuntimeFdBrokerError::RuntimeStreamBudgetExceeded {
                    max_bytes: self.max_bytes,
                });
            }

            let mut offset = 0usize;
            while offset < bytes.len() {
                let sent = unsafe {
                    libc::send(
                        self.fd,
                        bytes[offset..].as_ptr().cast::<libc::c_void>(),
                        bytes.len() - offset,
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.state = RevocableByteStreamState::Failed;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot send revocable runtime stream bytes",
                        error,
                    ));
                }
                if sent == 0 {
                    self.state = RevocableByteStreamState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "revocable runtime stream made zero send progress".to_owned(),
                    ));
                }
                offset += sent as usize;
                self.sent_bytes += sent as u64;
            }
            Ok(())
        }

        /// Stop all future host-to-target byte supply.
        ///
        /// Bytes already queued in the UNIX stream remain readable; once they
        /// drain, the target observes EOF. This does not remotely close or
        /// invalidate the target's received descriptor.
        pub fn revoke(&mut self) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RevocableByteStreamState::Active {
                let message = match self.state {
                    RevocableByteStreamState::Revoked => {
                        "revocable runtime stream may be revoked exactly once"
                    }
                    RevocableByteStreamState::Failed => {
                        "revocable runtime stream is closed after an I/O or protocol failure"
                    }
                    RevocableByteStreamState::Active => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }
            if unsafe { libc::shutdown(self.fd, libc::SHUT_WR) } == -1 {
                self.state = RevocableByteStreamState::Failed;
                return Err(RuntimeFdBrokerError::io(
                    "cannot revoke future runtime stream bytes",
                    std::io::Error::last_os_error(),
                ));
            }
            self.state = RevocableByteStreamState::Revoked;
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct PreparedRuntimeMessageChannel {
        fd: RawFd,
    }

    impl Drop for PreparedRuntimeMessageChannel {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeMessageExchangeState {
        AwaitingRequest,
        RequestReceived,
        Complete,
        Failed,
    }

    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController {
        fd: RawFd,
        max_request_bytes: u64,
        max_response_bytes: u64,
        state: RuntimeMessageExchangeState,
    }

    impl Drop for RuntimeMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct RuntimeMultiMessageExchangeController {
        controller: RuntimeMessageExchangeController,
        max_rounds: u32,
        completed_rounds: u32,
    }

    #[derive(Debug)]
    struct RequestDeadlineTimer {
        fd: RawFd,
    }

    impl RequestDeadlineTimer {
        fn new(wait_milliseconds: u64) -> Result<Self, RuntimeFdBrokerError> {
            let fd = unsafe {
                libc::timerfd_create(
                    libc::CLOCK_MONOTONIC,
                    libc::TFD_CLOEXEC | libc::TFD_NONBLOCK,
                )
            };
            if fd == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOSYS) {
                    return Err(RuntimeFdBrokerError::UnsupportedPlatform(
                        "runtime message request deadlines require timerfd".to_owned(),
                    ));
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot create runtime message request deadline timer",
                    error,
                ));
            }

            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: (wait_milliseconds / 1000) as libc::time_t,
                    tv_nsec: ((wait_milliseconds % 1000) * 1_000_000) as libc::c_long,
                },
            };
            if unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) } == -1 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot arm runtime message request deadline timer",
                    error,
                ));
            }

            Ok(Self { fd })
        }
    }

    impl Drop for RequestDeadlineTimer {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl RuntimeMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            self.state == RuntimeMessageExchangeState::Complete
        }

        /// Receive exactly one non-empty request packet from the target.
        ///
        /// SOCK_SEQPACKET preserves the message boundary. Oversized/truncated,
        /// empty/closed-peer, and I/O failures make the exchange terminal so a
        /// caller never retries an ambiguous protocol state.
        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            self.receive_request_inner(None)
        }

        /// Receive the one request packet with a bounded launcher-side wait.
        ///
        /// The timeout begins when this method is called, not when the target
        /// endpoint is granted. CLOCK_MONOTONIC timerfd state keeps elapsed time
        /// across EINTR. If request readiness and timer readiness are observed in
        /// one poll cycle, request readiness wins. Timeout is terminal.
        pub fn receive_request_with_deadline(
            &mut self,
            wait_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            if !(1..=super::MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS)
                .contains(&wait_milliseconds)
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                    "runtime message request wait must be between 1 and {} milliseconds",
                    super::MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS
                )));
            }
            self.receive_request_inner(Some(wait_milliseconds))
        }

        fn receive_request_inner(
            &mut self,
            wait_milliseconds: Option<u64>,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            if self.state != RuntimeMessageExchangeState::AwaitingRequest {
                let message = match self.state {
                    RuntimeMessageExchangeState::RequestReceived => {
                        "runtime message exchange already received its one request"
                    }
                    RuntimeMessageExchangeState::Complete => {
                        "runtime message exchange permits exactly one completed round"
                    }
                    RuntimeMessageExchangeState::Failed => {
                        "runtime message exchange is closed after a protocol or I/O failure"
                    }
                    RuntimeMessageExchangeState::AwaitingRequest => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            if let Some(wait_milliseconds) = wait_milliseconds {
                self.wait_for_request_ready(wait_milliseconds)?;
            }

            let capacity = self.max_request_bytes as usize + 1;
            let mut bytes = vec![0u8; capacity];
            let mut iovec = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: bytes.len(),
            };
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = &mut iovec;
            message.msg_iovlen = 1;

            loop {
                message.msg_flags = 0;
                let received = unsafe { libc::recvmsg(self.fd, &mut message, 0) };
                if received == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot receive runtime message request",
                        error,
                    ));
                }
                if received == 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime message request must be non-empty and arrive before peer shutdown"
                            .to_owned(),
                    ));
                }
                if message.msg_flags & libc::MSG_TRUNC != 0
                    || received as u64 > self.max_request_bytes
                {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::RuntimeRequestTooLarge {
                        max_bytes: self.max_request_bytes,
                    });
                }

                bytes.truncate(received as usize);
                self.state = RuntimeMessageExchangeState::RequestReceived;
                return Ok(bytes);
            }
        }

        fn wait_for_request_ready(
            &mut self,
            wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            let timer = match RequestDeadlineTimer::new(wait_milliseconds) {
                Ok(timer) => timer,
                Err(error) => {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(error);
                }
            };
            let mut fds = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: timer.fd,
                    events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                    revents: 0,
                },
            ];

            loop {
                fds[0].revents = 0;
                fds[1].revents = 0;
                let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
                if ready == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot poll runtime message request deadline",
                        error,
                    ));
                }

                // Data/peer readiness wins over a simultaneously readable timer.
                // recvmsg below decides whether the peer supplied a packet or shut down.
                if fds[0].revents != 0 {
                    return Ok(());
                }
                if fds[1].revents & libc::POLLIN != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::RuntimeRequestTimedOut { wait_milliseconds });
                }
                if fds[1].revents != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime message request deadline timer became unusable".to_owned(),
                    ));
                }
            }
        }

        /// Send exactly one non-empty response packet after a valid request.
        ///
        /// The response is completely budget-checked before the atomic
        /// SOCK_SEQPACKET send. Any invalid response or send failure makes the
        /// controller terminal; success completes the only permitted round.
        pub fn send_response(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeMessageExchangeState::RequestReceived {
                let message = match self.state {
                    RuntimeMessageExchangeState::AwaitingRequest => {
                        "runtime message response requires a request first"
                    }
                    RuntimeMessageExchangeState::Complete => {
                        "runtime message exchange permits exactly one completed round"
                    }
                    RuntimeMessageExchangeState::Failed => {
                        "runtime message exchange is closed after a protocol or I/O failure"
                    }
                    RuntimeMessageExchangeState::RequestReceived => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }
            if bytes.is_empty() {
                self.state = RuntimeMessageExchangeState::Failed;
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime message response must be non-empty".to_owned(),
                ));
            }
            if bytes.len() as u64 > self.max_response_bytes {
                self.state = RuntimeMessageExchangeState::Failed;
                return Err(RuntimeFdBrokerError::RuntimeResponseTooLarge {
                    max_bytes: self.max_response_bytes,
                });
            }

            loop {
                let sent = unsafe {
                    libc::send(
                        self.fd,
                        bytes.as_ptr().cast::<libc::c_void>(),
                        bytes.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot send runtime message response",
                        error,
                    ));
                }
                if sent != bytes.len() as isize {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(format!(
                        "runtime message response sent unexpected packet length {sent}"
                    )));
                }
                self.state = RuntimeMessageExchangeState::Complete;
                return Ok(());
            }
        }
    }

    impl RuntimeMultiMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            self.completed_rounds == self.max_rounds && self.controller.is_complete()
        }

        pub fn completed_rounds(&self) -> u32 {
            self.completed_rounds
        }

        pub fn max_rounds(&self) -> u32 {
            self.max_rounds
        }

        fn reject_after_round_limit(&self) -> Result<(), RuntimeFdBrokerError> {
            if self.is_complete() {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime multi-message exchange reached its configured round limit".to_owned(),
                ));
            }
            Ok(())
        }

        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            self.controller.receive_request()
        }

        pub fn receive_request_with_deadline(
            &mut self,
            wait_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            self.controller
                .receive_request_with_deadline(wait_milliseconds)
        }

        pub fn send_response(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            self.controller.send_response(bytes)?;
            self.completed_rounds += 1;
            if self.completed_rounds < self.max_rounds {
                self.controller.state = RuntimeMessageExchangeState::AwaitingRequest;
            }
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct RuntimeFdBroker {
        path: PathBuf,
        listener: UnixListener,
        owner_pid: i32,
        owner_uid: u32,
        owner_gid: u32,
        socket_dev: u64,
        socket_ino: u64,
    }

    impl Drop for RuntimeFdBroker {
        fn drop(&mut self) {
            let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
                return;
            };
            if metadata.file_type().is_socket()
                && metadata.dev() == self.socket_dev
                && metadata.ino() == self.socket_ino
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeFdSessionState {
        AwaitingReady,
        Ready,
        GrantSent,
        Failed,
    }

    #[derive(Debug)]
    pub struct RuntimeFdSession {
        stream: UnixStream,
        state: RuntimeFdSessionState,
    }

    impl RuntimeFdBroker {
        /// Bind one host pathname AF_UNIX listener owned by the trusted caller.
        ///
        /// The path must be absolute, must not contain parent traversal, and must
        /// not already exist. Drop removes only the exact socket inode created by
        /// this broker, so a replaced pathname is never unlinked opportunistically.
        pub fn bind(path: impl AsRef<Path>) -> Result<Self, RuntimeFdBrokerError> {
            let path = path.as_ref();
            validate_socket_path(path)?;
            let listener = UnixListener::bind(path).map_err(|error| {
                RuntimeFdBrokerError::io("cannot bind runtime FD broker", error)
            })?;
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                RuntimeFdBrokerError::io("cannot inspect runtime FD broker socket", error)
            })?;
            if !metadata.file_type().is_socket() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "bound broker pathname is not a UNIX socket".to_owned(),
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
                listener,
                owner_pid: unsafe { libc::getpid() },
                owner_uid: unsafe { libc::geteuid() },
                owner_gid: unsafe { libc::getegid() },
                socket_dev: metadata.dev(),
                socket_ino: metadata.ino(),
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Configure the existing exact-path launcher AF_UNIX broker to connect
        /// the direct target to this runtime broker at `target_fd`.
        ///
        /// Existing host-UNIX broker fields are never overwritten. The candidate
        /// policy is validated before the caller's policy is changed.
        pub fn configure_policy(
            &self,
            policy: &mut SandboxPolicy,
            target_fd: u32,
        ) -> Result<(), RuntimeFdBrokerError> {
            if !policy.seccomp.allowed_syscalls.contains("recvmsg") {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "target policy must explicitly allow recvmsg for runtime FD grants".to_owned(),
                ));
            }
            if policy.host_unix_stream_path.is_some()
                || policy.host_unix_stream_target_fd.is_some()
                || policy.host_unix_stream_peer_uid.is_some()
                || policy.host_unix_stream_peer_gid.is_some()
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "policy already declares a host UNIX stream broker".to_owned(),
                ));
            }

            let mut candidate = policy.clone();
            candidate.host_unix_stream_path = Some(self.path.clone());
            candidate.host_unix_stream_target_fd = Some(target_fd);
            candidate.host_unix_stream_peer_uid = Some(self.owner_uid);
            candidate.host_unix_stream_peer_gid = Some(self.owner_gid);
            candidate.validate().map_err(RuntimeFdBrokerError::Policy)?;
            *policy = candidate;
            Ok(())
        }

        /// Accept the launcher-created broker connection and require it to come
        /// from the exact process and effective credentials that created this
        /// broker object. This closes accidental or cross-process queue capture;
        /// code inside the trusted caller process remains in the trust boundary.
        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {
            let (stream, _) = self.listener.accept().map_err(|error| {
                RuntimeFdBrokerError::io("cannot accept runtime FD broker connection", error)
            })?;
            let (pid, uid, gid) = peer_credentials(stream.as_raw_fd())?;
            if pid != self.owner_pid || uid != self.owner_uid || gid != self.owner_gid {
                return Err(RuntimeFdBrokerError::UnexpectedPeer {
                    expected_pid: self.owner_pid,
                    expected_uid: self.owner_uid,
                    expected_gid: self.owner_gid,
                    actual_pid: pid,
                    actual_uid: uid,
                    actual_gid: gid,
                });
            }
            Ok(RuntimeFdSession {
                stream,
                state: RuntimeFdSessionState::AwaitingReady,
            })
        }

        /// Pin one regular-file source as a separate read-only open file
        /// description suitable for later SCM_RIGHTS transfer.
        ///
        /// The caller must already hold read authority (`O_RDONLY` or `O_RDWR`).
        /// `O_WRONLY`, `O_PATH`, directories, devices, pipes, and sockets are
        /// rejected. Reopening through the stable `/proc/self/fd/<n>` reference
        /// gives the target an independent offset and attenuates an `O_RDWR`
        /// source to `O_RDONLY`; device/inode identity is rechecked afterward.
        /// This is data-access-mode attenuation, not immutable-inode semantics:
        /// metadata-changing syscalls remain separately governed by target
        /// seccomp/Landlock policy and normal kernel ownership checks.
        pub fn prepare_readonly_regular_file(
            source: &File,
        ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
            prepare_readonly_regular_file(source)
        }

        /// Copy one readable regular file into a bounded sealed memfd snapshot.
        ///
        /// The completed snapshot freezes the copied bytes and length with
        /// F_SEAL_WRITE/GROW/SHRINK/SEAL, then reopens the sealed object as a
        /// separate O_RDONLY|O_CLOEXEC description for the one-shot runtime
        /// grant protocol. This does not claim an atomic point-in-time read
        /// against a hostile writer mutating the source while the copy runs.
        pub fn prepare_sealed_regular_file_snapshot(
            source: &File,
            max_bytes: u64,
        ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
            prepare_sealed_regular_file_snapshot(source, max_bytes)
        }

        /// Group 2-8 already-sealed snapshots into one bounded ordered grant.
        ///
        /// The aggregate ceiling is caller-selected but may not exceed the
        /// global 64 MiB runtime bundle limit. Preparation consumes the snapshots
        /// so their order and membership cannot be changed before transfer.
        pub fn prepare_sealed_snapshot_bundle(
            grants: Vec<PreparedSealedRegularFileSnapshot>,
            max_total_bytes: u64,
        ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
            prepare_sealed_snapshot_bundle(grants, max_total_bytes)
        }

        /// Prepare one host-controlled receive-only byte stream for a later
        /// one-shot runtime grant.
        ///
        /// The target endpoint is write-shutdown before transfer. The trusted
        /// controller retains the peer and can supply at most max_bytes, then
        /// explicitly revoke all future supply by publishing EOF.
        pub fn prepare_revocable_byte_stream(
            max_bytes: u64,
        ) -> Result<
            (PreparedRevocableByteStream, RevocableByteStreamController),
            RuntimeFdBrokerError,
        > {
            prepare_revocable_byte_stream(max_bytes)
        }

        /// Prepare one bounded one-shot bidirectional message exchange.
        ///
        /// The target receives one SOCK_SEQPACKET endpoint through the existing
        /// post-exec broker grant. The trusted controller accepts one bounded
        /// request packet and may publish one bounded response packet.
        pub fn prepare_runtime_message_exchange(
            max_request_bytes: u64,
            max_response_bytes: u64,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_message_exchange(max_request_bytes, max_response_bytes)
        }

        /// Prepare one bounded multi-round SOCK_SEQPACKET request/response session.
        ///
        /// Each request and response retains the existing per-message byte ceiling.
        /// The explicit 2-32 round bound also statically bounds total request and
        /// response bytes. Any protocol, I/O, truncation, oversize, or bounded-wait
        /// failure remains terminal for the whole session.
        pub fn prepare_runtime_multi_message_exchange(
            max_request_bytes: u64,
            max_response_bytes: u64,
            max_rounds: u32,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeMultiMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_multi_message_exchange(
                max_request_bytes,
                max_response_bytes,
                max_rounds,
            )
        }
    }

    impl RuntimeFdSession {
        /// Wait for one exact target-defined readiness byte. Tests use this to
        /// prove a grant is sent only after the untrusted image has executed.
        pub fn wait_for_ready(&mut self, expected: u8) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeFdSessionState::AwaitingReady {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime FD broker readiness may be consumed exactly once before the grant"
                        .to_owned(),
                ));
            }

            let mut byte = [0u8; 1];
            if let Err(error) = self.stream.read_exact(&mut byte) {
                self.state = RuntimeFdSessionState::Failed;
                return Err(RuntimeFdBrokerError::io(
                    "cannot read runtime FD broker readiness",
                    error,
                ));
            }
            if byte[0] != expected {
                self.state = RuntimeFdSessionState::Failed;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "expected readiness byte 0x{expected:02x}, got 0x{:02x}",
                    byte[0]
                )));
            }
            self.state = RuntimeFdSessionState::Ready;
            Ok(())
        }

        /// Transfer exactly one previously prepared read-only regular-file grant.
        pub fn send_readonly_regular_file(
            &mut self,
            grant: PreparedReadOnlyRegularFile,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer exactly one previously prepared sealed regular-file snapshot.
        /// This shares the same one-shot session state as the ordinary read-only
        /// regular-file grant; the two grant kinds cannot be combined on one session.
        pub fn send_sealed_regular_file_snapshot(
            &mut self,
            grant: PreparedSealedRegularFileSnapshot,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer one ordered sealed snapshot bundle in a single SCM_RIGHTS
        /// control message. The whole bundle consumes the same one-shot session
        /// transition as every other runtime grant.
        pub fn send_sealed_snapshot_bundle(
            &mut self,
            bundle: PreparedSealedSnapshotBundle,
        ) -> Result<(), RuntimeFdBrokerError> {
            let mut fds = [-1; super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS];
            for (index, grant) in bundle.grants.iter().enumerate() {
                fds[index] = grant.fd;
            }
            self.send_prepared_fds(&fds[..bundle.grants.len()])
        }

        /// Transfer one prepared receive-only byte stream endpoint. The trusted
        /// controller remains with the caller and the transfer consumes the same
        /// one-shot readiness/session transition as every other runtime grant.
        pub fn send_revocable_byte_stream(
            &mut self,
            grant: PreparedRevocableByteStream,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer one prepared SOCK_SEQPACKET request/response endpoint.
        /// The transfer consumes the same one-shot session transition as every
        /// other runtime capability grant.
        pub fn send_runtime_message_channel(
            &mut self,
            grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        fn send_prepared_fd(&mut self, fd: RawFd) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fds(&[fd])
        }

        fn send_prepared_fds(&mut self, fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeFdSessionState::Ready {
                let message = match self.state {
                    RuntimeFdSessionState::AwaitingReady => {
                        "runtime FD broker grant requires the target readiness handshake first"
                    }
                    RuntimeFdSessionState::GrantSent => {
                        "runtime FD broker session permits exactly one successful grant"
                    }
                    RuntimeFdSessionState::Failed => {
                        "runtime FD broker session is closed after a protocol or I/O failure"
                    }
                    RuntimeFdSessionState::Ready => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            match send_fds(self.stream.as_raw_fd(), fds) {
                Ok(()) => {
                    self.state = RuntimeFdSessionState::GrantSent;
                    Ok(())
                }
                Err(error) => {
                    self.state = RuntimeFdSessionState::Failed;
                    Err(error)
                }
            }
        }
    }

    fn validate_socket_path(path: &Path) -> Result<(), RuntimeFdBrokerError> {
        if !path.is_absolute() {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(
                "broker socket path must be absolute".to_owned(),
            ));
        }
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(
                "broker socket path must not contain NUL".to_owned(),
            ));
        }
        if bytes.len() > MAX_UNIX_PATH_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "broker socket path exceeds {MAX_UNIX_PATH_BYTES} bytes"
            )));
        }
        for component in path.components() {
            if matches!(component, Component::ParentDir | Component::CurDir) {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "broker socket path must not contain . or .. components".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn peer_credentials(fd: RawFd) -> Result<(i32, u32, u32), RuntimeFdBrokerError> {
        let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast::<libc::c_void>(),
                &mut length,
            )
        };
        if result == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker peer credentials",
                std::io::Error::last_os_error(),
            ));
        }
        if length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(RuntimeFdBrokerError::Protocol(
                "SO_PEERCRED returned an unexpected structure length".to_owned(),
            ));
        }
        Ok((credentials.pid, credentials.uid, credentials.gid))
    }

    fn prepare_readonly_regular_file(
        source: &File,
    ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
        let source_fd = source.as_raw_fd();
        let mut original_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(source_fd, &mut original_stat) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker source",
                std::io::Error::last_os_error(),
            ));
        }
        if original_stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(RuntimeFdBrokerError::SourceNotRegular);
        }

        let original_flags = unsafe { libc::fcntl(source_fd, libc::F_GETFL) };
        if original_flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker source flags",
                std::io::Error::last_os_error(),
            ));
        }
        if original_flags & libc::O_PATH != 0 {
            return Err(RuntimeFdBrokerError::SourcePathOnly);
        }
        if original_flags & libc::O_ACCMODE == libc::O_WRONLY {
            return Err(RuntimeFdBrokerError::SourceNotReadable);
        }

        let proc_path = CString::new(format!("/proc/self/fd/{source_fd}"))
            .expect("numeric procfd path cannot contain NUL");
        let reopened = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if reopened == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot reopen runtime FD broker source read-only through procfd",
                std::io::Error::last_os_error(),
            ));
        }
        let reopened = PreparedReadOnlyRegularFile { fd: reopened };

        let mut reopened_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(reopened.fd, &mut reopened_stat) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot revalidate runtime FD broker source identity",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || reopened_stat.st_dev != original_stat.st_dev
            || reopened_stat.st_ino != original_stat.st_ino
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "procfd reopen changed runtime FD broker source identity".to_owned(),
            ));
        }

        let reopened_flags = unsafe { libc::fcntl(reopened.fd, libc::F_GETFL) };
        if reopened_flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect attenuated runtime FD broker source flags",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_flags & libc::O_PATH != 0 || reopened_flags & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "runtime FD broker failed to attenuate source to O_RDONLY".to_owned(),
            ));
        }

        Ok(reopened)
    }

    fn prepare_sealed_regular_file_snapshot(
        source: &File,
        max_bytes: u64,
    ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
        if max_bytes == 0 || max_bytes > super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime snapshot max_bytes must be between 1 and {}",
                super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES
            )));
        }

        let readable = prepare_readonly_regular_file(source)?;
        let name = CString::new("security-lab-runtime-snapshot")
            .expect("static runtime snapshot memfd name contains no NUL");
        let raw_memfd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            )
        };
        if raw_memfd == -1 {
            let error = std::io::Error::last_os_error();
            return if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EPERM) | Some(libc::EACCES)
            ) {
                Err(RuntimeFdBrokerError::UnsupportedPlatform(format!(
                    "sealed runtime FD snapshots require memfd sealing support: {error}"
                )))
            } else {
                Err(RuntimeFdBrokerError::io(
                    "cannot create sealed runtime FD snapshot memfd",
                    error,
                ))
            };
        }
        let mut memfd = PreparedSealedRegularFileSnapshot {
            fd: raw_memfd as RawFd,
            len: 0,
        };
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = unsafe {
                libc::read(
                    readable.fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot read runtime FD source for sealed snapshot",
                    error,
                ));
            }
            if read == 0 {
                break;
            }
            let count = read as usize;
            let new_len = memfd.len.checked_add(count as u64).ok_or_else(|| {
                RuntimeFdBrokerError::Protocol(
                    "sealed runtime snapshot byte count overflow".to_owned(),
                )
            })?;
            if new_len > max_bytes {
                return Err(RuntimeFdBrokerError::SourceSnapshotTooLarge { max_bytes });
            }
            let mut offset = 0usize;
            while offset < count {
                let written = unsafe {
                    libc::write(
                        memfd.fd,
                        buffer[offset..count].as_ptr().cast::<libc::c_void>(),
                        count - offset,
                    )
                };
                if written == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(RuntimeFdBrokerError::io(
                        "cannot populate sealed runtime FD snapshot",
                        error,
                    ));
                }
                if written == 0 {
                    return Err(RuntimeFdBrokerError::Protocol(
                        "sealed runtime snapshot write made no progress".to_owned(),
                    ));
                }
                offset += written as usize;
            }
            memfd.len = new_len;
        }

        if unsafe { libc::fchmod(memfd.fd, 0o400) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot set sealed runtime FD snapshot mode",
                std::io::Error::last_os_error(),
            ));
        }
        let required_seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(memfd.fd, libc::F_ADD_SEALS, required_seals) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot seal runtime FD snapshot",
                std::io::Error::last_os_error(),
            ));
        }
        let observed = unsafe { libc::fcntl(memfd.fd, libc::F_GET_SEALS) };
        if observed == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD snapshot seals",
                std::io::Error::last_os_error(),
            ));
        }
        if observed & required_seals != required_seals {
            return Err(RuntimeFdBrokerError::Protocol(
                "sealed runtime FD snapshot is missing required immutable seals".to_owned(),
            ));
        }

        let proc_path = CString::new(format!("/proc/self/fd/{}", memfd.fd))
            .expect("numeric runtime snapshot procfd path contains no NUL");
        let readonly = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if readonly == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot reopen sealed runtime FD snapshot read-only",
                std::io::Error::last_os_error(),
            ));
        }
        let readonly = PreparedSealedRegularFileSnapshot {
            fd: readonly,
            len: memfd.len,
        };

        let mut original_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let mut readonly_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(memfd.fd, &mut original_stat) } == -1
            || unsafe { libc::fstat(readonly.fd, &mut readonly_stat) } == -1
        {
            return Err(RuntimeFdBrokerError::io(
                "cannot revalidate sealed runtime FD snapshot identity",
                std::io::Error::last_os_error(),
            ));
        }
        if original_stat.st_dev != readonly_stat.st_dev
            || original_stat.st_ino != readonly_stat.st_ino
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "read-only reopen changed sealed runtime FD snapshot identity".to_owned(),
            ));
        }
        let flags = unsafe { libc::fcntl(readonly.fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect sealed runtime FD snapshot access mode",
                std::io::Error::last_os_error(),
            ));
        }
        if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(RuntimeFdBrokerError::Protocol(
                "sealed runtime FD snapshot did not reopen as O_RDONLY".to_owned(),
            ));
        }
        let reopened_seals = unsafe { libc::fcntl(readonly.fd, libc::F_GET_SEALS) };
        if reopened_seals == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot verify seals after runtime FD snapshot reopen",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_seals & required_seals != required_seals {
            return Err(RuntimeFdBrokerError::Protocol(
                "read-only runtime FD snapshot lost required seals".to_owned(),
            ));
        }

        drop(memfd);
        Ok(readonly)
    }

    fn prepare_revocable_byte_stream(
        max_bytes: u64,
    ) -> Result<(PreparedRevocableByteStream, RevocableByteStreamController), RuntimeFdBrokerError>
    {
        if max_bytes == 0 || max_bytes > super::MAX_RUNTIME_REVOCABLE_STREAM_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "revocable runtime stream max_bytes must be between 1 and {}",
                super::MAX_RUNTIME_REVOCABLE_STREAM_BYTES
            )));
        }

        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } == -1
        {
            return Err(RuntimeFdBrokerError::io(
                "cannot create revocable runtime stream socketpair",
                std::io::Error::last_os_error(),
            ));
        }

        if unsafe { libc::shutdown(fds[0], libc::SHUT_WR) } == -1 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(RuntimeFdBrokerError::io(
                "cannot make runtime stream target endpoint receive-only",
                error,
            ));
        }
        if unsafe { libc::shutdown(fds[1], libc::SHUT_RD) } == -1 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(RuntimeFdBrokerError::io(
                "cannot make runtime stream controller send-only",
                error,
            ));
        }

        Ok((
            PreparedRevocableByteStream { fd: fds[0] },
            RevocableByteStreamController {
                fd: fds[1],
                max_bytes,
                sent_bytes: 0,
                state: RevocableByteStreamState::Active,
            },
        ))
    }

    fn prepare_runtime_multi_message_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_rounds: u32,
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeMultiMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
        if !(super::MIN_RUNTIME_MULTI_MESSAGE_ROUNDS..=super::MAX_RUNTIME_MULTI_MESSAGE_ROUNDS)
            .contains(&max_rounds)
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime multi-message max_rounds must be between {} and {}",
                super::MIN_RUNTIME_MULTI_MESSAGE_ROUNDS,
                super::MAX_RUNTIME_MULTI_MESSAGE_ROUNDS
            )));
        }

        let (grant, controller) =
            prepare_runtime_message_exchange(max_request_bytes, max_response_bytes)?;
        Ok((
            grant,
            RuntimeMultiMessageExchangeController {
                controller,
                max_rounds,
                completed_rounds: 0,
            },
        ))
    }

    fn prepare_runtime_message_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
        if max_request_bytes == 0 || max_request_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime message max_request_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }
        if max_response_bytes == 0 || max_response_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime message max_response_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }

        let mut fds = [-1; 2];
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                fds.as_mut_ptr(),
            )
        } == -1
        {
            return Err(RuntimeFdBrokerError::io(
                "cannot create runtime message exchange socketpair",
                std::io::Error::last_os_error(),
            ));
        }

        Ok((
            PreparedRuntimeMessageChannel { fd: fds[0] },
            RuntimeMessageExchangeController {
                fd: fds[1],
                max_request_bytes,
                max_response_bytes,
                state: RuntimeMessageExchangeState::AwaitingRequest,
            },
        ))
    }

    fn prepare_sealed_snapshot_bundle(
        grants: Vec<PreparedSealedRegularFileSnapshot>,
        max_total_bytes: u64,
    ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
        if max_total_bytes == 0 || max_total_bytes > super::MAX_RUNTIME_SEALED_BUNDLE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime bundle max_total_bytes must be between 1 and {}",
                super::MAX_RUNTIME_SEALED_BUNDLE_BYTES
            )));
        }
        if !(super::MIN_RUNTIME_SEALED_BUNDLE_ITEMS..=super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS)
            .contains(&grants.len())
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime bundle must contain between {} and {} snapshots",
                super::MIN_RUNTIME_SEALED_BUNDLE_ITEMS,
                super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS
            )));
        }

        let mut total_len = 0u64;
        for grant in &grants {
            total_len = total_len.checked_add(grant.len).ok_or_else(|| {
                RuntimeFdBrokerError::Protocol(
                    "sealed runtime bundle aggregate byte count overflow".to_owned(),
                )
            })?;
            if total_len > max_total_bytes {
                return Err(RuntimeFdBrokerError::SnapshotBundleTooLarge {
                    max_bytes: max_total_bytes,
                });
            }
        }
        Ok(PreparedSealedSnapshotBundle { grants, total_len })
    }

    #[repr(C, align(8))]
    struct FdControl([u8; 48]);

    fn cmsg_space_for_fd_count(count: usize) -> usize {
        let unaligned = std::mem::size_of::<libc::cmsghdr>() + count * std::mem::size_of::<RawFd>();
        let alignment = std::mem::size_of::<usize>();
        (unaligned + alignment - 1) & !(alignment - 1)
    }

    fn send_fds(socket_fd: RawFd, source_fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
        if source_fds.is_empty() || source_fds.len() > super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS {
            return Err(RuntimeFdBrokerError::Protocol(
                "SCM_RIGHTS grant descriptor count is outside the supported bound".to_owned(),
            ));
        }

        let mut payload = if source_fds.len() == 1 { *b"F" } else { *b"B" };
        let mut iovec = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: payload.len(),
        };
        let mut control = FdControl([0; 48]);
        let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_len =
                std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of_val(source_fds);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            let data = control
                .0
                .as_mut_ptr()
                .add(std::mem::size_of::<libc::cmsghdr>())
                .cast::<RawFd>();
            for (index, source_fd) in source_fds.iter().enumerate() {
                data.add(index).write(*source_fd);
            }
        }

        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
        message.msg_controllen = cmsg_space_for_fd_count(source_fds.len());

        loop {
            let sent = unsafe { libc::sendmsg(socket_fd, &message, libc::MSG_NOSIGNAL) };
            if sent == 1 {
                return Ok(());
            }
            if sent == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot send runtime FD broker SCM_RIGHTS grant",
                    error,
                ));
            }
            return Err(RuntimeFdBrokerError::Protocol(format!(
                "SCM_RIGHTS send wrote unexpected payload length {sent}"
            )));
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};

    #[derive(Debug)]
    pub struct PreparedReadOnlyRegularFile;

    #[derive(Debug)]
    pub struct PreparedSealedRegularFileSnapshot;

    #[derive(Debug)]
    pub struct PreparedSealedSnapshotBundle;

    #[derive(Debug)]
    pub struct PreparedRevocableByteStream;

    #[derive(Debug)]
    pub struct RevocableByteStreamController;

    #[derive(Debug)]
    pub struct PreparedRuntimeMessageChannel;

    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;

    #[derive(Debug)]
    pub struct RuntimeMultiMessageExchangeController;

    impl RuntimeMultiMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn completed_rounds(&self) -> u32 {
            0
        }

        pub fn max_rounds(&self) -> u32 {
            0
        }

        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn receive_request_with_deadline(
            &mut self,
            _wait_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message request deadlines currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn receive_request_with_deadline(
            &mut self,
            _wait_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message request deadlines currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RevocableByteStreamController {
        pub fn sent_bytes(&self) -> u64 {
            0
        }

        pub fn is_revoked(&self) -> bool {
            false
        }

        pub fn send_all(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable runtime byte streams currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn revoke(&mut self) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable runtime byte streams currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl PreparedSealedSnapshotBundle {
        pub fn item_count(&self) -> usize {
            0
        }

        pub fn total_len(&self) -> u64 {
            0
        }
    }

    impl PreparedSealedRegularFileSnapshot {
        pub fn len(&self) -> u64 {
            0
        }

        pub fn is_empty(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct RuntimeFdBroker;

    #[derive(Debug)]
    pub struct RuntimeFdSession;

    impl RuntimeFdBroker {
        pub fn bind(_path: impl AsRef<Path>) -> Result<Self, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn path(&self) -> &Path {
            Path::new("")
        }

        pub fn configure_policy(
            &self,
            _policy: &mut SandboxPolicy,
            _target_fd: u32,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_readonly_regular_file(
            _source: &File,
        ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_sealed_regular_file_snapshot(
            _source: &File,
            _max_bytes: u64,
        ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshots currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_sealed_snapshot_bundle(
            _grants: Vec<PreparedSealedRegularFileSnapshot>,
            _max_total_bytes: u64,
        ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshot bundles currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_revocable_byte_stream(
            _max_bytes: u64,
        ) -> Result<
            (PreparedRevocableByteStream, RevocableByteStreamController),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable runtime byte streams currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_runtime_message_exchange(
            _max_request_bytes: u64,
            _max_response_bytes: u64,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_runtime_multi_message_exchange(
            _max_request_bytes: u64,
            _max_response_bytes: u64,
            _max_rounds: u32,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeMultiMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeFdSession {
        pub fn wait_for_ready(&mut self, _expected: u8) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn send_readonly_regular_file(
            &mut self,
            _grant: PreparedReadOnlyRegularFile,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn send_sealed_regular_file_snapshot(
            &mut self,
            _grant: PreparedSealedRegularFileSnapshot,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshots currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_sealed_snapshot_bundle(
            &mut self,
            _bundle: PreparedSealedSnapshotBundle,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshot bundles currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_revocable_byte_stream(
            &mut self,
            _grant: PreparedRevocableByteStream,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable runtime byte streams currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_runtime_message_channel(
            &mut self,
            _grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }
}

pub use imp::{
    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdSession, RuntimeMessageExchangeController,
    RuntimeMultiMessageExchangeController,
};
