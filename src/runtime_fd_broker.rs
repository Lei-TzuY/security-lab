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
pub const MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS: u64 = 86_400_000;
pub const MAX_RUNTIME_MULTI_MESSAGE_SESSION_MILLISECONDS: u64 = 86_400_000;
pub const MIN_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 2;
pub const MAX_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 32;
pub const MIN_RUNTIME_CORRELATED_REQUESTS: u32 = 2;
pub const MAX_RUNTIME_CORRELATED_REQUESTS: u32 = 32;
pub const MIN_RUNTIME_CORRELATED_IN_FLIGHT: u32 = 2;
pub const MAX_RUNTIME_CORRELATED_IN_FLIGHT: u32 = 8;
pub const RUNTIME_AUTH_KEY_BYTES: usize = 32;
pub const RUNTIME_AUTH_CHALLENGE_BYTES: usize = 32;
pub const RUNTIME_AUTH_TAG_BYTES: usize = 32;
pub const MIN_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS: u32 = 2;
pub const MAX_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostUnixPeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

impl HostUnixPeerCredentials {
    pub fn pid(&self) -> i32 {
        self.pid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCorrelatedRequest {
    request_id: u64,
    payload: Vec<u8>,
}

impl RuntimeCorrelatedRequest {
    pub fn request_id(&self) -> u64 {
        self.request_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

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
    RuntimeResponseTimedOut {
        wait_milliseconds: u64,
    },
    RuntimeSessionTimedOut {
        limit_milliseconds: u64,
    },
    RuntimeDuplicateRequestId {
        request_id: u64,
    },
    RuntimeUnknownRequestId {
        request_id: u64,
    },
    RuntimeAuthenticationFailed,
    RuntimeAcknowledgmentMismatch {
        request_id: u64,
    },
    HostUnixPeerCredentialMismatch {
        expected_uid: u32,
        expected_gid: u32,
        actual_pid: i32,
        actual_uid: u32,
        actual_gid: u32,
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
            Self::RuntimeResponseTimedOut { wait_milliseconds } => write!(
                f,
                "runtime FD broker response publication wait exceeded {wait_milliseconds} ms"
            ),
            Self::RuntimeSessionTimedOut { limit_milliseconds } => write!(
                f,
                "runtime FD broker multi-message session lifetime exceeded {limit_milliseconds} ms"
            ),
            Self::RuntimeDuplicateRequestId { request_id } => write!(
                f,
                "runtime FD broker correlated request id {request_id} was already observed"
            ),
            Self::RuntimeUnknownRequestId { request_id } => write!(
                f,
                "runtime FD broker correlated response references non-pending request id {request_id}"
            ),
            Self::RuntimeAuthenticationFailed => f.write_str(
                "runtime FD broker authenticated message failed HMAC verification",
            ),
            Self::RuntimeAcknowledgmentMismatch { request_id } => write!(
                f,
                "runtime FD broker acknowledgment does not match published response for request id {request_id}"
            ),
            Self::HostUnixPeerCredentialMismatch {
                expected_uid,
                expected_gid,
                actual_pid,
                actual_uid,
                actual_gid,
            } => write!(
                f,
                "runtime host UNIX peer mismatch: expected uid/gid {expected_uid}/{expected_gid}, got pid/uid/gid {actual_pid}/{actual_uid}/{actual_gid}"
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
    use super::{
        File, HostUnixPeerCredentials, Path, RuntimeCorrelatedRequest, RuntimeFdBrokerError,
        SandboxPolicy,
    };
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
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
    pub struct PreparedHostUnixStream {
        stream: UnixStream,
        peer_pid: i32,
        peer_uid: u32,
        peer_gid: u32,
    }

    impl PreparedHostUnixStream {
        pub fn peer_pid(&self) -> i32 {
            self.peer_pid
        }

        pub fn peer_uid(&self) -> u32 {
            self.peer_uid
        }

        pub fn peer_gid(&self) -> u32 {
            self.peer_gid
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HostUnixStreamRevocationState {
        Active,
        Revoked,
        Failed,
    }

    #[derive(Debug)]
    pub struct HostUnixStreamRevocationController {
        stream: UnixStream,
        credentials: HostUnixPeerCredentials,
        state: HostUnixStreamRevocationState,
    }

    impl Drop for HostUnixStreamRevocationController {
        fn drop(&mut self) {
            if self.state == HostUnixStreamRevocationState::Active {
                let _ = self.stream.shutdown(std::net::Shutdown::Both);
            }
        }
    }

    impl HostUnixStreamRevocationController {
        pub fn peer_credentials(&self) -> HostUnixPeerCredentials {
            self.credentials
        }

        pub fn is_revoked(&self) -> bool {
            self.state == HostUnixStreamRevocationState::Revoked
        }

        pub fn is_failed(&self) -> bool {
            self.state == HostUnixStreamRevocationState::Failed
        }

        /// Terminate future bidirectional I/O on the exact connected socket
        /// object that was already transferred to the target.
        ///
        /// This changes socket shutdown state shared by every descriptor
        /// reference to that socket object. Dropping an active controller also
        /// attempts the same shutdown so controller loss fails closed. This does
        /// not close the target's fd number, roll back bytes already consumed,
        /// or undo remote side effects.
        pub fn revoke(&mut self) -> Result<(), RuntimeFdBrokerError> {
            if self.state != HostUnixStreamRevocationState::Active {
                let message = match self.state {
                    HostUnixStreamRevocationState::Revoked => {
                        "host UNIX stream capability may be revoked exactly once"
                    }
                    HostUnixStreamRevocationState::Failed => {
                        "host UNIX stream revocation controller is closed after failure"
                    }
                    HostUnixStreamRevocationState::Active => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            if let Err(error) = self.stream.shutdown(std::net::Shutdown::Both) {
                self.state = HostUnixStreamRevocationState::Failed;
                return Err(RuntimeFdBrokerError::io(
                    "cannot revoke transferred host UNIX stream",
                    error,
                ));
            }
            self.state = HostUnixStreamRevocationState::Revoked;
            Ok(())
        }
    }

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
        session_deadline: Option<SessionDeadlineTimer>,
    }

    #[derive(Debug)]
    pub struct RuntimeCorrelatedMessageExchangeController {
        fd: RawFd,
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_requests: u32,
        max_in_flight: u32,
        received_requests: u32,
        completed_responses: u32,
        seen_request_ids: BTreeSet<u64>,
        pending_request_ids: BTreeSet<u64>,
        failed: bool,
    }

    impl Drop for RuntimeCorrelatedMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    pub struct RuntimeAuthenticatedCorrelatedMessageExchangeController {
        fd: RawFd,
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_requests: u32,
        max_in_flight: u32,
        received_requests: u32,
        completed_responses: u32,
        seen_request_ids: BTreeSet<u64>,
        pending_request_ids: BTreeSet<u64>,
        key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
        challenge: [u8; super::RUNTIME_AUTH_CHALLENGE_BYTES],
        challenge_published: bool,
        failed: bool,
    }

    impl std::fmt::Debug for RuntimeAuthenticatedCorrelatedMessageExchangeController {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RuntimeAuthenticatedCorrelatedMessageExchangeController")
                .field("max_request_bytes", &self.max_request_bytes)
                .field("max_response_bytes", &self.max_response_bytes)
                .field("max_requests", &self.max_requests)
                .field("max_in_flight", &self.max_in_flight)
                .field("received_requests", &self.received_requests)
                .field("completed_responses", &self.completed_responses)
                .field("pending_requests", &self.pending_request_ids.len())
                .field("challenge_published", &self.challenge_published)
                .field("failed", &self.failed)
                .finish_non_exhaustive()
        }
    }

    impl Drop for RuntimeAuthenticatedCorrelatedMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    struct RuntimeResponseAcknowledgmentExpectation {
        request_id: u64,
        response_sha256: [u8; 32],
    }

    pub struct RuntimeAcknowledgedCorrelatedMessageExchangeController {
        controller: RuntimeAuthenticatedCorrelatedMessageExchangeController,
        awaiting_acknowledgment: Option<RuntimeResponseAcknowledgmentExpectation>,
        acknowledged_responses: u32,
    }

    impl std::fmt::Debug for RuntimeAcknowledgedCorrelatedMessageExchangeController {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RuntimeAcknowledgedCorrelatedMessageExchangeController")
                .field("controller", &self.controller)
                .field(
                    "awaiting_acknowledgment_request_id",
                    &self
                        .awaiting_acknowledgment
                        .as_ref()
                        .map(|expectation| expectation.request_id),
                )
                .field("acknowledged_responses", &self.acknowledged_responses)
                .finish_non_exhaustive()
        }
    }

    const RUNTIME_AUTH_PROTOCOL_VERSION: u8 = 1;
    const RUNTIME_AUTH_CHALLENGE_KIND: u8 = b'C';
    const RUNTIME_AUTH_REQUEST_KIND: u8 = b'Q';
    const RUNTIME_AUTH_RESPONSE_KIND: u8 = b'S';
    const RUNTIME_AUTH_ACKNOWLEDGMENT_KIND: u8 = b'A';
    const RUNTIME_AUTH_DOMAIN: &[u8] = b"security-lab-runtime-correlated-hmac-sha256-v1\0";
    type RuntimeHmacSha256 = Hmac<Sha256>;

    fn runtime_auth_mac(
        key: &[u8; super::RUNTIME_AUTH_KEY_BYTES],
        challenge: &[u8; super::RUNTIME_AUTH_CHALLENGE_BYTES],
        kind: u8,
        request_id: u64,
        payload: &[u8],
    ) -> RuntimeHmacSha256 {
        let mut mac = RuntimeHmacSha256::new_from_slice(key)
            .expect("HMAC-SHA256 accepts the fixed runtime authentication key length");
        mac.update(RUNTIME_AUTH_DOMAIN);
        mac.update(challenge);
        mac.update(&[kind, RUNTIME_AUTH_PROTOCOL_VERSION]);
        mac.update(&request_id.to_le_bytes());
        mac.update(&(payload.len() as u64).to_le_bytes());
        mac.update(payload);
        mac
    }

    fn runtime_auth_tag(
        key: &[u8; super::RUNTIME_AUTH_KEY_BYTES],
        challenge: &[u8; super::RUNTIME_AUTH_CHALLENGE_BYTES],
        kind: u8,
        request_id: u64,
        payload: &[u8],
    ) -> [u8; super::RUNTIME_AUTH_TAG_BYTES] {
        let result = runtime_auth_mac(key, challenge, kind, request_id, payload).finalize();
        let mut tag = [0u8; super::RUNTIME_AUTH_TAG_BYTES];
        tag.copy_from_slice(&result.into_bytes());
        tag
    }

    fn runtime_response_sha256(payload: &[u8]) -> [u8; 32] {
        let digest = Sha256::digest(payload);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }

    fn runtime_auth_verify(
        key: &[u8; super::RUNTIME_AUTH_KEY_BYTES],
        challenge: &[u8; super::RUNTIME_AUTH_CHALLENGE_BYTES],
        kind: u8,
        request_id: u64,
        payload: &[u8],
        tag: &[u8],
    ) -> bool {
        runtime_auth_mac(key, challenge, kind, request_id, payload)
            .verify_slice(tag)
            .is_ok()
    }

    fn random_runtime_auth_challenge(
    ) -> Result<[u8; super::RUNTIME_AUTH_CHALLENGE_BYTES], RuntimeFdBrokerError> {
        let mut challenge = [0u8; super::RUNTIME_AUTH_CHALLENGE_BYTES];
        let mut offset = 0usize;
        while offset < challenge.len() {
            let read = unsafe {
                libc::getrandom(
                    challenge[offset..].as_mut_ptr().cast::<libc::c_void>(),
                    challenge.len() - offset,
                    0,
                )
            };
            if read == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                if error.raw_os_error() == Some(libc::ENOSYS) {
                    return Err(RuntimeFdBrokerError::UnsupportedPlatform(
                        "authenticated runtime exchanges require Linux getrandom".to_owned(),
                    ));
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot generate authenticated runtime session challenge",
                    error,
                ));
            }
            if read == 0 {
                return Err(RuntimeFdBrokerError::Protocol(
                    "authenticated runtime session challenge generation made no progress"
                        .to_owned(),
                ));
            }
            offset += read as usize;
        }
        Ok(challenge)
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

    #[derive(Debug)]
    struct ResponseDeadlineTimer {
        fd: RawFd,
    }

    impl ResponseDeadlineTimer {
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
                        "runtime message response publication deadlines require timerfd".to_owned(),
                    ));
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot create runtime message response publication deadline timer",
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
                    "cannot arm runtime message response publication deadline timer",
                    error,
                ));
            }

            Ok(Self { fd })
        }
    }

    impl Drop for ResponseDeadlineTimer {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    struct SessionDeadlineTimer {
        fd: RawFd,
        limit_milliseconds: u64,
    }

    impl SessionDeadlineTimer {
        fn new(limit_milliseconds: u64) -> Result<Self, RuntimeFdBrokerError> {
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
                        "runtime multi-message session deadlines require timerfd".to_owned(),
                    ));
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot create runtime multi-message session deadline timer",
                    error,
                ));
            }

            let spec = libc::itimerspec {
                it_interval: libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                },
                it_value: libc::timespec {
                    tv_sec: (limit_milliseconds / 1000) as libc::time_t,
                    tv_nsec: ((limit_milliseconds % 1000) * 1_000_000) as libc::c_long,
                },
            };
            if unsafe { libc::timerfd_settime(fd, 0, &spec, std::ptr::null_mut()) } == -1 {
                let error = std::io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot arm runtime multi-message session deadline timer",
                    error,
                ));
            }

            Ok(Self {
                fd,
                limit_milliseconds,
            })
        }
    }

    impl Drop for SessionDeadlineTimer {
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

        fn receive_request_with_session_deadline(
            &mut self,
            timer_fd: RawFd,
            limit_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            if self.state != RuntimeMessageExchangeState::AwaitingRequest {
                return self.receive_request();
            }

            let mut fds = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: timer_fd,
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
                        "cannot poll runtime multi-message session request deadline",
                        error,
                    ));
                }

                // The whole-session ceiling is stricter than a per-operation
                // wait: once expiration is observable, queued request readiness
                // cannot revive the session.
                if fds[1].revents & libc::POLLIN != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::RuntimeSessionTimedOut {
                        limit_milliseconds,
                    });
                }
                if fds[1].revents != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime multi-message session deadline timer became unusable".to_owned(),
                    ));
                }
                if fds[0].revents != 0 {
                    return self.receive_request();
                }
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
            self.send_response_inner(bytes, None)
        }

        /// Send one response packet while bounding only publication into the
        /// peer socket's kernel receive queue.
        ///
        /// The timeout starts at this method call and does not claim that the
        /// target has read or processed the response. Socket writability wins
        /// over a simultaneously readable timer, but the actual atomic
        /// MSG_DONTWAIT send remains the arbiter when readiness races.
        pub fn send_response_with_deadline(
            &mut self,
            bytes: &[u8],
            wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            if !(1..=super::MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS)
                .contains(&wait_milliseconds)
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                    "runtime message response publication wait must be between 1 and {} milliseconds",
                    super::MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS
                )));
            }
            self.send_response_inner(bytes, Some(wait_milliseconds))
        }

        fn send_response_inner(
            &mut self,
            bytes: &[u8],
            wait_milliseconds: Option<u64>,
        ) -> Result<(), RuntimeFdBrokerError> {
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

            if let Some(wait_milliseconds) = wait_milliseconds {
                return self.send_response_with_timer(bytes, wait_milliseconds);
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

        fn send_response_with_session_deadline(
            &mut self,
            bytes: &[u8],
            timer_fd: RawFd,
            limit_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeMessageExchangeState::RequestReceived {
                return self.send_response(bytes);
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

            let mut fds = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT | libc::POLLERR | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: timer_fd,
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
                        "cannot poll runtime multi-message session response deadline",
                        error,
                    ));
                }

                // Session expiration wins over a simultaneously writable socket,
                // so an already-expired global budget cannot be refreshed by
                // entering another response operation.
                if fds[1].revents & libc::POLLIN != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::RuntimeSessionTimedOut {
                        limit_milliseconds,
                    });
                }
                if fds[1].revents != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime multi-message session deadline timer became unusable".to_owned(),
                    ));
                }
                if fds[0].revents != 0 {
                    let sent = unsafe {
                        libc::send(
                            self.fd,
                            bytes.as_ptr().cast::<libc::c_void>(),
                            bytes.len(),
                            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                        )
                    };
                    if sent == bytes.len() as isize {
                        self.state = RuntimeMessageExchangeState::Complete;
                        return Ok(());
                    }
                    if sent == -1 {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() == Some(libc::EINTR)
                            || error.raw_os_error() == Some(libc::EAGAIN)
                        {
                            continue;
                        }
                        self.state = RuntimeMessageExchangeState::Failed;
                        return Err(RuntimeFdBrokerError::io(
                            "cannot send runtime message response",
                            error,
                        ));
                    }

                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(format!(
                        "runtime message response sent unexpected packet length {sent}"
                    )));
                }
            }
        }

        fn send_response_with_timer(
            &mut self,
            bytes: &[u8],
            wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            let timer = match ResponseDeadlineTimer::new(wait_milliseconds) {
                Ok(timer) => timer,
                Err(error) => {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(error);
                }
            };
            let mut fds = [
                libc::pollfd {
                    fd: self.fd,
                    events: libc::POLLOUT | libc::POLLERR | libc::POLLHUP,
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
                        "cannot poll runtime message response publication deadline",
                        error,
                    ));
                }

                // Socket readiness wins over a simultaneously readable timer.
                // MSG_DONTWAIT makes the atomic send itself the final race arbiter.
                if fds[0].revents != 0 {
                    let sent = unsafe {
                        libc::send(
                            self.fd,
                            bytes.as_ptr().cast::<libc::c_void>(),
                            bytes.len(),
                            libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                        )
                    };
                    if sent == bytes.len() as isize {
                        self.state = RuntimeMessageExchangeState::Complete;
                        return Ok(());
                    }
                    if sent == -1 {
                        let error = std::io::Error::last_os_error();
                        if error.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        if error.raw_os_error() == Some(libc::EAGAIN) {
                            if fds[1].revents & libc::POLLIN != 0 {
                                self.state = RuntimeMessageExchangeState::Failed;
                                return Err(RuntimeFdBrokerError::RuntimeResponseTimedOut {
                                    wait_milliseconds,
                                });
                            }
                            if fds[1].revents != 0 {
                                self.state = RuntimeMessageExchangeState::Failed;
                                return Err(RuntimeFdBrokerError::Protocol(
                                    "runtime message response deadline timer became unusable"
                                        .to_owned(),
                                ));
                            }
                            continue;
                        }
                        self.state = RuntimeMessageExchangeState::Failed;
                        return Err(RuntimeFdBrokerError::io(
                            "cannot send runtime message response",
                            error,
                        ));
                    }

                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(format!(
                        "runtime message response sent unexpected packet length {sent}"
                    )));
                }

                if fds[1].revents & libc::POLLIN != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::RuntimeResponseTimedOut {
                        wait_milliseconds,
                    });
                }
                if fds[1].revents != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime message response deadline timer became unusable".to_owned(),
                    ));
                }
            }
        }
    }

    impl RuntimeMultiMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            self.completed_rounds == self.max_rounds && self.controller.is_complete()
        }

        /// Arm one non-resettable CLOCK_MONOTONIC lifetime budget for every
        /// remaining request/response operation in this multi-round session.
        ///
        /// The timer starts at this call. It must be armed before the first
        /// request. Once active, use the ordinary receive_request/send_response
        /// methods; per-operation deadline methods are intentionally rejected
        /// rather than composing two independent clocks.
        pub fn start_session_deadline(
            &mut self,
            limit_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            if !(1..=super::MAX_RUNTIME_MULTI_MESSAGE_SESSION_MILLISECONDS)
                .contains(&limit_milliseconds)
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                    "runtime multi-message session lifetime must be between 1 and {} milliseconds",
                    super::MAX_RUNTIME_MULTI_MESSAGE_SESSION_MILLISECONDS
                )));
            }
            if self.session_deadline.is_some() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "runtime multi-message session deadline cannot be reset".to_owned(),
                ));
            }
            if self.completed_rounds != 0
                || self.controller.state != RuntimeMessageExchangeState::AwaitingRequest
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "runtime multi-message session deadline must be armed before the first request"
                        .to_owned(),
                ));
            }

            match SessionDeadlineTimer::new(limit_milliseconds) {
                Ok(timer) => {
                    self.session_deadline = Some(timer);
                    Ok(())
                }
                Err(error) => {
                    self.controller.state = RuntimeMessageExchangeState::Failed;
                    Err(error)
                }
            }
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
            let session_deadline = self
                .session_deadline
                .as_ref()
                .map(|timer| (timer.fd, timer.limit_milliseconds));
            match session_deadline {
                Some((timer_fd, limit_milliseconds)) => self
                    .controller
                    .receive_request_with_session_deadline(timer_fd, limit_milliseconds),
                None => self.controller.receive_request(),
            }
        }

        pub fn receive_request_with_deadline(
            &mut self,
            wait_milliseconds: u64,
        ) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            if self.controller.state == RuntimeMessageExchangeState::Failed {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime message exchange is closed after a protocol or I/O failure".to_owned(),
                ));
            }
            if self.session_deadline.is_some() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "per-operation request deadlines cannot be combined with an active runtime multi-message session deadline".to_owned(),
                ));
            }
            self.controller
                .receive_request_with_deadline(wait_milliseconds)
        }

        pub fn send_response(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            let session_deadline = self
                .session_deadline
                .as_ref()
                .map(|timer| (timer.fd, timer.limit_milliseconds));
            match session_deadline {
                Some((timer_fd, limit_milliseconds)) => self
                    .controller
                    .send_response_with_session_deadline(bytes, timer_fd, limit_milliseconds)?,
                None => self.controller.send_response(bytes)?,
            }
            self.complete_response_round();
            Ok(())
        }

        pub fn send_response_with_deadline(
            &mut self,
            bytes: &[u8],
            wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            if self.controller.state == RuntimeMessageExchangeState::Failed {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime message exchange is closed after a protocol or I/O failure".to_owned(),
                ));
            }
            if self.session_deadline.is_some() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "per-operation response deadlines cannot be combined with an active runtime multi-message session deadline".to_owned(),
                ));
            }
            self.controller
                .send_response_with_deadline(bytes, wait_milliseconds)?;
            self.complete_response_round();
            Ok(())
        }

        fn complete_response_round(&mut self) {
            self.completed_rounds += 1;
            if self.completed_rounds < self.max_rounds {
                self.controller.state = RuntimeMessageExchangeState::AwaitingRequest;
            }
        }
    }

    impl RuntimeCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            !self.failed
                && self.received_requests == self.max_requests
                && self.completed_responses == self.max_requests
                && self.pending_request_ids.is_empty()
        }

        pub fn received_requests(&self) -> u32 {
            self.received_requests
        }

        pub fn completed_responses(&self) -> u32 {
            self.completed_responses
        }

        pub fn pending_requests(&self) -> u32 {
            self.pending_request_ids.len() as u32
        }

        pub fn max_requests(&self) -> u32 {
            self.max_requests
        }

        pub fn max_in_flight(&self) -> u32 {
            self.max_in_flight
        }

        fn reject_if_failed(&self) -> Result<(), RuntimeFdBrokerError> {
            if self.failed {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime correlated exchange is closed after a protocol or I/O failure"
                        .to_owned(),
                ));
            }
            Ok(())
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            self.reject_if_failed()?;
            if self.received_requests == self.max_requests {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime correlated exchange reached its configured request limit".to_owned(),
                ));
            }
            if self.pending_request_ids.len() as u32 == self.max_in_flight {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "runtime correlated exchange reached its in-flight request limit; publish a response before receiving another request".to_owned(),
                ));
            }

            let capacity = self.max_request_bytes as usize + 9;
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
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot receive runtime correlated request",
                        error,
                    ));
                }
                if received == 0 {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime correlated request must arrive before peer shutdown".to_owned(),
                    ));
                }
                if message.msg_flags & libc::MSG_TRUNC != 0
                    || received as u64 > self.max_request_bytes + 8
                {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeRequestTooLarge {
                        max_bytes: self.max_request_bytes,
                    });
                }
                if received < 9 {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime correlated request requires an 8-byte request id and a non-empty payload"
                            .to_owned(),
                    ));
                }

                let received = received as usize;
                let mut request_id_bytes = [0u8; 8];
                request_id_bytes.copy_from_slice(&bytes[..8]);
                let request_id = u64::from_le_bytes(request_id_bytes);
                if !self.seen_request_ids.insert(request_id) {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeDuplicateRequestId { request_id });
                }
                if !self.pending_request_ids.insert(request_id) {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime correlated request pending-set insertion was inconsistent"
                            .to_owned(),
                    ));
                }
                self.received_requests += 1;
                let payload = bytes[8..received].to_vec();
                return Ok(RuntimeCorrelatedRequest {
                    request_id,
                    payload,
                });
            }
        }

        pub fn send_response(
            &mut self,
            request_id: u64,
            bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            self.reject_if_failed()?;
            if !self.pending_request_ids.contains(&request_id) {
                self.failed = true;
                return Err(RuntimeFdBrokerError::RuntimeUnknownRequestId { request_id });
            }
            if bytes.is_empty() {
                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime correlated response must be non-empty".to_owned(),
                ));
            }
            if bytes.len() as u64 > self.max_response_bytes {
                self.failed = true;
                return Err(RuntimeFdBrokerError::RuntimeResponseTooLarge {
                    max_bytes: self.max_response_bytes,
                });
            }

            let mut frame = Vec::with_capacity(8 + bytes.len());
            frame.extend_from_slice(&request_id.to_le_bytes());
            frame.extend_from_slice(bytes);
            loop {
                let sent = unsafe {
                    libc::send(
                        self.fd,
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };
                if sent == frame.len() as isize {
                    self.pending_request_ids.remove(&request_id);
                    self.completed_responses += 1;
                    return Ok(());
                }
                if sent == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.failed = true;
                    if error.raw_os_error() == Some(libc::EAGAIN)
                        || error.raw_os_error() == Some(libc::EWOULDBLOCK)
                    {
                        return Err(RuntimeFdBrokerError::Protocol(
                            "runtime correlated response publication would block; the controller does not buffer responses"
                                .to_owned(),
                        ));
                    }
                    return Err(RuntimeFdBrokerError::io(
                        "cannot send runtime correlated response",
                        error,
                    ));
                }

                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "runtime correlated response sent unexpected packet length {sent}"
                )));
            }
        }
    }

    impl RuntimeAuthenticatedCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            !self.failed
                && self.challenge_published
                && self.received_requests == self.max_requests
                && self.completed_responses == self.max_requests
                && self.pending_request_ids.is_empty()
        }

        pub fn received_requests(&self) -> u32 {
            self.received_requests
        }

        pub fn completed_responses(&self) -> u32 {
            self.completed_responses
        }

        pub fn pending_requests(&self) -> u32 {
            self.pending_request_ids.len() as u32
        }

        pub fn max_requests(&self) -> u32 {
            self.max_requests
        }

        pub fn max_in_flight(&self) -> u32 {
            self.max_in_flight
        }

        pub fn challenge_published(&self) -> bool {
            self.challenge_published
        }

        fn reject_if_failed(&self) -> Result<(), RuntimeFdBrokerError> {
            if self.failed {
                return Err(RuntimeFdBrokerError::Protocol(
                    "authenticated runtime correlated exchange is closed after a protocol, authentication, or I/O failure".to_owned(),
                ));
            }
            Ok(())
        }

        /// Publish the fresh per-session public authentication challenge.
        pub fn publish_challenge(&mut self) -> Result<(), RuntimeFdBrokerError> {
            self.reject_if_failed()?;
            if self.challenge_published {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "authenticated runtime session challenge may be published exactly once"
                        .to_owned(),
                ));
            }
            let mut frame = [0u8; 2 + super::RUNTIME_AUTH_CHALLENGE_BYTES];
            frame[0] = RUNTIME_AUTH_CHALLENGE_KIND;
            frame[1] = RUNTIME_AUTH_PROTOCOL_VERSION;
            frame[2..].copy_from_slice(&self.challenge);
            loop {
                let sent = unsafe {
                    libc::send(
                        self.fd,
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if sent == frame.len() as isize {
                    self.challenge_published = true;
                    return Ok(());
                }
                if sent == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot publish authenticated runtime session challenge",
                        error,
                    ));
                }
                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "authenticated runtime challenge sent unexpected packet length {sent}"
                )));
            }
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            self.reject_if_failed()?;
            if !self.challenge_published {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "authenticated runtime session challenge must be published before receiving requests".to_owned(),
                ));
            }
            if self.received_requests == self.max_requests {
                return Err(RuntimeFdBrokerError::Protocol(
                    "authenticated runtime correlated exchange reached its configured request limit".to_owned(),
                ));
            }
            if self.pending_request_ids.len() as u32 == self.max_in_flight {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "authenticated runtime correlated exchange reached its in-flight request limit; publish a response before receiving another request".to_owned(),
                ));
            }

            let framing_bytes = 2usize + 8 + super::RUNTIME_AUTH_TAG_BYTES;
            let capacity = self.max_request_bytes as usize + framing_bytes;
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
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot receive authenticated runtime correlated request",
                        error,
                    ));
                }
                if received == 0 {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime request must arrive before peer shutdown".to_owned(),
                    ));
                }
                if message.msg_flags & libc::MSG_TRUNC != 0 || received as usize > capacity {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeRequestTooLarge {
                        max_bytes: self.max_request_bytes,
                    });
                }
                if received as usize <= framing_bytes {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime request requires type/version, an 8-byte request id, a non-empty payload, and a 32-byte tag".to_owned(),
                    ));
                }

                let received = received as usize;
                if bytes[0] != RUNTIME_AUTH_REQUEST_KIND
                    || bytes[1] != RUNTIME_AUTH_PROTOCOL_VERSION
                {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime request has an unsupported frame type or version"
                            .to_owned(),
                    ));
                }
                let mut request_id_bytes = [0u8; 8];
                request_id_bytes.copy_from_slice(&bytes[2..10]);
                let request_id = u64::from_le_bytes(request_id_bytes);
                let payload_end = received - super::RUNTIME_AUTH_TAG_BYTES;
                let payload = &bytes[10..payload_end];
                let tag = &bytes[payload_end..received];
                if !runtime_auth_verify(
                    &self.key,
                    &self.challenge,
                    RUNTIME_AUTH_REQUEST_KIND,
                    request_id,
                    payload,
                    tag,
                ) {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeAuthenticationFailed);
                }
                if !self.seen_request_ids.insert(request_id) {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeDuplicateRequestId { request_id });
                }
                if !self.pending_request_ids.insert(request_id) {
                    self.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime request pending-set insertion was inconsistent"
                            .to_owned(),
                    ));
                }
                self.received_requests += 1;
                return Ok(RuntimeCorrelatedRequest {
                    request_id,
                    payload: payload.to_vec(),
                });
            }
        }

        pub fn send_response(
            &mut self,
            request_id: u64,
            bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            self.reject_if_failed()?;
            if !self.challenge_published {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "authenticated runtime session challenge must be published before sending responses".to_owned(),
                ));
            }
            if !self.pending_request_ids.contains(&request_id) {
                self.failed = true;
                return Err(RuntimeFdBrokerError::RuntimeUnknownRequestId { request_id });
            }
            if bytes.is_empty() {
                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(
                    "authenticated runtime correlated response must be non-empty".to_owned(),
                ));
            }
            if bytes.len() as u64 > self.max_response_bytes {
                self.failed = true;
                return Err(RuntimeFdBrokerError::RuntimeResponseTooLarge {
                    max_bytes: self.max_response_bytes,
                });
            }

            let tag = runtime_auth_tag(
                &self.key,
                &self.challenge,
                RUNTIME_AUTH_RESPONSE_KIND,
                request_id,
                bytes,
            );
            let mut frame = Vec::with_capacity(2 + 8 + bytes.len() + tag.len());
            frame.push(RUNTIME_AUTH_RESPONSE_KIND);
            frame.push(RUNTIME_AUTH_PROTOCOL_VERSION);
            frame.extend_from_slice(&request_id.to_le_bytes());
            frame.extend_from_slice(bytes);
            frame.extend_from_slice(&tag);
            loop {
                let sent = unsafe {
                    libc::send(
                        self.fd,
                        frame.as_ptr().cast::<libc::c_void>(),
                        frame.len(),
                        libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
                    )
                };
                if sent == frame.len() as isize {
                    self.pending_request_ids.remove(&request_id);
                    self.completed_responses += 1;
                    return Ok(());
                }
                if sent == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.failed = true;
                    if error.raw_os_error() == Some(libc::EAGAIN)
                        || error.raw_os_error() == Some(libc::EWOULDBLOCK)
                    {
                        return Err(RuntimeFdBrokerError::Protocol(
                            "authenticated runtime correlated response publication would block; the controller does not buffer responses".to_owned(),
                        ));
                    }
                    return Err(RuntimeFdBrokerError::io(
                        "cannot send authenticated runtime correlated response",
                        error,
                    ));
                }
                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "authenticated runtime correlated response sent unexpected packet length {sent}"
                )));
            }
        }
    }

    impl RuntimeAcknowledgedCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            self.controller.is_complete()
                && self.acknowledged_responses == self.controller.max_requests()
                && self.awaiting_acknowledgment.is_none()
        }

        pub fn received_requests(&self) -> u32 {
            self.controller.received_requests()
        }

        pub fn published_responses(&self) -> u32 {
            self.controller.completed_responses()
        }

        pub fn acknowledged_responses(&self) -> u32 {
            self.acknowledged_responses
        }

        pub fn pending_requests(&self) -> u32 {
            self.controller.pending_requests()
        }

        pub fn max_requests(&self) -> u32 {
            self.controller.max_requests()
        }

        pub fn max_in_flight(&self) -> u32 {
            self.controller.max_in_flight()
        }

        pub fn challenge_published(&self) -> bool {
            self.controller.challenge_published()
        }

        pub fn awaiting_acknowledgment_request_id(&self) -> Option<u64> {
            self.awaiting_acknowledgment
                .as_ref()
                .map(|expectation| expectation.request_id)
        }

        pub fn publish_challenge(&mut self) -> Result<(), RuntimeFdBrokerError> {
            self.controller.publish_challenge()
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            self.controller.reject_if_failed()?;
            if self.awaiting_acknowledgment.is_some() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "acknowledged runtime exchange must consume the outstanding response acknowledgment before receiving another request"
                        .to_owned(),
                ));
            }
            self.controller.receive_request()
        }

        pub fn send_response(
            &mut self,
            request_id: u64,
            bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            self.controller.reject_if_failed()?;
            if self.awaiting_acknowledgment.is_some() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "acknowledged runtime exchange permits only one published response awaiting acknowledgment"
                        .to_owned(),
                ));
            }

            let response_sha256 = runtime_response_sha256(bytes);
            self.controller.send_response(request_id, bytes)?;
            self.awaiting_acknowledgment = Some(RuntimeResponseAcknowledgmentExpectation {
                request_id,
                response_sha256,
            });
            Ok(())
        }

        /// Consume one authenticated acknowledgment for the exact response bytes
        /// most recently published by this controller.
        ///
        /// The acknowledgment frame is fixed-size:
        /// `A || version=1 || request_id_le || sha256(response) || hmac_tag`.
        /// While this barrier is outstanding, the acknowledgment must be the
        /// peer's next packet; any request or other frame is a terminal protocol
        /// violation rather than a packet the controller can reorder or skip.
        pub fn receive_acknowledgment(&mut self) -> Result<u64, RuntimeFdBrokerError> {
            self.controller.reject_if_failed()?;
            let (expected_request_id, expected_response_sha256) = match self
                .awaiting_acknowledgment
                .as_ref()
            {
                Some(expectation) => (expectation.request_id, expectation.response_sha256),
                None => {
                    return Err(RuntimeFdBrokerError::InvalidConfiguration(
                        "acknowledged runtime exchange has no published response awaiting acknowledgment"
                            .to_owned(),
                    ));
                }
            };

            const ACK_FRAME_BYTES: usize = 2 + 8 + 32 + super::RUNTIME_AUTH_TAG_BYTES;
            let mut frame = [0u8; ACK_FRAME_BYTES];
            let mut iovec = libc::iovec {
                iov_base: frame.as_mut_ptr().cast::<libc::c_void>(),
                iov_len: frame.len(),
            };
            let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
            message.msg_iov = &mut iovec;
            message.msg_iovlen = 1;

            loop {
                message.msg_flags = 0;
                let received = unsafe { libc::recvmsg(self.controller.fd, &mut message, 0) };
                if received == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::io(
                        "cannot receive authenticated runtime response acknowledgment",
                        error,
                    ));
                }
                if received == 0 {
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime response acknowledgment must arrive before peer shutdown"
                            .to_owned(),
                    ));
                }
                if received >= 2
                    && (frame[0] != RUNTIME_AUTH_ACKNOWLEDGMENT_KIND
                        || frame[1] != RUNTIME_AUTH_PROTOCOL_VERSION)
                {
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime response acknowledgment must be the peer's next packet"
                            .to_owned(),
                    ));
                }
                if message.msg_flags & libc::MSG_TRUNC != 0 || received as usize != ACK_FRAME_BYTES
                {
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "authenticated runtime response acknowledgment has invalid packet length"
                            .to_owned(),
                    ));
                }

                let mut request_id_bytes = [0u8; 8];
                request_id_bytes.copy_from_slice(&frame[2..10]);
                let request_id = u64::from_le_bytes(request_id_bytes);
                let mut response_sha256 = [0u8; 32];
                response_sha256.copy_from_slice(&frame[10..42]);
                let tag = &frame[42..];

                if !runtime_auth_verify(
                    &self.controller.key,
                    &self.controller.challenge,
                    RUNTIME_AUTH_ACKNOWLEDGMENT_KIND,
                    request_id,
                    &response_sha256,
                    tag,
                ) {
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeAuthenticationFailed);
                }
                if request_id != expected_request_id || response_sha256 != expected_response_sha256
                {
                    self.controller.failed = true;
                    return Err(RuntimeFdBrokerError::RuntimeAcknowledgmentMismatch {
                        request_id: expected_request_id,
                    });
                }

                self.awaiting_acknowledgment = None;
                self.acknowledged_responses += 1;
                return Ok(request_id);
            }
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

    #[derive(Debug)]
    pub struct RuntimeHostUnixReconnectController {
        stream: UnixStream,
        service_path: PathBuf,
        expected_peer: Option<(u32, u32)>,
        max_connections: u32,
        granted_connections: u32,
        failed: bool,
    }

    impl RuntimeHostUnixReconnectController {
        pub fn max_connections(&self) -> u32 {
            self.max_connections
        }

        pub fn granted_connections(&self) -> u32 {
            self.granted_connections
        }

        pub fn is_complete(&self) -> bool {
            !self.failed && self.granted_connections == self.max_connections
        }

        pub fn is_failed(&self) -> bool {
            self.failed
        }

        /// Wait for one target readiness byte, then connect a fresh stream to
        /// the exact trusted service path and transfer only that connected
        /// object. Each round re-checks SO_PEERCRED before SCM_RIGHTS transfer.
        ///
        /// Any readiness, connect, credential, or transfer failure closes the
        /// controller terminally so an ambiguous round is never retried.
        pub fn grant_next(
            &mut self,
            expected_ready: u8,
        ) -> Result<HostUnixPeerCredentials, RuntimeFdBrokerError> {
            if self.failed {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime host UNIX reconnect controller is closed after a failed round"
                        .to_owned(),
                ));
            }
            if self.granted_connections >= self.max_connections {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime host UNIX reconnect controller exhausted its connection bound"
                        .to_owned(),
                ));
            }

            let mut ready = [0u8; 1];
            if let Err(error) = self.stream.read_exact(&mut ready) {
                self.failed = true;
                return Err(RuntimeFdBrokerError::io(
                    "cannot read runtime host UNIX reconnect readiness",
                    error,
                ));
            }
            if ready[0] != expected_ready {
                self.failed = true;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "expected reconnect readiness byte 0x{expected_ready:02x}, got 0x{:02x}",
                    ready[0]
                )));
            }

            let grant = match prepare_host_unix_stream(&self.service_path, self.expected_peer) {
                Ok(grant) => grant,
                Err(error) => {
                    self.failed = true;
                    return Err(error);
                }
            };
            let credentials = HostUnixPeerCredentials {
                pid: grant.peer_pid,
                uid: grant.peer_uid,
                gid: grant.peer_gid,
            };
            if let Err(error) = send_fds(self.stream.as_raw_fd(), &[grant.stream.as_raw_fd()]) {
                self.failed = true;
                return Err(error);
            }

            self.granted_connections += 1;
            Ok(credentials)
        }
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
            let stream = self.accept_trusted_stream()?;
            Ok(RuntimeFdSession {
                stream,
                state: RuntimeFdSessionState::AwaitingReady,
            })
        }

        /// Accept the already-configured target broker channel as a bounded
        /// reconnect controller for one exact host filesystem AF_UNIX service.
        ///
        /// The controller preserves the existing one-shot RuntimeFdSession ABI:
        /// it is a separate opt-in state machine with an explicit 2-8 connection
        /// ceiling. The service is not connected until each target readiness byte
        /// has been consumed.
        pub fn accept_host_unix_reconnect_controller(
            &self,
            service_path: impl AsRef<Path>,
            expected_peer: Option<(u32, u32)>,
            max_connections: u32,
        ) -> Result<RuntimeHostUnixReconnectController, RuntimeFdBrokerError> {
            if !(super::MIN_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS
                ..=super::MAX_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS)
                .contains(&max_connections)
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                    "runtime host UNIX reconnect connection bound must be between {} and {}",
                    super::MIN_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS,
                    super::MAX_RUNTIME_HOST_UNIX_RECONNECT_CONNECTIONS
                )));
            }
            let service_path = service_path.as_ref();
            validate_socket_path(service_path)?;
            let stream = self.accept_trusted_stream()?;
            Ok(RuntimeHostUnixReconnectController {
                stream,
                service_path: service_path.to_path_buf(),
                expected_peer,
                max_connections,
                granted_connections: 0,
                failed: false,
            })
        }

        fn accept_trusted_stream(&self) -> Result<UnixStream, RuntimeFdBrokerError> {
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
            Ok(stream)
        }

        /// Connect one exact host filesystem-path AF_UNIX stream before transfer.
        ///
        /// The trusted caller chooses the pathname. Optional expected UID/GID
        /// credentials are checked with Linux SO_PEERCRED before the connected
        /// socket can become a prepared runtime grant. The target receives only
        /// the connected socket object after the normal readiness handshake; it
        /// does not receive pathname lookup, socket creation, or connect authority.
        pub fn prepare_host_unix_stream(
            path: impl AsRef<Path>,
            expected_peer: Option<(u32, u32)>,
        ) -> Result<PreparedHostUnixStream, RuntimeFdBrokerError> {
            prepare_host_unix_stream(path.as_ref(), expected_peer)
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

        /// Prepare one bounded correlated request/response session.
        ///
        /// Each packet carries an 8-byte little-endian request id followed by a
        /// non-empty bounded payload. The controller may accept multiple unique
        /// requests before responding and may publish responses out of request
        /// order by id, while bounding both total requests and simultaneous
        /// in-flight requests.
        pub fn prepare_runtime_correlated_exchange(
            max_request_bytes: u64,
            max_response_bytes: u64,
            max_requests: u32,
            max_in_flight: u32,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_correlated_exchange(
                max_request_bytes,
                max_response_bytes,
                max_requests,
                max_in_flight,
            )
        }

        /// Prepare one authenticated bounded correlated request/response session.
        ///
        /// A fresh 256-bit challenge is generated by Linux `getrandom`. The
        /// trusted controller must publish it once after endpoint transfer before
        /// accepting requests. HMAC-SHA256 then binds that challenge, frame
        /// direction/version, request id, payload length, and payload.
        pub fn prepare_runtime_authenticated_correlated_exchange(
            max_request_bytes: u64,
            max_response_bytes: u64,
            max_requests: u32,
            max_in_flight: u32,
            key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeAuthenticatedCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_authenticated_correlated_exchange(
                max_request_bytes,
                max_response_bytes,
                max_requests,
                max_in_flight,
                key,
            )
        }

        /// Prepare authenticated correlated messaging with an acknowledgment
        /// barrier for every published response.
        ///
        /// The target must authenticate the SHA-256 of the exact response bytes
        /// before the trusted controller can consume another request.
        pub fn prepare_runtime_acknowledged_correlated_exchange(
            max_request_bytes: u64,
            max_response_bytes: u64,
            max_requests: u32,
            max_in_flight: u32,
            key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeAcknowledgedCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_acknowledged_correlated_exchange(
                max_request_bytes,
                max_response_bytes,
                max_requests,
                max_in_flight,
                key,
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

        /// Transfer exactly one previously prepared connected host AF_UNIX stream.
        pub fn send_host_unix_stream(
            &mut self,
            grant: PreparedHostUnixStream,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.stream.as_raw_fd())
        }

        /// Transfer one prepared host AF_UNIX stream while retaining trusted
        /// shutdown authority over the same socket object after transfer.
        pub fn send_revocable_host_unix_stream(
            &mut self,
            grant: PreparedHostUnixStream,
        ) -> Result<HostUnixStreamRevocationController, RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.stream.as_raw_fd())?;
            Ok(HostUnixStreamRevocationController {
                credentials: HostUnixPeerCredentials {
                    pid: grant.peer_pid,
                    uid: grant.peer_uid,
                    gid: grant.peer_gid,
                },
                stream: grant.stream,
                state: HostUnixStreamRevocationState::Active,
            })
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

    fn prepare_host_unix_stream(
        path: &Path,
        expected_peer: Option<(u32, u32)>,
    ) -> Result<PreparedHostUnixStream, RuntimeFdBrokerError> {
        validate_socket_path(path)?;
        let stream = UnixStream::connect(path).map_err(|error| {
            RuntimeFdBrokerError::io("cannot connect runtime host UNIX stream", error)
        })?;
        let (peer_pid, peer_uid, peer_gid) = peer_credentials(stream.as_raw_fd())?;
        if let Some((expected_uid, expected_gid)) = expected_peer {
            if peer_uid != expected_uid || peer_gid != expected_gid {
                return Err(RuntimeFdBrokerError::HostUnixPeerCredentialMismatch {
                    expected_uid,
                    expected_gid,
                    actual_pid: peer_pid,
                    actual_uid: peer_uid,
                    actual_gid: peer_gid,
                });
            }
        }
        Ok(PreparedHostUnixStream {
            stream,
            peer_pid,
            peer_uid,
            peer_gid,
        })
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

    fn prepare_runtime_correlated_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_requests: u32,
        max_in_flight: u32,
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeCorrelatedMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
        if max_request_bytes == 0 || max_request_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime correlated max_request_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }
        if max_response_bytes == 0 || max_response_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime correlated max_response_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }
        if !(super::MIN_RUNTIME_CORRELATED_REQUESTS..=super::MAX_RUNTIME_CORRELATED_REQUESTS)
            .contains(&max_requests)
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime correlated max_requests must be between {} and {}",
                super::MIN_RUNTIME_CORRELATED_REQUESTS,
                super::MAX_RUNTIME_CORRELATED_REQUESTS
            )));
        }
        if !(super::MIN_RUNTIME_CORRELATED_IN_FLIGHT..=super::MAX_RUNTIME_CORRELATED_IN_FLIGHT)
            .contains(&max_in_flight)
            || max_in_flight > max_requests
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime correlated max_in_flight must be between {} and {}, and may not exceed max_requests",
                super::MIN_RUNTIME_CORRELATED_IN_FLIGHT,
                super::MAX_RUNTIME_CORRELATED_IN_FLIGHT
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
                "cannot create runtime correlated exchange socketpair",
                std::io::Error::last_os_error(),
            ));
        }

        Ok((
            PreparedRuntimeMessageChannel { fd: fds[0] },
            RuntimeCorrelatedMessageExchangeController {
                fd: fds[1],
                max_request_bytes,
                max_response_bytes,
                max_requests,
                max_in_flight,
                received_requests: 0,
                completed_responses: 0,
                seen_request_ids: BTreeSet::new(),
                pending_request_ids: BTreeSet::new(),
                failed: false,
            },
        ))
    }

    fn prepare_runtime_authenticated_correlated_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_requests: u32,
        max_in_flight: u32,
        key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeAuthenticatedCorrelatedMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
        if max_request_bytes == 0 || max_request_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "authenticated runtime correlated max_request_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }
        if max_response_bytes == 0 || max_response_bytes > super::MAX_RUNTIME_MESSAGE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "authenticated runtime correlated max_response_bytes must be between 1 and {}",
                super::MAX_RUNTIME_MESSAGE_BYTES
            )));
        }
        if !(super::MIN_RUNTIME_CORRELATED_REQUESTS..=super::MAX_RUNTIME_CORRELATED_REQUESTS)
            .contains(&max_requests)
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "authenticated runtime correlated max_requests must be between {} and {}",
                super::MIN_RUNTIME_CORRELATED_REQUESTS,
                super::MAX_RUNTIME_CORRELATED_REQUESTS
            )));
        }
        if !(super::MIN_RUNTIME_CORRELATED_IN_FLIGHT..=super::MAX_RUNTIME_CORRELATED_IN_FLIGHT)
            .contains(&max_in_flight)
            || max_in_flight > max_requests
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "authenticated runtime correlated max_in_flight must be between {} and {}, and may not exceed max_requests",
                super::MIN_RUNTIME_CORRELATED_IN_FLIGHT,
                super::MAX_RUNTIME_CORRELATED_IN_FLIGHT
            )));
        }

        let challenge = random_runtime_auth_challenge()?;
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
                "cannot create authenticated runtime correlated exchange socketpair",
                std::io::Error::last_os_error(),
            ));
        }

        Ok((
            PreparedRuntimeMessageChannel { fd: fds[0] },
            RuntimeAuthenticatedCorrelatedMessageExchangeController {
                fd: fds[1],
                max_request_bytes,
                max_response_bytes,
                max_requests,
                max_in_flight,
                received_requests: 0,
                completed_responses: 0,
                seen_request_ids: BTreeSet::new(),
                pending_request_ids: BTreeSet::new(),
                key,
                challenge,
                challenge_published: false,
                failed: false,
            },
        ))
    }

    fn prepare_runtime_acknowledged_correlated_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
        max_requests: u32,
        max_in_flight: u32,
        key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeAcknowledgedCorrelatedMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
        let (grant, controller) = prepare_runtime_authenticated_correlated_exchange(
            max_request_bytes,
            max_response_bytes,
            max_requests,
            max_in_flight,
            key,
        )?;
        Ok((
            grant,
            RuntimeAcknowledgedCorrelatedMessageExchangeController {
                controller,
                awaiting_acknowledgment: None,
                acknowledged_responses: 0,
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
                session_deadline: None,
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
    use super::{
        File, HostUnixPeerCredentials, Path, RuntimeCorrelatedRequest, RuntimeFdBrokerError,
        SandboxPolicy,
    };

    #[derive(Debug)]
    pub struct PreparedHostUnixStream;

    #[derive(Debug)]
    pub struct HostUnixStreamRevocationController;

    impl HostUnixStreamRevocationController {
        pub fn peer_credentials(&self) -> HostUnixPeerCredentials {
            HostUnixPeerCredentials {
                pid: 0,
                uid: 0,
                gid: 0,
            }
        }

        pub fn is_revoked(&self) -> bool {
            false
        }

        pub fn is_failed(&self) -> bool {
            false
        }

        pub fn revoke(&mut self) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable host UNIX stream grants currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl PreparedHostUnixStream {
        pub fn peer_pid(&self) -> i32 {
            0
        }

        pub fn peer_uid(&self) -> u32 {
            0
        }

        pub fn peer_gid(&self) -> u32 {
            0
        }
    }

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

    #[derive(Debug)]
    pub struct RuntimeCorrelatedMessageExchangeController;

    #[derive(Debug)]
    pub struct RuntimeAuthenticatedCorrelatedMessageExchangeController;

    #[derive(Debug)]
    pub struct RuntimeAcknowledgedCorrelatedMessageExchangeController;

    impl RuntimeCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn received_requests(&self) -> u32 {
            0
        }

        pub fn completed_responses(&self) -> u32 {
            0
        }

        pub fn pending_requests(&self) -> u32 {
            0
        }

        pub fn max_requests(&self) -> u32 {
            0
        }

        pub fn max_in_flight(&self) -> u32 {
            0
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime correlated exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_response(
            &mut self,
            _request_id: u64,
            _bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime correlated exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeAuthenticatedCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn received_requests(&self) -> u32 {
            0
        }

        pub fn completed_responses(&self) -> u32 {
            0
        }

        pub fn pending_requests(&self) -> u32 {
            0
        }

        pub fn max_requests(&self) -> u32 {
            0
        }

        pub fn max_in_flight(&self) -> u32 {
            0
        }

        pub fn challenge_published(&self) -> bool {
            false
        }

        pub fn publish_challenge(&mut self) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "authenticated runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "authenticated runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn send_response(
            &mut self,
            _request_id: u64,
            _bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "authenticated runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }
    }

    impl RuntimeAcknowledgedCorrelatedMessageExchangeController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn received_requests(&self) -> u32 {
            0
        }

        pub fn published_responses(&self) -> u32 {
            0
        }

        pub fn acknowledged_responses(&self) -> u32 {
            0
        }

        pub fn pending_requests(&self) -> u32 {
            0
        }

        pub fn max_requests(&self) -> u32 {
            0
        }

        pub fn max_in_flight(&self) -> u32 {
            0
        }

        pub fn challenge_published(&self) -> bool {
            false
        }

        pub fn awaiting_acknowledgment_request_id(&self) -> Option<u64> {
            None
        }

        pub fn publish_challenge(&mut self) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "acknowledged runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn receive_request(
            &mut self,
        ) -> Result<RuntimeCorrelatedRequest, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "acknowledged runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn send_response(
            &mut self,
            _request_id: u64,
            _bytes: &[u8],
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "acknowledged runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn receive_acknowledgment(&mut self) -> Result<u64, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "acknowledged runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }
    }

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

        pub fn start_session_deadline(
            &mut self,
            _limit_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message session deadlines currently require Linux x86_64".to_owned(),
            ))
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

        pub fn send_response_with_deadline(
            &mut self,
            _bytes: &[u8],
            _wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message response deadlines currently require Linux x86_64"
                    .to_owned(),
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

        pub fn send_response_with_deadline(
            &mut self,
            _bytes: &[u8],
            _wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message response deadlines currently require Linux x86_64".to_owned(),
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

    #[derive(Debug)]
    pub struct RuntimeHostUnixReconnectController;

    impl RuntimeHostUnixReconnectController {
        pub fn max_connections(&self) -> u32 {
            0
        }

        pub fn granted_connections(&self) -> u32 {
            0
        }

        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn is_failed(&self) -> bool {
            false
        }

        pub fn grant_next(
            &mut self,
            _expected_ready: u8,
        ) -> Result<HostUnixPeerCredentials, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime host UNIX reconnect controllers currently require Linux x86_64".to_owned(),
            ))
        }
    }

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

        pub fn accept_host_unix_reconnect_controller(
            &self,
            _service_path: impl AsRef<Path>,
            _expected_peer: Option<(u32, u32)>,
            _max_connections: u32,
        ) -> Result<RuntimeHostUnixReconnectController, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime host UNIX reconnect controllers currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_host_unix_stream(
            _path: impl AsRef<Path>,
            _expected_peer: Option<(u32, u32)>,
        ) -> Result<PreparedHostUnixStream, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime host UNIX stream grants currently require Linux x86_64".to_owned(),
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

        pub fn prepare_runtime_correlated_exchange(
            _max_request_bytes: u64,
            _max_response_bytes: u64,
            _max_requests: u32,
            _max_in_flight: u32,
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime correlated exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_runtime_authenticated_correlated_exchange(
            _max_request_bytes: u64,
            _max_response_bytes: u64,
            _max_requests: u32,
            _max_in_flight: u32,
            _key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeAuthenticatedCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "authenticated runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn prepare_runtime_acknowledged_correlated_exchange(
            _max_request_bytes: u64,
            _max_response_bytes: u64,
            _max_requests: u32,
            _max_in_flight: u32,
            _key: [u8; super::RUNTIME_AUTH_KEY_BYTES],
        ) -> Result<
            (
                PreparedRuntimeMessageChannel,
                RuntimeAcknowledgedCorrelatedMessageExchangeController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "acknowledged runtime correlated exchanges currently require Linux x86_64"
                    .to_owned(),
            ))
        }
    }

    impl RuntimeFdSession {
        pub fn wait_for_ready(&mut self, _expected: u8) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn send_host_unix_stream(
            &mut self,
            _grant: PreparedHostUnixStream,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime host UNIX stream grants currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_revocable_host_unix_stream(
            &mut self,
            _grant: PreparedHostUnixStream,
        ) -> Result<HostUnixStreamRevocationController, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "revocable host UNIX stream grants currently require Linux x86_64".to_owned(),
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
    HostUnixStreamRevocationController, PreparedHostUnixStream, PreparedReadOnlyRegularFile,
    PreparedRevocableByteStream, PreparedRuntimeMessageChannel, PreparedSealedRegularFileSnapshot,
    PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeAcknowledgedCorrelatedMessageExchangeController,
    RuntimeAuthenticatedCorrelatedMessageExchangeController,
    RuntimeCorrelatedMessageExchangeController, RuntimeFdBroker, RuntimeFdSession,
    RuntimeHostUnixReconnectController, RuntimeMessageExchangeController,
    RuntimeMultiMessageExchangeController,
};
