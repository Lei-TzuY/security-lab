from pathlib import Path
import re

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

broker = "src/runtime_fd_broker.rs"

replace_one(
    broker,
    "    use std::os::unix::io::{AsRawFd, RawFd};\n",
    "    use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};\n",
    "linux raw-fd imports",
)

channel_marker = '''    impl Drop for PreparedRuntimeMessageChannel {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeMessageExchangeState {
'''
channel_insert = '''    impl Drop for PreparedRuntimeMessageChannel {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct PreparedRuntimeSnapshotReturnChannel {
        fd: RawFd,
    }

    impl Drop for PreparedRuntimeSnapshotReturnChannel {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct ReturnedSealedRuntimeSnapshot {
        snapshot: PreparedSealedRegularFileSnapshot,
    }

    impl ReturnedSealedRuntimeSnapshot {
        pub fn len(&self) -> u64 {
            self.snapshot.len
        }

        pub fn is_empty(&self) -> bool {
            self.snapshot.len == 0
        }

        /// Read the immutable returned bytes without changing the snapshot's file offset.
        pub fn read_all(&self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            let len = usize::try_from(self.snapshot.len).map_err(|_| {
                RuntimeFdBrokerError::Protocol(
                    "returned sealed runtime snapshot length does not fit usize".to_owned(),
                )
            })?;
            let mut bytes = vec![0u8; len];
            let mut done = 0usize;
            while done < bytes.len() {
                let read = unsafe {
                    libc::pread(
                        self.snapshot.fd,
                        bytes[done..].as_mut_ptr().cast::<libc::c_void>(),
                        bytes.len() - done,
                        done as libc::off_t,
                    )
                };
                if read == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(RuntimeFdBrokerError::io(
                        "cannot read returned sealed runtime snapshot",
                        error,
                    ));
                }
                if read == 0 {
                    return Err(RuntimeFdBrokerError::Protocol(
                        "returned sealed runtime snapshot ended before its sealed length".to_owned(),
                    ));
                }
                done += read as usize;
            }
            Ok(bytes)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeSnapshotReturnState {
        AwaitingSnapshot,
        Complete,
        Failed,
    }

    #[derive(Debug)]
    pub struct RuntimeSnapshotReturnController {
        fd: RawFd,
        max_bytes: u64,
        state: RuntimeSnapshotReturnState,
    }

    impl Drop for RuntimeSnapshotReturnController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl RuntimeSnapshotReturnController {
        pub fn is_complete(&self) -> bool {
            self.state == RuntimeSnapshotReturnState::Complete
        }

        /// Receive exactly one target-returned regular-file descriptor, attenuate it
        /// to read-only authority, and freeze a bounded byte copy into a sealed memfd.
        pub fn receive_snapshot(
            &mut self,
        ) -> Result<ReturnedSealedRuntimeSnapshot, RuntimeFdBrokerError> {
            if self.state != RuntimeSnapshotReturnState::AwaitingSnapshot {
                let message = match self.state {
                    RuntimeSnapshotReturnState::Complete => {
                        "runtime snapshot return permits exactly one completed result"
                    }
                    RuntimeSnapshotReturnState::Failed => {
                        "runtime snapshot return is closed after a protocol or I/O failure"
                    }
                    RuntimeSnapshotReturnState::AwaitingSnapshot => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            let received_fd = match receive_one_fd(self.fd, "runtime snapshot return") {
                Ok(fd) => fd,
                Err(error) => {
                    self.state = RuntimeSnapshotReturnState::Failed;
                    return Err(error);
                }
            };
            let received = unsafe { File::from_raw_fd(received_fd) };
            let snapshot = match prepare_sealed_regular_file_snapshot(&received, self.max_bytes) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    self.state = RuntimeSnapshotReturnState::Failed;
                    return Err(error);
                }
            };

            self.state = RuntimeSnapshotReturnState::Complete;
            Ok(ReturnedSealedRuntimeSnapshot { snapshot })
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeMessageExchangeState {
'''
replace_one(broker, channel_marker, channel_insert, "runtime snapshot return public types")

broker_method_marker = '''        pub fn prepare_runtime_message_exchange(
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
    }
'''
broker_method_insert = '''        pub fn prepare_runtime_message_exchange(
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

        /// Prepare one receive-only controller channel for a bounded target result.
        ///
        /// The target endpoint can only send. The trusted controller receives
        /// exactly one SCM_RIGHTS descriptor, validates regular/readable authority,
        /// and freezes a bounded byte copy into an immutable sealed memfd.
        pub fn prepare_runtime_snapshot_return(
            max_bytes: u64,
        ) -> Result<
            (
                PreparedRuntimeSnapshotReturnChannel,
                RuntimeSnapshotReturnController,
            ),
            RuntimeFdBrokerError,
        > {
            prepare_runtime_snapshot_return(max_bytes)
        }
    }
'''
replace_one(broker, broker_method_marker, broker_method_insert, "runtime snapshot return broker method")

session_marker = '''        pub fn send_runtime_message_channel(
            &mut self,
            grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        fn send_prepared_fd(&mut self, fd: RawFd) -> Result<(), RuntimeFdBrokerError> {
'''
session_insert = '''        pub fn send_runtime_message_channel(
            &mut self,
            grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer the send-only target endpoint for one returned sealed snapshot.
        pub fn send_runtime_snapshot_return_channel(
            &mut self,
            grant: PreparedRuntimeSnapshotReturnChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        fn send_prepared_fd(&mut self, fd: RawFd) -> Result<(), RuntimeFdBrokerError> {
'''
replace_one(broker, session_marker, session_insert, "runtime snapshot return session grant")

private_marker = '''    fn prepare_runtime_message_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
'''
private_insert = '''    fn prepare_runtime_snapshot_return(
        max_bytes: u64,
    ) -> Result<
        (
            PreparedRuntimeSnapshotReturnChannel,
            RuntimeSnapshotReturnController,
        ),
        RuntimeFdBrokerError,
    > {
        if max_bytes == 0 || max_bytes > super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "runtime snapshot return max_bytes must be between 1 and {}",
                super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES
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
                "cannot create runtime snapshot return socketpair",
                std::io::Error::last_os_error(),
            ));
        }

        if unsafe { libc::shutdown(fds[0], libc::SHUT_RD) } == -1 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(RuntimeFdBrokerError::io(
                "cannot make runtime snapshot target endpoint send-only",
                error,
            ));
        }
        if unsafe { libc::shutdown(fds[1], libc::SHUT_WR) } == -1 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fds[0]);
                libc::close(fds[1]);
            }
            return Err(RuntimeFdBrokerError::io(
                "cannot make runtime snapshot controller endpoint receive-only",
                error,
            ));
        }

        Ok((
            PreparedRuntimeSnapshotReturnChannel { fd: fds[0] },
            RuntimeSnapshotReturnController {
                fd: fds[1],
                max_bytes,
                state: RuntimeSnapshotReturnState::AwaitingSnapshot,
            },
        ))
    }

    fn prepare_runtime_message_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
'''
replace_one(broker, private_marker, private_insert, "runtime snapshot return private prepare")

cmsg_marker = '''    fn cmsg_space_for_fd_count(count: usize) -> usize {
        let unaligned = std::mem::size_of::<libc::cmsghdr>() + count * std::mem::size_of::<RawFd>();
        let alignment = std::mem::size_of::<usize>();
        (unaligned + alignment - 1) & !(alignment - 1)
    }

    fn send_fds(socket_fd: RawFd, source_fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
'''
cmsg_insert = '''    fn cmsg_space_for_fd_count(count: usize) -> usize {
        let unaligned = std::mem::size_of::<libc::cmsghdr>() + count * std::mem::size_of::<RawFd>();
        let alignment = std::mem::size_of::<usize>();
        (unaligned + alignment - 1) & !(alignment - 1)
    }

    fn close_fds(fds: &[RawFd]) {
        for fd in fds {
            if *fd >= 0 {
                unsafe {
                    libc::close(*fd);
                }
            }
        }
    }

    fn parse_received_rights(
        control: &FdControl,
        used: usize,
    ) -> Result<(Vec<RawFd>, usize), RuntimeFdBrokerError> {
        if used > control.0.len() {
            return Err(RuntimeFdBrokerError::Protocol(
                "SCM_RIGHTS receive reported control length beyond its bounded buffer".to_owned(),
            ));
        }

        let header_bytes = std::mem::size_of::<libc::cmsghdr>();
        let alignment = std::mem::size_of::<usize>();
        let mut offset = 0usize;
        let mut cmsg_count = 0usize;
        let mut rights = Vec::new();

        while offset < used {
            if used - offset < header_bytes {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "SCM_RIGHTS receive ended with a truncated ancillary header".to_owned(),
                ));
            }

            let header = unsafe {
                &*control
                    .0
                    .as_ptr()
                    .add(offset)
                    .cast::<libc::cmsghdr>()
            };
            let cmsg_len = header.cmsg_len;
            if cmsg_len < header_bytes || cmsg_len > used - offset {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "SCM_RIGHTS receive reported an invalid ancillary length".to_owned(),
                ));
            }
            if header.cmsg_level != libc::SOL_SOCKET || header.cmsg_type != libc::SCM_RIGHTS {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime snapshot return received unexpected ancillary data".to_owned(),
                ));
            }

            let data_bytes = cmsg_len - header_bytes;
            if data_bytes == 0 || data_bytes % std::mem::size_of::<RawFd>() != 0 {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "SCM_RIGHTS receive contained an invalid descriptor payload".to_owned(),
                ));
            }
            let count = data_bytes / std::mem::size_of::<RawFd>();
            if rights.len() + count > super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "SCM_RIGHTS receive exceeded the bounded descriptor count".to_owned(),
                ));
            }

            let data = unsafe {
                control
                    .0
                    .as_ptr()
                    .add(offset + header_bytes)
                    .cast::<RawFd>()
            };
            for index in 0..count {
                let fd = unsafe { data.add(index).read() };
                if fd < 0 {
                    close_fds(&rights);
                    return Err(RuntimeFdBrokerError::Protocol(
                        "SCM_RIGHTS receive produced an invalid descriptor".to_owned(),
                    ));
                }
                rights.push(fd);
            }

            cmsg_count += 1;
            let step = (cmsg_len + alignment - 1) & !(alignment - 1);
            if step == 0 || step > used - offset {
                close_fds(&rights);
                return Err(RuntimeFdBrokerError::Protocol(
                    "SCM_RIGHTS receive had invalid ancillary alignment".to_owned(),
                ));
            }
            offset += step;
        }

        Ok((rights, cmsg_count))
    }

    fn receive_one_fd(
        socket_fd: RawFd,
        label: &'static str,
    ) -> Result<RawFd, RuntimeFdBrokerError> {
        let mut payload = [0u8; 1];
        let mut iovec = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: payload.len(),
        };
        let mut control = FdControl([0; 48]);
        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
        message.msg_controllen = control.0.len();

        loop {
            message.msg_flags = 0;
            message.msg_controllen = control.0.len();
            let received =
                unsafe { libc::recvmsg(socket_fd, &mut message, libc::MSG_CMSG_CLOEXEC) };
            if received == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot receive runtime snapshot return descriptor",
                    error,
                ));
            }
            if received == 0 {
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "{label} peer closed before returning a descriptor"
                )));
            }

            let parsed = parse_received_rights(&control, message.msg_controllen);
            let (rights, cmsg_count) = match parsed {
                Ok(parsed) => parsed,
                Err(error) => return Err(error),
            };
            let fail = |rights: Vec<RawFd>, message: String| {
                close_fds(&rights);
                RuntimeFdBrokerError::Protocol(message)
            };

            if received != 1 {
                return Err(fail(
                    rights,
                    format!("{label} used unexpected payload length {received}"),
                ));
            }
            if payload != *b"F" {
                return Err(fail(
                    rights,
                    format!("{label} used an unexpected payload marker"),
                ));
            }
            if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
                return Err(fail(
                    rights,
                    format!("{label} ancillary or packet data was truncated"),
                ));
            }
            if cmsg_count != 1 || rights.len() != 1 {
                return Err(fail(
                    rights,
                    format!("{label} must return exactly one SCM_RIGHTS descriptor"),
                ));
            }
            return Ok(rights[0]);
        }
    }

    fn send_fds(socket_fd: RawFd, source_fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
'''
replace_one(broker, cmsg_marker, cmsg_insert, "reverse SCM_RIGHTS receive helper")

# Unsupported-platform API parity.
replace_one(
    broker,
    '''    #[derive(Debug)]
    pub struct PreparedRuntimeMessageChannel;

    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;
''',
    '''    #[derive(Debug)]
    pub struct PreparedRuntimeMessageChannel;

    #[derive(Debug)]
    pub struct PreparedRuntimeSnapshotReturnChannel;

    #[derive(Debug)]
    pub struct ReturnedSealedRuntimeSnapshot;

    #[derive(Debug)]
    pub struct RuntimeSnapshotReturnController;

    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;
''',
    "unsupported snapshot return types",
)

replace_one(
    broker,
    '''    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;

    impl RuntimeMessageExchangeController {
''',
    '''    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;

    impl ReturnedSealedRuntimeSnapshot {
        pub fn len(&self) -> u64 {
            0
        }

        pub fn is_empty(&self) -> bool {
            true
        }

        pub fn read_all(&self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "returned sealed runtime snapshots currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeSnapshotReturnController {
        pub fn is_complete(&self) -> bool {
            false
        }

        pub fn receive_snapshot(
            &mut self,
        ) -> Result<ReturnedSealedRuntimeSnapshot, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime snapshot returns currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeMessageExchangeController {
''',
    "unsupported snapshot return impls",
)

replace_one(
    broker,
    '''        pub fn prepare_runtime_message_exchange(
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
    }
''',
    '''        pub fn prepare_runtime_message_exchange(
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

        pub fn prepare_runtime_snapshot_return(
            _max_bytes: u64,
        ) -> Result<
            (
                PreparedRuntimeSnapshotReturnChannel,
                RuntimeSnapshotReturnController,
            ),
            RuntimeFdBrokerError,
        > {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime snapshot returns currently require Linux x86_64".to_owned(),
            ))
        }
    }
''',
    "unsupported snapshot return prepare",
)

replace_one(
    broker,
    '''        pub fn send_runtime_message_channel(
            &mut self,
            _grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }
''',
    '''        pub fn send_runtime_message_channel(
            &mut self,
            _grant: PreparedRuntimeMessageChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_runtime_snapshot_return_channel(
            &mut self,
            _grant: PreparedRuntimeSnapshotReturnChannel,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime snapshot returns currently require Linux x86_64".to_owned(),
            ))
        }
    }
''',
    "unsupported snapshot return send",
)

replace_one(
    broker,
    '''pub use imp::{
    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdSession, RuntimeMessageExchangeController,
};
''',
    '''pub use imp::{
    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedRuntimeSnapshotReturnChannel, PreparedSealedRegularFileSnapshot,
    PreparedSealedSnapshotBundle, ReturnedSealedRuntimeSnapshot, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdSession, RuntimeMessageExchangeController,
    RuntimeSnapshotReturnController,
};
''',
    "runtime snapshot return re-export",
)

replace_one(
    "src/lib.rs",
    '''pub use runtime_fd_broker::{
    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdBrokerError, RuntimeFdSession, RuntimeMessageExchangeController,
''',
    '''pub use runtime_fd_broker::{
    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedRuntimeSnapshotReturnChannel, PreparedSealedRegularFileSnapshot,
    PreparedSealedSnapshotBundle, ReturnedSealedRuntimeSnapshot, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdBrokerError, RuntimeFdSession, RuntimeMessageExchangeController,
    RuntimeSnapshotReturnController,
''',
    "lib runtime snapshot return exports",
)

# Test helpers and deterministic local regressions.
tests = "tests/runtime_fd_broker.rs"

send_helper_marker = '''fn receive_one_fd(stream: &UnixStream) -> TestFd {
'''
send_helper = '''fn send_one_fd(socket_fd: RawFd, source_fd: RawFd) {
    let mut payload = *b"F";
    let mut iovec = libc::iovec {
        iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: payload.len(),
    };
    let mut control = OneFdControl([0; 24]);
    let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
    unsafe {
        (*header).cmsg_len =
            std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>();
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        control
            .0
            .as_mut_ptr()
            .add(std::mem::size_of::<libc::cmsghdr>())
            .cast::<RawFd>()
            .write(source_fd);
    }

    let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
    message.msg_controllen = control.0.len();

    assert_eq!(
        unsafe { libc::sendmsg(socket_fd, &message, libc::MSG_NOSIGNAL) },
        1,
        "send one reverse SCM_RIGHTS descriptor failed: {}",
        std::io::Error::last_os_error()
    );
}

fn receive_one_fd(stream: &UnixStream) -> TestFd {
'''
replace_one(tests, send_helper_marker, send_helper, "reverse send-one-fd test helper")

replace_one(
    tests,
    '''    std::fs::create_dir_all(root.join("work")).expect("create sandbox work directory");
''',
    '''    std::fs::create_dir_all(root.join("work")).expect("create sandbox work directory");
    std::fs::create_dir_all(root.join("scratch")).expect("create sandbox scratch directory");
''',
    "runtime broker scratch fixture",
)

test_insert_marker = '''#[test]
fn bounded_runtime_message_exchange_reaches_real_target() {
'''
test_insert = '''#[test]
fn runtime_snapshot_return_rejects_invalid_bounds_and_malformed_result() {
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_snapshot_return(0),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));
    assert!(matches!(
        RuntimeFdBroker::prepare_runtime_snapshot_return(
            MAX_RUNTIME_SEALED_SNAPSHOT_BYTES + 1
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    let socket_path = unique_path("runtime-return-malformed.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_snapshot_return(4096).unwrap();
    session
        .send_runtime_snapshot_return_channel(grant)
        .unwrap();
    let endpoint = receive_one_fd(&client);

    assert_eq!(
        unsafe {
            libc::send(
                endpoint.raw(),
                b"F".as_ptr().cast::<libc::c_void>(),
                1,
                libc::MSG_NOSIGNAL,
            )
        },
        1
    );
    assert!(matches!(
        controller.receive_snapshot(),
        Err(RuntimeFdBrokerError::Protocol(message))
            if message.contains("exactly one SCM_RIGHTS descriptor")
                || message.contains("ancillary")
    ));
    assert!(matches!(
        controller.receive_snapshot(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
}

#[test]
fn runtime_snapshot_return_enforces_copy_ceiling_and_terminal_failure() {
    let socket_path = unique_path("runtime-return-too-large.sock");
    let file_path = unique_path("runtime-return-too-large-source");
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&file_path);
    std::fs::write(&file_path, b"12345").unwrap();

    let broker = RuntimeFdBroker::bind(&socket_path).unwrap();
    let mut client = UnixStream::connect(broker.path()).unwrap();
    let mut session = broker.accept().unwrap();
    client.write_all(b"R").unwrap();
    session.wait_for_ready(b'R').unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_snapshot_return(4).unwrap();
    session
        .send_runtime_snapshot_return_channel(grant)
        .unwrap();
    let endpoint = receive_one_fd(&client);
    let source = File::open(&file_path).unwrap();
    send_one_fd(endpoint.raw(), source.as_raw_fd());

    assert!(matches!(
        controller.receive_snapshot(),
        Err(RuntimeFdBrokerError::SourceSnapshotTooLarge { max_bytes: 4 })
    ));
    assert!(matches!(
        controller.receive_snapshot(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("closed after")
    ));

    drop(source);
    drop(endpoint);
    drop(session);
    drop(client);
    drop(broker);
    std::fs::remove_file(&file_path).unwrap();
}

#[test]
fn returned_sealed_snapshot_reaches_host_from_real_target_private_scratch() {
    let root = build_probe_root();
    let socket_path = unique_path("runtime-return-sandbox.sock");
    let _ = std::fs::remove_file(&socket_path);
    let broker = RuntimeFdBroker::bind(&socket_path)
        .expect("bind sandbox runtime snapshot return broker");
    let text = format!(
        "filesystem.root = {}\\n\\
         identity.hostname = security-lab\\n\\
         filesystem.scratch = /scratch\\n\\
         filesystem.scratch_bytes = 1048576\\n\\
         executable = /probe\\n\\
         arg = 6\\n\\
         working_dir = /work\\n\\
         stdio.stdin = closed\\n\\
         stdio.stdout = closed\\n\\
         stdio.stderr = closed\\n\\
         limit.wall_clock_milliseconds = 3000\\n\\
         limit.cpu_seconds = 2\\n\\
         limit.address_space_bytes = 134217728\\n\\
         limit.file_size_bytes = 1048576\\n\\
         limit.open_files = 32\\n\\
         seccomp.allow = execveat,write,recvmsg,openat,sendmsg,close,exit\\n",
        root.display()
    );
    let mut policy: SandboxPolicy = text.parse().expect("parse runtime snapshot return policy");
    broker.configure_policy(&mut policy, 10).unwrap();

    let (grant, mut controller) =
        RuntimeFdBroker::prepare_runtime_snapshot_return(4096).unwrap();
    let runner = thread::spawn(move || run(&policy));
    let mut session = broker.accept().expect("accept runtime snapshot return target");
    if let Err(readiness_error) = session.wait_for_ready(b'R') {
        let runner_result = runner.join().expect("runtime snapshot return runner panicked");
        panic!(
            "runtime snapshot return target failed before readiness: {readiness_error}; runner result: {runner_result:?}"
        );
    }
    session
        .send_runtime_snapshot_return_channel(grant)
        .expect("transfer send-only runtime snapshot return endpoint");

    let snapshot = controller
        .receive_snapshot()
        .expect("receive and seal target result snapshot");
    assert_eq!(snapshot.len(), b"runtime-result-snapshot\\n".len() as u64);
    assert!(!snapshot.is_empty());
    assert_eq!(
        snapshot.read_all().expect("read returned sealed snapshot"),
        b"runtime-result-snapshot\\n"
    );
    assert!(controller.is_complete());
    assert!(matches!(
        controller.receive_snapshot(),
        Err(RuntimeFdBrokerError::Protocol(message)) if message.contains("exactly one")
    ));

    assert_eq!(
        runner
            .join()
            .expect("runtime snapshot return runner panicked")
            .unwrap(),
        ChildOutcome::Exited(0)
    );
    assert!(
        !root.join("scratch/runtime-result").exists(),
        "private scratch result unexpectedly persisted into the host root tree"
    );

    drop(session);
    drop(broker);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn bounded_runtime_message_exchange_reaches_real_target() {
'''
replace_one(tests, test_insert_marker, test_insert, "runtime snapshot return tests")

# Raw target: mode 6 receives a send-only return endpoint, creates one private scratch
# result, and returns exactly that O_RDWR regular-file descriptor by SCM_RIGHTS.
probe = "tests/fixtures/probe.S"
replace_one(
    probe,
    "#   5 exchange one bounded request/response packet over a runtime SOCK_SEQPACKET channel\n",
    "#   5 exchange one bounded request/response packet over a runtime SOCK_SEQPACKET channel\n"
    "#   6 return one private-scratch regular-file result through a send-only SCM_RIGHTS channel\n",
    "probe mode documentation",
)
replace_one(
    probe,
    '''    cmp $53, %al
    je .brokered_runtime_message_exchange
    cmp $49, %al
''',
    '''    cmp $53, %al
    je .brokered_runtime_message_exchange
    cmp $54, %al
    je .brokered_runtime_snapshot_return
    cmp $49, %al
''',
    "probe mode dispatch",
)

mode_marker = '''    jmp .fail29


.brokered_host_unix_scm_rights:
'''
mode_code = '''    jmp .fail29


.brokered_runtime_snapshot_return:
    sub $192, %rsp
    mov $-1, %r12
    mov $-1, %r13

    # Publish post-exec readiness before receiving the private send-only endpoint.
    movb $82, 175(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 175(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .brokered_runtime_snapshot_return_fail

    # Receive exactly one return-channel endpoint through the normal broker.
    xor %eax, %eax
    mov %rax, 0(%rsp)
    mov %rax, 8(%rsp)
    lea 64(%rsp), %rax
    mov %rax, 16(%rsp)
    movq $1, 24(%rsp)
    lea 80(%rsp), %rax
    mov %rax, 32(%rsp)
    movq $24, 40(%rsp)
    movq $0, 48(%rsp)
    lea 176(%rsp), %rax
    mov %rax, 64(%rsp)
    movq $1, 72(%rsp)
    movq $0, 80(%rsp)
    movq $0, 88(%rsp)
    movq $0, 96(%rsp)

    mov $47, %eax
    mov $10, %edi
    mov %rsp, %rsi
    mov $0x40000000, %edx
    syscall
    cmp $1, %rax
    jne .brokered_runtime_snapshot_return_fail
    cmpb $70, 176(%rsp)
    jne .brokered_runtime_snapshot_return_fail
    testl $8, 48(%rsp)
    jne .brokered_runtime_snapshot_return_fail
    cmpq $20, 80(%rsp)
    jne .brokered_runtime_snapshot_return_fail
    cmpl $1, 88(%rsp)
    jne .brokered_runtime_snapshot_return_fail
    cmpl $1, 92(%rsp)
    jne .brokered_runtime_snapshot_return_fail
    mov 96(%rsp), %r12d
    test %r12d, %r12d
    js .brokered_runtime_snapshot_return_fail

    # Produce one result only inside private scratch. O_RDWR lets the target write
    # it while allowing the trusted host to attenuate the returned descriptor.
    mov $257, %eax
    mov $-100, %edi
    lea runtime_result_path(%rip), %rsi
    mov $0x80242, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .brokered_runtime_snapshot_return_fail
    mov %eax, %r13d

    mov $1, %eax
    mov %r13d, %edi
    lea runtime_result_snapshot(%rip), %rsi
    mov $runtime_result_snapshot_len, %edx
    syscall
    cmp $runtime_result_snapshot_len, %rax
    jne .brokered_runtime_snapshot_return_fail

    # Return exactly one descriptor and one-byte marker via SCM_RIGHTS.
    movq $0, 0(%rsp)
    movq $0, 8(%rsp)
    lea 64(%rsp), %rax
    mov %rax, 16(%rsp)
    movq $1, 24(%rsp)
    lea 80(%rsp), %rax
    mov %rax, 32(%rsp)
    movq $24, 40(%rsp)
    movq $0, 48(%rsp)
    movb $70, 176(%rsp)
    lea 176(%rsp), %rax
    mov %rax, 64(%rsp)
    movq $1, 72(%rsp)
    movq $20, 80(%rsp)
    movl $1, 88(%rsp)
    movl $1, 92(%rsp)
    mov %r13d, 96(%rsp)

    mov $46, %eax
    mov %r12d, %edi
    mov %rsp, %rsi
    mov $0x4000, %edx
    syscall
    cmp $1, %rax
    jne .brokered_runtime_snapshot_return_fail

    mov $3, %eax
    mov %r13d, %edi
    syscall
    test %rax, %rax
    js .brokered_runtime_snapshot_return_fail
    mov $-1, %r13

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .brokered_runtime_snapshot_return_fail
    mov $-1, %r12

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .brokered_runtime_snapshot_return_fail

    add $192, %rsp
    xor %edi, %edi
    jmp .exit

.brokered_runtime_snapshot_return_fail:
    test %r13d, %r13d
    js .brokered_runtime_snapshot_return_close_endpoint
    mov $3, %eax
    mov %r13d, %edi
    syscall
.brokered_runtime_snapshot_return_close_endpoint:
    test %r12d, %r12d
    js .brokered_runtime_snapshot_return_restore
    mov $3, %eax
    mov %r12d, %edi
    syscall
.brokered_runtime_snapshot_return_restore:
    add $192, %rsp
    jmp .fail29


.brokered_host_unix_scm_rights:
'''
replace_one(probe, mode_marker, mode_code, "probe returned snapshot implementation")

replace_one(
    probe,
    '''runtime_message_response:
    .ascii "runtime-response\\n"
.set runtime_message_response_len, . - runtime_message_response
brokered_host_unix_reply:
''',
    '''runtime_message_response:
    .ascii "runtime-response\\n"
.set runtime_message_response_len, . - runtime_message_response
runtime_result_path:
    .asciz "/scratch/runtime-result"
runtime_result_snapshot:
    .ascii "runtime-result-snapshot\\n"
.set runtime_result_snapshot_len, . - runtime_result_snapshot
brokered_host_unix_reply:
''',
    "probe returned snapshot data",
)
