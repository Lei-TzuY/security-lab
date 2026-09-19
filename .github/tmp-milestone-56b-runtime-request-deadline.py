from pathlib import Path
import re

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

def regex_one(path: str, pattern: str, replacement: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, got {count}")
    p.write_text(updated)

broker = "src/runtime_fd_broker.rs"

replace_one(
    broker,
    "pub const MAX_RUNTIME_MESSAGE_BYTES: u64 = 64 * 1024;\n",
    "pub const MAX_RUNTIME_MESSAGE_BYTES: u64 = 64 * 1024;\n"
    "pub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;\n",
    "request wait ceiling constant",
)

replace_one(
    broker,
    "    RuntimeResponseTooLarge {\n"
    "        max_bytes: u64,\n"
    "    },\n"
    "    UnexpectedPeer {\n",
    "    RuntimeResponseTooLarge {\n"
    "        max_bytes: u64,\n"
    "    },\n"
    "    RuntimeRequestTimedOut {\n"
    "        wait_milliseconds: u64,\n"
    "    },\n"
    "    UnexpectedPeer {\n",
    "request timeout error variant",
)

replace_one(
    broker,
    "            Self::RuntimeResponseTooLarge { max_bytes } => write!(\n"
    "                f,\n"
    "                \"runtime FD broker response exceeds message byte ceiling of {max_bytes}\"\n"
    "            ),\n"
    "            Self::UnexpectedPeer {\n",
    "            Self::RuntimeResponseTooLarge { max_bytes } => write!(\n"
    "                f,\n"
    "                \"runtime FD broker response exceeds message byte ceiling of {max_bytes}\"\n"
    "            ),\n"
    "            Self::RuntimeRequestTimedOut { wait_milliseconds } => write!(\n"
    "                f,\n"
    "                \"runtime FD broker request wait exceeded {wait_milliseconds} ms\"\n"
    "            ),\n"
    "            Self::UnexpectedPeer {\n",
    "request timeout display",
)

timer_marker = '''    impl Drop for RuntimeMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl RuntimeMessageExchangeController {
'''
timer_insert = '''    impl Drop for RuntimeMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
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
'''
replace_one(broker, timer_marker, timer_insert, "request deadline timer helper")

receive_pattern = r'''        pub fn receive_request\(&mut self\) -> Result<Vec<u8>, RuntimeFdBrokerError> \{
.*?
        \}

        /// Send exactly one non-empty response packet after a valid request\.'''
receive_replacement = '''        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
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
                let ready =
                    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
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
                    return Err(RuntimeFdBrokerError::RuntimeRequestTimedOut {
                        wait_milliseconds,
                    });
                }
                if fds[1].revents != 0 {
                    self.state = RuntimeMessageExchangeState::Failed;
                    return Err(RuntimeFdBrokerError::Protocol(
                        "runtime message request deadline timer became unusable".to_owned(),
                    ));
                }
            }
        }

        /// Send exactly one non-empty response packet after a valid request.'''
regex_one(broker, receive_pattern, receive_replacement, "deadline-aware receive request")

replace_one(
    broker,
    '''        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
''',
    '''        pub fn receive_request(&mut self) -> Result<Vec<u8>, RuntimeFdBrokerError> {
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
''',
    "non-linux deadline stub",
)

replace_one(
    "src/lib.rs",
    "    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,\n",
    "    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,\n"
    "    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,\n",
    "deadline constant re-export",
)

tests = "tests/runtime_fd_broker.rs"
replace_one(
    tests,
    "    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,\n",
    "    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,\n"
    "    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,\n",
    "deadline test import",
)

insert_marker = '''#[test]
fn runtime_message_exchange_rejects_invalid_bounds_and_oversized_request() {
'''
new_tests = '''#[test]
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
        controller.receive_request_with_deadline(
            MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS + 1
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    let request = b"queued-before-deadline\n";
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
'''
replace_one(tests, insert_marker, new_tests, "deadline regressions")

replace_one(
    tests,
    '    assert_eq!(controller.receive_request().unwrap(), b"runtime-request\\n");\n',
    '    assert_eq!(\n'
    '        controller.receive_request_with_deadline(1000).unwrap(),\n'
    '        b"runtime-request\\n"\n'
    '    );\n',
    "real-target deadline path",
)
