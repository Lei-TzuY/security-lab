from pathlib import Path

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

def replace_span(path: str, start: str, end: str, replacement: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"{label}: start marker missing")
    j = text.find(end, i)
    if j < 0:
        raise SystemExit(f"{label}: end marker missing")
    if text.find(start, i + 1) >= 0:
        raise SystemExit(f"{label}: start marker not unique")
    p.write_text(text[:i] + replacement + text[j:])

runtime = "src/runtime_fd_broker.rs"

replace_one(
    runtime,
    "pub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;\n",
    "pub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;\npub const MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS: u64 = 86_400_000;\n",
    "response deadline constant",
)

replace_one(
    runtime,
    """    RuntimeRequestTimedOut {
        wait_milliseconds: u64,
    },
""",
    """    RuntimeRequestTimedOut {
        wait_milliseconds: u64,
    },
    RuntimeResponseTimedOut {
        wait_milliseconds: u64,
    },
""",
    "response timeout error variant",
)

replace_one(
    runtime,
    """            Self::RuntimeRequestTimedOut { wait_milliseconds } => write!(
                f,
                "runtime FD broker request wait exceeded {wait_milliseconds} ms"
            ),
""",
    """            Self::RuntimeRequestTimedOut { wait_milliseconds } => write!(
                f,
                "runtime FD broker request wait exceeded {wait_milliseconds} ms"
            ),
            Self::RuntimeResponseTimedOut { wait_milliseconds } => write!(
                f,
                "runtime FD broker response publication wait exceeded {wait_milliseconds} ms"
            ),
""",
    "response timeout display",
)

replace_one(
    runtime,
    """    impl Drop for RequestDeadlineTimer {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    impl RuntimeMessageExchangeController {
""",
    """    impl Drop for RequestDeadlineTimer {
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
                        "runtime message response publication deadlines require timerfd"
                            .to_owned(),
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

    impl RuntimeMessageExchangeController {
""",
    "response deadline timer",
)

send_block = r'''        /// Send exactly one non-empty response packet after a valid request.
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
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
                        ) {
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

'''
replace_span(
    runtime,
    "        /// Send exactly one non-empty response packet after a valid request.\n",
    "    impl RuntimeMultiMessageExchangeController {",
    send_block,
    "response send implementation",
)

replace_one(
    runtime,
    """        pub fn send_response(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            self.controller.send_response(bytes)?;
            self.completed_rounds += 1;
            if self.completed_rounds < self.max_rounds {
                self.controller.state = RuntimeMessageExchangeState::AwaitingRequest;
            }
            Ok(())
        }
""",
    """        pub fn send_response(&mut self, bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
            self.controller.send_response(bytes)?;
            self.complete_response_round();
            Ok(())
        }

        pub fn send_response_with_deadline(
            &mut self,
            bytes: &[u8],
            wait_milliseconds: u64,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.reject_after_round_limit()?;
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
""",
    "multi response deadline wrapper",
)

replace_one(
    runtime,
    """        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeMessageExchangeController {
""",
    """        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
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
""",
    "nonlinux multi response deadline",
)

replace_one(
    runtime,
    """        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RevocableByteStreamController {
""",
    """        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
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
""",
    "nonlinux response deadline",
)

replace_one(
    "src/lib.rs",
    """    MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS, MAX_RUNTIME_MULTI_MESSAGE_ROUNDS,
""",
    """    MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS, MAX_RUNTIME_MULTI_MESSAGE_ROUNDS,
""",
    "lib response deadline export",
)

replace_one(
    "tests/runtime_fd_broker.rs",
    """    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_MULTI_MESSAGE_ROUNDS, MAX_RUNTIME_REVOCABLE_STREAM_BYTES,
""",
    """    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS, MAX_RUNTIME_MULTI_MESSAGE_ROUNDS,
    MAX_RUNTIME_REVOCABLE_STREAM_BYTES,
""",
    "test response deadline import",
)

tests = r'''
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
        controller.send_response_with_deadline(
            b"ok",
            MAX_RUNTIME_MESSAGE_RESPONSE_WAIT_MILLISECONDS + 1
        ),
        Err(RuntimeFdBrokerError::InvalidConfiguration(_))
    ));

    controller
        .send_response_with_deadline(b"ok", 1000)
        .unwrap();
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

'''

replace_one(
    "tests/runtime_fd_broker.rs",
    """#[test]
fn bounded_runtime_multi_message_exchange_completes_exact_round_limit() {
""",
    tests + """#[test]
fn bounded_runtime_multi_message_exchange_completes_exact_round_limit() {
""",
    "response deadline tests",
)
