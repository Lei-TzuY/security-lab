from pathlib import Path

def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

runtime = "src/runtime_fd_broker.rs"

replace_one(
    runtime,
    "pub const MAX_RUNTIME_MESSAGE_BYTES: u64 = 64 * 1024;\npub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;\n",
    "pub const MAX_RUNTIME_MESSAGE_BYTES: u64 = 64 * 1024;\npub const MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS: u64 = 86_400_000;\npub const MIN_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 2;\npub const MAX_RUNTIME_MULTI_MESSAGE_ROUNDS: u32 = 32;\n",
    "runtime constants",
)

replace_one(
    runtime,
    """    impl Drop for RuntimeMessageExchangeController {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    struct RequestDeadlineTimer {
""",
    """    impl Drop for RuntimeMessageExchangeController {
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
""",
    "multi controller struct",
)

replace_one(
    runtime,
    """    }

    #[derive(Debug)]
    pub struct RuntimeFdBroker {
""",
    """    }

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
""",
    "multi controller implementation",
)

replace_one(
    runtime,
    """        pub fn prepare_runtime_message_exchange(
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
""",
    """        pub fn prepare_runtime_message_exchange(
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
""",
    "public multi prepare",
)

replace_one(
    runtime,
    """    fn prepare_runtime_message_exchange(
        max_request_bytes: u64,
        max_response_bytes: u64,
    ) -> Result<
        (
            PreparedRuntimeMessageChannel,
            RuntimeMessageExchangeController,
        ),
        RuntimeFdBrokerError,
    > {
""",
    """    fn prepare_runtime_multi_message_exchange(
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
""",
    "private multi prepare",
)

replace_one(
    runtime,
    """    #[derive(Debug)]
    pub struct RuntimeMessageExchangeController;

    impl RuntimeMessageExchangeController {
""",
    """    #[derive(Debug)]
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
                "runtime multi-message request deadlines currently require Linux x86_64"
                    .to_owned(),
            ))
        }

        pub fn send_response(&mut self, _bytes: &[u8]) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime multi-message exchanges currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeMessageExchangeController {
""",
    "nonlinux multi controller",
)

replace_one(
    runtime,
    """        pub fn prepare_runtime_message_exchange(
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
""",
    """        pub fn prepare_runtime_message_exchange(
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
""",
    "nonlinux multi prepare",
)

replace_one(
    runtime,
    """    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdSession, RuntimeMessageExchangeController,
};
""",
    """    PreparedReadOnlyRegularFile, PreparedRevocableByteStream, PreparedRuntimeMessageChannel,
    PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle, RevocableByteStreamController,
    RuntimeFdBroker, RuntimeFdSession, RuntimeMessageExchangeController,
    RuntimeMultiMessageExchangeController,
};
""",
    "runtime re-export",
)

replace_one(
    "src/lib.rs",
    """    RuntimeFdBroker, RuntimeFdBrokerError, RuntimeFdSession, RuntimeMessageExchangeController,
    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,
""",
    """    RuntimeFdBroker, RuntimeFdBrokerError, RuntimeFdSession, RuntimeMessageExchangeController,
    RuntimeMultiMessageExchangeController, MAX_RUNTIME_MESSAGE_BYTES,
    MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS, MAX_RUNTIME_MULTI_MESSAGE_ROUNDS,
    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,
""",
    "lib multi exports",
)

replace_one(
    "src/lib.rs",
    """    MAX_RUNTIME_SEALED_BUNDLE_ITEMS, MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
    MIN_RUNTIME_SEALED_BUNDLE_ITEMS,
""",
    """    MAX_RUNTIME_SEALED_BUNDLE_ITEMS, MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
    MIN_RUNTIME_MULTI_MESSAGE_ROUNDS, MIN_RUNTIME_SEALED_BUNDLE_ITEMS,
""",
    "lib minimum rounds export",
)

replace_one(
    "tests/runtime_fd_broker.rs",
    """    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_REVOCABLE_STREAM_BYTES, MAX_RUNTIME_SEALED_BUNDLE_BYTES,
""",
    """    MAX_RUNTIME_MESSAGE_BYTES, MAX_RUNTIME_MESSAGE_REQUEST_WAIT_MILLISECONDS,
    MAX_RUNTIME_MULTI_MESSAGE_ROUNDS, MAX_RUNTIME_REVOCABLE_STREAM_BYTES,
    MAX_RUNTIME_SEALED_BUNDLE_BYTES,
""",
    "test max round import",
)

replace_one(
    "tests/runtime_fd_broker.rs",
    """    MAX_RUNTIME_SEALED_BUNDLE_ITEMS, MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
};
""",
    """    MAX_RUNTIME_SEALED_BUNDLE_ITEMS, MAX_RUNTIME_SEALED_SNAPSHOT_BYTES,
    MIN_RUNTIME_MULTI_MESSAGE_ROUNDS,
};
""",
    "test min round import",
)

tests = r'''
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

'''

replace_one(
    "tests/runtime_fd_broker.rs",
    """#[test]
fn bounded_runtime_message_exchange_reaches_real_target() {
""",
    tests + """#[test]
fn bounded_runtime_message_exchange_reaches_real_target() {
""",
    "multi-message tests",
)
