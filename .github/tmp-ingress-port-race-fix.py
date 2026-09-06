from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "tests/sandbox.rs",
    '''fn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {
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
''',
    '''fn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {
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
''',
    "fallible readiness helper",
)

replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn brokered_host_loopback_tcp_listener_accepts_one_host_ingress_capability() {
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
    read_exact_fd(read_end.raw(), &mut ready);
    assert_eq!(&ready, b"brokered-host-ingress-ready\\n");

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
}
''',
    '''#[test]
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
        assert_eq!(&ready, b"brokered-host-ingress-ready\\n");

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
''',
    "ingress acquisition retry",
)
