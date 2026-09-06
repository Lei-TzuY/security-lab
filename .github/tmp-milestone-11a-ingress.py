from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface + fail-closed validation.
replace_one(
    "src/policy.rs",
    '''    pub host_loopback_tcp_port: Option<u16>,\n    pub host_loopback_tcp_target_fd: Option<u32>,\n    /// Optional trusted host directory exposed read-only at exactly one\n''',
    '''    pub host_loopback_tcp_port: Option<u16>,\n    pub host_loopback_tcp_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.\n    /// The port and target descriptor must be specified together.\n    pub host_loopback_tcp_listen_port: Option<u16>,\n    pub host_loopback_tcp_listen_target_fd: Option<u32>,\n    /// Optional trusted host directory exposed read-only at exactly one\n''',
    "policy ingress fields",
)

replace_one(
    "src/policy.rs",
    '''        match (&self.readonly_volume_source, &self.readonly_volume_target) {\n''',
    '''        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n            (None, None) => {}\n            (Some(port), Some(target_fd)) => {\n                if port == 0 {\n                    return Err(PolicyError::new(\n                        "network.host_loopback_tcp_listen_port must be between 1 and 65535",\n                    ));\n                }\n                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        "network.host_loopback_tcp_listen_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}"\n                    )));\n                }\n                if u64::from(target_fd) >= self.limits.open_files {\n                    return Err(PolicyError::new(format!(\n                        "network.host_loopback_tcp_listen_target_fd {target_fd} must be below limit.open_files {}",\n                        self.limits.open_files\n                    )));\n                }\n                if self.selected_handles.contains_key(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        "network host-loopback listener target fd {target_fd} collides with a selected handle target"\n                    )));\n                }\n                if self.host_loopback_tcp_target_fd == Some(target_fd) {\n                    return Err(PolicyError::new(format!(\n                        "network host-loopback listener target fd {target_fd} collides with the brokered connection target"\n                    )));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    "network.host_loopback_tcp_listen_port and network.host_loopback_tcp_listen_target_fd must be specified together",\n                ));\n            }\n        }\n\n        match (&self.readonly_volume_source, &self.readonly_volume_target) {\n''',
    "policy ingress validation",
)

replace_one(
    "src/policy.rs",
    '''        let mut host_loopback_tcp_port = None;\n        let mut host_loopback_tcp_target_fd = None;\n        let mut readonly_volume_source = None;\n''',
    '''        let mut host_loopback_tcp_port = None;\n        let mut host_loopback_tcp_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;\n        let mut host_loopback_tcp_listen_target_fd = None;\n        let mut readonly_volume_source = None;\n''',
    "parser ingress vars",
)

replace_one(
    "src/policy.rs",
    '''                "network.host_loopback_tcp_target_fd" => set_once(\n                    &mut host_loopback_tcp_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!("{key} must be an unsigned integer"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                "volume.readonly_source" => {\n''',
    '''                "network.host_loopback_tcp_target_fd" => set_once(\n                    &mut host_loopback_tcp_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!("{key} must be an unsigned integer"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                "network.host_loopback_tcp_listen_port" => set_once(\n                    &mut host_loopback_tcp_listen_port,\n                    parse_tcp_port(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                "network.host_loopback_tcp_listen_target_fd" => set_once(\n                    &mut host_loopback_tcp_listen_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!("{key} must be an unsigned integer"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                "volume.readonly_source" => {\n''',
    "parser ingress keys",
)

replace_one(
    "src/policy.rs",
    '''            host_loopback_tcp_port,\n            host_loopback_tcp_target_fd,\n            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n''',
    '''            host_loopback_tcp_port,\n            host_loopback_tcp_target_fd,\n            host_loopback_tcp_listen_port,\n            host_loopback_tcp_listen_target_fd,\n            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n''',
    "parser ingress output",
)

replace_one(
    "src/policy.rs",
    '''    #[test]\n    fn parses_readonly_volume_pair() {\n''',
    '''    #[test]\n    fn parses_brokered_host_loopback_tcp_listener() {\n        let text = format!(\n            "{VALID}\\nnetwork.host_loopback_tcp_listen_port = 9090\\nnetwork.host_loopback_tcp_listen_target_fd = 11"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.host_loopback_tcp_listen_port, Some(9090));\n        assert_eq!(policy.host_loopback_tcp_listen_target_fd, Some(11));\n    }\n\n    #[test]\n    fn rejects_incomplete_or_colliding_brokered_host_loopback_tcp_listener() {\n        let incomplete = format!("{VALID}\\nnetwork.host_loopback_tcp_listen_port = 9090");\n        assert!(incomplete.parse::<SandboxPolicy>().is_err());\n\n        let collision = format!(\n            "{VALID}\\nhandle.11 = 0\\nnetwork.host_loopback_tcp_listen_port = 9090\\nnetwork.host_loopback_tcp_listen_target_fd = 11"\n        );\n        let error = collision.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains("collides with a selected handle target"));\n\n        let broker_collision = format!(\n            "{VALID}\\nnetwork.host_loopback_tcp_port = 8080\\nnetwork.host_loopback_tcp_target_fd = 11\\nnetwork.host_loopback_tcp_listen_port = 9090\\nnetwork.host_loopback_tcp_listen_target_fd = 11"\n        );\n        let error = broker_collision.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains("collides with the brokered connection target"));\n    }\n\n    #[test]\n    fn parses_readonly_volume_pair() {\n''',
    "policy ingress tests",
)

# Linux launcher: build the listening socket in the host network namespace and
# route it through the same collision-safe selected-object plane.
replace_one(
    "src/platform/linux.rs",
    '''    fn prepare_volume(\n''',
    '''    fn listen_host_loopback_tcp(\n        port: u16,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n        let socket_fd =\n            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };\n        if socket_fd == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot create brokered host-loopback TCP listener: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        let socket_fd = OwnedFd(socket_fd);\n        let address = libc::sockaddr_in {\n            sin_family: libc::AF_INET as libc::sa_family_t,\n            sin_port: port.to_be(),\n            sin_addr: libc::in_addr {\n                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),\n            },\n            sin_zero: [0; 8],\n        };\n        loop {\n            let bound = unsafe {\n                libc::bind(\n                    socket_fd.raw(),\n                    (&address as *const libc::sockaddr_in).cast::<libc::sockaddr>(),\n                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,\n                )\n            };\n            if bound == 0 {\n                break;\n            }\n            let error = io::Error::last_os_error();\n            if error.raw_os_error() == Some(libc::EINTR) {\n                continue;\n            }\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot bind brokered host-loopback TCP listener 127.0.0.1:{port}: {error}"\n            )));\n        }\n        loop {\n            if unsafe { libc::listen(socket_fd.raw(), 1) } == 0 {\n                break;\n            }\n            let error = io::Error::last_os_error();\n            if error.raw_os_error() == Some(libc::EINTR) {\n                continue;\n            }\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot listen on brokered host-loopback TCP endpoint 127.0.0.1:{port}: {error}"\n            )));\n        }\n        let storage_fd = move_owned_fd_to_selected_storage(\n            socket_fd,\n            storage_floor,\n            "brokered host-loopback TCP listener",\n        )?;\n        Ok(PreparedSelectedHandle {\n            storage_fd,\n            target_fd: target_fd as RawFd,\n        })\n    }\n\n    fn prepare_volume(\n''',
    "launcher ingress listener",
)

replace_one(
    "src/platform/linux.rs",
    '''                .chain(policy.host_loopback_tcp_target_fd.iter().copied())\n                .max()\n''',
    '''                .chain(policy.host_loopback_tcp_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())\n                .max()\n''',
    "listener storage floor",
)

replace_one(
    "src/platform/linux.rs",
    '''                policy.selected_handles.len()\n                    + if policy.host_loopback_tcp_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },\n''',
    '''                policy.selected_handles.len()\n                    + if policy.host_loopback_tcp_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    }\n                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },\n''',
    "listener selected capacity",
)

replace_one(
    "src/platform/linux.rs",
    '''            let cancellation_fd = cancellation\n''',
    '''            match (\n                policy.host_loopback_tcp_listen_port,\n                policy.host_loopback_tcp_listen_target_fd,\n            ) {\n                (Some(port), Some(target_fd)) => selected_handles.push(listen_host_loopback_tcp(\n                    port,\n                    target_fd,\n                    selected_storage_floor,\n                )?),\n                (None, None) => {}\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        "network.host_loopback_tcp_listen_port and network.host_loopback_tcp_listen_target_fd must be specified together",\n                    )));\n                }\n            }\n            let cancellation_fd = cancellation\n''',
    "listener preparation",
)

# Integration helper and deterministic host<->target exchange.
replace_one(
    "tests/sandbox.rs",
    '''fn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {\n''',
    '''fn write_all_fd(fd: RawFd, buffer: &[u8]) {\n    let mut offset = 0usize;\n    while offset < buffer.len() {\n        let written = unsafe {\n            libc::write(\n                fd,\n                buffer[offset..].as_ptr().cast::<libc::c_void>(),\n                buffer.len() - offset,\n            )\n        };\n        if written == -1 {\n            let error = std::io::Error::last_os_error();\n            if error.raw_os_error() == Some(libc::EINTR) {\n                continue;\n            }\n            panic!("fd write failed: {error}");\n        }\n        assert!(written > 0, "fd write made no progress");\n        offset += written as usize;\n    }\n}\n\nfn read_exact_fd(fd: RawFd, buffer: &mut [u8]) {\n''',
    "host write helper",
)

replace_one(
    "tests/sandbox.rs",
    '''        host_loopback_tcp_port: None,\n        host_loopback_tcp_target_fd: None,\n        readonly_volume_source: None,\n''',
    '''        host_loopback_tcp_port: None,\n        host_loopback_tcp_target_fd: None,\n        host_loopback_tcp_listen_port: None,\n        host_loopback_tcp_listen_target_fd: None,\n        readonly_volume_source: None,\n''',
    "integration policy listener defaults",
)

replace_one(
    "tests/sandbox.rs",
    '''#[test]\nfn loopback_is_down_unless_policy_enables_it() {\n''',
    '''#[test]\nfn brokered_host_loopback_tcp_listener_accepts_one_host_ingress_capability() {\n    let reservation = TcpListener::bind(("127.0.0.1", 0)).expect("reserve ingress host port");\n    let port = reservation.local_addr().expect("read reserved ingress port").port();\n    drop(reservation);\n\n    let mut pipe = [-1; 2];\n    assert_eq!(\n        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },\n        0,\n        "create ingress readiness pipe"\n    );\n    let read_end = TestFd(pipe[0]);\n    let write_end = TestFd(pipe[1]);\n\n    let runner = thread::spawn(move || {\n        let mut ingress = policy(\n            "q",\n            &[],\n            &["execveat", "write", "accept", "read", "close", "exit"],\n        );\n        ingress\n            .selected_handles\n            .insert(9, write_end.raw() as u32);\n        ingress.host_loopback_tcp_listen_port = Some(port);\n        ingress.host_loopback_tcp_listen_target_fd = Some(10);\n        ingress.wall_clock_milliseconds = Some(5000);\n        run(&ingress)\n    });\n\n    let mut ready = [0u8; 28];\n    read_exact_fd(read_end.raw(), &mut ready);\n    assert_eq!(&ready, b"brokered-host-ingress-ready\\n");\n\n    let client = TcpStream::connect(("127.0.0.1", port))\n        .expect("connect to launcher-brokered host-loopback listener");\n    write_all_fd(client.as_raw_fd(), b"brokered-host-ingress-request");\n    let mut reply = [0u8; 24];\n    read_exact_fd(client.as_raw_fd(), &mut reply);\n    assert_eq!(&reply, b"brokered-host-ingress-ok");\n    drop(client);\n\n    assert_eq!(\n        runner\n            .join()\n            .expect("ingress sandbox thread panicked")\n            .expect("ingress sandbox run failed"),\n        ChildOutcome::Exited(0)\n    );\n}\n\n#[test]\nfn brokered_host_loopback_tcp_listener_bind_failure_is_fail_closed() {\n    let occupied = TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied ingress port");\n    let port = occupied.local_addr().expect("read occupied ingress port").port();\n    let mut ingress = policy("X", &[], &["execveat", "exit"]);\n    ingress.host_loopback_tcp_listen_port = Some(port);\n    ingress.host_loopback_tcp_listen_target_fd = Some(10);\n\n    match run(&ingress).unwrap_err() {\n        SandboxError::SetupFailed(message) => {\n            assert!(message.contains("cannot bind brokered host-loopback TCP listener"));\n        }\n        other => panic!("unexpected occupied-ingress result: {other}"),\n    }\n}\n\n#[test]\nfn loopback_is_down_unless_policy_enables_it() {\n''',
    "integration ingress tests",
)

# Raw target oracle. q never receives socket/bind/listen/connect in target seccomp;
# accept succeeds solely because the launcher transferred a host-netns listener fd.
replace_one(
    "tests/fixtures/probe.S",
    '''#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file\n''',
    '''#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   q accept one connection through a launcher-brokered host-loopback TCP listening fd\n#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file\n''',
    "fixture ingress mode docs",
)

replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $112, %al\n    je .brokered_host_loopback\n    cmp $114, %al\n''',
    '''    cmp $112, %al\n    je .brokered_host_loopback\n    cmp $113, %al\n    je .brokered_host_loopback_ingress\n    cmp $114, %al\n''',
    "fixture ingress dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    '''.landlock_read_envelope:\n''',
    '''.brokered_host_loopback_ingress:\n    mov $1, %eax\n    mov $9, %edi\n    lea brokered_ingress_ready(%rip), %rsi\n    mov $brokered_ingress_ready_len, %edx\n    syscall\n    cmp $brokered_ingress_ready_len, %rax\n    jne .fail39\n\n    mov $3, %eax\n    mov $9, %edi\n    syscall\n    test %rax, %rax\n    js .fail39\n\n    mov $43, %eax\n    mov $10, %edi\n    xor %esi, %esi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail39\n    mov %rax, %r12\n\n    xor %r13d, %r13d\n.ingress_read_loop:\n    mov $brokered_ingress_request_len, %edx\n    sub %r13d, %edx\n    jz .ingress_read_done\n    xor %eax, %eax\n    mov %r12, %rdi\n    lea network_buffer(%rip), %rsi\n    add %r13, %rsi\n    syscall\n    test %rax, %rax\n    jg .ingress_read_progress\n    je .fail39\n    cmp $-4, %rax\n    je .ingress_read_loop\n    jmp .fail39\n.ingress_read_progress:\n    add %rax, %r13\n    jmp .ingress_read_loop\n.ingress_read_done:\n    lea network_buffer(%rip), %rdi\n    lea brokered_ingress_request(%rip), %rsi\n    mov $brokered_ingress_request_len, %ecx\n    repe cmpsb\n    jne .fail39\n\n    xor %r13d, %r13d\n.ingress_write_loop:\n    mov $brokered_ingress_reply_len, %edx\n    sub %r13d, %edx\n    jz .ingress_write_done\n    mov $1, %eax\n    mov %r12, %rdi\n    lea brokered_ingress_reply(%rip), %rsi\n    add %r13, %rsi\n    syscall\n    test %rax, %rax\n    jg .ingress_write_progress\n    cmp $-4, %rax\n    je .ingress_write_loop\n    jmp .fail39\n.ingress_write_progress:\n    add %rax, %r13\n    jmp .ingress_write_loop\n.ingress_write_done:\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail39\n\n    mov $3, %eax\n    mov $10, %edi\n    syscall\n    test %rax, %rax\n    js .fail39\n    xor %edi, %edi\n    jmp .exit\n\n.landlock_read_envelope:\n''',
    "fixture ingress oracle",
)

replace_one(
    "tests/fixtures/probe.S",
    '''.fail38:\n    mov $38, %edi\n\n.exit:\n''',
    '''.fail38:\n    mov $38, %edi\n    jmp .exit\n.fail39:\n    mov $39, %edi\n\n.exit:\n''',
    "fixture ingress failure",
)

replace_one(
    "tests/fixtures/probe.S",
    '''brokered_host_message:\n    .ascii "brokered-host-loopback-ok"\n.set brokered_host_message_len, . - brokered_host_message\nlandlock_allowed_path:\n''',
    '''brokered_host_message:\n    .ascii "brokered-host-loopback-ok"\n.set brokered_host_message_len, . - brokered_host_message\nbrokered_ingress_ready:\n    .ascii "brokered-host-ingress-ready\\n"\n.set brokered_ingress_ready_len, . - brokered_ingress_ready\nbrokered_ingress_request:\n    .ascii "brokered-host-ingress-request"\n.set brokered_ingress_request_len, . - brokered_ingress_request\nbrokered_ingress_reply:\n    .ascii "brokered-host-ingress-ok"\n.set brokered_ingress_reply_len, . - brokered_ingress_reply\nlandlock_allowed_path:\n''',
    "fixture ingress data",
)
