from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: one already-open source FD and one target-visible control channel FD.
replace_one(
    "src/policy.rs",
    "    pub host_unix_stream_peer_uid: Option<u32>,\n    pub host_unix_stream_peer_gid: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.\n",
    "    pub host_unix_stream_peer_uid: Option<u32>,\n    pub host_unix_stream_peer_gid: Option<u32>,\n    /// Optional one-shot post-exec descriptor broker. The source names an already-open\n    /// caller FD pinned before fork; the target names the AF_UNIX control channel\n    /// installed into the direct target. The descriptor transfer occurs only after\n    /// the exec'd target sends the one-byte readiness request.\n    pub runtime_fd_broker_source_fd: Option<u32>,\n    pub runtime_fd_broker_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.\n",
    "policy broker fields",
)
replace_one(
    "src/policy.rs",
    "        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n",
    "        match (self.runtime_fd_broker_source_fd, self.runtime_fd_broker_target_fd) {\n            (None, None) => {}\n            (Some(source_fd), Some(target_fd)) => {\n                if source_fd > i32::MAX as u32 {\n                    return Err(PolicyError::new(format!(\n                        \"ipc.runtime_fd_broker_source_fd exceeds the Linux descriptor range: {source_fd}\"\n                    )));\n                }\n                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"ipc.runtime_fd_broker_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}\"\n                    )));\n                }\n                if u64::from(target_fd) >= self.limits.open_files {\n                    return Err(PolicyError::new(format!(\n                        \"ipc.runtime_fd_broker_target_fd {target_fd} must be below limit.open_files {}\",\n                        self.limits.open_files\n                    )));\n                }\n                if self.selected_handles.contains_key(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"runtime FD broker target fd {target_fd} collides with a selected handle target\"\n                    )));\n                }\n                for (label, existing) in [\n                    (\"host-loopback TCP connection\", self.host_loopback_tcp_target_fd),\n                    (\"host-IPv4 TCP connection\", self.host_ipv4_tcp_target_fd),\n                    (\"host-IPv4 UDP connection\", self.host_ipv4_udp_target_fd),\n                    (\"host-UNIX stream\", self.host_unix_stream_target_fd),\n                    (\"host-loopback TCP listener\", self.host_loopback_tcp_listen_target_fd),\n                ] {\n                    if existing == Some(target_fd) {\n                        return Err(PolicyError::new(format!(\n                            \"runtime FD broker target fd {target_fd} collides with the brokered {label} target\"\n                        )));\n                    }\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"ipc.runtime_fd_broker_source_fd and ipc.runtime_fd_broker_target_fd must be specified together\",\n                ));\n            }\n        }\n\n        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n",
    "policy broker validation",
)
replace_one(
    "src/policy.rs",
    "        let mut host_unix_stream_peer_uid = None;\n        let mut host_unix_stream_peer_gid = None;\n        let mut host_loopback_tcp_listen_port = None;\n",
    "        let mut host_unix_stream_peer_uid = None;\n        let mut host_unix_stream_peer_gid = None;\n        let mut runtime_fd_broker_source_fd = None;\n        let mut runtime_fd_broker_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;\n",
    "policy parser vars",
)
replace_one(
    "src/policy.rs",
    "                \"ipc.host_unix_stream_peer_gid\" => set_once(\n                    &mut host_unix_stream_peer_gid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n",
    "                \"ipc.host_unix_stream_peer_gid\" => set_once(\n                    &mut host_unix_stream_peer_gid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"ipc.runtime_fd_broker_source_fd\" => set_once(\n                    &mut runtime_fd_broker_source_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"ipc.runtime_fd_broker_target_fd\" => set_once(\n                    &mut runtime_fd_broker_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n",
    "policy parser keys",
)
replace_one(
    "src/policy.rs",
    "            host_unix_stream_peer_uid,\n            host_unix_stream_peer_gid,\n            host_loopback_tcp_listen_port,\n",
    "            host_unix_stream_peer_uid,\n            host_unix_stream_peer_gid,\n            runtime_fd_broker_source_fd,\n            runtime_fd_broker_target_fd,\n            host_loopback_tcp_listen_port,\n",
    "policy constructor",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_time_namespace_offsets() {\n",
    "    #[test]\n    fn parses_runtime_fd_broker_pair() {\n        let text = format!(\n            \"{VALID}\\nipc.runtime_fd_broker_source_fd = 200\\nipc.runtime_fd_broker_target_fd = 10\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.runtime_fd_broker_source_fd, Some(200));\n        assert_eq!(policy.runtime_fd_broker_target_fd, Some(10));\n    }\n\n    #[test]\n    fn rejects_incomplete_or_colliding_runtime_fd_broker() {\n        for invalid in [\n            format!(\"{VALID}\\nipc.runtime_fd_broker_source_fd = 200\"),\n            format!(\"{VALID}\\nipc.runtime_fd_broker_target_fd = 10\"),\n            format!(\"{VALID}\\nipc.runtime_fd_broker_source_fd = 2147483648\\nipc.runtime_fd_broker_target_fd = 10\"),\n            format!(\"{VALID}\\nipc.runtime_fd_broker_source_fd = 200\\nipc.runtime_fd_broker_target_fd = 2\"),\n            format!(\"{VALID}\\nipc.runtime_fd_broker_source_fd = 200\\nipc.runtime_fd_broker_target_fd = 40\"),\n            format!(\"{VALID}\\nhandle.10 = 201\\nipc.runtime_fd_broker_source_fd = 200\\nipc.runtime_fd_broker_target_fd = 10\"),\n        ] {\n            assert!(invalid.parse::<SandboxPolicy>().is_err());\n        }\n    }\n\n    #[test]\n    fn parses_time_namespace_offsets() {\n",
    "policy broker unit tests",
)

# Linux launcher: pin source before fork, install only the target control endpoint,
# and service one SCM_RIGHTS transfer after the exec'd target requests it.
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_COW_ROOT_ATTACH: u32 = 64;\n    const PHASE_COW_DIFF_EXPORT: u32 = 65;\n",
    "    const PHASE_COW_ROOT_ATTACH: u32 = 64;\n    const PHASE_COW_DIFF_EXPORT: u32 = 65;\n    const PHASE_RUNTIME_FD_BROKER_ISOLATE: u32 = 66;\n",
    "runtime broker phase",
)
replace_one(
    "src/platform/linux.rs",
    "    struct PreparedSelectedHandle {\n        storage_fd: OwnedFd,\n        target_fd: RawFd,\n    }\n\n    #[derive(Clone, Copy, PartialEq, Eq)]\n",
    "    struct PreparedSelectedHandle {\n        storage_fd: OwnedFd,\n        target_fd: RawFd,\n    }\n\n    struct PreparedRuntimeFdBroker {\n        host_fd: OwnedFd,\n        source_fd: OwnedFd,\n    }\n\n    #[derive(Clone, Copy, PartialEq, Eq)]\n",
    "prepared broker type",
)
replace_one(
    "src/platform/linux.rs",
    "    fn connect_host_tcp_ipv4(\n",
    "    fn prepare_runtime_fd_broker(\n        source_fd: u32,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<(PreparedSelectedHandle, PreparedRuntimeFdBroker), SandboxError> {\n        if source_fd > i32::MAX as u32 {\n            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(\n                \"runtime FD broker source exceeds the Linux descriptor range: {source_fd}\"\n            ))));\n        }\n        let pinned = unsafe {\n            libc::fcntl(source_fd as RawFd, libc::F_DUPFD_CLOEXEC, storage_floor)\n        };\n        if pinned == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"cannot pin runtime FD broker source fd {source_fd}: {}\",\n                io::Error::last_os_error()\n            )));\n        }\n        let source_fd = OwnedFd(pinned);\n        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };\n        if unsafe { libc::fstat(source_fd.raw(), &mut stat) } == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"cannot inspect runtime FD broker source: {}\",\n                io::Error::last_os_error()\n            )));\n        }\n        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {\n            return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                \"runtime FD broker source must not be a directory descriptor\",\n            )));\n        }\n\n        let mut sockets = [-1; 2];\n        if unsafe {\n            libc::socketpair(\n                libc::AF_UNIX,\n                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,\n                0,\n                sockets.as_mut_ptr(),\n            )\n        } == -1\n        {\n            return Err(SandboxError::SetupFailed(format!(\n                \"cannot create runtime FD broker socketpair: {}\",\n                io::Error::last_os_error()\n            )));\n        }\n        let target_storage = move_owned_fd_to_selected_storage(\n            OwnedFd(sockets[0]),\n            storage_floor,\n            \"runtime FD broker target channel\",\n        )?;\n        let host_fd = move_owned_fd_to_selected_storage(\n            OwnedFd(sockets[1]),\n            storage_floor,\n            \"runtime FD broker host channel\",\n        )?;\n        Ok((\n            PreparedSelectedHandle {\n                storage_fd: target_storage,\n                target_fd: target_fd as RawFd,\n            },\n            PreparedRuntimeFdBroker { host_fd, source_fd },\n        ))\n    }\n\n    fn service_runtime_fd_broker(broker: PreparedRuntimeFdBroker) -> Result<(), SandboxError> {\n        let mut request = [0u8; 2];\n        let received = loop {\n            let result = unsafe {\n                libc::recv(\n                    broker.host_fd.raw(),\n                    request.as_mut_ptr().cast::<libc::c_void>(),\n                    request.len(),\n                    0,\n                )\n            };\n            if result == -1 {\n                let error = io::Error::last_os_error();\n                if error.raw_os_error() == Some(libc::EINTR) {\n                    continue;\n                }\n                return Err(SandboxError::SetupFailed(format!(\n                    \"runtime FD broker readiness receive failed: {error}\"\n                )));\n            }\n            break result;\n        };\n        if received == 0 {\n            return Ok(());\n        }\n        if received != 1 || request[0] != b'R' {\n            return Err(SandboxError::SetupFailed(\n                \"runtime FD broker received an invalid readiness request\".to_owned(),\n            ));\n        }\n\n        let mut payload = *b\"F\";\n        let mut iov = libc::iovec {\n            iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),\n            iov_len: payload.len(),\n        };\n        let mut control = [0u64; 3];\n        let control_bytes = control.as_mut_ptr().cast::<u8>();\n        unsafe {\n            let header = control_bytes.cast::<libc::cmsghdr>();\n            (*header).cmsg_len =\n                std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>();\n            (*header).cmsg_level = libc::SOL_SOCKET;\n            (*header).cmsg_type = libc::SCM_RIGHTS;\n            ptr::write_unaligned(\n                control_bytes\n                    .add(std::mem::size_of::<libc::cmsghdr>())\n                    .cast::<RawFd>(),\n                broker.source_fd.raw(),\n            );\n        }\n        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };\n        message.msg_iov = &mut iov;\n        message.msg_iovlen = 1;\n        message.msg_control = control_bytes.cast::<libc::c_void>();\n        message.msg_controllen = std::mem::size_of_val(&control);\n        loop {\n            let sent = unsafe { libc::sendmsg(broker.host_fd.raw(), &message, 0) };\n            if sent == 1 {\n                return Ok(());\n            }\n            if sent == -1 {\n                let error = io::Error::last_os_error();\n                if error.raw_os_error() == Some(libc::EINTR) {\n                    continue;\n                }\n                return Err(SandboxError::SetupFailed(format!(\n                    \"runtime FD broker SCM_RIGHTS transfer failed: {error}\"\n                )));\n            }\n            return Err(SandboxError::SetupFailed(\n                \"runtime FD broker SCM_RIGHTS transfer returned a short send\".to_owned(),\n            ));\n        }\n    }\n\n    fn connect_host_tcp_ipv4(\n",
    "runtime broker helpers",
)
replace_one(
    "src/platform/linux.rs",
    "        selected_handles: Vec<PreparedSelectedHandle>,\n        selected_storage_floor: RawFd,\n        landlock: PreparedLandlock,\n",
    "        selected_handles: Vec<PreparedSelectedHandle>,\n        selected_storage_floor: RawFd,\n        runtime_fd_broker: Option<PreparedRuntimeFdBroker>,\n        landlock: PreparedLandlock,\n",
    "prepared launch broker field",
)
replace_one(
    "src/platform/linux.rs",
    "                .chain(policy.host_unix_stream_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())\n",
    "                .chain(policy.host_unix_stream_target_fd.iter().copied())\n                .chain(policy.runtime_fd_broker_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())\n",
    "storage floor broker target",
)
replace_one(
    "src/platform/linux.rs",
    "                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },\n",
    "                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    }\n                    + if policy.runtime_fd_broker_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },\n",
    "selected broker capacity",
)
replace_one(
    "src/platform/linux.rs",
    "            let cancellation_fd = cancellation\n",
    "            let runtime_fd_broker = match (\n                policy.runtime_fd_broker_source_fd,\n                policy.runtime_fd_broker_target_fd,\n            ) {\n                (Some(source_fd), Some(target_fd)) => {\n                    let (target_handle, broker) = prepare_runtime_fd_broker(\n                        source_fd,\n                        target_fd,\n                        selected_storage_floor,\n                    )?;\n                    selected_handles.push(target_handle);\n                    Some(broker)\n                }\n                (None, None) => None,\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.runtime_fd_broker_source_fd and ipc.runtime_fd_broker_target_fd must be specified together\",\n                    )));\n                }\n            };\n\n            let cancellation_fd = cancellation\n",
    "prepare broker",
)
replace_one(
    "src/platform/linux.rs",
    "                selected_handles,\n                selected_storage_floor,\n                landlock: PreparedLandlock {\n",
    "                selected_handles,\n                selected_storage_floor,\n                runtime_fd_broker,\n                landlock: PreparedLandlock {\n",
    "construct prepared broker",
)
replace_one(
    "src/platform/linux.rs",
    "            \"accept\" => libc::SYS_accept,\n            \"bind\" => libc::SYS_bind,\n",
    "            \"accept\" => libc::SYS_accept,\n            \"recvmsg\" => libc::SYS_recvmsg,\n            \"bind\" => libc::SYS_bind,\n",
    "seccomp recvmsg",
)
replace_one(
    "src/platform/linux.rs",
    "        let prepared = PreparedLaunch::new(policy, cancellation)?;\n",
    "        let mut prepared = PreparedLaunch::new(policy, cancellation)?;\n",
    "mutable prepared",
)
replace_one(
    "src/platform/linux.rs",
    "        // The host parent does not retain launcher-owned duplicates of selected\n        // object capabilities while the target runs. Caller-owned source FDs\n        // remain under caller control.\n        drop(prepared);\n",
    "        let runtime_fd_broker = prepared.runtime_fd_broker.take();\n        let runtime_fd_broker_thread = runtime_fd_broker\n            .map(|broker| std::thread::spawn(move || service_runtime_fd_broker(broker)));\n        // The host parent does not retain launcher-owned duplicates of selected\n        // object capabilities while the target runs. Caller-owned source FDs\n        // remain under caller control. The runtime broker's pinned source is owned\n        // only by its one-shot host thread until transfer or target-channel EOF.\n        drop(prepared);\n",
    "spawn broker thread",
)
replace_one(
    "src/platform/linux.rs",
    "        let bootstrap_status = wait_for_child(pid)?;\n        let launch_error = launch_state.snapshot();\n",
    "        let bootstrap_status = wait_for_child(pid)?;\n        if let Some(thread) = runtime_fd_broker_thread {\n            match thread.join() {\n                Ok(result) => result?,\n                Err(_) => {\n                    return Err(SandboxError::SetupFailed(\n                        \"runtime FD broker thread panicked\".to_owned(),\n                    ));\n                }\n            }\n        }\n        let launch_error = launch_state.snapshot();\n",
    "join broker thread",
)
replace_one(
    "src/platform/linux.rs",
    "        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {\n",
    "        if let Some(broker) = &prepared.runtime_fd_broker {\n            for fd in [broker.host_fd.raw(), broker.source_fd.raw()] {\n                if libc::close(fd) == -1 {\n                    child_fail(\n                        launch_error,\n                        PHASE_RUNTIME_FD_BROKER_ISOLATE,\n                        seccomp.error_exit_syscall,\n                    );\n                }\n            }\n        }\n        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {\n",
    "child broker isolation",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_COW_DIFF_EXPORT => \"copy-on-write diff export\",\n            _ => \"unknown launch phase\",\n",
    "            PHASE_COW_DIFF_EXPORT => \"copy-on-write diff export\",\n            PHASE_RUNTIME_FD_BROKER_ISOLATE => \"runtime FD broker launcher-state isolation\",\n            _ => \"unknown launch phase\",\n",
    "broker phase label",
)

# Integration helper and runtime evidence.
replace_one(
    "tests/sandbox.rs",
    "        host_unix_stream_peer_uid: None,\n        host_unix_stream_peer_gid: None,\n        host_loopback_tcp_listen_port: None,\n",
    "        host_unix_stream_peer_uid: None,\n        host_unix_stream_peer_gid: None,\n        runtime_fd_broker_source_fd: None,\n        runtime_fd_broker_target_fd: None,\n        host_loopback_tcp_listen_port: None,\n",
    "test policy defaults",
)
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n",
    "#[test]\nfn runtime_fd_broker_delivers_one_descriptor_after_exec_readiness() {\n    let mut pipe = [-1; 2];\n    assert_eq!(unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) }, 0);\n    let read_end = TestFd(pipe[0]);\n    let write_end = TestFd(pipe[1]);\n    let source = duplicate_fd_at_least(read_end.raw(), 200, \"runtime broker source\");\n    drop(read_end);\n    write_all_fd(write_end.raw(), b\"runtime-fd-ok\");\n    drop(write_end);\n\n    let source_text = source.raw().to_string();\n    let mut brokered = policy(\n        \"0\",\n        &[source_text.as_str()],\n        &[\"execveat\", \"write\", \"recvmsg\", \"read\", \"close\", \"fcntl\", \"exit\"],\n    );\n    brokered.runtime_fd_broker_source_fd = Some(source.raw() as u32);\n    brokered.runtime_fd_broker_target_fd = Some(10);\n\n    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn runtime_fd_broker_does_not_widen_target_seccomp() {\n    let null_file = std::fs::File::open(\"/dev/null\").expect(\"open runtime broker source\");\n    let mut brokered = policy(\n        \"0\",\n        &[null_file.as_raw_fd().to_string().as_str()],\n        &[\"execveat\", \"write\", \"close\", \"fcntl\", \"exit\"],\n    );\n    brokered.runtime_fd_broker_source_fd = Some(null_file.as_raw_fd() as u32);\n    brokered.runtime_fd_broker_target_fd = Some(10);\n    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(30));\n}\n\n#[test]\nfn runtime_fd_broker_rejects_directory_source_before_launch() {\n    let directory = std::fs::File::open(fixture_root()).expect(\"open broker directory source\");\n    let mut brokered = policy(\"A\", &[], &[\"execveat\", \"write\", \"exit\"]);\n    brokered.runtime_fd_broker_source_fd = Some(directory.as_raw_fd() as u32);\n    brokered.runtime_fd_broker_target_fd = Some(10);\n    match run(&brokered).unwrap_err() {\n        SandboxError::InvalidPolicy(error) => {\n            assert!(error.to_string().contains(\"directory descriptor\"));\n        }\n        other => panic!(\"unexpected runtime broker directory-source result: {other}\"),\n    }\n}\n\n#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n",
    "runtime broker integration tests",
)

# Raw target protocol. Mode '0' is deliberately outside the already saturated A-Z/a-z table.
replace_one(
    "tests/fixtures/probe.S",
    "#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden\n",
    "#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden\n#   0 request and consume one post-exec SCM_RIGHTS descriptor from the launcher\n",
    "probe comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $65, %al\n    je .allowed\n",
    "    cmp $48, %al\n    je .runtime_fd_broker\n    cmp $65, %al\n    je .allowed\n",
    "probe dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".time_namespace_clocks:\n",
    ".runtime_fd_broker:\n    mov 24(%rsp), %rdi\n    test %rdi, %rdi\n    je .fail30\n    call .parse_handle_fd\n    mov %eax, %r12d\n\n    mov $1, %eax\n    mov $10, %edi\n    lea runtime_fd_broker_ready(%rip), %rsi\n    mov $1, %edx\n    syscall\n    cmp $1, %rax\n    jne .fail30\n\n    sub $128, %rsp\n    lea 0(%rsp), %rax\n    mov %rax, 16(%rsp)\n    movq $1, 24(%rsp)\n    movq $0, 32(%rsp)\n    movq $0, 40(%rsp)\n    lea 16(%rsp), %rax\n    mov %rax, 48(%rsp)\n    movq $1, 56(%rsp)\n    lea 88(%rsp), %rax\n    mov %rax, 64(%rsp)\n    movq $24, 72(%rsp)\n    movq $0, 80(%rsp)\n\n    mov $47, %eax\n    mov $10, %edi\n    lea 32(%rsp), %rsi\n    mov $0x40000000, %edx\n    syscall\n    cmp $1, %rax\n    jne .runtime_fd_broker_fail_stack\n    cmpb $70, 0(%rsp)\n    jne .runtime_fd_broker_fail_stack\n    testl $8, 80(%rsp)\n    jne .runtime_fd_broker_fail_stack\n    cmpq $20, 88(%rsp)\n    jne .runtime_fd_broker_fail_stack\n    cmpl $1, 96(%rsp)\n    jne .runtime_fd_broker_fail_stack\n    cmpl $1, 100(%rsp)\n    jne .runtime_fd_broker_fail_stack\n    mov 104(%rsp), %r14d\n    cmp $0, %r14d\n    jl .runtime_fd_broker_fail_stack\n\n    xor %eax, %eax\n    mov %r14d, %edi\n    lea 112(%rsp), %rsi\n    mov $runtime_fd_broker_message_len, %edx\n    syscall\n    cmp $runtime_fd_broker_message_len, %rax\n    jne .runtime_fd_broker_fail_close_stack\n    lea 112(%rsp), %rdi\n    lea runtime_fd_broker_message(%rip), %rsi\n    mov $runtime_fd_broker_message_len, %ecx\n.runtime_fd_broker_compare:\n    test %ecx, %ecx\n    je .runtime_fd_broker_close_received\n    movzbl (%rdi), %eax\n    movzbl (%rsi), %edx\n    cmp %dl, %al\n    jne .runtime_fd_broker_fail_close_stack\n    inc %rdi\n    inc %rsi\n    dec %ecx\n    jmp .runtime_fd_broker_compare\n\n.runtime_fd_broker_close_received:\n    mov $3, %eax\n    mov %r14d, %edi\n    syscall\n    test %rax, %rax\n    js .runtime_fd_broker_fail_stack\n    add $128, %rsp\n\n    mov $72, %eax\n    mov %r12d, %edi\n    mov $1, %esi\n    xor %edx, %edx\n    syscall\n    cmp $-9, %rax\n    jne .fail30\n    mov $3, %eax\n    mov $10, %edi\n    syscall\n    test %rax, %rax\n    js .fail30\n    xor %edi, %edi\n    jmp .exit\n\n.runtime_fd_broker_fail_close_stack:\n    mov $3, %eax\n    mov %r14d, %edi\n    syscall\n.runtime_fd_broker_fail_stack:\n    add $128, %rsp\n    jmp .fail30\n\n.time_namespace_clocks:\n",
    "raw broker oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    "selected_handle_message:\n    .ascii \"selected-handle-ok\"\n.set selected_handle_message_len, . - selected_handle_message\n",
    "selected_handle_message:\n    .ascii \"selected-handle-ok\"\n.set selected_handle_message_len, . - selected_handle_message\nruntime_fd_broker_ready:\n    .ascii \"R\"\nruntime_fd_broker_message:\n    .ascii \"runtime-fd-ok\"\n.set runtime_fd_broker_message_len, . - runtime_fd_broker_message\n",
    "raw broker data",
)

# Static authority manifest and delta must account for the new capability.
replace_one(
    "src/authority_manifest.rs",
    "        _ => output.push_str(\"null\"),\n    }\n    output.push('}');\n\n    output.push_str(\",\\\"descriptors\\\":{\\\"stdio\\\":{\\\"stdin\\\":\");\n",
    "        _ => output.push_str(\"null\"),\n    }\n    output.push_str(\",\\\"runtime_fd_broker\\\":\");\n    match (\n        policy.runtime_fd_broker_source_fd,\n        policy.runtime_fd_broker_target_fd,\n    ) {\n        (Some(source_fd), Some(target_fd)) => {\n            output.push_str(\"{\\\"source_fd\\\":\");\n            write!(&mut output, \"{source_fd}\").expect(\"write to String cannot fail\");\n            output.push_str(\",\\\"channel_target_fd\\\":\");\n            write!(&mut output, \"{target_fd}\").expect(\"write to String cannot fail\");\n            output.push('}');\n        }\n        _ => output.push_str(\"null\"),\n    }\n    output.push('}');\n\n    output.push_str(\",\\\"descriptors\\\":{\\\"stdio\\\":{\\\"stdin\\\":\");\n",
    "manifest JSON broker",
)
replace_one(
    "src/authority_manifest.rs",
    "    writeln!(\n        &mut output,\n        \"host-unix-stream-broker: {}\",\n        if policy.host_unix_stream_path.is_some() {\n            \"present\"\n        } else {\n            \"none\"\n        }\n    )\n    .expect(\"write to String cannot fail\");\n",
    "    writeln!(\n        &mut output,\n        \"host-unix-stream-broker: {}\",\n        if policy.host_unix_stream_path.is_some() {\n            \"present\"\n        } else {\n            \"none\"\n        }\n    )\n    .expect(\"write to String cannot fail\");\n    writeln!(\n        &mut output,\n        \"runtime-fd-broker: {}\",\n        if policy.runtime_fd_broker_source_fd.is_some() {\n            \"present\"\n        } else {\n            \"none\"\n        }\n    )\n    .expect(\"write to String cannot fail\");\n",
    "manifest human broker",
)
replace_one(
    "src/authority_delta.rs",
    "    compare_optional_restriction(\n        \"host_ipc.unix_stream_peer_credentials\",\n        baseline\n            .host_unix_stream_peer_uid\n            .zip(baseline.host_unix_stream_peer_gid),\n        candidate\n            .host_unix_stream_peer_uid\n            .zip(candidate.host_unix_stream_peer_gid),\n        &mut changes,\n    );\n\n    compare_stdio(\n",
    "    compare_optional_restriction(\n        \"host_ipc.unix_stream_peer_credentials\",\n        baseline\n            .host_unix_stream_peer_uid\n            .zip(baseline.host_unix_stream_peer_gid),\n        candidate\n            .host_unix_stream_peer_uid\n            .zip(candidate.host_unix_stream_peer_gid),\n        &mut changes,\n    );\n    compare_optional_capability(\n        \"host_ipc.runtime_fd_broker\",\n        baseline\n            .runtime_fd_broker_source_fd\n            .zip(baseline.runtime_fd_broker_target_fd),\n        candidate\n            .runtime_fd_broker_source_fd\n            .zip(candidate.runtime_fd_broker_target_fd),\n        &mut changes,\n    );\n\n    compare_stdio(\n",
    "authority delta broker",
)
