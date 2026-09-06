from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: optional all-or-nothing UID/GID credential pin for the exact host AF_UNIX broker.
replace_one(
    "src/policy.rs",
    """    /// Optional launcher-brokered connected filesystem-path AF_UNIX stream.\n    /// Host pathname and target descriptor are all-or-nothing.\n    pub host_unix_stream_path: Option<PathBuf>,\n    pub host_unix_stream_target_fd: Option<u32>,\n""",
    """    /// Optional launcher-brokered connected filesystem-path AF_UNIX stream.\n    /// Host pathname and target descriptor are all-or-nothing.\n    pub host_unix_stream_path: Option<PathBuf>,\n    pub host_unix_stream_target_fd: Option<u32>,\n    /// Optional exact peer UID/GID required on the connected host AF_UNIX stream.\n    /// The pair only narrows an already-declared host-UNIX broker.\n    pub host_unix_stream_peer_uid: Option<u32>,\n    pub host_unix_stream_peer_gid: Option<u32>,\n""",
    "policy fields",
)

replace_one(
    "src/policy.rs",
    """        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n""",
    """        match (\n            self.host_unix_stream_peer_uid,\n            self.host_unix_stream_peer_gid,\n        ) {\n            (None, None) => {}\n            (Some(_), Some(_)) => {\n                if self.host_unix_stream_path.is_none()\n                    || self.host_unix_stream_target_fd.is_none()\n                {\n                    return Err(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid require a brokered host-UNIX stream endpoint\",\n                    ));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                ));\n            }\n        }\n\n        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n""",
    "peer credential validation",
)

replace_one(
    "src/policy.rs",
    """        let mut host_unix_stream_path = None;\n        let mut host_unix_stream_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;\n""",
    """        let mut host_unix_stream_path = None;\n        let mut host_unix_stream_target_fd = None;\n        let mut host_unix_stream_peer_uid = None;\n        let mut host_unix_stream_peer_gid = None;\n        let mut host_loopback_tcp_listen_port = None;\n""",
    "parser variables",
)

replace_one(
    "src/policy.rs",
    """                \"ipc.host_unix_stream_target_fd\" => set_once(\n                    &mut host_unix_stream_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n""",
    """                \"ipc.host_unix_stream_target_fd\" => set_once(\n                    &mut host_unix_stream_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"ipc.host_unix_stream_peer_uid\" => set_once(\n                    &mut host_unix_stream_peer_uid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"ipc.host_unix_stream_peer_gid\" => set_once(\n                    &mut host_unix_stream_peer_gid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n""",
    "parser keys",
)

replace_one(
    "src/policy.rs",
    """            host_unix_stream_path: host_unix_stream_path.map(PathBuf::from),\n            host_unix_stream_target_fd,\n            host_loopback_tcp_listen_port,\n""",
    """            host_unix_stream_path: host_unix_stream_path.map(PathBuf::from),\n            host_unix_stream_target_fd,\n            host_unix_stream_peer_uid,\n            host_unix_stream_peer_gid,\n            host_loopback_tcp_listen_port,\n""",
    "policy construction",
)

replace_one(
    "src/policy.rs",
    """        assert_eq!(policy.host_unix_stream_path, None);\n        assert_eq!(policy.host_unix_stream_target_fd, None);\n        assert!(policy.landlock_read_execute.is_empty());\n""",
    """        assert_eq!(policy.host_unix_stream_path, None);\n        assert_eq!(policy.host_unix_stream_target_fd, None);\n        assert_eq!(policy.host_unix_stream_peer_uid, None);\n        assert_eq!(policy.host_unix_stream_peer_gid, None);\n        assert!(policy.landlock_read_execute.is_empty());\n""",
    "complete policy defaults",
)

replace_one(
    "src/policy.rs",
    """    #[test]\n    fn rejects_incomplete_unsafe_or_colliding_host_unix_stream_endpoint() {\n""",
    """    #[test]\n    fn parses_brokered_host_unix_peer_credentials() {\n        let base = volume_valid();\n        let text = format!(\n            \"{base}\\nipc.host_unix_stream_path = /run/security-lab.sock\\nipc.host_unix_stream_target_fd = 14\\nipc.host_unix_stream_peer_uid = 1000\\nipc.host_unix_stream_peer_gid = 1001\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.host_unix_stream_peer_uid, Some(1000));\n        assert_eq!(policy.host_unix_stream_peer_gid, Some(1001));\n    }\n\n    #[test]\n    fn rejects_incomplete_or_detached_host_unix_peer_credentials() {\n        let base = volume_valid();\n        let incomplete = format!(\n            \"{base}\\nipc.host_unix_stream_path = /run/security-lab.sock\\nipc.host_unix_stream_target_fd = 14\\nipc.host_unix_stream_peer_uid = 1000\"\n        );\n        let error = incomplete.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error.to_string().contains(\"must be specified together\"));\n\n        let detached = format!(\n            \"{base}\\nipc.host_unix_stream_peer_uid = 1000\\nipc.host_unix_stream_peer_gid = 1001\"\n        );\n        let error = detached.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains(\"require a brokered host-UNIX stream endpoint\"));\n    }\n\n    #[test]\n    fn rejects_incomplete_unsafe_or_colliding_host_unix_stream_endpoint() {\n""",
    "peer credential parser tests",
)

# Runtime: query kernel SO_PEERCRED after connect and before transferring the object to target authority.
replace_one(
    "src/platform/linux.rs",
    """    fn connect_host_unix_stream(\n        path: &Path,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n""",
    """    fn connect_host_unix_stream(\n        path: &Path,\n        target_fd: u32,\n        storage_floor: RawFd,\n        expected_peer: Option<(u32, u32)>,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n""",
    "runtime function signature",
)

replace_one(
    "src/platform/linux.rs",
    """        let storage_fd = move_owned_fd_to_selected_storage(\n            socket_fd,\n            storage_floor,\n            \"brokered host-UNIX stream socket\",\n        )?;\n""",
    """        if let Some((expected_uid, expected_gid)) = expected_peer {\n            let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };\n            let mut credentials_len =\n                std::mem::size_of::<libc::ucred>() as libc::socklen_t;\n            if unsafe {\n                libc::getsockopt(\n                    socket_fd.raw(),\n                    libc::SOL_SOCKET,\n                    libc::SO_PEERCRED,\n                    (&mut credentials as *mut libc::ucred).cast::<libc::c_void>(),\n                    &mut credentials_len,\n                )\n            } == -1\n            {\n                return Err(SandboxError::SetupFailed(format!(\n                    \"cannot inspect brokered host-UNIX peer credentials for {}: {}\",\n                    path.display(),\n                    io::Error::last_os_error()\n                )));\n            }\n            if credentials_len as usize != std::mem::size_of::<libc::ucred>() {\n                return Err(SandboxError::SetupFailed(format!(\n                    \"brokered host-UNIX peer credential query for {} returned {} bytes, expected {}\",\n                    path.display(),\n                    credentials_len,\n                    std::mem::size_of::<libc::ucred>()\n                )));\n            }\n            if credentials.uid != expected_uid || credentials.gid != expected_gid {\n                return Err(SandboxError::SetupFailed(format!(\n                    \"brokered host-UNIX peer credentials mismatch for {}: expected uid {expected_uid} gid {expected_gid}, got uid {} gid {}\",\n                    path.display(),\n                    credentials.uid,\n                    credentials.gid\n                )));\n            }\n        }\n\n        let storage_fd = move_owned_fd_to_selected_storage(\n            socket_fd,\n            storage_floor,\n            \"brokered host-UNIX stream socket\",\n        )?;\n""",
    "runtime peer credential enforcement",
)

replace_one(
    "src/platform/linux.rs",
    """            match (\n                &policy.host_unix_stream_path,\n                policy.host_unix_stream_target_fd,\n            ) {\n                (Some(path), Some(target_fd)) => selected_handles.push(connect_host_unix_stream(\n                    path,\n                    target_fd,\n                    selected_storage_floor,\n                )?),\n                (None, None) => {}\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.host_unix_stream_path and ipc.host_unix_stream_target_fd must be specified together\",\n                    )));\n                }\n            }\n""",
    """            let host_unix_expected_peer = match (\n                policy.host_unix_stream_peer_uid,\n                policy.host_unix_stream_peer_gid,\n            ) {\n                (Some(uid), Some(gid)) => Some((uid, gid)),\n                (None, None) => None,\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                    )));\n                }\n            };\n            match (\n                &policy.host_unix_stream_path,\n                policy.host_unix_stream_target_fd,\n            ) {\n                (Some(path), Some(target_fd)) => selected_handles.push(connect_host_unix_stream(\n                    path,\n                    target_fd,\n                    selected_storage_floor,\n                    host_unix_expected_peer,\n                )?),\n                (None, None) if host_unix_expected_peer.is_none() => {}\n                (None, None) => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"host-UNIX peer credentials require a brokered endpoint\",\n                    )));\n                }\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.host_unix_stream_path and ipc.host_unix_stream_target_fd must be specified together\",\n                    )));\n                }\n            }\n""",
    "runtime preparation",
)

# Integration evidence: positive exact credential match and fail-closed mismatch before target execution.
replace_one(
    "tests/sandbox.rs",
    """        host_unix_stream_path: None,\n        host_unix_stream_target_fd: None,\n        host_loopback_tcp_listen_port: None,\n""",
    """        host_unix_stream_path: None,\n        host_unix_stream_target_fd: None,\n        host_unix_stream_peer_uid: None,\n        host_unix_stream_peer_gid: None,\n        host_loopback_tcp_listen_port: None,\n""",
    "test policy literal",
)

replace_one(
    "tests/sandbox.rs",
    """    brokered.host_unix_stream_path = Some(socket_path.clone());\n    brokered.host_unix_stream_target_fd = Some(10);\n    brokered.wall_clock_milliseconds = Some(2000);\n""",
    """    brokered.host_unix_stream_path = Some(socket_path.clone());\n    brokered.host_unix_stream_target_fd = Some(10);\n    brokered.host_unix_stream_peer_uid = Some(unsafe { libc::geteuid() });\n    brokered.host_unix_stream_peer_gid = Some(unsafe { libc::getegid() });\n    brokered.wall_clock_milliseconds = Some(2000);\n""",
    "positive peer credentials",
)

replace_one(
    "tests/sandbox.rs",
    """#[test]\nfn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {\n""",
    """#[test]\nfn brokered_host_unix_stream_rejects_wrong_peer_credentials_before_target_exec() {\n    let socket_path = std::env::temp_dir().join(format!(\n        \"security-lab-host-unix-peer-mismatch-{}.sock\",\n        process::id()\n    ));\n    let _ = std::fs::remove_file(&socket_path);\n    let listener = UnixListener::bind(&socket_path).expect(\"bind peer-credential test endpoint\");\n\n    let actual_uid = unsafe { libc::geteuid() };\n    let actual_gid = unsafe { libc::getegid() };\n    let wrong_uid = actual_uid.wrapping_add(1);\n    assert_ne!(wrong_uid, actual_uid);\n\n    let mut brokered = policy(\"A\", &[], &[\"execveat\", \"write\", \"exit\"]);\n    brokered.host_unix_stream_path = Some(socket_path.clone());\n    brokered.host_unix_stream_target_fd = Some(10);\n    brokered.host_unix_stream_peer_uid = Some(wrong_uid);\n    brokered.host_unix_stream_peer_gid = Some(actual_gid);\n\n    let result = run(&brokered);\n    drop(listener);\n    let _ = std::fs::remove_file(&socket_path);\n    match result.unwrap_err() {\n        SandboxError::SetupFailed(message) => {\n            assert!(message.contains(\"peer credentials mismatch\"));\n        }\n        other => panic!(\"unexpected peer-credential mismatch result: {other}\"),\n    }\n}\n\n#[test]\nfn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {\n""",
    "negative peer credential integration test",
)
