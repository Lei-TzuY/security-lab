from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: add one exact numeric host IPv4 TCP broker surface.
replace_one(
    "src/policy.rs",
    "use std::fmt;\nuse std::path::{Component, Path, PathBuf};",
    "use std::fmt;\nuse std::net::Ipv4Addr;\nuse std::path::{Component, Path, PathBuf};",
    "policy IPv4 import",
)
replace_one(
    "src/policy.rs",
    "    pub host_loopback_tcp_port: Option<u16>,\n    pub host_loopback_tcp_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.",
    "    pub host_loopback_tcp_port: Option<u16>,\n    pub host_loopback_tcp_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP connection to one exact numeric host IPv4\n    /// endpoint. Address, port, and target descriptor are all-or-nothing.\n    pub host_ipv4_tcp_address: Option<Ipv4Addr>,\n    pub host_ipv4_tcp_port: Option<u16>,\n    pub host_ipv4_tcp_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.",
    "policy IPv4 fields",
)

validation_marker = """        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {\n"""
validation_block = """        match (\n            self.host_ipv4_tcp_address,\n            self.host_ipv4_tcp_port,\n            self.host_ipv4_tcp_target_fd,\n        ) {\n            (None, None, None) => {}\n            (Some(address), Some(port), Some(target_fd)) => {\n                let octets = address.octets();\n                if octets == [0, 0, 0, 0] || octets[0] >= 224 {\n                    return Err(PolicyError::new(\n                        \"network.host_ipv4_tcp_address must be a unicast IPv4 address\",\n                    ));\n                }\n                if port == 0 {\n                    return Err(PolicyError::new(\n                        \"network.host_ipv4_tcp_port must be between 1 and 65535\",\n                    ));\n                }\n                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network.host_ipv4_tcp_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}\"\n                    )));\n                }\n                if u64::from(target_fd) >= self.limits.open_files {\n                    return Err(PolicyError::new(format!(\n                        \"network.host_ipv4_tcp_target_fd {target_fd} must be below limit.open_files {}\",\n                        self.limits.open_files\n                    )));\n                }\n                if self.selected_handles.contains_key(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network host-IPv4 target fd {target_fd} collides with a selected handle target\"\n                    )));\n                }\n                if self.host_loopback_tcp_target_fd == Some(target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network host-IPv4 target fd {target_fd} collides with the brokered host-loopback connection target\"\n                    )));\n                }\n                if self.host_loopback_tcp_listen_target_fd == Some(target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network host-IPv4 target fd {target_fd} collides with the brokered host-loopback listener target\"\n                    )));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"network.host_ipv4_tcp_address, network.host_ipv4_tcp_port, and network.host_ipv4_tcp_target_fd must be specified together\",\n                ));\n            }\n        }\n\n"""
replace_one(
    "src/policy.rs",
    validation_marker,
    validation_block + validation_marker,
    "policy IPv4 validation",
)
replace_one(
    "src/policy.rs",
    "        let mut host_loopback_tcp_port = None;\n        let mut host_loopback_tcp_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;",
    "        let mut host_loopback_tcp_port = None;\n        let mut host_loopback_tcp_target_fd = None;\n        let mut host_ipv4_tcp_address = None;\n        let mut host_ipv4_tcp_port = None;\n        let mut host_ipv4_tcp_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;",
    "policy IPv4 parser variables",
)
replace_one(
    "src/policy.rs",
    "                \"network.host_loopback_tcp_listen_port\" => set_once(\n",
    "                \"network.host_ipv4_tcp_address\" => set_once(\n                    &mut host_ipv4_tcp_address,\n                    parse_ipv4_address(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_ipv4_tcp_port\" => set_once(\n                    &mut host_ipv4_tcp_port,\n                    parse_tcp_port(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_ipv4_tcp_target_fd\" => set_once(\n                    &mut host_ipv4_tcp_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n",
    "policy IPv4 parser keys",
)
replace_one(
    "src/policy.rs",
    "            host_loopback_tcp_port,\n            host_loopback_tcp_target_fd,\n            host_loopback_tcp_listen_port,",
    "            host_loopback_tcp_port,\n            host_loopback_tcp_target_fd,\n            host_ipv4_tcp_address,\n            host_ipv4_tcp_port,\n            host_ipv4_tcp_target_fd,\n            host_loopback_tcp_listen_port,",
    "policy IPv4 construction",
)
replace_one(
    "src/policy.rs",
    "fn parse_tcp_port(value: &str, line: usize, key: &str) -> Result<u16, PolicyError> {",
    "fn parse_ipv4_address(value: &str, line: usize, key: &str) -> Result<Ipv4Addr, PolicyError> {\n    let address = value.parse::<Ipv4Addr>().map_err(|_| {\n        PolicyError::at(line, format!(\"{key} must be a numeric IPv4 address\"))\n    })?;\n    let octets = address.octets();\n    if octets == [0, 0, 0, 0] || octets[0] >= 224 {\n        return Err(PolicyError::at(\n            line,\n            format!(\"{key} must be a unicast IPv4 address\"),\n        ));\n    }\n    Ok(address)\n}\n\nfn parse_tcp_port(value: &str, line: usize, key: &str) -> Result<u16, PolicyError> {",
    "policy IPv4 parser helper",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.host_loopback_tcp_target_fd, None);\n        assert!(policy.landlock_read_execute.is_empty());",
    "        assert_eq!(policy.host_loopback_tcp_target_fd, None);\n        assert_eq!(policy.host_ipv4_tcp_address, None);\n        assert_eq!(policy.host_ipv4_tcp_port, None);\n        assert_eq!(policy.host_ipv4_tcp_target_fd, None);\n        assert!(policy.landlock_read_execute.is_empty());",
    "policy complete defaults",
)

ipv4_policy_tests = r'''
    #[test]
    fn parses_brokered_host_ipv4_tcp_endpoint() {
        let text = format!(
            "{VALID}\nnetwork.host_ipv4_tcp_address = 127.0.0.2\nnetwork.host_ipv4_tcp_port = 8080\nnetwork.host_ipv4_tcp_target_fd = 12"
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.host_ipv4_tcp_address, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(policy.host_ipv4_tcp_port, Some(8080));
        assert_eq!(policy.host_ipv4_tcp_target_fd, Some(12));
    }

    #[test]
    fn rejects_incomplete_or_unsafe_brokered_host_ipv4_tcp_endpoint() {
        let incomplete = format!(
            "{VALID}\nnetwork.host_ipv4_tcp_address = 127.0.0.2\nnetwork.host_ipv4_tcp_port = 8080"
        );
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        for address in ["example.com", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            let text = format!(
                "{VALID}\nnetwork.host_ipv4_tcp_address = {address}\nnetwork.host_ipv4_tcp_port = 8080\nnetwork.host_ipv4_tcp_target_fd = 12"
            );
            assert!(text.parse::<SandboxPolicy>().is_err(), "accepted unsafe address {address}");
        }

        let collision = format!(
            "{VALID}\nhandle.12 = 0\nnetwork.host_ipv4_tcp_address = 127.0.0.2\nnetwork.host_ipv4_tcp_port = 8080\nnetwork.host_ipv4_tcp_target_fd = 12"
        );
        let error = collision.parse::<SandboxPolicy>().unwrap_err();
        assert!(error
            .to_string()
            .contains("collides with a selected handle target"));

        let legacy_collision = format!(
            "{VALID}\nnetwork.host_loopback_tcp_port = 8080\nnetwork.host_loopback_tcp_target_fd = 12\nnetwork.host_ipv4_tcp_address = 127.0.0.2\nnetwork.host_ipv4_tcp_port = 8080\nnetwork.host_ipv4_tcp_target_fd = 12"
        );
        let error = legacy_collision.parse::<SandboxPolicy>().unwrap_err();
        assert!(error
            .to_string()
            .contains("collides with the brokered host-loopback connection target"));
    }

'''
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_brokered_host_loopback_tcp_listener() {",
    ipv4_policy_tests + "    #[test]\n    fn parses_brokered_host_loopback_tcp_listener() {",
    "policy IPv4 tests",
)

# Linux launcher: share one host-IPv4 TCP connection path between legacy fixed
# loopback and the new exact-address broker.
replace_one(
    "src/platform/linux.rs",
    "    use std::io;\n    use std::os::unix::ffi::OsStrExt;",
    "    use std::io;\n    use std::net::Ipv4Addr;\n    use std::os::unix::ffi::OsStrExt;",
    "linux IPv4 import",
)
linux_path = Path("src/platform/linux.rs")
linux = linux_path.read_text()
start = linux.index("    fn connect_host_loopback_tcp(")
end = linux.index("\n    fn listen_host_loopback_tcp(", start)
shared_connector = r'''    fn connect_host_tcp_ipv4(
        address: Ipv4Addr,
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
        broker_label: &str,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered {broker_label} TCP socket: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let address_struct = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        };
        loop {
            let connected = unsafe {
                libc::connect(
                    socket_fd.raw(),
                    (&address_struct as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if connected == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot connect brokered {broker_label} TCP endpoint {address}:{port}: {error}"
            )));
        }
        let storage_label = format!("brokered {broker_label} TCP socket");
        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            &storage_label,
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn connect_host_loopback_tcp(
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        connect_host_tcp_ipv4(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            target_fd,
            storage_floor,
            "host-loopback",
        )
    }
'''
linux = linux[:start] + shared_connector + linux[end:]
linux_path.write_text(linux)
replace_one(
    "src/platform/linux.rs",
    "                .chain(policy.host_loopback_tcp_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())",
    "                .chain(policy.host_loopback_tcp_target_fd.iter().copied())\n                .chain(policy.host_ipv4_tcp_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())",
    "linux IPv4 storage floor",
)
replace_one(
    "src/platform/linux.rs",
    "                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },",
    "                    + if policy.host_ipv4_tcp_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    }\n                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },",
    "linux IPv4 selected capacity",
)
listener_match = """            match (\n                policy.host_loopback_tcp_listen_port,\n                policy.host_loopback_tcp_listen_target_fd,\n            ) {\n"""
ipv4_match = """            match (\n                policy.host_ipv4_tcp_address,\n                policy.host_ipv4_tcp_port,\n                policy.host_ipv4_tcp_target_fd,\n            ) {\n                (Some(address), Some(port), Some(target_fd)) => {\n                    selected_handles.push(connect_host_tcp_ipv4(\n                        address,\n                        port,\n                        target_fd,\n                        selected_storage_floor,\n                        \"host-IPv4\",\n                    )?)\n                }\n                (None, None, None) => {}\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"network.host_ipv4_tcp_address, network.host_ipv4_tcp_port, and network.host_ipv4_tcp_target_fd must be specified together\",\n                    )));\n                }\n            }\n"""
replace_one(
    "src/platform/linux.rs",
    listener_match,
    ipv4_match + listener_match,
    "linux IPv4 prepared broker",
)

# Integration: two host addresses share one port; only the policy-selected
# address may receive the brokered connection. The target's own TCP connect
# still runs inside the isolated netns and cannot reach the other host listener.
replace_one(
    "tests/sandbox.rs",
    "use std::net::{TcpListener, TcpStream};",
    "use std::net::{Ipv4Addr, TcpListener, TcpStream};",
    "sandbox IPv4 import",
)
replace_one(
    "tests/sandbox.rs",
    "        host_loopback_tcp_port: None,\n        host_loopback_tcp_target_fd: None,\n        host_loopback_tcp_listen_port: None,",
    "        host_loopback_tcp_port: None,\n        host_loopback_tcp_target_fd: None,\n        host_ipv4_tcp_address: None,\n        host_ipv4_tcp_port: None,\n        host_ipv4_tcp_target_fd: None,\n        host_loopback_tcp_listen_port: None,",
    "sandbox policy IPv4 defaults",
)
ipv4_integration = r'''
#[test]
fn brokered_host_ipv4_tcp_selects_exact_address_on_shared_port() {
    const PORT_ACQUIRE_ATTEMPTS: usize = 32;
    let mut listeners = None;
    for _ in 0..PORT_ACQUIRE_ATTEMPTS {
        let other = TcpListener::bind(("127.0.0.1", 0))
            .expect("bind first address-aware broker listener");
        let port = other
            .local_addr()
            .expect("read address-aware broker port")
            .port();
        match TcpListener::bind(("127.0.0.2", port)) {
            Ok(selected) => {
                listeners = Some((other, selected, port));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind selected address-aware broker listener: {error}"),
        }
    }
    let (other, selected, port) = listeners.expect("acquire one port on two host loopback addresses");
    other
        .set_nonblocking(true)
        .expect("set other address listener nonblocking");
    selected
        .set_nonblocking(true)
        .expect("set selected address listener nonblocking");

    let port_text = port.to_string();
    let mut brokered = policy(
        "p",
        &[port_text.as_str()],
        &["execveat", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_ipv4_tcp_address = Some(Ipv4Addr::new(127, 0, 0, 2));
    brokered.host_ipv4_tcp_port = Some(port);
    brokered.host_ipv4_tcp_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));

    let (peer, _) = selected
        .accept()
        .expect("selected host IPv4 listener must receive brokered connection");
    let mut marker = [0u8; 25];
    read_exact_fd(peer.as_raw_fd(), &mut marker);
    assert_eq!(&marker, b"brokered-host-loopback-ok");

    match other.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => panic!("unexpected other-address accept error: {error}"),
        Ok(_) => panic!("brokered connection reached the wrong host IPv4 address"),
    }
}

'''
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn brokered_host_loopback_tcp_listener_accepts_one_host_ingress_capability() {",
    ipv4_integration + "#[test]\nfn brokered_host_loopback_tcp_listener_accepts_one_host_ingress_capability() {",
    "sandbox IPv4 integration",
)
