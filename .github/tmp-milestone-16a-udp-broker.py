from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, addition: str, label: str) -> None:
    replace_one(path, marker, addition + marker, label)


# Policy surface: one exact numeric host IPv4 UDP endpoint, all-or-nothing.
replace_one(
    "src/policy.rs",
    """    /// Optional launcher-brokered TCP connection to one exact numeric host IPv4
    /// endpoint. Address, port, and target descriptor are all-or-nothing.
    pub host_ipv4_tcp_address: Option<Ipv4Addr>,
    pub host_ipv4_tcp_port: Option<u16>,
    pub host_ipv4_tcp_target_fd: Option<u32>,
    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.
""",
    """    /// Optional launcher-brokered TCP connection to one exact numeric host IPv4
    /// endpoint. Address, port, and target descriptor are all-or-nothing.
    pub host_ipv4_tcp_address: Option<Ipv4Addr>,
    pub host_ipv4_tcp_port: Option<u16>,
    pub host_ipv4_tcp_target_fd: Option<u32>,
    /// Optional launcher-brokered connected UDP socket to one exact numeric host
    /// IPv4 endpoint. Address, port, and target descriptor are all-or-nothing.
    pub host_ipv4_udp_address: Option<Ipv4Addr>,
    pub host_ipv4_udp_port: Option<u16>,
    pub host_ipv4_udp_target_fd: Option<u32>,
    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.
""",
    "policy UDP fields",
)

udp_validation = """        match (
            self.host_ipv4_udp_address,
            self.host_ipv4_udp_port,
            self.host_ipv4_udp_target_fd,
        ) {
            (None, None, None) => {}
            (Some(address), Some(port), Some(target_fd)) => {
                let octets = address.octets();
                if octets[0] == 0 || octets[0] >= 224 {
                    return Err(PolicyError::new(
                        "network.host_ipv4_udp_address must be a unicast IPv4 address",
                    ));
                }
                if port == 0 {
                    return Err(PolicyError::new(
                        "network.host_ipv4_udp_port must be between 1 and 65535",
                    ));
                }
                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {
                    return Err(PolicyError::new(format!(
                        "network.host_ipv4_udp_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}"
                    )));
                }
                if u64::from(target_fd) >= self.limits.open_files {
                    return Err(PolicyError::new(format!(
                        "network.host_ipv4_udp_target_fd {target_fd} must be below limit.open_files {}",
                        self.limits.open_files
                    )));
                }
                if self.selected_handles.contains_key(&target_fd) {
                    return Err(PolicyError::new(format!(
                        "network host-IPv4 UDP target fd {target_fd} collides with a selected handle target"
                    )));
                }
                if self.host_loopback_tcp_target_fd == Some(target_fd) {
                    return Err(PolicyError::new(format!(
                        "network host-IPv4 UDP target fd {target_fd} collides with the brokered host-loopback TCP connection target"
                    )));
                }
                if self.host_ipv4_tcp_target_fd == Some(target_fd) {
                    return Err(PolicyError::new(format!(
                        "network host-IPv4 UDP target fd {target_fd} collides with the brokered host-IPv4 TCP connection target"
                    )));
                }
                if self.host_loopback_tcp_listen_target_fd == Some(target_fd) {
                    return Err(PolicyError::new(format!(
                        "network host-IPv4 UDP target fd {target_fd} collides with the brokered host-loopback TCP listener target"
                    )));
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "network.host_ipv4_udp_address, network.host_ipv4_udp_port, and network.host_ipv4_udp_target_fd must be specified together",
                ));
            }
        }

"""
insert_before(
    "src/policy.rs",
    """        match (
            self.host_loopback_tcp_listen_port,
""",
    udp_validation,
    "policy UDP validation",
)

replace_one(
    "src/policy.rs",
    """        let mut host_ipv4_tcp_address = None;
        let mut host_ipv4_tcp_port = None;
        let mut host_ipv4_tcp_target_fd = None;
        let mut host_loopback_tcp_listen_port = None;
""",
    """        let mut host_ipv4_tcp_address = None;
        let mut host_ipv4_tcp_port = None;
        let mut host_ipv4_tcp_target_fd = None;
        let mut host_ipv4_udp_address = None;
        let mut host_ipv4_udp_port = None;
        let mut host_ipv4_udp_target_fd = None;
        let mut host_loopback_tcp_listen_port = None;
""",
    "policy parser UDP locals",
)

udp_parse_arms = """                "network.host_ipv4_udp_address" => set_once(
                    &mut host_ipv4_udp_address,
                    parse_ipv4_address(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "network.host_ipv4_udp_port" => set_once(
                    &mut host_ipv4_udp_port,
                    parse_tcp_port(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "network.host_ipv4_udp_target_fd" => set_once(
                    &mut host_ipv4_udp_target_fd,
                    value.parse::<u32>().map_err(|_| {
                        PolicyError::at(line_no, format!("{key} must be an unsigned integer"))
                    })?,
                    line_no,
                    key,
                )?,
"""
insert_before(
    "src/policy.rs",
    """                "network.host_loopback_tcp_listen_port" => set_once(
""",
    udp_parse_arms,
    "policy parser UDP arms",
)

replace_one(
    "src/policy.rs",
    """            host_ipv4_tcp_address,
            host_ipv4_tcp_port,
            host_ipv4_tcp_target_fd,
            host_loopback_tcp_listen_port,
""",
    """            host_ipv4_tcp_address,
            host_ipv4_tcp_port,
            host_ipv4_tcp_target_fd,
            host_ipv4_udp_address,
            host_ipv4_udp_port,
            host_ipv4_udp_target_fd,
            host_loopback_tcp_listen_port,
""",
    "policy parser UDP construction",
)

replace_one(
    "src/policy.rs",
    """        assert_eq!(policy.host_ipv4_tcp_address, None);
        assert_eq!(policy.host_ipv4_tcp_port, None);
        assert_eq!(policy.host_ipv4_tcp_target_fd, None);
        assert!(policy.landlock_read_execute.is_empty());
""",
    """        assert_eq!(policy.host_ipv4_tcp_address, None);
        assert_eq!(policy.host_ipv4_tcp_port, None);
        assert_eq!(policy.host_ipv4_tcp_target_fd, None);
        assert_eq!(policy.host_ipv4_udp_address, None);
        assert_eq!(policy.host_ipv4_udp_port, None);
        assert_eq!(policy.host_ipv4_udp_target_fd, None);
        assert!(policy.landlock_read_execute.is_empty());
""",
    "policy default UDP assertions",
)

udp_policy_tests = r'''    #[test]
    fn parses_brokered_host_ipv4_udp_endpoint() {
        let text = format!(
            "{VALID}\
network.host_ipv4_udp_address = 127.0.0.2\
network.host_ipv4_udp_port = 5353\
network.host_ipv4_udp_target_fd = 13"
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(
            policy.host_ipv4_udp_address,
            Some(Ipv4Addr::new(127, 0, 0, 2))
        );
        assert_eq!(policy.host_ipv4_udp_port, Some(5353));
        assert_eq!(policy.host_ipv4_udp_target_fd, Some(13));
    }

    #[test]
    fn rejects_incomplete_or_unsafe_brokered_host_ipv4_udp_endpoint() {
        let incomplete = format!(
            "{VALID}\
network.host_ipv4_udp_address = 127.0.0.2\
network.host_ipv4_udp_port = 5353"
        );
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        for address in ["example.com", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {
            let text = format!(
                "{VALID}\
network.host_ipv4_udp_address = {address}\
network.host_ipv4_udp_port = 5353\
network.host_ipv4_udp_target_fd = 13"
            );
            assert!(
                text.parse::<SandboxPolicy>().is_err(),
                "accepted unsafe UDP address {address}"
            );
        }

        let selected_collision = format!(
            "{VALID}\
handle.13 = 0\
network.host_ipv4_udp_address = 127.0.0.2\
network.host_ipv4_udp_port = 5353\
network.host_ipv4_udp_target_fd = 13"
        );
        assert!(selected_collision.parse::<SandboxPolicy>().is_err());

        let tcp_collision = format!(
            "{VALID}\
network.host_ipv4_tcp_address = 127.0.0.2\
network.host_ipv4_tcp_port = 8080\
network.host_ipv4_tcp_target_fd = 13\
network.host_ipv4_udp_address = 127.0.0.2\
network.host_ipv4_udp_port = 5353\
network.host_ipv4_udp_target_fd = 13"
        );
        let error = tcp_collision.parse::<SandboxPolicy>().unwrap_err();
        assert!(error
            .to_string()
            .contains("collides with the brokered host-IPv4 TCP connection target"));
    }

'''
insert_before(
    "src/policy.rs",
    """    #[test]
    fn parses_brokered_host_loopback_tcp_listener() {
""",
    udp_policy_tests,
    "policy UDP unit tests",
)

# Linux launcher: create a connected UDP socket in the trusted host parent, then
# feed it through the existing selected-handle installation plane.
udp_connector = r'''    fn connect_host_udp_ipv4(
        address: Ipv4Addr,
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered host-IPv4 UDP socket: {}",
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
                "cannot connect brokered host-IPv4 UDP socket to {address}:{port}: {error}"
            )));
        }
        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            "brokered host-IPv4 UDP socket",
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

'''
insert_before(
    "src/platform/linux.rs",
    """    fn listen_host_loopback_tcp(
""",
    udp_connector,
    "Linux UDP connector",
)

replace_one(
    "src/platform/linux.rs",
    """                .chain(policy.host_ipv4_tcp_target_fd.iter().copied())
                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())
""",
    """                .chain(policy.host_ipv4_tcp_target_fd.iter().copied())
                .chain(policy.host_ipv4_udp_target_fd.iter().copied())
                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())
""",
    "Linux UDP storage floor",
)

replace_one(
    "src/platform/linux.rs",
    """                    + if policy.host_ipv4_tcp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {
""",
    """                    + if policy.host_ipv4_tcp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_ipv4_udp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {
""",
    "Linux UDP selected capacity",
)

udp_prepare = r'''            match (
                policy.host_ipv4_udp_address,
                policy.host_ipv4_udp_port,
                policy.host_ipv4_udp_target_fd,
            ) {
                (Some(address), Some(port), Some(target_fd)) => {
                    selected_handles.push(connect_host_udp_ipv4(
                        address,
                        port,
                        target_fd,
                        selected_storage_floor,
                    )?)
                }
                (None, None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "network.host_ipv4_udp_address, network.host_ipv4_udp_port, and network.host_ipv4_udp_target_fd must be specified together",
                    )));
                }
            }
'''
insert_before(
    "src/platform/linux.rs",
    """            match (
                policy.host_loopback_tcp_listen_port,
""",
    udp_prepare,
    "Linux UDP preparation",
)

# Integration harness: exact datagram, same-port address discrimination, and no
# target-side host route even when socket/connect/write are explicitly granted.
replace_one(
    "tests/sandbox.rs",
    "use std::net::{Ipv4Addr, TcpListener, TcpStream};",
    "use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};",
    "test UDP import",
)
replace_one(
    "tests/sandbox.rs",
    "use std::thread;\n",
    "use std::thread;\nuse std::time::Duration;\n",
    "test Duration import",
)
replace_one(
    "tests/sandbox.rs",
    """        host_ipv4_tcp_address: None,
        host_ipv4_tcp_port: None,
        host_ipv4_tcp_target_fd: None,
        host_loopback_tcp_listen_port: None,
""",
    """        host_ipv4_tcp_address: None,
        host_ipv4_tcp_port: None,
        host_ipv4_tcp_target_fd: None,
        host_ipv4_udp_address: None,
        host_ipv4_udp_port: None,
        host_ipv4_udp_target_fd: None,
        host_loopback_tcp_listen_port: None,
""",
    "test policy UDP defaults",
)

udp_integration_test = r'''#[test]
fn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {
    const PORT_ACQUIRE_ATTEMPTS: usize = 32;
    let mut endpoints = None;
    for _ in 0..PORT_ACQUIRE_ATTEMPTS {
        let other = UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 1), 0))
            .expect("bind first address-aware UDP broker endpoint");
        let port = other
            .local_addr()
            .expect("read first UDP broker endpoint")
            .port();
        match UdpSocket::bind((Ipv4Addr::new(127, 0, 0, 2), port)) {
            Ok(selected) => {
                endpoints = Some((other, selected, port));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind selected UDP broker endpoint failed: {error}"),
        }
    }
    let (other, selected, port) = endpoints.expect("acquire shared UDP port across 127/8");
    selected
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set selected UDP receive timeout");

    let port_text = port.to_string();
    let mut brokered = policy(
        "e",
        &[port_text.as_str()],
        &["execveat", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_ipv4_udp_address = Some(Ipv4Addr::new(127, 0, 0, 2));
    brokered.host_ipv4_udp_port = Some(port);
    brokered.host_ipv4_udp_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));

    let mut datagram = [0u8; 64];
    let (received, _) = selected
        .recv_from(&mut datagram)
        .expect("selected UDP endpoint did not receive brokered datagram");
    assert_eq!(&datagram[..received], b"brokered-host-udp-ok");

    selected
        .set_nonblocking(true)
        .expect("make selected UDP endpoint nonblocking");
    match selected.recv_from(&mut datagram) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((received, peer)) => panic!(
            "isolated target unexpectedly delivered a second UDP datagram from {peer}: {:?}",
            &datagram[..received]
        ),
        Err(error) => panic!("unexpected selected UDP receive error: {error}"),
    }

    other
        .set_nonblocking(true)
        .expect("make non-selected UDP endpoint nonblocking");
    match other.recv_from(&mut datagram) {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((received, peer)) => panic!(
            "UDP broker selected the wrong same-port address; received from {peer}: {:?}",
            &datagram[..received]
        ),
        Err(error) => panic!("unexpected non-selected UDP receive error: {error}"),
    }
}

'''
insert_before(
    "tests/sandbox.rs",
    """#[test]
fn landlock_device_ioctl_envelope_binds_rights_at_post_restriction_open() {
""",
    udp_integration_test,
    "UDP integration test",
)

# Raw target mode `e`: emit one exact datagram through broker fd 10, then make a
# fresh target-side UDP attempt toward the same host endpoint. The latter may
# fail immediately or appear locally successful; host-side evidence proves it
# never crosses the isolated network namespace.
replace_one(
    "tests/fixtures/probe.S",
    "#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n",
    "#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   e write one brokered host-IPv4 UDP datagram while fresh target UDP stays isolated\n",
    "probe UDP mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    """    cmp $112, %al
    je .brokered_host_loopback
    cmp $113, %al
""",
    """    cmp $112, %al
    je .brokered_host_loopback
    cmp $101, %al
    je .brokered_host_udp
    cmp $113, %al
""",
    "probe UDP dispatch",
)

udp_probe = r'''.brokered_host_udp:
    mov $1, %eax
    mov $10, %edi
    lea brokered_host_udp_message(%rip), %rsi
    mov $brokered_host_udp_message_len, %edx
    syscall
    cmp $brokered_host_udp_message_len, %rax
    jne .fail45

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail45

    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail45
    xor %r12d, %r12d
.brokered_udp_port_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .brokered_udp_port_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail45
    imul $10, %r12d, %r12d
    add %eax, %r12d
    cmp $65535, %r12d
    ja .fail45
    inc %rdi
    jmp .brokered_udp_port_parse_loop
.brokered_udp_port_parsed:
    test %r12d, %r12d
    je .fail45
    movw $2, network_addr(%rip)
    rolw $8, %r12w
    movw %r12w, network_addr+2(%rip)
    movl $0x0200007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $2, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail45
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .brokered_udp_direct_error

    mov $1, %eax
    mov %r13, %rdi
    lea brokered_host_udp_direct_probe(%rip), %rsi
    mov $brokered_host_udp_direct_probe_len, %edx
    syscall
    cmp $brokered_host_udp_direct_probe_len, %rax
    je .brokered_udp_direct_done
    cmp $-101, %rax
    je .brokered_udp_direct_done
    cmp $-111, %rax
    je .brokered_udp_direct_done
    cmp $-113, %rax
    je .brokered_udp_direct_done
    jmp .brokered_udp_direct_fail

.brokered_udp_direct_error:
    cmp $-101, %rax
    je .brokered_udp_direct_done
    cmp $-111, %rax
    je .brokered_udp_direct_done
    cmp $-113, %rax
    je .brokered_udp_direct_done
    jmp .brokered_udp_direct_fail

.brokered_udp_direct_done:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail45
    xor %edi, %edi
    jmp .exit

.brokered_udp_direct_fail:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    jmp .fail45

'''
insert_before(
    "tests/fixtures/probe.S",
    ".brokered_host_loopback_ingress:\n",
    udp_probe,
    "probe UDP behavior",
)
replace_one(
    "tests/fixtures/probe.S",
    """brokered_host_message:
    .ascii "brokered-host-loopback-ok"
.set brokered_host_message_len, . - brokered_host_message
brokered_ingress_ready:
""",
    """brokered_host_message:
    .ascii "brokered-host-loopback-ok"
.set brokered_host_message_len, . - brokered_host_message
brokered_host_udp_message:
    .ascii "brokered-host-udp-ok"
.set brokered_host_udp_message_len, . - brokered_host_udp_message
brokered_host_udp_direct_probe:
    .ascii "direct-host-udp-probe"
.set brokered_host_udp_direct_probe_len, . - brokered_host_udp_direct_probe
brokered_ingress_ready:
""",
    "probe UDP messages",
)
replace_one(
    "tests/fixtures/probe.S",
    """.fail44:
    mov $44, %edi

.exit:
""",
    """.fail44:
    mov $44, %edi
    jmp .exit
.fail45:
    mov $45, %edi

.exit:
""",
    "probe UDP failure code",
)
