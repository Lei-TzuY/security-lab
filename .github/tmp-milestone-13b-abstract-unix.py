from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: one independent ABI-6 Landlock scope bit.
replace_one(
    "src/policy.rs",
    """    /// Whether the direct target enters a Landlock signal scope. This attenuates
    /// signal authority toward processes outside the same or a nested domain.
    pub landlock_scope_signal: bool,
""",
    """    /// Whether the direct target enters a Landlock abstract-UNIX-socket scope.
    /// This attenuates connect authority toward abstract sockets outside the
    /// same or a nested Landlock domain without granting connect itself.
    pub landlock_scope_abstract_unix_socket: bool,
    /// Whether the direct target enters a Landlock signal scope. This attenuates
    /// signal authority toward processes outside the same or a nested domain.
    pub landlock_scope_signal: bool,
""",
    "policy struct scope field",
)
replace_one(
    "src/policy.rs",
    """        let mut landlock_tcp_bind_ports = Vec::new();
        let mut landlock_tcp_connect_ports = Vec::new();
        let mut landlock_scope_signal = None;
        let mut loopback_enabled = None;
""",
    """        let mut landlock_tcp_bind_ports = Vec::new();
        let mut landlock_tcp_connect_ports = Vec::new();
        let mut landlock_scope_abstract_unix_socket = None;
        let mut landlock_scope_signal = None;
        let mut loopback_enabled = None;
""",
    "policy parser scope state",
)
replace_one(
    "src/policy.rs",
    """                "landlock.scope_signal" => set_once(
                    &mut landlock_scope_signal,
                    parse_enabled_disabled(value, line_no, key)?,
                    line_no,
                    key,
                )?,
""",
    """                "landlock.scope_abstract_unix_socket" => set_once(
                    &mut landlock_scope_abstract_unix_socket,
                    parse_enabled_disabled(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "landlock.scope_signal" => set_once(
                    &mut landlock_scope_signal,
                    parse_enabled_disabled(value, line_no, key)?,
                    line_no,
                    key,
                )?,
""",
    "policy parser scope key",
)
replace_one(
    "src/policy.rs",
    """            landlock_tcp_bind_ports,
            landlock_tcp_connect_ports,
            landlock_scope_signal: landlock_scope_signal.unwrap_or(false),
            loopback_enabled: loopback_enabled.unwrap_or(false),
""",
    """            landlock_tcp_bind_ports,
            landlock_tcp_connect_ports,
            landlock_scope_abstract_unix_socket: landlock_scope_abstract_unix_socket
                .unwrap_or(false),
            landlock_scope_signal: landlock_scope_signal.unwrap_or(false),
            loopback_enabled: loopback_enabled.unwrap_or(false),
""",
    "policy construction scope field",
)
replace_one(
    "src/policy.rs",
    """        assert!(policy.landlock_tcp_connect_ports.is_empty());
        assert!(!policy.landlock_scope_signal);
""",
    """        assert!(policy.landlock_tcp_connect_ports.is_empty());
        assert!(!policy.landlock_scope_abstract_unix_socket);
        assert!(!policy.landlock_scope_signal);
""",
    "policy default scope assertion",
)
replace_one(
    "src/policy.rs",
    """    #[test]
    fn parses_landlock_signal_scope_mode() {
        let enabled: SandboxPolicy = format!("{VALID}\\nlandlock.scope_signal = enabled")
            .parse()
            .unwrap();
        assert!(enabled.landlock_scope_signal);

        let disabled: SandboxPolicy = format!("{VALID}\\nlandlock.scope_signal = disabled")
            .parse()
            .unwrap();
        assert!(!disabled.landlock_scope_signal);

        let invalid = format!("{VALID}\\nlandlock.scope_signal = yes");
        assert!(invalid.parse::<SandboxPolicy>().is_err());

        let duplicate =
            format!("{VALID}\\nlandlock.scope_signal = enabled\\nlandlock.scope_signal = disabled");
        assert!(duplicate.parse::<SandboxPolicy>().is_err());
    }
""",
    """    #[test]
    fn parses_landlock_abstract_unix_scope_mode() {
        let enabled: SandboxPolicy =
            format!("{VALID}\\nlandlock.scope_abstract_unix_socket = enabled")
                .parse()
                .unwrap();
        assert!(enabled.landlock_scope_abstract_unix_socket);

        let disabled: SandboxPolicy =
            format!("{VALID}\\nlandlock.scope_abstract_unix_socket = disabled")
                .parse()
                .unwrap();
        assert!(!disabled.landlock_scope_abstract_unix_socket);

        let invalid = format!("{VALID}\\nlandlock.scope_abstract_unix_socket = yes");
        assert!(invalid.parse::<SandboxPolicy>().is_err());

        let duplicate = format!(
            "{VALID}\\nlandlock.scope_abstract_unix_socket = enabled\\nlandlock.scope_abstract_unix_socket = disabled"
        );
        assert!(duplicate.parse::<SandboxPolicy>().is_err());

        let combined: SandboxPolicy = format!(
            "{VALID}\\nlandlock.scope_abstract_unix_socket = enabled\\nlandlock.scope_signal = enabled"
        )
        .parse()
        .unwrap();
        assert!(combined.landlock_scope_abstract_unix_socket);
        assert!(combined.landlock_scope_signal);
    }

    #[test]
    fn parses_landlock_signal_scope_mode() {
        let enabled: SandboxPolicy = format!("{VALID}\\nlandlock.scope_signal = enabled")
            .parse()
            .unwrap();
        assert!(enabled.landlock_scope_signal);

        let disabled: SandboxPolicy = format!("{VALID}\\nlandlock.scope_signal = disabled")
            .parse()
            .unwrap();
        assert!(!disabled.landlock_scope_signal);

        let invalid = format!("{VALID}\\nlandlock.scope_signal = yes");
        assert!(invalid.parse::<SandboxPolicy>().is_err());

        let duplicate =
            format!("{VALID}\\nlandlock.scope_signal = enabled\\nlandlock.scope_signal = disabled");
        assert!(duplicate.parse::<SandboxPolicy>().is_err());
    }
""",
    "policy abstract scope tests",
)

# Linux Landlock plumbing: keep scope bits independent and preserve ABI sizing.
replace_one(
    "src/platform/linux.rs",
    """    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;
""",
    """    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;
""",
    "Linux Landlock abstract scope constant",
)
replace_one(
    "src/platform/linux.rs",
    """        tcp_bind_ports: Vec<u16>,
        tcp_connect_ports: Vec<u16>,
        scope_signal: bool,
""",
    """        tcp_bind_ports: Vec<u16>,
        tcp_connect_ports: Vec<u16>,
        scope_abstract_unix_socket: bool,
        scope_signal: bool,
""",
    "prepared Landlock scope field",
)
replace_one(
    "src/platform/linux.rs",
    """                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),
                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),
                    scope_signal: policy.landlock_scope_signal,
""",
    """                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),
                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),
                    scope_abstract_unix_socket: policy.landlock_scope_abstract_unix_socket,
                    scope_signal: policy.landlock_scope_signal,
""",
    "prepare Landlock scope assignment",
)
replace_one(
    "src/platform/linux.rs",
    """            && policy.landlock_tcp_bind_ports.is_empty()
            && policy.landlock_tcp_connect_ports.is_empty()
            && !policy.landlock_scope_signal
""",
    """            && policy.landlock_tcp_bind_ports.is_empty()
            && policy.landlock_tcp_connect_ports.is_empty()
            && !policy.landlock_scope_abstract_unix_socket
            && !policy.landlock_scope_signal
""",
    "Landlock preflight empty policy",
)
replace_one(
    "src/platform/linux.rs",
    """            if policy.landlock_scope_signal && abi < 6 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock signal scoping requires ABI 6; kernel reports ABI {abi}"
                )));
            }
""",
    """            if policy.landlock_scope_abstract_unix_socket && abi < 6 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock abstract UNIX socket scoping requires ABI 6; kernel reports ABI {abi}"
                )));
            }
            if policy.landlock_scope_signal && abi < 6 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock signal scoping requires ABI 6; kernel reports ABI {abi}"
                )));
            }
""",
    "Landlock ABI-6 abstract scope preflight",
)
replace_one(
    "src/platform/linux.rs",
    """            && landlock.tcp_bind_ports.is_empty()
            && landlock.tcp_connect_ports.is_empty()
            && !landlock.scope_signal
""",
    """            && landlock.tcp_bind_ports.is_empty()
            && landlock.tcp_connect_ports.is_empty()
            && !landlock.scope_abstract_unix_socket
            && !landlock.scope_signal
""",
    "Landlock child empty ruleset",
)
replace_one(
    "src/platform/linux.rs",
    """        let scoped = if landlock.scope_signal {
            LANDLOCK_SCOPE_SIGNAL
        } else {
            0
        };
""",
    """        let mut scoped = 0;
        if landlock.scope_abstract_unix_socket {
            scoped |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
        }
        if landlock.scope_signal {
            scoped |= LANDLOCK_SCOPE_SIGNAL;
        }
""",
    "Landlock scope bitmask composition",
)

# Integration helper: host-domain abstract listener and explicit selected client socket.
replace_one(
    "tests/sandbox.rs",
    """fn duplicate_fd_at_least(fd: RawFd, minimum: RawFd, label: &str) -> TestFd {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(
        duplicated >= minimum,
        "failed to duplicate {label} at or above {minimum}: {}",
        std::io::Error::last_os_error()
    );
    TestFd(duplicated)
}
""",
    """fn duplicate_fd_at_least(fd: RawFd, minimum: RawFd, label: &str) -> TestFd {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
    assert!(
        duplicated >= minimum,
        "failed to duplicate {label} at or above {minimum}: {}",
        std::io::Error::last_os_error()
    );
    TestFd(duplicated)
}

fn abstract_unix_address(name: &[u8]) -> (libc::sockaddr_un, libc::socklen_t) {
    assert!(!name.is_empty(), "abstract UNIX socket name must not be empty");
    assert!(
        name.len() + 1 <= 108,
        "abstract UNIX socket name exceeds sockaddr_un.sun_path"
    );
    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (index, byte) in name.iter().enumerate() {
        address.sun_path[index + 1] = *byte as libc::c_char;
    }
    let length = (std::mem::size_of::<libc::sa_family_t>() + 1 + name.len()) as libc::socklen_t;
    (address, length)
}

fn abstract_unix_stream_listener(name: &[u8]) -> TestFd {
    let listener = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    assert!(
        listener >= 0,
        "create abstract UNIX listener failed: {}",
        std::io::Error::last_os_error()
    );
    let listener = TestFd(listener);
    let (address, length) = abstract_unix_address(name);
    let bound = unsafe {
        libc::bind(
            listener.raw(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            length,
        )
    };
    assert_eq!(
        bound,
        0,
        "bind abstract UNIX listener failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        unsafe { libc::listen(listener.raw(), 4) },
        0,
        "listen on abstract UNIX socket failed: {}",
        std::io::Error::last_os_error()
    );
    listener
}

fn unix_stream_client() -> TestFd {
    let client = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        client >= 0,
        "create abstract UNIX client failed: {}",
        std::io::Error::last_os_error()
    );
    TestFd(client)
}
""",
    "abstract UNIX integration helpers",
)
replace_one(
    "tests/sandbox.rs",
    """        landlock_tcp_bind_ports: Vec::new(),
        landlock_tcp_connect_ports: Vec::new(),
        landlock_scope_signal: false,
""",
    """        landlock_tcp_bind_ports: Vec::new(),
        landlock_tcp_connect_ports: Vec::new(),
        landlock_scope_abstract_unix_socket: false,
        landlock_scope_signal: false,
""",
    "test policy abstract scope default",
)
replace_one(
    "tests/sandbox.rs",
    """#[test]
fn landlock_signal_scope_attenuates_namespace_init_signal_permission() {
""",
    """#[test]
fn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {
    let name = format!("security-lab-landlock-abstract-{}", process::id());
    let listener = abstract_unix_stream_listener(name.as_bytes());

    let unscoped_client = unix_stream_client();
    let mut unscoped = policy("a", &[name.as_str()], &["execveat", "connect", "exit"]);
    unscoped
        .selected_handles
        .insert(9, unscoped_client.raw() as u32);
    assert_eq!(run(&unscoped).unwrap(), ChildOutcome::Exited(0));

    let accepted = unsafe {
        libc::accept4(
            listener.raw(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert!(
        accepted >= 0,
        "unscoped target did not reach host-domain abstract listener: {}",
        std::io::Error::last_os_error()
    );
    drop(TestFd(accepted));
    drop(unscoped_client);

    let scoped_client = unix_stream_client();
    let mut scoped = policy("a", &[name.as_str()], &["execveat", "connect", "exit"]);
    scoped
        .selected_handles
        .insert(9, scoped_client.raw() as u32);
    scoped.landlock_scope_abstract_unix_socket = true;
    assert_eq!(
        run(&scoped).unwrap(),
        ChildOutcome::Exited(libc::EPERM),
        "Landlock abstract UNIX scope must deny connect with exact EPERM"
    );

    let unexpected = unsafe {
        libc::accept4(
            listener.raw(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    assert_eq!(unexpected, -1, "scoped target unexpectedly queued a connection");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EAGAIN),
        "scoped target changed listener state without an accepted connection"
    );
}

#[test]
fn landlock_signal_scope_attenuates_namespace_init_signal_permission() {
""",
    "abstract UNIX Landlock integration regression",
)

# Raw fixture: one common connect oracle. Exit 0 on success, errno on denial.
replace_one(
    "tests/fixtures/probe.S",
    """#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports
#   t permission-check namespace PID1 through a target-opened pidfd; unscoped succeeds
""",
    """#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports
#   a connect selected fd 9 to argv[2] in the abstract UNIX socket namespace
#   t permission-check namespace PID1 through a target-opened pidfd; unscoped succeeds
""",
    "probe abstract mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    """    cmp $115, %al
    je .landlock_tcp_ports
    cmp $116, %al
""",
    """    cmp $115, %al
    je .landlock_tcp_ports
    cmp $97, %al
    je .abstract_unix_connect
    cmp $116, %al
""",
    "probe abstract mode dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    """.pidfd_signal_allowed:
""",
    """.abstract_unix_connect:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    lea abstract_unix_addr(%rip), %rdi
    movw $1, (%rdi)
    movb $0, 2(%rdi)
    xor %ecx, %ecx
.abstract_unix_name_copy:
    movzbl (%rsi,%rcx), %eax
    test %al, %al
    je .abstract_unix_name_done
    cmp $107, %ecx
    jae .fail42
    movb %al, 3(%rdi,%rcx)
    inc %ecx
    jmp .abstract_unix_name_copy
.abstract_unix_name_done:
    lea 3(%rcx), %edx
    mov $42, %eax
    mov $9, %edi
    lea abstract_unix_addr(%rip), %rsi
    syscall
    test %rax, %rax
    jns .abstract_unix_connected
    neg %eax
    mov %eax, %edi
    jmp .exit
.abstract_unix_connected:
    xor %edi, %edi
    jmp .exit

.pidfd_signal_allowed:
""",
    "probe abstract connect oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    """.fail41:
    mov $41, %edi

.exit:
""",
    """.fail41:
    mov $41, %edi
    jmp .exit
.fail42:
    mov $42, %edi

.exit:
""",
    "probe abstract failure code",
)
replace_one(
    "tests/fixtures/probe.S",
    """network_addr_denied:
    .skip 16
.balign 8
network_ifreq:
""",
    """network_addr_denied:
    .skip 16
abstract_unix_addr:
    .skip 110
.balign 8
network_ifreq:
""",
    "probe abstract sockaddr storage",
)
