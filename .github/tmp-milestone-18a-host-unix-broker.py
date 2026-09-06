from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: one exact filesystem-path AF_UNIX stream endpoint and one target fd.
replace_one(
    "src/policy.rs",
    "use std::net::Ipv4Addr;\nuse std::path::{Component, Path, PathBuf};",
    "use std::net::Ipv4Addr;\n#[cfg(unix)]\nuse std::os::unix::ffi::OsStrExt;\nuse std::path::{Component, Path, PathBuf};",
    "policy unix path bytes import",
)

replace_one(
    "src/policy.rs",
    "    pub host_ipv4_udp_address: Option<Ipv4Addr>,\n    pub host_ipv4_udp_port: Option<u16>,\n    pub host_ipv4_udp_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.",
    "    pub host_ipv4_udp_address: Option<Ipv4Addr>,\n    pub host_ipv4_udp_port: Option<u16>,\n    pub host_ipv4_udp_target_fd: Option<u32>,\n    /// Optional launcher-brokered connected filesystem-path AF_UNIX stream.\n    /// Host pathname and target descriptor are all-or-nothing.\n    pub host_unix_stream_path: Option<PathBuf>,\n    pub host_unix_stream_target_fd: Option<u32>,\n    /// Optional launcher-brokered TCP listener bound only to host 127.0.0.1.",
    "policy unix broker fields",
)

unix_validator = r'''        match (&self.host_unix_stream_path, self.host_unix_stream_target_fd) {
            (None, None) => {}
            (Some(path), Some(target_fd)) => {
                validate_unix_socket_path("ipc.host_unix_stream_path", path)?;
                if path.starts_with(&self.root_dir) || self.root_dir.starts_with(path) {
                    return Err(PolicyError::new(
                        "ipc.host_unix_stream_path must not overlap filesystem.root",
                    ));
                }
                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {
                    return Err(PolicyError::new(format!(
                        "ipc.host_unix_stream_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}"
                    )));
                }
                if u64::from(target_fd) >= self.limits.open_files {
                    return Err(PolicyError::new(format!(
                        "ipc.host_unix_stream_target_fd {target_fd} must be below limit.open_files {}",
                        self.limits.open_files
                    )));
                }
                if self.selected_handles.contains_key(&target_fd) {
                    return Err(PolicyError::new(format!(
                        "IPC host-UNIX stream target fd {target_fd} collides with a selected handle target"
                    )));
                }
                for (label, existing) in [
                    ("host-loopback TCP connection", self.host_loopback_tcp_target_fd),
                    ("host-IPv4 TCP connection", self.host_ipv4_tcp_target_fd),
                    ("host-IPv4 UDP connection", self.host_ipv4_udp_target_fd),
                    ("host-loopback TCP listener", self.host_loopback_tcp_listen_target_fd),
                ] {
                    if existing == Some(target_fd) {
                        return Err(PolicyError::new(format!(
                            "IPC host-UNIX stream target fd {target_fd} collides with the brokered {label} target"
                        )));
                    }
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "ipc.host_unix_stream_path and ipc.host_unix_stream_target_fd must be specified together",
                ));
            }
        }

'''
replace_one(
    "src/policy.rs",
    "        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {",
    unix_validator
    + "        match (\n            self.host_loopback_tcp_listen_port,\n            self.host_loopback_tcp_listen_target_fd,\n        ) {",
    "policy unix broker validator",
)

replace_one(
    "src/policy.rs",
    "        let mut host_ipv4_udp_address = None;\n        let mut host_ipv4_udp_port = None;\n        let mut host_ipv4_udp_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;",
    "        let mut host_ipv4_udp_address = None;\n        let mut host_ipv4_udp_port = None;\n        let mut host_ipv4_udp_target_fd = None;\n        let mut host_unix_stream_path = None;\n        let mut host_unix_stream_target_fd = None;\n        let mut host_loopback_tcp_listen_port = None;",
    "policy parser unix broker variables",
)

replace_one(
    "src/policy.rs",
    "                \"network.host_loopback_tcp_listen_port\" => set_once(\n                    &mut host_loopback_tcp_listen_port,",
    "                \"ipc.host_unix_stream_path\" => set_once(\n                    &mut host_unix_stream_path,\n                    value.to_owned(),\n                    line_no,\n                    key,\n                )?,\n                \"ipc.host_unix_stream_target_fd\" => set_once(\n                    &mut host_unix_stream_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_listen_port\" => set_once(\n                    &mut host_loopback_tcp_listen_port,",
    "policy parser unix broker keys",
)

replace_one(
    "src/policy.rs",
    "            host_ipv4_udp_address,\n            host_ipv4_udp_port,\n            host_ipv4_udp_target_fd,\n            host_loopback_tcp_listen_port,",
    "            host_ipv4_udp_address,\n            host_ipv4_udp_port,\n            host_ipv4_udp_target_fd,\n            host_unix_stream_path: host_unix_stream_path.map(PathBuf::from),\n            host_unix_stream_target_fd,\n            host_loopback_tcp_listen_port,",
    "policy final unix broker fields",
)

replace_one(
    "src/policy.rs",
    "fn validate_absolute_path(label: &str, path: &Path) -> Result<(), PolicyError> {",
    '''fn validate_unix_socket_path(label: &str, path: &Path) -> Result<(), PolicyError> {
    validate_absolute_path(label, path)?;
    #[cfg(unix)]
    let path_bytes = path.as_os_str().as_bytes();
    #[cfg(not(unix))]
    let path_bytes = path.as_os_str().to_string_lossy().as_bytes();
    if path_bytes.len() >= 108 {
        return Err(PolicyError::new(format!(
            "{label} must fit Linux sockaddr_un.sun_path (at most 107 pathname bytes)"
        )));
    }
    Ok(())
}

fn validate_absolute_path(label: &str, path: &Path) -> Result<(), PolicyError> {''',
    "policy unix path validator helper",
)

replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.host_ipv4_udp_address, None);\n        assert_eq!(policy.host_ipv4_udp_port, None);\n        assert_eq!(policy.host_ipv4_udp_target_fd, None);",
    "        assert_eq!(policy.host_ipv4_udp_address, None);\n        assert_eq!(policy.host_ipv4_udp_port, None);\n        assert_eq!(policy.host_ipv4_udp_target_fd, None);\n        assert_eq!(policy.host_unix_stream_path, None);\n        assert_eq!(policy.host_unix_stream_target_fd, None);",
    "policy default unix broker assertions",
)

unix_policy_tests = r'''    #[test]
    fn parses_brokered_host_unix_stream_endpoint() {
        let base = volume_valid();
        let text = format!(
            "{base}\nipc.host_unix_stream_path = /run/security-lab.sock\nipc.host_unix_stream_target_fd = 14"
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(
            policy.host_unix_stream_path,
            Some(PathBuf::from("/run/security-lab.sock"))
        );
        assert_eq!(policy.host_unix_stream_target_fd, Some(14));
    }

    #[test]
    fn rejects_incomplete_unsafe_or_colliding_host_unix_stream_endpoint() {
        let base = volume_valid();
        let incomplete = format!("{base}\nipc.host_unix_stream_path = /run/security-lab.sock");
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        let relative = format!(
            "{base}\nipc.host_unix_stream_path = run/security-lab.sock\nipc.host_unix_stream_target_fd = 14"
        );
        assert!(relative.parse::<SandboxPolicy>().is_err());

        let inside_root = format!(
            "{base}\nipc.host_unix_stream_path = /sandbox/root/run/service.sock\nipc.host_unix_stream_target_fd = 14"
        );
        let error = inside_root.parse::<SandboxPolicy>().unwrap_err();
        assert!(error.to_string().contains("must not overlap filesystem.root"));

        let too_long = format!("/run/{}", "x".repeat(108));
        let oversized = format!(
            "{base}\nipc.host_unix_stream_path = {too_long}\nipc.host_unix_stream_target_fd = 14"
        );
        assert!(oversized.parse::<SandboxPolicy>().is_err());

        let stdio_target = format!(
            "{base}\nipc.host_unix_stream_path = /run/security-lab.sock\nipc.host_unix_stream_target_fd = 2"
        );
        assert!(stdio_target.parse::<SandboxPolicy>().is_err());

        let selected_collision = format!(
            "{base}\nhandle.14 = 0\nipc.host_unix_stream_path = /run/security-lab.sock\nipc.host_unix_stream_target_fd = 14"
        );
        assert!(selected_collision.parse::<SandboxPolicy>().is_err());

        let broker_collision = format!(
            "{base}\nnetwork.host_ipv4_tcp_address = 127.0.0.2\nnetwork.host_ipv4_tcp_port = 8080\nnetwork.host_ipv4_tcp_target_fd = 14\nipc.host_unix_stream_path = /run/security-lab.sock\nipc.host_unix_stream_target_fd = 14"
        );
        let error = broker_collision.parse::<SandboxPolicy>().unwrap_err();
        assert!(error
            .to_string()
            .contains("collides with the brokered host-IPv4 TCP connection target"));
    }

'''
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_readonly_volume_pair() {",
    unix_policy_tests + "    #[test]\n    fn parses_readonly_volume_pair() {",
    "policy unix broker tests",
)

# Linux launcher: create the AF_UNIX connection while still in the trusted host context,
# then reuse the selected-handle storage/remap plane.
unix_connect_helper = r'''    fn connect_host_unix_stream(
        path: &Path,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() >= 108 || path_bytes.contains(&0) {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "ipc.host_unix_stream_path must be a nonempty Linux pathname of at most 107 bytes without NUL",
            )));
        }
        let socket_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered host-UNIX stream socket: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in path_bytes.iter().copied().enumerate() {
            address.sun_path[index] = byte as libc::c_char;
        }
        let address_length =
            (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
        loop {
            let connected = unsafe {
                libc::connect(
                    socket_fd.raw(),
                    (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                    address_length,
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
                "cannot connect brokered host-UNIX stream endpoint {}: {error}",
                path.display()
            )));
        }
        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            "brokered host-UNIX stream socket",
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

'''
replace_one(
    "src/platform/linux.rs",
    "    fn listen_host_loopback_tcp(\n",
    unix_connect_helper + "    fn listen_host_loopback_tcp(\n",
    "linux unix connect helper",
)

replace_one(
    "src/platform/linux.rs",
    "                .chain(policy.host_ipv4_udp_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())",
    "                .chain(policy.host_ipv4_udp_target_fd.iter().copied())\n                .chain(policy.host_unix_stream_target_fd.iter().copied())\n                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())",
    "linux selected storage floor unix fd",
)

replace_one(
    "src/platform/linux.rs",
    "                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },",
    "                    + if policy.host_unix_stream_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    }\n                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {\n                        1\n                    } else {\n                        0\n                    },",
    "linux selected capacity unix fd",
)

unix_prepare_match = r'''            match (&policy.host_unix_stream_path, policy.host_unix_stream_target_fd) {
                (Some(path), Some(target_fd)) => selected_handles.push(connect_host_unix_stream(
                    path,
                    target_fd,
                    selected_storage_floor,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "ipc.host_unix_stream_path and ipc.host_unix_stream_target_fd must be specified together",
                    )));
                }
            }
'''
replace_one(
    "src/platform/linux.rs",
    "            match (\n                policy.host_loopback_tcp_listen_port,\n                policy.host_loopback_tcp_listen_target_fd,\n            ) {",
    unix_prepare_match
    + "            match (\n                policy.host_loopback_tcp_listen_port,\n                policy.host_loopback_tcp_listen_target_fd,\n            ) {",
    "linux prepare unix broker",
)

# Rust integration: a real host pathname listener exchanges exact bytes over the broker,
# while a fresh target-created AF_UNIX socket receives ENOENT for the same host pathname.
replace_one(
    "tests/sandbox.rs",
    "use std::os::unix::io::{AsRawFd, RawFd};",
    "use std::os::unix::io::{AsRawFd, RawFd};\nuse std::os::unix::net::UnixListener;",
    "test unix listener import",
)
replace_one(
    "tests/sandbox.rs",
    "        host_ipv4_udp_address: None,\n        host_ipv4_udp_port: None,\n        host_ipv4_udp_target_fd: None,\n        host_loopback_tcp_listen_port: None,",
    "        host_ipv4_udp_address: None,\n        host_ipv4_udp_port: None,\n        host_ipv4_udp_target_fd: None,\n        host_unix_stream_path: None,\n        host_unix_stream_target_fd: None,\n        host_loopback_tcp_listen_port: None,",
    "test policy unix broker defaults",
)

unix_integration_test = r'''#[test]
fn brokered_host_unix_stream_is_usable_while_host_path_stays_hidden() {
    let socket_path = std::env::temp_dir().join(format!(
        "security-lab-host-unix-{}.sock",
        process::id()
    ));
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixListener::bind(&socket_path).expect("bind host UNIX stream endpoint");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept brokered UNIX connection");
        let expected = b"brokered-host-unix-ok";
        let mut request = vec![0u8; expected.len()];
        read_exact_fd(stream.as_raw_fd(), &mut request);
        assert_eq!(&request, expected);
        write_all_fd(stream.as_raw_fd(), b"host-unix-reply");
    });

    let socket_argument = socket_path.to_string_lossy().into_owned();
    let mut brokered = policy(
        "b",
        &[socket_argument.as_str()],
        &["execveat", "read", "write", "close", "socket", "connect", "exit"],
    );
    brokered.host_unix_stream_path = Some(socket_path.clone());
    brokered.host_unix_stream_target_fd = Some(10);
    brokered.wall_clock_milliseconds = Some(2000);

    let result = run(&brokered);
    server.join().expect("host UNIX server thread failed");
    let _ = std::fs::remove_file(&socket_path);
    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));
}

'''
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {",
    unix_integration_test
    + "#[test]\nfn brokered_host_ipv4_udp_preserves_datagram_boundary_and_exact_address() {",
    "test unix broker integration",
)

# Raw target mode 'b': consume only the brokered fd, then prove the original host pathname
# is not directly reachable from the chrooted target even when socket/connect are allowed.
replace_one(
    "tests/fixtures/probe.S",
    "#   e write one brokered host-IPv4 UDP datagram while fresh target UDP stays isolated\n#   q accept one connection through a launcher-brokered host-loopback TCP listening fd",
    "#   e write one brokered host-IPv4 UDP datagram while fresh target UDP stays isolated\n#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden\n#   q accept one connection through a launcher-brokered host-loopback TCP listening fd",
    "probe unix mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $101, %al\n    je .brokered_host_udp\n    cmp $113, %al",
    "    cmp $101, %al\n    je .brokered_host_udp\n    cmp $98, %al\n    je .brokered_host_unix\n    cmp $113, %al",
    "probe unix mode dispatch",
)

unix_probe = r'''.brokered_host_unix:
    mov $1, %eax
    mov $10, %edi
    lea brokered_host_unix_message(%rip), %rsi
    mov $brokered_host_unix_message_len, %edx
    syscall
    cmp $brokered_host_unix_message_len, %rax
    jne .fail46

    xor %r12d, %r12d
.brokered_host_unix_read_reply:
    xor %eax, %eax
    mov $10, %edi
    lea brokered_host_unix_buffer(%rip), %rsi
    add %r12, %rsi
    mov $brokered_host_unix_reply_len, %edx
    sub %r12d, %edx
    syscall
    test %rax, %rax
    jle .fail46
    add %rax, %r12
    cmp $brokered_host_unix_reply_len, %r12d
    jne .brokered_host_unix_read_reply

    lea brokered_host_unix_buffer(%rip), %rdi
    lea brokered_host_unix_reply(%rip), %rsi
    mov $brokered_host_unix_reply_len, %ecx
    repe cmpsb
    jne .fail46

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail46

    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail46
    lea host_unix_addr(%rip), %r13
    movw $1, (%r13)
    lea 2(%r13), %rdi
    xor %r15d, %r15d
.brokered_host_unix_copy_path:
    movzbl (%rsi,%r15,1), %eax
    test %al, %al
    je .brokered_host_unix_path_done
    cmp $107, %r15d
    jae .fail46
    movb %al, (%rdi,%r15,1)
    inc %r15d
    jmp .brokered_host_unix_copy_path
.brokered_host_unix_path_done:
    movb $0, (%rdi,%r15,1)
    add $3, %r15d

    mov $41, %eax
    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail46
    mov %rax, %r12

    mov $42, %eax
    mov %r12, %rdi
    lea host_unix_addr(%rip), %rsi
    mov %r15d, %edx
    syscall
    cmp $-2, %rax
    jne .brokered_host_unix_direct_fail

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail46
    xor %edi, %edi
    jmp .exit

.brokered_host_unix_direct_fail:
    mov $3, %eax
    mov %r12, %rdi
    syscall
    jmp .fail46

'''
replace_one(
    "tests/fixtures/probe.S",
    ".brokered_host_loopback_ingress:\n",
    unix_probe + ".brokered_host_loopback_ingress:\n",
    "probe unix mode body",
)

replace_one(
    "tests/fixtures/probe.S",
    "brokered_host_udp_message:\n    .ascii \"brokered-host-udp-ok\"\n.set brokered_host_udp_message_len, . - brokered_host_udp_message",
    "brokered_host_udp_message:\n    .ascii \"brokered-host-udp-ok\"\n.set brokered_host_udp_message_len, . - brokered_host_udp_message\nbrokered_host_unix_message:\n    .ascii \"brokered-host-unix-ok\"\n.set brokered_host_unix_message_len, . - brokered_host_unix_message\nbrokered_host_unix_reply:\n    .ascii \"host-unix-reply\"\n.set brokered_host_unix_reply_len, . - brokered_host_unix_reply",
    "probe unix data",
)
replace_one(
    "tests/fixtures/probe.S",
    ".section .bss\nlandlock_ioctl_entropy:",
    ".section .bss\n.balign 8\nhost_unix_addr:\n    .zero 110\nbrokered_host_unix_buffer:\n    .zero brokered_host_unix_reply_len\nlandlock_ioctl_entropy:",
    "probe unix bss",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail45:\n    mov $45, %edi\n\n.exit:",
    ".fail45:\n    mov $45, %edi\n    jmp .exit\n.fail46:\n    mov $46, %edi\n\n.exit:",
    "probe unix failure code",
)
