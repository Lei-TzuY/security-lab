from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: one optional brokered host-loopback TCP connection.
replace_one(
    "src/policy.rs",
    """    /// Whether the launcher activates `lo` inside the isolated network namespace.\n    /// This does not attach the namespace to any host or external network.\n    pub loopback_enabled: bool,\n    /// Optional trusted host directory exposed read-only at exactly one\n""",
    """    /// Whether the launcher activates `lo` inside the isolated network namespace.\n    /// This does not attach the namespace to any host or external network.\n    pub loopback_enabled: bool,\n    /// Optional launcher-brokered TCP connection to host 127.0.0.1. The port\n    /// and target descriptor must be specified together.\n    pub host_loopback_tcp_port: Option<u16>,\n    pub host_loopback_tcp_target_fd: Option<u32>,\n    /// Optional trusted host directory exposed read-only at exactly one\n""",
    "policy network fields",
)

replace_one(
    "src/policy.rs",
    """        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        match (&self.readonly_volume_source, &self.readonly_volume_target) {\n""",
    """        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        match (self.host_loopback_tcp_port, self.host_loopback_tcp_target_fd) {\n            (None, None) => {}\n            (Some(port), Some(target_fd)) => {\n                if port == 0 {\n                    return Err(PolicyError::new(\n                        \"network.host_loopback_tcp_port must be between 1 and 65535\",\n                    ));\n                }\n                if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network.host_loopback_tcp_target_fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}\"\n                    )));\n                }\n                if u64::from(target_fd) >= self.limits.open_files {\n                    return Err(PolicyError::new(format!(\n                        \"network.host_loopback_tcp_target_fd {target_fd} must be below limit.open_files {}\",\n                        self.limits.open_files\n                    )));\n                }\n                if self.selected_handles.contains_key(&target_fd) {\n                    return Err(PolicyError::new(format!(\n                        \"network host-loopback target fd {target_fd} collides with a selected handle target\"\n                    )));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"network.host_loopback_tcp_port and network.host_loopback_tcp_target_fd must be specified together\",\n                ));\n            }\n        }\n\n        match (&self.readonly_volume_source, &self.readonly_volume_target) {\n""",
    "policy broker validation",
)

replace_one(
    "src/policy.rs",
    """        let mut working_dir = None;\n        let mut loopback_enabled = None;\n        let mut readonly_volume_source = None;\n""",
    """        let mut working_dir = None;\n        let mut loopback_enabled = None;\n        let mut host_loopback_tcp_port = None;\n        let mut host_loopback_tcp_target_fd = None;\n        let mut readonly_volume_source = None;\n""",
    "policy broker parser state",
)

replace_one(
    "src/policy.rs",
    """                \"network.loopback\" => set_once(\n                    &mut loopback_enabled,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"volume.readonly_source\" => {\n""",
    """                \"network.loopback\" => set_once(\n                    &mut loopback_enabled,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_port\" => set_once(\n                    &mut host_loopback_tcp_port,\n                    parse_tcp_port(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.host_loopback_tcp_target_fd\" => set_once(\n                    &mut host_loopback_tcp_target_fd,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"volume.readonly_source\" => {\n""",
    "policy broker parser keys",
)

replace_one(
    "src/policy.rs",
    """            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n""",
    """            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n            host_loopback_tcp_port,\n            host_loopback_tcp_target_fd,\n            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n""",
    "policy broker construction",
)

replace_one(
    "src/policy.rs",
    """fn parse_enabled_disabled(value: &str, line: usize, key: &str) -> Result<bool, PolicyError> {\n    match value {\n        \"enabled\" => Ok(true),\n        \"disabled\" => Ok(false),\n        _ => Err(PolicyError::at(\n            line,\n            format!(\"{key} must be enabled or disabled\"),\n        )),\n    }\n}\n\nfn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {\n""",
    """fn parse_enabled_disabled(value: &str, line: usize, key: &str) -> Result<bool, PolicyError> {\n    match value {\n        \"enabled\" => Ok(true),\n        \"disabled\" => Ok(false),\n        _ => Err(PolicyError::at(\n            line,\n            format!(\"{key} must be enabled or disabled\"),\n        )),\n    }\n}\n\nfn parse_tcp_port(value: &str, line: usize, key: &str) -> Result<u16, PolicyError> {\n    let port = parse_u64(value, line, key)?;\n    if !(1..=u16::MAX as u64).contains(&port) {\n        return Err(PolicyError::at(\n            line,\n            format!(\"{key} must be between 1 and 65535\"),\n        ));\n    }\n    Ok(port as u16)\n}\n\nfn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {\n""",
    "policy tcp port parser",
)

replace_one(
    "src/policy.rs",
    """        assert_eq!(policy.hostname, \"security-lab\");\n        assert!(!policy.loopback_enabled);\n        assert_eq!(policy.readonly_volume_source, None);\n""",
    """        assert_eq!(policy.hostname, \"security-lab\");\n        assert!(!policy.loopback_enabled);\n        assert_eq!(policy.host_loopback_tcp_port, None);\n        assert_eq!(policy.host_loopback_tcp_target_fd, None);\n        assert_eq!(policy.readonly_volume_source, None);\n""",
    "policy defaults test",
)

replace_one(
    "src/policy.rs",
    """    #[test]\n    fn rejects_invalid_or_duplicate_loopback_networking_mode() {\n        let invalid = format!(\"{VALID}\\nnetwork.loopback = host\");\n        let error = invalid.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error.to_string().contains(\"must be enabled or disabled\"));\n\n        let duplicate = format!(\"{VALID}\\nnetwork.loopback = enabled\\nnetwork.loopback = disabled\");\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_readonly_volume_pair() {\n""",
    """    #[test]\n    fn rejects_invalid_or_duplicate_loopback_networking_mode() {\n        let invalid = format!(\"{VALID}\\nnetwork.loopback = host\");\n        let error = invalid.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error.to_string().contains(\"must be enabled or disabled\"));\n\n        let duplicate = format!(\"{VALID}\\nnetwork.loopback = enabled\\nnetwork.loopback = disabled\");\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_brokered_host_loopback_tcp_endpoint() {\n        let text = format!(\n            \"{VALID}\\nnetwork.host_loopback_tcp_port = 8080\\nnetwork.host_loopback_tcp_target_fd = 10\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.host_loopback_tcp_port, Some(8080));\n        assert_eq!(policy.host_loopback_tcp_target_fd, Some(10));\n    }\n\n    #[test]\n    fn rejects_incomplete_or_unsafe_brokered_host_loopback_tcp_endpoint() {\n        let incomplete = format!(\"{VALID}\\nnetwork.host_loopback_tcp_port = 8080\");\n        assert!(incomplete.parse::<SandboxPolicy>().is_err());\n\n        let zero_port = format!(\n            \"{VALID}\\nnetwork.host_loopback_tcp_port = 0\\nnetwork.host_loopback_tcp_target_fd = 10\"\n        );\n        assert!(zero_port.parse::<SandboxPolicy>().is_err());\n\n        let oversized_port = format!(\n            \"{VALID}\\nnetwork.host_loopback_tcp_port = 65536\\nnetwork.host_loopback_tcp_target_fd = 10\"\n        );\n        assert!(oversized_port.parse::<SandboxPolicy>().is_err());\n\n        let stdio_target = format!(\n            \"{VALID}\\nnetwork.host_loopback_tcp_port = 8080\\nnetwork.host_loopback_tcp_target_fd = 2\"\n        );\n        assert!(stdio_target.parse::<SandboxPolicy>().is_err());\n\n        let rlimit_target = format!(\n            \"{VALID}\\nnetwork.host_loopback_tcp_port = 8080\\nnetwork.host_loopback_tcp_target_fd = 32\"\n        );\n        assert!(rlimit_target.parse::<SandboxPolicy>().is_err());\n\n        let collision = format!(\n            \"{VALID}\\nhandle.10 = 0\\nnetwork.host_loopback_tcp_port = 8080\\nnetwork.host_loopback_tcp_target_fd = 10\"\n        );\n        let error = collision.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error.to_string().contains(\"collides with a selected handle target\"));\n    }\n\n    #[test]\n    fn parses_readonly_volume_pair() {\n""",
    "policy broker tests",
)

# Linux parent preparation: connect in the host netns, then reuse selected-handle remapping.
replace_one(
    "src/platform/linux.rs",
    """        Ok(PreparedSelectedHandle {\n            storage_fd,\n            target_fd: target_fd as RawFd,\n        })\n    }\n\n    fn prepare_volume(\n""",
    """        Ok(PreparedSelectedHandle {\n            storage_fd,\n            target_fd: target_fd as RawFd,\n        })\n    }\n\n    fn connect_host_loopback_tcp(\n        port: u16,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n        let socket_fd = unsafe {\n            libc::socket(\n                libc::AF_INET,\n                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,\n                0,\n            )\n        };\n        if socket_fd == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                \"cannot create brokered host-loopback TCP socket: {}\",\n                io::Error::last_os_error()\n            )));\n        }\n        let socket_fd = OwnedFd(socket_fd);\n        let address = libc::sockaddr_in {\n            sin_family: libc::AF_INET as libc::sa_family_t,\n            sin_port: port.to_be(),\n            sin_addr: libc::in_addr {\n                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),\n            },\n            sin_zero: [0; 8],\n        };\n        loop {\n            let connected = unsafe {\n                libc::connect(\n                    socket_fd.raw(),\n                    (&address as *const libc::sockaddr_in).cast::<libc::sockaddr>(),\n                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,\n                )\n            };\n            if connected == 0 {\n                break;\n            }\n            let error = io::Error::last_os_error();\n            if error.raw_os_error() == Some(libc::EINTR) {\n                continue;\n            }\n            return Err(SandboxError::SetupFailed(format!(\n                \"cannot connect brokered host-loopback TCP endpoint 127.0.0.1:{port}: {error}\"\n            )));\n        }\n        let storage_fd = move_owned_fd_to_selected_storage(\n            socket_fd,\n            storage_floor,\n            \"brokered host-loopback TCP socket\",\n        )?;\n        Ok(PreparedSelectedHandle {\n            storage_fd,\n            target_fd: target_fd as RawFd,\n        })\n    }\n\n    fn prepare_volume(\n""",
    "linux broker connect helper",
)

replace_one(
    "src/platform/linux.rs",
    """            let selected_storage_floor = policy\n                .selected_handles\n                .keys()\n                .next_back()\n                .map_or(FIRST_NON_STDIO_FD as RawFd, |target_fd| {\n                    *target_fd as RawFd + 1\n                });\n""",
    """            let selected_storage_floor = policy\n                .selected_handles\n                .keys()\n                .copied()\n                .chain(policy.host_loopback_tcp_target_fd.iter().copied())\n                .max()\n                .map_or(FIRST_NON_STDIO_FD as RawFd, |target_fd| {\n                    target_fd as RawFd + 1\n                });\n""",
    "linux broker storage floor",
)

replace_one(
    "src/platform/linux.rs",
    """            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());\n            for (target_fd, source_fd) in &policy.selected_handles {\n                selected_handles.push(pin_selected_handle(\n                    *source_fd,\n                    *target_fd,\n                    selected_storage_floor,\n                )?);\n            }\n            let cancellation_fd = cancellation\n""",
    """            let mut selected_handles = Vec::with_capacity(\n                policy.selected_handles.len()\n                    + if policy.host_loopback_tcp_target_fd.is_some() { 1 } else { 0 },\n            );\n            for (target_fd, source_fd) in &policy.selected_handles {\n                selected_handles.push(pin_selected_handle(\n                    *source_fd,\n                    *target_fd,\n                    selected_storage_floor,\n                )?);\n            }\n            match (\n                policy.host_loopback_tcp_port,\n                policy.host_loopback_tcp_target_fd,\n            ) {\n                (Some(port), Some(target_fd)) => selected_handles.push(\n                    connect_host_loopback_tcp(port, target_fd, selected_storage_floor)?,\n                ),\n                (None, None) => {}\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"network.host_loopback_tcp_port and network.host_loopback_tcp_target_fd must be specified together\",\n                    )));\n                }\n            }\n            let cancellation_fd = cancellation\n""",
    "linux broker prepared handle",
)

# Integration helper and positive+negative endpoint oracle.
replace_one(
    "tests/sandbox.rs",
    """        working_dir: PathBuf::from(\"/work\"),\n        loopback_enabled: false,\n        readonly_volume_source: None,\n""",
    """        working_dir: PathBuf::from(\"/work\"),\n        loopback_enabled: false,\n        host_loopback_tcp_port: None,\n        host_loopback_tcp_target_fd: None,\n        readonly_volume_source: None,\n""",
    "integration helper broker defaults",
)

replace_one(
    "tests/sandbox.rs",
    """#[test]\nfn loopback_is_down_unless_policy_enables_it() {\n""",
    """#[test]\nfn brokered_host_loopback_tcp_exposes_one_endpoint_without_rejoining_host_network() {\n    let listener = TcpListener::bind((\"127.0.0.1\", 0)).expect(\"bind brokered host listener\");\n    let address = listener.local_addr().expect(\"read brokered host listener address\");\n    let port = address.port().to_string();\n\n    let mut brokered = policy(\n        \"p\",\n        &[port.as_str()],\n        &[\"execveat\", \"write\", \"close\", \"socket\", \"connect\", \"exit\"],\n    );\n    brokered.host_loopback_tcp_port = Some(address.port());\n    brokered.host_loopback_tcp_target_fd = Some(10);\n    brokered.wall_clock_milliseconds = Some(2000);\n\n    assert_eq!(run(&brokered).unwrap(), ChildOutcome::Exited(0));\n    let (peer, _) = listener.accept().expect(\"accept brokered target connection\");\n    let mut marker = [0u8; 25];\n    read_exact_fd(peer.as_raw_fd(), &mut marker);\n    assert_eq!(&marker, b\"brokered-host-loopback-ok\");\n}\n\n#[test]\nfn loopback_is_down_unless_policy_enables_it() {\n""",
    "integration broker oracle",
)

# Raw fixture: fd 10 must carry the brokered connection while a fresh socket cannot reach host loopback.
replace_one(
    "tests/fixtures/probe.S",
    """#   n prove policy-owned loopback supports positive intra-sandbox TCP\n#   o prove loopback remains down unless policy explicitly enables it\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n""",
    """#   n prove policy-owned loopback supports positive intra-sandbox TCP\n#   o prove loopback remains down unless policy explicitly enables it\n#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n""",
    "fixture mode documentation",
)

replace_one(
    "tests/fixtures/probe.S",
    """    cmp $111, %al\n    je .loopback_disabled\n    cmp $70, %al\n""",
    """    cmp $111, %al\n    je .loopback_disabled\n    cmp $112, %al\n    je .brokered_host_loopback\n    cmp $70, %al\n""",
    "fixture broker dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    """.loopback_disabled:\n    mov $41, %eax\n    mov $2, %edi\n    mov $2, %esi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail35\n    mov %rax, %r12\n\n    movb $108, network_ifreq(%rip)\n    movb $111, network_ifreq+1(%rip)\n    movb $0, network_ifreq+2(%rip)\n    mov $16, %eax\n    mov %r12, %rdi\n    mov $0x8913, %esi\n    lea network_ifreq(%rip), %rdx\n    syscall\n    test %rax, %rax\n    js .fail35\n\n    movzwl network_ifreq+16(%rip), %eax\n    test $1, %eax\n    jnz .fail35\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail35\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n""",
    """.loopback_disabled:\n    mov $41, %eax\n    mov $2, %edi\n    mov $2, %esi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail35\n    mov %rax, %r12\n\n    movb $108, network_ifreq(%rip)\n    movb $111, network_ifreq+1(%rip)\n    movb $0, network_ifreq+2(%rip)\n    mov $16, %eax\n    mov %r12, %rdi\n    mov $0x8913, %esi\n    lea network_ifreq(%rip), %rdx\n    syscall\n    test %rax, %rax\n    js .fail35\n\n    movzwl network_ifreq+16(%rip), %eax\n    test $1, %eax\n    jnz .fail35\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail35\n    xor %edi, %edi\n    jmp .exit\n\n.brokered_host_loopback:\n    mov $1, %eax\n    mov $10, %edi\n    lea brokered_host_message(%rip), %rsi\n    mov $brokered_host_message_len, %edx\n    syscall\n    cmp $brokered_host_message_len, %rax\n    jne .fail36\n\n    mov $3, %eax\n    mov $10, %edi\n    syscall\n    test %rax, %rax\n    js .fail36\n\n    mov 24(%rsp), %rdi\n    test %rdi, %rdi\n    je .fail36\n    xor %r12d, %r12d\n.brokered_port_parse_loop:\n    movzbl (%rdi), %eax\n    test %al, %al\n    je .brokered_port_parsed\n    sub $48, %eax\n    cmp $9, %eax\n    ja .fail36\n    imul $10, %r12d, %r12d\n    add %eax, %r12d\n    cmp $65535, %r12d\n    ja .fail36\n    inc %rdi\n    jmp .brokered_port_parse_loop\n.brokered_port_parsed:\n    test %r12d, %r12d\n    je .fail36\n    movw $2, network_addr(%rip)\n    rolw $8, %r12w\n    movw %r12w, network_addr+2(%rip)\n    movl $0x0100007f, network_addr+4(%rip)\n\n    mov $41, %eax\n    mov $2, %edi\n    mov $1, %esi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail36\n    mov %rax, %r13\n\n    mov $42, %eax\n    mov %r13, %rdi\n    lea network_addr(%rip), %rsi\n    mov $16, %edx\n    syscall\n    test %rax, %rax\n    jns .brokered_unexpected_reachability\n    cmp $-111, %rax\n    je .brokered_direct_isolated\n    cmp $-101, %rax\n    je .brokered_direct_isolated\n    cmp $-113, %rax\n    je .brokered_direct_isolated\n    jmp .fail36\n\n.brokered_unexpected_reachability:\n    mov $3, %eax\n    mov %r13, %rdi\n    syscall\n    jmp .fail36\n\n.brokered_direct_isolated:\n    mov $3, %eax\n    mov %r13, %rdi\n    syscall\n    test %rax, %rax\n    js .fail36\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n""",
    "fixture broker implementation",
)

replace_one(
    "tests/fixtures/probe.S",
    """.fail35:\n    mov $35, %edi\n\n.exit:\n""",
    """.fail35:\n    mov $35, %edi\n    jmp .exit\n.fail36:\n    mov $36, %edi\n\n.exit:\n""",
    "fixture broker fail code",
)

replace_one(
    "tests/fixtures/probe.S",
    """loopback_message:\n    .ascii \"loopback-ok\"\n.set loopback_message_len, . - loopback_message\ndeadline_message:\n""",
    """loopback_message:\n    .ascii \"loopback-ok\"\n.set loopback_message_len, . - loopback_message\nbrokered_host_message:\n    .ascii \"brokered-host-loopback-ok\"\n.set brokered_host_message_len, . - brokered_host_message\ndeadline_message:\n""",
    "fixture broker marker",
)
