from pathlib import Path
import sys


def read(path: str) -> str:
    return Path(path).read_text()


def write(path: str, text: str) -> None:
    Path(path).write_text(text)


def replace_one(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)


def insert_before(text: str, marker: str, addition: str, label: str) -> str:
    return replace_one(text, marker, addition + marker, label)


TEST_SPEC = '''    #[test]
    fn parses_landlock_tcp_port_rules() {
        let allowed = format!("{VALID}\\
landlock.tcp_bind_port = 42421\\
landlock.tcp_connect_port = 42421");
        assert!(allowed.parse::<SandboxPolicy>().is_ok());

        let duplicate = format!("{VALID}\\
landlock.tcp_bind_port = 42421\\
landlock.tcp_bind_port = 42421");
        assert!(duplicate.parse::<SandboxPolicy>().is_err());
    }

'''

TEST_FINAL = '''    #[test]
    fn parses_landlock_tcp_port_rules() {
        let allowed = format!("{VALID}\\
landlock.tcp_bind_port = 42421\\
landlock.tcp_bind_port = 42423\\
landlock.tcp_connect_port = 42421");
        let policy: SandboxPolicy = allowed.parse().unwrap();
        assert_eq!(policy.landlock_tcp_bind_ports, [42421, 42423]);
        assert_eq!(policy.landlock_tcp_connect_ports, [42421]);

        for key in ["landlock.tcp_bind_port", "landlock.tcp_connect_port"] {
            let zero = format!("{VALID}\\n{key} = 0");
            assert!(zero.parse::<SandboxPolicy>().is_err());

            let duplicate = format!("{VALID}\\n{key} = 42421\\n{key} = 42421");
            assert!(duplicate.parse::<SandboxPolicy>().is_err());

            let mut oversized = VALID.to_owned();
            for port in 1..=33 {
                oversized.push_str(&format!("\\n{key} = {}", 43000 + port));
            }
            assert!(oversized.parse::<SandboxPolicy>().is_err());
        }
    }

'''


def stage_tests() -> None:
    path = "src/policy.rs"
    text = read(path)
    marker = "    #[test]\n    fn parses_landlock_file_mutation_paths() {"
    text = insert_before(text, marker, TEST_SPEC, "policy TCP spec test")
    write(path, text)


def stage_production() -> None:
    # Policy surface and validation.
    path = "src/policy.rs"
    text = read(path)
    text = replace_one(
        text,
        "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\n",
        "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_TCP_PORTS: usize = 32;\n",
        "policy Landlock TCP max",
    )
    text = replace_one(
        text,
        "    /// Optional Landlock regular-file mutation allowlist. Each path names a\n    /// directory within an already-writable scratch or persistent-volume surface.\n    pub landlock_file_mutate: Vec<PathBuf>,\n",
        "    /// Optional Landlock regular-file mutation allowlist. Each path names a\n    /// directory within an already-writable scratch or persistent-volume surface.\n    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Optional Landlock TCP port envelopes for target-created sockets. These\n    /// rules restrict bind/connect syscalls without granting those syscalls.\n    pub landlock_tcp_bind_ports: Vec<u16>,\n    pub landlock_tcp_connect_ports: Vec<u16>,\n",
        "policy Landlock TCP fields",
    )
    marker = "        match (\n            self.host_loopback_tcp_port,\n            self.host_loopback_tcp_target_fd,\n        ) {"
    validation = '''        validate_landlock_tcp_ports(
            "landlock.tcp_bind_port",
            &self.landlock_tcp_bind_ports,
        )?;
        validate_landlock_tcp_ports(
            "landlock.tcp_connect_port",
            &self.landlock_tcp_connect_ports,
        )?;

'''
    text = insert_before(text, marker, validation, "policy Landlock TCP validation")
    text = replace_one(
        text,
        "        let mut landlock_read_execute = Vec::new();\n        let mut landlock_file_mutate = Vec::new();\n        let mut loopback_enabled = None;\n",
        "        let mut landlock_read_execute = Vec::new();\n        let mut landlock_file_mutate = Vec::new();\n        let mut landlock_tcp_bind_ports = Vec::new();\n        let mut landlock_tcp_connect_ports = Vec::new();\n        let mut loopback_enabled = None;\n",
        "policy parser TCP vars",
    )
    text = insert_before(
        text,
        '                "network.loopback" => set_once(\n',
        '                "landlock.tcp_bind_port" => {\n                    landlock_tcp_bind_ports.push(parse_tcp_port(value, line_no, key)?)\n                }\n                "landlock.tcp_connect_port" => {\n                    landlock_tcp_connect_ports.push(parse_tcp_port(value, line_no, key)?)\n                }\n',
        "policy parser TCP keys",
    )
    text = replace_one(
        text,
        "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
        "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_tcp_bind_ports,\n            landlock_tcp_connect_ports,\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
        "policy construct TCP fields",
    )
    text = insert_before(
        text,
        "fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {",
        '''fn validate_landlock_tcp_ports(label: &str, ports: &[u16]) -> Result<(), PolicyError> {
    if ports.len() > MAX_LANDLOCK_TCP_PORTS {
        return Err(PolicyError::new(format!(
            "too many {label} entries: {} > {MAX_LANDLOCK_TCP_PORTS}",
            ports.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for port in ports {
        if *port == 0 {
            return Err(PolicyError::new(format!(
                "{label} must be between 1 and 65535"
            )));
        }
        if !seen.insert(*port) {
            return Err(PolicyError::new(format!(
                "duplicate {label}: {port}"
            )));
        }
    }
    Ok(())
}

''',
        "policy TCP validator helper",
    )
    text = replace_one(
        text,
        "        assert!(policy.landlock_read_execute.is_empty());\n        assert!(policy.landlock_file_mutate.is_empty());\n",
        "        assert!(policy.landlock_read_execute.is_empty());\n        assert!(policy.landlock_file_mutate.is_empty());\n        assert!(policy.landlock_tcp_bind_ports.is_empty());\n        assert!(policy.landlock_tcp_connect_ports.is_empty());\n",
        "policy complete defaults",
    )
    text = replace_one(text, TEST_SPEC, TEST_FINAL, "policy TCP finalized test")
    write(path, text)

    # Linux Landlock ABI 4 network enforcement.
    path = "src/platform/linux.rs"
    text = read(path)
    text = replace_one(
        text,
        "    const PHASE_LANDLOCK_RESTRICT: u32 = 51;\n",
        "    const PHASE_LANDLOCK_RESTRICT: u32 = 51;\n    const PHASE_LANDLOCK_NET_RULE: u32 = 52;\n",
        "Linux Landlock network phase",
    )
    text = replace_one(
        text,
        "    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;\n",
        "    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;\n    const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;\n    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;\n",
        "Linux Landlock network constants",
    )
    text = replace_one(
        text,
        "    struct LandlockRulesetAttr {\n        handled_access_fs: u64,\n    }\n",
        "    struct LandlockRulesetAttr {\n        handled_access_fs: u64,\n        handled_access_net: u64,\n    }\n",
        "Linux Landlock ruleset network attr",
    )
    text = insert_before(
        text,
        "    #[repr(C, align(8))]\n    struct IfreqFlags {",
        '''    #[repr(C)]
    struct LandlockNetPortAttr {
        allowed_access: u64,
        port: u64,
    }

''',
        "Linux Landlock net port attr",
    )
    text = replace_one(
        text,
        "        landlock_read_execute: Vec<CString>,\n        landlock_file_mutate: Vec<CString>,\n        cancellation_fd: Option<OwnedFd>,\n",
        "        landlock_read_execute: Vec<CString>,\n        landlock_file_mutate: Vec<CString>,\n        landlock_tcp_bind_ports: Vec<u16>,\n        landlock_tcp_connect_ports: Vec<u16>,\n        cancellation_fd: Option<OwnedFd>,\n",
        "Linux prepared Landlock TCP fields",
    )
    text = replace_one(
        text,
        "                landlock_read_execute,\n                landlock_file_mutate,\n                cancellation_fd,\n",
        "                landlock_read_execute,\n                landlock_file_mutate,\n                landlock_tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),\n                landlock_tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),\n                cancellation_fd,\n",
        "Linux prepared Landlock TCP values",
    )
    text = replace_one(
        text,
        "        if policy.landlock_read_execute.is_empty() && policy.landlock_file_mutate.is_empty() {\n            return Ok(());\n        }\n",
        "        if policy.landlock_read_execute.is_empty()\n            && policy.landlock_file_mutate.is_empty()\n            && policy.landlock_tcp_bind_ports.is_empty()\n            && policy.landlock_tcp_connect_ports.is_empty()\n        {\n            return Ok(());\n        }\n",
        "Linux Landlock preflight empty condition",
    )
    text = replace_one(
        text,
        "            if !policy.landlock_file_mutate.is_empty() && abi < 3 {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock file-mutation enforcement requires ABI 3 for TRUNCATE control; kernel reports ABI {abi}\"\n                )));\n            }\n            return Ok(());\n",
        "            if !policy.landlock_file_mutate.is_empty() && abi < 3 {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock file-mutation enforcement requires ABI 3 for TRUNCATE control; kernel reports ABI {abi}\"\n                )));\n            }\n            if (!policy.landlock_tcp_bind_ports.is_empty()\n                || !policy.landlock_tcp_connect_ports.is_empty())\n                && abi < 4\n            {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock TCP port enforcement requires ABI 4; kernel reports ABI {abi}\"\n                )));\n            }\n            return Ok(());\n",
        "Linux Landlock ABI 4 preflight",
    )
    text = replace_one(
        text,
        "    unsafe fn prepare_landlock_ruleset_or_fail(\n        read_execute_paths: &[CString],\n        file_mutate_paths: &[CString],\n        root_tree_fd: RawFd,\n",
        "    unsafe fn prepare_landlock_ruleset_or_fail(\n        read_execute_paths: &[CString],\n        file_mutate_paths: &[CString],\n        tcp_bind_ports: &[u16],\n        tcp_connect_ports: &[u16],\n        root_tree_fd: RawFd,\n",
        "Linux Landlock prepare signature",
    )
    text = replace_one(
        text,
        "        if read_execute_paths.is_empty() && file_mutate_paths.is_empty() {\n            return -1;\n        }\n\n        let mut handled_access_fs = 0;\n",
        "        if read_execute_paths.is_empty()\n            && file_mutate_paths.is_empty()\n            && tcp_bind_ports.is_empty()\n            && tcp_connect_ports.is_empty()\n        {\n            return -1;\n        }\n\n        let mut handled_access_fs = 0;\n",
        "Linux Landlock prepare empty condition",
    )
    text = replace_one(
        text,
        "        if !file_mutate_paths.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        let ruleset = LandlockRulesetAttr { handled_access_fs };\n        let raw_ruleset_fd = libc::syscall(\n            SYS_LANDLOCK_CREATE_RULESET,\n            &ruleset as *const LandlockRulesetAttr,\n            std::mem::size_of::<LandlockRulesetAttr>(),\n            0u32,\n        );\n",
        "        if !file_mutate_paths.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        let mut handled_access_net = 0;\n        if !tcp_bind_ports.is_empty() {\n            handled_access_net |= LANDLOCK_ACCESS_NET_BIND_TCP;\n        }\n        if !tcp_connect_ports.is_empty() {\n            handled_access_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;\n        }\n        let ruleset = LandlockRulesetAttr {\n            handled_access_fs,\n            handled_access_net,\n        };\n        // Preserve ABI 1-3 filesystem-only compatibility: handled_access_net\n        // was added in ABI 4, so only include the second u64 when it is used.\n        let ruleset_size = if handled_access_net == 0 {\n            std::mem::size_of::<u64>()\n        } else {\n            std::mem::size_of::<LandlockRulesetAttr>()\n        };\n        let raw_ruleset_fd = libc::syscall(\n            SYS_LANDLOCK_CREATE_RULESET,\n            &ruleset as *const LandlockRulesetAttr,\n            ruleset_size,\n            0u32,\n        );\n",
        "Linux Landlock handled network rights",
    )
    marker = "        ruleset_fd\n    }\n\n    unsafe fn restrict_landlock_or_fail("
    net_rules = '''        for port in tcp_bind_ports {
            let mut allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP;
            if tcp_connect_ports.contains(port) {
                allowed_access |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
            }
            let rule = LandlockNetPortAttr {
                allowed_access,
                port: u64::from(*port),
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_NET_RULE, error_exit_syscall);
            }
        }
        for port in tcp_connect_ports {
            if tcp_bind_ports.contains(port) {
                continue;
            }
            let rule = LandlockNetPortAttr {
                allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port: u64::from(*port),
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_NET_RULE, error_exit_syscall);
            }
        }
'''
    text = replace_one(text, marker, net_rules + marker, "Linux Landlock net rules")
    text = replace_one(
        text,
        "            &prepared.landlock_read_execute,\n            &prepared.landlock_file_mutate,\n            root_tree_fd,\n",
        "            &prepared.landlock_read_execute,\n            &prepared.landlock_file_mutate,\n            &prepared.landlock_tcp_bind_ports,\n            &prepared.landlock_tcp_connect_ports,\n            root_tree_fd,\n",
        "Linux Landlock prepare call",
    )
    text = replace_one(
        text,
        "            PHASE_LANDLOCK_RULE => \"Landlock path-beneath rule installation\",\n            PHASE_LANDLOCK_RESTRICT => \"Landlock self restriction\",\n",
        "            PHASE_LANDLOCK_RULE => \"Landlock path-beneath rule installation\",\n            PHASE_LANDLOCK_RESTRICT => \"Landlock self restriction\",\n            PHASE_LANDLOCK_NET_RULE => \"Landlock TCP port rule installation\",\n",
        "Linux Landlock phase decoding",
    )
    write(path, text)

    # Integration helper and executable regression.
    path = "tests/sandbox.rs"
    text = read(path)
    text = replace_one(
        text,
        "        landlock_read_execute: Vec::new(),\n        landlock_file_mutate: Vec::new(),\n        loopback_enabled: false,\n",
        "        landlock_read_execute: Vec::new(),\n        landlock_file_mutate: Vec::new(),\n        landlock_tcp_bind_ports: Vec::new(),\n        landlock_tcp_connect_ports: Vec::new(),\n        loopback_enabled: false,\n",
        "integration policy TCP defaults",
    )
    marker = "#[test]\nfn ipc_namespace_cannot_observe_host_sysv_message_queue() {"
    test = '''#[test]
fn landlock_tcp_port_envelope_allows_declared_loopback_endpoint_and_denies_other_ports() {
    let mut confined = policy(
        "s",
        &[],
        &[
            "execveat", "socket", "bind", "listen", "fork", "connect", "accept", "read",
            "write", "close", "exit",
        ],
    );
    confined.loopback_enabled = true;
    confined.landlock_tcp_bind_ports = vec![42421];
    confined.landlock_tcp_connect_ports = vec![42421];
    confined.wall_clock_milliseconds = Some(2000);

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
}

'''
    text = insert_before(text, marker, test, "integration Landlock TCP test")
    write(path, text)

    path = "tests/fixtures/probe.S"
    text = read(path)
    text = replace_one(
        text,
        "#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume\n",
        "#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports\n",
        "probe TCP mode comment",
    )
    text = replace_one(
        text,
        "    cmp $109, %al\n    je .landlock_file_mutation\n    cmp $70, %al\n",
        "    cmp $109, %al\n    je .landlock_file_mutation\n    cmp $115, %al\n    je .landlock_tcp_ports\n    cmp $70, %al\n",
        "probe TCP mode dispatch",
    )
    marker = ".forbidden:\n"
    body = r'''.landlock_tcp_ports:
    movw $2, network_addr(%rip)
    movw $0xb5a5, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)
    movw $2, network_addr_denied(%rip)
    movw $0xb6a5, network_addr_denied+2(%rip)
    movl $0x0100007f, network_addr_denied+4(%rip)

    # Allowed local bind on TCP 42421 must succeed.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r12

    mov $49, %eax
    mov %r12, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail40

    mov $50, %eax
    mov %r12, %rdi
    mov $1, %esi
    syscall
    test %rax, %rax
    js .fail40

    # Same network namespace and seccomp authority, but undeclared bind port
    # 42422 must be denied specifically by Landlock with EACCES.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $49, %eax
    mov %r13, %rdi
    lea network_addr_denied(%rip), %rsi
    mov $16, %edx
    syscall
    cmp $-13, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40

    # Undeclared remote TCP port must likewise return Landlock EACCES rather
    # than the ordinary ECONNREFUSED result of an unserved loopback port.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr_denied(%rip), %rsi
    mov $16, %edx
    syscall
    cmp $-13, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40

    # Positive connect on the declared remote port proves the rule does not
    # merely deny all target-created networking.
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail40
    jz .landlock_tcp_client

    mov $43, %eax
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    xor %eax, %eax
    mov %r13, %rdi
    lea network_buffer(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail40

    lea network_buffer(%rip), %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %ecx
    repe cmpsb
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail40
    xor %edi, %edi
    jmp .exit

.landlock_tcp_client:
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail40

    mov $1, %eax
    mov %r13, %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40
    xor %edi, %edi
    jmp .exit

'''
    text = insert_before(text, marker, body, "probe Landlock TCP behavior")
    text = replace_one(
        text,
        ".fail39:\n    mov $39, %edi\n\n.exit:\n",
        ".fail39:\n    mov $39, %edi\n    jmp .exit\n.fail40:\n    mov $40, %edi\n\n.exit:\n",
        "probe fail40",
    )
    text = replace_one(
        text,
        "network_addr:\n    .skip 16\n.balign 8\nnetwork_ifreq:\n",
        "network_addr:\n    .skip 16\nnetwork_addr_denied:\n    .skip 16\n.balign 8\nnetwork_ifreq:\n",
        "probe denied network addr",
    )
    write(path, text)


if len(sys.argv) != 2 or sys.argv[1] not in {"tests", "production"}:
    raise SystemExit("usage: tmp-milestone-12a.py tests|production")
if sys.argv[1] == "tests":
    stage_tests()
else:
    stage_production()
