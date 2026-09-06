from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: one explicit, default-off Landlock signal scope.
replace_one(
    "src/policy.rs",
    "    pub landlock_tcp_bind_ports: Vec<u16>,\n    pub landlock_tcp_connect_ports: Vec<u16>,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.\n",
    "    pub landlock_tcp_bind_ports: Vec<u16>,\n    pub landlock_tcp_connect_ports: Vec<u16>,\n    /// Whether the direct target enters a Landlock signal scope. This attenuates\n    /// signal authority toward processes outside the same or a nested domain.\n    pub landlock_scope_signal: bool,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.\n",
    "policy field",
)
replace_one(
    "src/policy.rs",
    "        let mut landlock_tcp_bind_ports = Vec::new();\n        let mut landlock_tcp_connect_ports = Vec::new();\n        let mut loopback_enabled = None;\n",
    "        let mut landlock_tcp_bind_ports = Vec::new();\n        let mut landlock_tcp_connect_ports = Vec::new();\n        let mut landlock_scope_signal = None;\n        let mut loopback_enabled = None;\n",
    "parser state",
)
replace_one(
    "src/policy.rs",
    "                \"landlock.tcp_connect_port\" => {\n                    landlock_tcp_connect_ports.push(parse_tcp_port(value, line_no, key)?)\n                }\n                \"network.loopback\" => set_once(\n",
    "                \"landlock.tcp_connect_port\" => {\n                    landlock_tcp_connect_ports.push(parse_tcp_port(value, line_no, key)?)\n                }\n                \"landlock.scope_signal\" => set_once(\n                    &mut landlock_scope_signal,\n                    parse_enabled_disabled(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"network.loopback\" => set_once(\n",
    "parser key",
)
replace_one(
    "src/policy.rs",
    "            landlock_tcp_bind_ports,\n            landlock_tcp_connect_ports,\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
    "            landlock_tcp_bind_ports,\n            landlock_tcp_connect_ports,\n            landlock_scope_signal: landlock_scope_signal.unwrap_or(false),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
    "parser construction",
)
replace_one(
    "src/policy.rs",
    "        assert!(policy.landlock_tcp_bind_ports.is_empty());\n        assert!(policy.landlock_tcp_connect_ports.is_empty());\n        assert_eq!(policy.readonly_volume_source, None);\n",
    "        assert!(policy.landlock_tcp_bind_ports.is_empty());\n        assert!(policy.landlock_tcp_connect_ports.is_empty());\n        assert!(!policy.landlock_scope_signal);\n        assert_eq!(policy.readonly_volume_source, None);\n",
    "policy default assertion",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_loopback_networking_mode() {\n",
    "    #[test]\n    fn parses_landlock_signal_scope_mode() {\n        let enabled: SandboxPolicy = format!(\"{VALID}\\nlandlock.scope_signal = enabled\")\n            .parse()\n            .unwrap();\n        assert!(enabled.landlock_scope_signal);\n\n        let disabled: SandboxPolicy = format!(\"{VALID}\\nlandlock.scope_signal = disabled\")\n            .parse()\n            .unwrap();\n        assert!(!disabled.landlock_scope_signal);\n\n        let invalid = format!(\"{VALID}\\nlandlock.scope_signal = yes\");\n        assert!(invalid.parse::<SandboxPolicy>().is_err());\n\n        let duplicate = format!(\n            \"{VALID}\\nlandlock.scope_signal = enabled\\nlandlock.scope_signal = disabled\"\n        );\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_loopback_networking_mode() {\n",
    "signal scope policy tests",
)

# Linux UAPI/runtime: ABI 6 appended `scoped` to landlock_ruleset_attr.
replace_one(
    "src/platform/linux.rs",
    "    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;\n    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;\n",
    "    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;\n    const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;\n    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;\n",
    "signal scope constant",
)
replace_one(
    "src/platform/linux.rs",
    "    struct LandlockRulesetAttr {\n        handled_access_fs: u64,\n        handled_access_net: u64,\n    }\n",
    "    struct LandlockRulesetAttr {\n        handled_access_fs: u64,\n        handled_access_net: u64,\n        scoped: u64,\n    }\n",
    "ruleset UAPI",
)
replace_one(
    "src/platform/linux.rs",
    "    struct PreparedLandlock {\n        read_execute: Vec<CString>,\n        file_mutate: Vec<CString>,\n        tcp_bind_ports: Vec<u16>,\n        tcp_connect_ports: Vec<u16>,\n    }\n",
    "    struct PreparedLandlock {\n        read_execute: Vec<CString>,\n        file_mutate: Vec<CString>,\n        tcp_bind_ports: Vec<u16>,\n        tcp_connect_ports: Vec<u16>,\n        scope_signal: bool,\n    }\n",
    "prepared Landlock",
)
replace_one(
    "src/platform/linux.rs",
    "                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),\n                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),\n                },\n",
    "                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),\n                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),\n                    scope_signal: policy.landlock_scope_signal,\n                },\n",
    "prepared Landlock construction",
)
replace_one(
    "src/platform/linux.rs",
    "            && policy.landlock_tcp_bind_ports.is_empty()\n            && policy.landlock_tcp_connect_ports.is_empty()\n        {\n",
    "            && policy.landlock_tcp_bind_ports.is_empty()\n            && policy.landlock_tcp_connect_ports.is_empty()\n            && !policy.landlock_scope_signal\n        {\n",
    "Landlock support early return",
)
replace_one(
    "src/platform/linux.rs",
    "            if (!policy.landlock_tcp_bind_ports.is_empty()\n                || !policy.landlock_tcp_connect_ports.is_empty())\n                && abi < 4\n            {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock TCP port enforcement requires ABI 4; kernel reports ABI {abi}\"\n                )));\n            }\n            return Ok(());\n",
    "            if (!policy.landlock_tcp_bind_ports.is_empty()\n                || !policy.landlock_tcp_connect_ports.is_empty())\n                && abi < 4\n            {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock TCP port enforcement requires ABI 4; kernel reports ABI {abi}\"\n                )));\n            }\n            if policy.landlock_scope_signal && abi < 6 {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock signal scoping requires ABI 6; kernel reports ABI {abi}\"\n                )));\n            }\n            return Ok(());\n",
    "Landlock ABI 6 gate",
)
# There are two identical all-empty checks in ensure/prepare; the first was changed above.
replace_one(
    "src/platform/linux.rs",
    "            && landlock.tcp_bind_ports.is_empty()\n            && landlock.tcp_connect_ports.is_empty()\n        {\n            return -1;\n        }\n",
    "            && landlock.tcp_bind_ports.is_empty()\n            && landlock.tcp_connect_ports.is_empty()\n            && !landlock.scope_signal\n        {\n            return -1;\n        }\n",
    "Landlock ruleset empty check",
)
replace_one(
    "src/platform/linux.rs",
    "        let ruleset = LandlockRulesetAttr {\n            handled_access_fs,\n            handled_access_net,\n        };\n        // Preserve ABI 1-3 filesystem-only compatibility: handled_access_net\n        // was added in ABI 4, so only include the second u64 when it is used.\n        let ruleset_size = if handled_access_net == 0 {\n            std::mem::size_of::<u64>()\n        } else {\n            std::mem::size_of::<LandlockRulesetAttr>()\n        };\n",
    "        let scoped = if landlock.scope_signal {\n            LANDLOCK_SCOPE_SIGNAL\n        } else {\n            0\n        };\n        let ruleset = LandlockRulesetAttr {\n            handled_access_fs,\n            handled_access_net,\n            scoped,\n        };\n        // Preserve old-ABI struct sizing: handled_access_net was appended in\n        // ABI 4 and scoped in ABI 6. Only expose fields the active policy uses.\n        let ruleset_size = if scoped != 0 {\n            std::mem::size_of::<LandlockRulesetAttr>()\n        } else if handled_access_net != 0 {\n            2 * std::mem::size_of::<u64>()\n        } else {\n            std::mem::size_of::<u64>()\n        };\n",
    "Landlock ruleset scope",
)
replace_one(
    "src/platform/linux.rs",
    "            \"readlinkat\" => libc::SYS_readlinkat,\n            _ => return None,\n",
    "            \"readlinkat\" => libc::SYS_readlinkat,\n            \"pidfd_send_signal\" => libc::SYS_pidfd_send_signal,\n            _ => return None,\n",
    "pidfd_send_signal syscall mapping",
)

# Integration policy literal learns the new default-off field.
replace_one(
    "tests/sandbox.rs",
    "        landlock_tcp_bind_ports: Vec::new(),\n        landlock_tcp_connect_ports: Vec::new(),\n        loopback_enabled: false,\n",
    "        landlock_tcp_bind_ports: Vec::new(),\n        landlock_tcp_connect_ports: Vec::new(),\n        landlock_scope_signal: false,\n        loopback_enabled: false,\n",
    "integration policy field",
)

# Deterministic external helper used to prove positive signal authority and its attenuation.
replace_one(
    "tests/sandbox.rs",
    "}\n\n#[test]\nfn landlock_read_execute_envelope_denies_visible_undeclared_path() {\n",
    "}\n\nstruct PausedExternalHelper {\n    pid: libc::pid_t,\n}\n\nimpl PausedExternalHelper {\n    fn spawn() -> Self {\n        let mut ready = [-1; 2];\n        assert_eq!(\n            unsafe { libc::pipe2(ready.as_mut_ptr(), libc::O_CLOEXEC) },\n            0,\n            \"create external-helper readiness pipe\"\n        );\n        let ready_read = TestFd(ready[0]);\n        let ready_write = TestFd(ready[1]);\n        let pid = unsafe { libc::fork() };\n        assert!(pid >= 0, \"fork external helper: {}\", std::io::Error::last_os_error());\n        if pid == 0 {\n            unsafe {\n                libc::close(ready_read.raw());\n                let marker = b'R';\n                if libc::write(\n                    ready_write.raw(),\n                    (&marker as *const u8).cast::<libc::c_void>(),\n                    1,\n                ) != 1\n                {\n                    libc::_exit(91);\n                }\n                libc::close(ready_write.raw());\n                loop {\n                    libc::pause();\n                }\n            }\n        }\n        drop(ready_write);\n        let mut marker = [0u8; 1];\n        read_exact_fd(ready_read.raw(), &mut marker);\n        assert_eq!(marker, [b'R']);\n        drop(ready_read);\n        Self { pid }\n    }\n\n    fn pidfd(&self) -> TestFd {\n        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, self.pid, 0u32) };\n        assert!(fd >= 0, \"open external-helper pidfd: {}\", std::io::Error::last_os_error());\n        TestFd(fd as RawFd)\n    }\n\n    fn wait_for_signal(&mut self, signal: libc::c_int) {\n        let mut status = 0;\n        loop {\n            let waited = unsafe { libc::waitpid(self.pid, &mut status, 0) };\n            if waited == self.pid {\n                break;\n            }\n            assert_eq!(waited, -1, \"unexpected waitpid result {waited}\");\n            let error = std::io::Error::last_os_error();\n            if error.raw_os_error() == Some(libc::EINTR) {\n                continue;\n            }\n            panic!(\"wait for external helper failed: {error}\");\n        }\n        assert!(libc::WIFSIGNALED(status), \"helper status was 0x{status:x}\");\n        assert_eq!(libc::WTERMSIG(status), signal);\n        self.pid = -1;\n    }\n\n    fn assert_alive(&self) {\n        let mut status = 0;\n        let waited = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };\n        assert_eq!(waited, 0, \"external helper unexpectedly changed state: status=0x{status:x}\");\n    }\n}\n\nimpl Drop for PausedExternalHelper {\n    fn drop(&mut self) {\n        if self.pid <= 0 {\n            return;\n        }\n        unsafe {\n            libc::kill(self.pid, libc::SIGKILL);\n            loop {\n                let mut status = 0;\n                let waited = libc::waitpid(self.pid, &mut status, 0);\n                if waited == self.pid {\n                    break;\n                }\n                if waited == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {\n                    continue;\n                }\n                break;\n            }\n        }\n        self.pid = -1;\n    }\n}\n\n#[test]\nfn selected_pidfd_signal_authority_is_attenuated_by_landlock_scope() {\n    let mut unscoped_helper = PausedExternalHelper::spawn();\n    let unscoped_pidfd = unscoped_helper.pidfd();\n    let mut unscoped = policy(\n        \"t\",\n        &[],\n        &[\"execveat\", \"pidfd_send_signal\", \"exit\"],\n    );\n    unscoped\n        .selected_handles\n        .insert(9, unscoped_pidfd.raw() as u32);\n    assert_eq!(run(&unscoped).unwrap(), ChildOutcome::Exited(0));\n    unscoped_helper.wait_for_signal(libc::SIGUSR1);\n\n    let scoped_helper = PausedExternalHelper::spawn();\n    let scoped_pidfd = scoped_helper.pidfd();\n    let mut scoped = policy(\n        \"u\",\n        &[],\n        &[\"execveat\", \"pidfd_send_signal\", \"exit\"],\n    );\n    scoped.landlock_scope_signal = true;\n    scoped.selected_handles.insert(9, scoped_pidfd.raw() as u32);\n    assert_eq!(run(&scoped).unwrap(), ChildOutcome::Exited(0));\n    scoped_helper.assert_alive();\n}\n\n#[test]\nfn landlock_read_execute_envelope_denies_visible_undeclared_path() {\n",
    "selected pidfd signal integration",
)

# Raw target oracle: same selected pidfd, success without scope and exact EPERM with scope.
replace_one(
    "tests/fixtures/probe.S",
    "#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n",
    "#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports\n#   t send SIGUSR1 through selected pidfd 9; succeeds only without signal scope\n#   u send SIGUSR1 through selected pidfd 9; requires Landlock signal-scope EPERM\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n",
    "fixture mode comments",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $115, %al\n    je .landlock_tcp_ports\n    cmp $70, %al\n",
    "    cmp $115, %al\n    je .landlock_tcp_ports\n    cmp $116, %al\n    je .pidfd_signal_allowed\n    cmp $117, %al\n    je .pidfd_signal_denied\n    cmp $70, %al\n",
    "fixture dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    "    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n",
    "    xor %edi, %edi\n    jmp .exit\n\n.pidfd_signal_allowed:\n    mov $424, %eax\n    mov $9, %edi\n    mov $10, %esi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail41\n    xor %edi, %edi\n    jmp .exit\n\n.pidfd_signal_denied:\n    mov $424, %eax\n    mov $9, %edi\n    mov $10, %esi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    cmp $-1, %rax\n    jne .fail41\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n",
    "fixture pidfd modes",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail40:\n    mov $40, %edi\n\n.exit:\n",
    ".fail40:\n    mov $40, %edi\n    jmp .exit\n.fail41:\n    mov $41, %edi\n\n.exit:\n",
    "fixture failure code",
)
