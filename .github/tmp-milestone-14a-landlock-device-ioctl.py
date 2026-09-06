from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface: bounded repeatable final-sandbox device paths.
replace_one(
    "src/policy.rs",
    "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_TCP_PORTS: usize = 32;",
    "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_DEVICE_IOCTL_PATHS: usize = 32;\nconst MAX_LANDLOCK_TCP_PORTS: usize = 32;",
    "device ioctl limit",
)
replace_one(
    "src/policy.rs",
    "    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Optional Landlock TCP port envelopes for target-created sockets. These",
    "    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Optional Landlock device-ioctl allowlist. Each entry names a character\n    /// or block device in the final mounted sandbox tree. When non-empty,\n    /// ioctl on newly opened devices is denied unless covered by one entry.\n    pub landlock_device_ioctl: Vec<PathBuf>,\n    /// Optional Landlock TCP port envelopes for target-created sockets. These",
    "device ioctl policy field",
)
replace_one(
    "src/policy.rs",
    "        validate_landlock_tcp_ports(\"landlock.tcp_bind_port\", &self.landlock_tcp_bind_ports)?;",
    "        if self.landlock_device_ioctl.len() > MAX_LANDLOCK_DEVICE_IOCTL_PATHS {\n            return Err(PolicyError::new(format!(\n                \"too many landlock.device_ioctl paths: {} > {MAX_LANDLOCK_DEVICE_IOCTL_PATHS}\",\n                self.landlock_device_ioctl.len()\n            )));\n        }\n        if !self.landlock_device_ioctl.is_empty() {\n            let mut seen = BTreeSet::new();\n            for path in &self.landlock_device_ioctl {\n                validate_absolute_path(\"landlock.device_ioctl\", path)?;\n                if path == Path::new(\"/\") {\n                    return Err(PolicyError::new(\n                        \"landlock.device_ioctl must not grant the entire sandbox root\",\n                    ));\n                }\n                if !seen.insert(path.clone()) {\n                    return Err(PolicyError::new(format!(\n                        \"duplicate landlock.device_ioctl path: {}\",\n                        path.display()\n                    )));\n                }\n            }\n        }\n\n        validate_landlock_tcp_ports(\"landlock.tcp_bind_port\", &self.landlock_tcp_bind_ports)?;",
    "device ioctl validation",
)
replace_one(
    "src/policy.rs",
    "        let mut landlock_file_mutate = Vec::new();\n        let mut landlock_tcp_bind_ports = Vec::new();",
    "        let mut landlock_file_mutate = Vec::new();\n        let mut landlock_device_ioctl = Vec::new();\n        let mut landlock_tcp_bind_ports = Vec::new();",
    "device ioctl parser state",
)
replace_one(
    "src/policy.rs",
    "                \"landlock.file_mutate\" => landlock_file_mutate.push(value.to_owned()),\n                \"stdio.stdin\" => set_once(",
    "                \"landlock.file_mutate\" => landlock_file_mutate.push(value.to_owned()),\n                \"landlock.device_ioctl\" => landlock_device_ioctl.push(value.to_owned()),\n                \"stdio.stdin\" => set_once(",
    "device ioctl parser key",
)
replace_one(
    "src/policy.rs",
    "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_tcp_bind_ports,",
    "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_device_ioctl: landlock_device_ioctl\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_tcp_bind_ports,",
    "device ioctl policy construction",
)
replace_one(
    "src/policy.rs",
    "        assert!(policy.landlock_file_mutate.is_empty());\n        assert!(policy.landlock_tcp_bind_ports.is_empty());",
    "        assert!(policy.landlock_file_mutate.is_empty());\n        assert!(policy.landlock_device_ioctl.is_empty());\n        assert!(policy.landlock_tcp_bind_ports.is_empty());",
    "device ioctl default test",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_landlock_abstract_unix_scope_mode() {",
    "    #[test]\n    fn parses_and_rejects_landlock_device_ioctl_paths() {\n        let allowed: SandboxPolicy = format!(\n            \"{VALID}\\nlandlock.device_ioctl = /devices/urandom\\nlandlock.device_ioctl = /devices/random\"\n        )\n        .parse()\n        .unwrap();\n        assert_eq!(\n            allowed.landlock_device_ioctl,\n            [PathBuf::from(\"/devices/urandom\"), PathBuf::from(\"/devices/random\")]\n        );\n\n        for invalid in [\n            format!(\"{VALID}\\nlandlock.device_ioctl = /\"),\n            format!(\"{VALID}\\nlandlock.device_ioctl = devices/urandom\"),\n            format!(\"{VALID}\\nlandlock.device_ioctl = /devices/urandom\\nlandlock.device_ioctl = /devices/urandom\"),\n        ] {\n            assert!(invalid.parse::<SandboxPolicy>().is_err());\n        }\n\n        let mut oversized = VALID.to_owned();\n        for index in 0..=MAX_LANDLOCK_DEVICE_IOCTL_PATHS {\n            oversized.push_str(&format!(\"\\nlandlock.device_ioctl = /devices/device-{index}\"));\n        }\n        assert!(oversized.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_landlock_abstract_unix_scope_mode() {",
    "device ioctl parser tests",
)

# Linux enforcement: ABI-5 handled right and final-tree path rules.
replace_one(
    "src/platform/linux.rs",
    "    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;\n    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 =",
    "    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;\n    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;\n    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 =",
    "ioctl right constant",
)
replace_one(
    "src/platform/linux.rs",
    "        file_mutate: Vec<CString>,\n        tcp_bind_ports: Vec<u16>,",
    "        file_mutate: Vec<CString>,\n        device_ioctl: Vec<CString>,\n        tcp_bind_ports: Vec<u16>,",
    "prepared device ioctl field",
)
replace_one(
    "src/platform/linux.rs",
    "            let mut landlock_file_mutate = Vec::with_capacity(policy.landlock_file_mutate.len());\n            for path in &policy.landlock_file_mutate {\n                landlock_file_mutate.push(sandbox_relative(path)?);\n            }\n\n            // Keep every launcher-owned source above all target-visible handle",
    "            let mut landlock_file_mutate = Vec::with_capacity(policy.landlock_file_mutate.len());\n            for path in &policy.landlock_file_mutate {\n                landlock_file_mutate.push(sandbox_relative(path)?);\n            }\n            // Device paths may be supplied by a persistent volume, so the final\n            // mounted object is pinned and type-checked by the direct target.\n            let mut landlock_device_ioctl =\n                Vec::with_capacity(policy.landlock_device_ioctl.len());\n            for path in &policy.landlock_device_ioctl {\n                landlock_device_ioctl.push(sandbox_relative(path)?);\n            }\n\n            // Keep every launcher-owned source above all target-visible handle",
    "prepare device ioctl paths",
)
replace_one(
    "src/platform/linux.rs",
    "                    read_execute: landlock_read_execute,\n                    file_mutate: landlock_file_mutate,\n                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),",
    "                    read_execute: landlock_read_execute,\n                    file_mutate: landlock_file_mutate,\n                    device_ioctl: landlock_device_ioctl,\n                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),",
    "prepared device ioctl initialization",
)
replace_one(
    "src/platform/linux.rs",
    "            && policy.landlock_file_mutate.is_empty()\n            && policy.landlock_tcp_bind_ports.is_empty()",
    "            && policy.landlock_file_mutate.is_empty()\n            && policy.landlock_device_ioctl.is_empty()\n            && policy.landlock_tcp_bind_ports.is_empty()",
    "Landlock preflight empty policy",
)
replace_one(
    "src/platform/linux.rs",
    "            if (!policy.landlock_tcp_bind_ports.is_empty()\n                || !policy.landlock_tcp_connect_ports.is_empty())\n                && abi < 4",
    "            if !policy.landlock_device_ioctl.is_empty() && abi < 5 {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    \"Landlock device ioctl enforcement requires ABI 5; kernel reports ABI {abi}\"\n                )));\n            }\n            if (!policy.landlock_tcp_bind_ports.is_empty()\n                || !policy.landlock_tcp_connect_ports.is_empty())\n                && abi < 4",
    "Landlock ABI5 preflight",
)
replace_one(
    "src/platform/linux.rs",
    "            && landlock.file_mutate.is_empty()\n            && landlock.tcp_bind_ports.is_empty()",
    "            && landlock.file_mutate.is_empty()\n            && landlock.device_ioctl.is_empty()\n            && landlock.tcp_bind_ports.is_empty()",
    "Landlock ruleset empty policy",
)
replace_one(
    "src/platform/linux.rs",
    "        if !landlock.file_mutate.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        let mut handled_access_net = 0;",
    "        if !landlock.file_mutate.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        if !landlock.device_ioctl.is_empty() {\n            handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;\n        }\n        let mut handled_access_net = 0;",
    "Landlock handled ioctl right",
)
replace_one(
    "src/platform/linux.rs",
    "        for &port in &landlock.tcp_bind_ports {",
    "        let device_path_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        for path in &landlock.device_ioctl {\n            let path_fd = libc::syscall(\n                libc::SYS_openat2,\n                root_tree_fd,\n                path.as_ptr(),\n                &device_path_how as *const OpenHow,\n                std::mem::size_of::<OpenHow>(),\n            );\n            if path_fd == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let path_fd = path_fd as RawFd;\n            let mut stat = std::mem::zeroed::<libc::stat>();\n            if libc::fstat(path_fd, &mut stat) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let kind = stat.st_mode & libc::S_IFMT;\n            if kind != libc::S_IFCHR && kind != libc::S_IFBLK {\n                child_fail_errno(\n                    launch_error,\n                    PHASE_LANDLOCK_PATH,\n                    libc::ENODEV,\n                    error_exit_syscall,\n                );\n            }\n            let rule = LandlockPathBeneathAttr {\n                allowed_access: LANDLOCK_ACCESS_FS_IOCTL_DEV,\n                parent_fd: path_fd,\n                reserved: 0,\n            };\n            if libc::syscall(\n                SYS_LANDLOCK_ADD_RULE,\n                ruleset_fd,\n                LANDLOCK_RULE_PATH_BENEATH,\n                &rule as *const LandlockPathBeneathAttr,\n                0u32,\n            ) == -1\n            {\n                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);\n            }\n            if libc::close(path_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n        }\n        for &port in &landlock.tcp_bind_ports {",
    "Landlock device ioctl rules",
)

# Raw device oracle. RNDGETENTCNT is a real unprivileged ioctl on random devices.
replace_one(
    "tests/fixtures/probe.S",
    "#   a connect selected fd 9 to argv[2] in the abstract UNIX socket namespace\n#   t permission-check namespace PID1",
    "#   a connect selected fd 9 to argv[2] in the abstract UNIX socket namespace\n#   d prove Landlock device ioctl allows /devices/urandom and denies /devices/random\n#   t permission-check namespace PID1",
    "probe device mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $97, %al\n    je .abstract_unix_connect\n    cmp $116, %al",
    "    cmp $97, %al\n    je .abstract_unix_connect\n    cmp $100, %al\n    je .landlock_device_ioctl\n    cmp $116, %al",
    "probe device mode dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".pidfd_signal_allowed:\n",
    ".landlock_device_ioctl:\n    # The allowed device must be opened after Landlock restriction and its\n    # RNDGETENTCNT ioctl must really succeed.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_ioctl_allowed(%rip), %rsi\n    mov $524288, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail44\n    mov %rax, %r12\n\n    mov $16, %eax\n    mov %r12, %rdi\n    mov $0x80045200, %esi\n    lea landlock_ioctl_entropy(%rip), %rdx\n    syscall\n    test %rax, %rax\n    js .fail44\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail44\n\n    # The sibling random device is equally visible/openable but has no\n    # IOCTL_DEV rule, so the same ioctl must be denied by Landlock with EACCES.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_ioctl_denied(%rip), %rsi\n    mov $524288, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail44\n    mov %rax, %r12\n\n    mov $16, %eax\n    mov %r12, %rdi\n    mov $0x80045200, %esi\n    lea landlock_ioctl_entropy(%rip), %rdx\n    syscall\n    cmp $-13, %rax\n    jne .fail44\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail44\n    xor %edi, %edi\n    jmp .exit\n\n.pidfd_signal_allowed:\n",
    "probe device ioctl implementation",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail42:\n    mov $42, %edi\n\n.exit:",
    ".fail42:\n    mov $42, %edi\n    jmp .exit\n.fail44:\n    mov $44, %edi\n\n.exit:",
    "probe device failure code",
)
replace_one(
    "tests/fixtures/probe.S",
    "landlock_allowed_path:\n    .asciz \"/landlock-allowed/marker\"",
    "landlock_ioctl_allowed:\n    .asciz \"/devices/urandom\"\nlandlock_ioctl_denied:\n    .asciz \"/devices/random\"\nlandlock_allowed_path:\n    .asciz \"/landlock-allowed/marker\"",
    "probe device paths",
)
replace_one(
    "tests/fixtures/probe.S",
    ".section .bss\n",
    ".section .bss\nlandlock_ioctl_entropy:\n    .zero 4\n",
    "probe device ioctl storage",
)

# Integration test: use existing read-only volume machinery to expose /dev only
# at /devices, then open both device files after Landlock is active.
replace_one(
    "tests/sandbox.rs",
    "        std::fs::create_dir_all(root.join(\"persist\"))\n            .expect(\"create sandbox writable-volume mountpoint\");",
    "        std::fs::create_dir_all(root.join(\"persist\"))\n            .expect(\"create sandbox writable-volume mountpoint\");\n        std::fs::create_dir_all(root.join(\"devices\"))\n            .expect(\"create sandbox device-volume mountpoint\");",
    "device mountpoint fixture",
)
replace_one(
    "tests/sandbox.rs",
    "        landlock_file_mutate: Vec::new(),\n        landlock_tcp_bind_ports: Vec::new(),",
    "        landlock_file_mutate: Vec::new(),\n        landlock_device_ioctl: Vec::new(),\n        landlock_tcp_bind_ports: Vec::new(),",
    "integration policy device field",
)
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {",
    "fn assert_random_device_ioctl_available(path: &str) {\n    const RNDGETENTCNT: libc::c_ulong = 0x80045200;\n    let device = std::fs::File::open(path).expect(\"open host random device\");\n    let mut entropy_bits: libc::c_int = 0;\n    assert_eq!(\n        unsafe { libc::ioctl(device.as_raw_fd(), RNDGETENTCNT, &mut entropy_bits) },\n        0,\n        \"host random-device ioctl baseline failed for {path}: {}\",\n        std::io::Error::last_os_error()\n    );\n}\n\n#[test]\nfn landlock_device_ioctl_envelope_binds_rights_at_post_restriction_open() {\n    assert_random_device_ioctl_available(\"/dev/urandom\");\n    assert_random_device_ioctl_available(\"/dev/random\");\n\n    let mut confined = policy(\n        \"d\",\n        &[],\n        &[\"execveat\", \"openat\", \"ioctl\", \"close\", \"exit\"],\n    );\n    confined.readonly_volume_source = Some(PathBuf::from(\"/dev\"));\n    confined.readonly_volume_target = Some(PathBuf::from(\"/devices\"));\n    confined.landlock_device_ioctl = vec![PathBuf::from(\"/devices/urandom\")];\n\n    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn landlock_abstract_unix_scope_attenuates_selected_socket_connect_authority() {",
    "integration device ioctl evidence",
)
