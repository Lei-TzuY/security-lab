from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy surface and validation.
replace_one(
    "src/policy.rs",
    "const MAX_ENV_VALUE_BYTES: usize = 8192;\n",
    "const MAX_ENV_VALUE_BYTES: usize = 8192;\nconst MAX_HOSTNAME_BYTES: usize = 63;\n",
    "hostname bound",
)
replace_one(
    "src/policy.rs",
    "    /// Host path pinned as the sandbox filesystem root before fork.\n    pub root_dir: PathBuf,\n",
    "    /// Host path pinned as the sandbox filesystem root before fork.\n    pub root_dir: PathBuf,\n    /// Launcher-owned hostname installed inside the sandbox UTS namespace.\n    pub hostname: String,\n",
    "policy hostname field",
)
replace_one(
    "src/policy.rs",
    "        validate_absolute_path(\"filesystem.root\", &self.root_dir)?;\n",
    "        validate_absolute_path(\"filesystem.root\", &self.root_dir)?;\n        validate_hostname(&self.hostname)?;\n",
    "hostname validation call",
)
replace_one(
    "src/policy.rs",
    "        let mut root_dir = None;\n        let mut executable = None;\n",
    "        let mut root_dir = None;\n        let mut hostname = None;\n        let mut executable = None;\n",
    "hostname parser state",
)
replace_one(
    "src/policy.rs",
    "                \"filesystem.root\" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,\n",
    "                \"filesystem.root\" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,\n                \"identity.hostname\" => {\n                    set_once(&mut hostname, value.to_owned(), line_no, key)?\n                }\n",
    "hostname parser key",
)
replace_one(
    "src/policy.rs",
    "            root_dir: PathBuf::from(required(root_dir, \"filesystem.root\")?),\n            executable: PathBuf::from(required(executable, \"executable\")?),\n",
    "            root_dir: PathBuf::from(required(root_dir, \"filesystem.root\")?),\n            hostname: required(hostname, \"identity.hostname\")?,\n            executable: PathBuf::from(required(executable, \"executable\")?),\n",
    "hostname policy construction",
)
replace_one(
    "src/policy.rs",
    "fn valid_env_key(key: &str) -> bool {\n",
    "fn validate_hostname(hostname: &str) -> Result<(), PolicyError> {\n    let bytes = hostname.as_bytes();\n    if bytes.is_empty() || bytes.len() > MAX_HOSTNAME_BYTES {\n        return Err(PolicyError::new(format!(\n            \"identity.hostname must contain between 1 and {MAX_HOSTNAME_BYTES} bytes\"\n        )));\n    }\n    if !bytes\n        .iter()\n        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'.')\n    {\n        return Err(PolicyError::new(\n            \"identity.hostname may contain only ASCII letters, digits, '-' and '.'\",\n        ));\n    }\n    if matches!(bytes.first(), Some(b'-' | b'.'))\n        || matches!(bytes.last(), Some(b'-' | b'.'))\n    {\n        return Err(PolicyError::new(\n            \"identity.hostname must start and end with an ASCII letter or digit\",\n        ));\n    }\n    Ok(())\n}\n\nfn valid_env_key(key: &str) -> bool {\n",
    "hostname validator",
)
replace_one(
    "src/policy.rs",
    "        filesystem.root = /\n        filesystem.scratch = /scratch\n",
    "        filesystem.root = /\n        identity.hostname = security-lab\n        filesystem.scratch = /scratch\n",
    "valid policy hostname",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.root_dir, PathBuf::from(\"/\"));\n",
    "        assert_eq!(policy.root_dir, PathBuf::from(\"/\"));\n        assert_eq!(policy.hostname, \"security-lab\");\n",
    "hostname parse assertion",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn rejects_missing_stdio_disposition() {\n",
    "    #[test]\n    fn rejects_missing_hostname() {\n        let text = VALID.replace(\"identity.hostname = security-lab\\n\", \"\");\n        let err = text.parse::<SandboxPolicy>().unwrap_err();\n        assert!(err.to_string().contains(\"identity.hostname\"));\n    }\n\n    #[test]\n    fn rejects_invalid_hostname() {\n        for hostname in [\"-bad\", \"bad_underscore\", \"bad.\", \"\"] {\n            let text = VALID.replace(\n                \"identity.hostname = security-lab\",\n                &format!(\"identity.hostname = {hostname}\"),\n            );\n            assert!(text.parse::<SandboxPolicy>().is_err(), \"accepted {hostname:?}\");\n        }\n        let oversized = \"a\".repeat(MAX_HOSTNAME_BYTES + 1);\n        let text = VALID.replace(\n            \"identity.hostname = security-lab\",\n            &format!(\"identity.hostname = {oversized}\"),\n        );\n        assert!(text.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn rejects_duplicate_hostname() {\n        let text = format!(\"{VALID}\\nidentity.hostname = duplicate\");\n        assert!(text.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn rejects_missing_stdio_disposition() {\n",
    "hostname policy regressions",
)

# Linux UTS namespace and trusted hostname setup.
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_DEADLINE_POLL: u32 = 37;\n",
    "    const PHASE_DEADLINE_POLL: u32 = 37;\n    const PHASE_HOSTNAME: u32 = 38;\n",
    "hostname phase",
)
replace_one(
    "src/platform/linux.rs",
    "        gid_map: Vec<u8>,\n    }\n",
    "        gid_map: Vec<u8>,\n        hostname: Vec<u8>,\n    }\n",
    "prepared hostname field",
)
replace_one(
    "src/platform/linux.rs",
    "            let gid_map = format!(\"0 {} 1\\n\", unsafe { libc::getegid() }).into_bytes();\n\n            Ok(Self {\n",
    "            let gid_map = format!(\"0 {} 1\\n\", unsafe { libc::getegid() }).into_bytes();\n            let hostname = policy.hostname.as_bytes().to_vec();\n\n            Ok(Self {\n",
    "prepared hostname bytes",
)
replace_one(
    "src/platform/linux.rs",
    "                uid_map,\n                gid_map,\n            })\n",
    "                uid_map,\n                gid_map,\n                hostname,\n            })\n",
    "prepared hostname construction",
)
replace_one(
    "src/platform/linux.rs",
    "                | libc::CLONE_NEWNET\n                | libc::CLONE_NEWIPC,\n",
    "                | libc::CLONE_NEWNET\n                | libc::CLONE_NEWIPC\n                | libc::CLONE_NEWUTS,\n",
    "UTS namespace unshare",
)
replace_one(
    "src/platform/linux.rs",
    "        write_proc_file_or_fail(\n            b\"/proc/self/gid_map\\0\",\n            &prepared.gid_map,\n            launch_error,\n            PHASE_GID_MAP,\n            seccomp.error_exit_syscall,\n        );\n\n        if libc::syscall(\n            libc::SYS_mount,\n",
    "        write_proc_file_or_fail(\n            b\"/proc/self/gid_map\\0\",\n            &prepared.gid_map,\n            launch_error,\n            PHASE_GID_MAP,\n            seccomp.error_exit_syscall,\n        );\n\n        if libc::syscall(\n            libc::SYS_sethostname,\n            prepared.hostname.as_ptr(),\n            prepared.hostname.len(),\n        ) == -1\n        {\n            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);\n        }\n\n        if libc::syscall(\n            libc::SYS_mount,\n",
    "trusted sethostname",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_NAMESPACE => \"user/mount/PID/network/IPC namespace creation\",\n",
    "            PHASE_NAMESPACE => \"user/mount/PID/network/IPC/UTS namespace creation\",\n",
    "namespace error UTS",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_DEADLINE_POLL => \"wall-clock deadline supervision poll\",\n",
    "            PHASE_DEADLINE_POLL => \"wall-clock deadline supervision poll\",\n            PHASE_HOSTNAME => \"UTS hostname installation\",\n",
    "hostname error phase label",
)

# Raw uname evidence.
replace_one(
    "tests/fixtures/probe.S",
    "#   L assert host SysV message queue key is invisible in the target IPC namespace\n",
    "#   L assert host SysV message queue key is invisible in the target IPC namespace\n#   J assert target UTS nodename matches argv[2]\n",
    "UTS fixture mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $76, %al\n    je .ipc_isolation\n    jmp .fail2\n",
    "    cmp $76, %al\n    je .ipc_isolation\n    cmp $74, %al\n    je .uts_identity\n    jmp .fail2\n",
    "UTS fixture dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    "    xor %edi, %edi\n    jmp .exit\n\n.str_eq:\n",
    "    xor %edi, %edi\n    jmp .exit\n\n.uts_identity:\n    mov 24(%rsp), %rsi\n    test %rsi, %rsi\n    je .fail2\n    mov $63, %eax\n    lea uts_buffer(%rip), %rdi\n    syscall\n    test %rax, %rax\n    js .fail28\n    lea uts_buffer+65(%rip), %rdi\n    call .str_eq\n    test %eax, %eax\n    je .fail28\n    xor %edi, %edi\n    jmp .exit\n\n.str_eq:\n",
    "UTS raw fixture",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail27:\n    mov $27, %edi\n\n.exit:\n",
    ".fail27:\n    mov $27, %edi\n    jmp .exit\n.fail28:\n    mov $28, %edi\n\n.exit:\n",
    "UTS fixture failure label",
)
replace_one(
    "tests/fixtures/probe.S",
    "redirect_buffer:\n    .skip 1\n",
    "redirect_buffer:\n    .skip 1\n.balign 16\nuts_buffer:\n    .skip 512\n",
    "UTS fixture buffer",
)

# Integration policy and host-unchanged UTS evidence.
replace_one(
    "tests/sandbox.rs",
    "        root_dir: fixture_root().to_path_buf(),\n        executable: PathBuf::from(\"/probe\"),\n",
    "        root_dir: fixture_root().to_path_buf(),\n        hostname: \"security-lab\".to_owned(),\n        executable: PathBuf::from(\"/probe\"),\n",
    "integration hostname default",
)
ipc_test_end = '''    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn allowed_operation_succeeds() {\n'''
uts_test = '''    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn uts_namespace_uses_policy_hostname_without_changing_host() {\n    let host_before = std::fs::read_to_string("/proc/sys/kernel/hostname")\n        .expect("read host hostname before sandbox");\n    let sandbox_hostname = format!("security-lab-{}", process::id());\n    let mut identity = policy(\n        "J",\n        &[sandbox_hostname.as_str()],\n        &["execveat", "uname", "exit"],\n    );\n    identity.hostname = sandbox_hostname;\n\n    let result = run(&identity);\n    let host_after = std::fs::read_to_string("/proc/sys/kernel/hostname")\n        .expect("read host hostname after sandbox");\n    assert_eq!(host_after, host_before, "sandbox UTS hostname changed host hostname");\n    assert_eq!(result.unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn allowed_operation_succeeds() {\n'''
replace_one(
    "tests/sandbox.rs",
    ipc_test_end,
    uts_test,
    "UTS integration test",
)
replace_one(
    "tests/sandbox.rs",
    "        filesystem.root = /\n        executable = /bin/true\n",
    "        filesystem.root = /\n        identity.hostname = malformed-policy\n        executable = /bin/true\n",
    "malformed policy hostname",
)

# Example policy must remain parseable now that hostname is required.
replace_one(
    "examples/policies/echo.conf",
    "filesystem.root = /\nfilesystem.scratch = /tmp\n",
    "filesystem.root = /\nidentity.hostname = security-lab\nfilesystem.scratch = /tmp\n",
    "example hostname",
)
