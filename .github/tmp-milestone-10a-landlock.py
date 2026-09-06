from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# ---------------- policy ----------------
replace_one(
    "src/policy.rs",
    "const MAX_SELECTED_HANDLES: usize = 16;\n",
    "const MAX_SELECTED_HANDLES: usize = 16;\nconst MAX_LANDLOCK_READ_EXECUTE_PATHS: usize = 32;\n",
    "policy landlock limit",
)

replace_one(
    "src/policy.rs",
    "    /// Absolute path interpreted inside `root_dir`.\n    pub working_dir: PathBuf,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.\n",
    "    /// Absolute path interpreted inside `root_dir`.\n    pub working_dir: PathBuf,\n    /// Optional Landlock read/execute allowlist. When non-empty, only these\n    /// sandbox paths may be read or executed after trusted setup completes.\n    pub landlock_read_execute: Vec<PathBuf>,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.\n",
    "policy landlock field",
)

replace_one(
    "src/policy.rs",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        match (\n",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if self.landlock_read_execute.len() > MAX_LANDLOCK_READ_EXECUTE_PATHS {\n            return Err(PolicyError::new(format!(\n                \"too many landlock.read_execute paths: {} > {MAX_LANDLOCK_READ_EXECUTE_PATHS}\",\n                self.landlock_read_execute.len()\n            )));\n        }\n        if !self.landlock_read_execute.is_empty() {\n            let mut seen = BTreeSet::new();\n            let mut executable_covered = false;\n            for path in &self.landlock_read_execute {\n                validate_absolute_path(\"landlock.read_execute\", path)?;\n                if path == Path::new(\"/\") {\n                    return Err(PolicyError::new(\n                        \"landlock.read_execute must not grant the entire sandbox root\",\n                    ));\n                }\n                if !seen.insert(path.clone()) {\n                    return Err(PolicyError::new(format!(\n                        \"duplicate landlock.read_execute path: {}\",\n                        path.display()\n                    )));\n                }\n                if self.executable.starts_with(path) {\n                    executable_covered = true;\n                }\n            }\n            if !executable_covered {\n                return Err(PolicyError::new(\n                    \"landlock.read_execute must cover the initial executable\",\n                ));\n            }\n        }\n\n        match (\n",
    "policy landlock validation",
)

replace_one(
    "src/policy.rs",
    "        let mut working_dir = None;\n        let mut loopback_enabled = None;\n",
    "        let mut working_dir = None;\n        let mut landlock_read_execute = Vec::new();\n        let mut loopback_enabled = None;\n",
    "policy landlock parser storage",
)

replace_one(
    "src/policy.rs",
    "                \"working_dir\" => set_once(&mut working_dir, value.to_owned(), line_no, key)?,\n                \"stdio.stdin\" => set_once(\n",
    "                \"working_dir\" => set_once(&mut working_dir, value.to_owned(), line_no, key)?,\n                \"landlock.read_execute\" => landlock_read_execute.push(value.to_owned()),\n                \"stdio.stdin\" => set_once(\n",
    "policy landlock parser key",
)

replace_one(
    "src/policy.rs",
    "            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
    "            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            landlock_read_execute: landlock_read_execute\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            loopback_enabled: loopback_enabled.unwrap_or(false),\n",
    "policy landlock construction",
)

replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.host_loopback_tcp_target_fd, None);\n        assert_eq!(policy.readonly_volume_source, None);\n",
    "        assert_eq!(policy.host_loopback_tcp_target_fd, None);\n        assert!(policy.landlock_read_execute.is_empty());\n        assert_eq!(policy.readonly_volume_source, None);\n",
    "policy landlock default assertion",
)

replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_loopback_networking_mode() {\n",
    "    #[test]\n    fn parses_landlock_read_execute_paths() {\n        let text = format!(\n            \"{VALID}\\nlandlock.read_execute = /bin\\nlandlock.read_execute = /usr/share\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(\n            policy.landlock_read_execute,\n            [PathBuf::from(\"/bin\"), PathBuf::from(\"/usr/share\")]\n        );\n    }\n\n    #[test]\n    fn rejects_unsafe_landlock_read_execute_paths() {\n        let root = format!(\"{VALID}\\nlandlock.read_execute = /\");\n        assert!(root.parse::<SandboxPolicy>().is_err());\n\n        let relative = format!(\"{VALID}\\nlandlock.read_execute = bin\");\n        assert!(relative.parse::<SandboxPolicy>().is_err());\n\n        let duplicate = format!(\n            \"{VALID}\\nlandlock.read_execute = /bin\\nlandlock.read_execute = /bin\"\n        );\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n\n        let misses_executable = format!(\"{VALID}\\nlandlock.read_execute = /tmp\");\n        let error = misses_executable.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error.to_string().contains(\"cover the initial executable\"));\n    }\n\n    #[test]\n    fn parses_loopback_networking_mode() {\n",
    "policy landlock tests",
)

# ---------------- Linux backend ----------------
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_NETWORK_LOOPBACK: u32 = 47;\n\n    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;\n",
    "    const PHASE_NETWORK_LOOPBACK: u32 = 47;\n    const PHASE_LANDLOCK_RULESET: u32 = 48;\n    const PHASE_LANDLOCK_PATH: u32 = 49;\n    const PHASE_LANDLOCK_RULE: u32 = 50;\n    const PHASE_LANDLOCK_RESTRICT: u32 = 51;\n\n    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;\n    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;\n    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;\n    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;\n    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;\n    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;\n    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;\n    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_EXECUTE\n        | LANDLOCK_ACCESS_FS_READ_FILE\n        | LANDLOCK_ACCESS_FS_READ_DIR;\n\n    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;\n",
    "linux landlock constants",
)

replace_one(
    "src/platform/linux.rs",
    "    #[repr(C)]\n    struct MountAttr {\n        attr_set: u64,\n        attr_clr: u64,\n        propagation: u64,\n        userns_fd: u64,\n    }\n\n    #[repr(C, align(8))]\n",
    "    #[repr(C)]\n    struct MountAttr {\n        attr_set: u64,\n        attr_clr: u64,\n        propagation: u64,\n        userns_fd: u64,\n    }\n\n    #[repr(C)]\n    struct LandlockRulesetAttr {\n        handled_access_fs: u64,\n    }\n\n    #[repr(C)]\n    struct LandlockPathBeneathAttr {\n        allowed_access: u64,\n        parent_fd: i32,\n        reserved: u32,\n    }\n\n    #[repr(C, align(8))]\n",
    "linux landlock structs",
)

replace_one(
    "src/platform/linux.rs",
    "        executable_fd: OwnedFd,\n        selected_handles: Vec<PreparedSelectedHandle>,\n",
    "        executable_fd: OwnedFd,\n        selected_handles: Vec<PreparedSelectedHandle>,\n        selected_storage_floor: RawFd,\n        landlock_read_execute: Vec<CString>,\n",
    "linux prepared landlock fields",
)

replace_one(
    "src/platform/linux.rs",
    "            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n            // Keep every launcher-owned source above all target-visible handle\n",
    "            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n\n            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());\n            for path in &policy.landlock_read_execute {\n                let checked = open_beneath_root(\n                    root_fd.raw(),\n                    path,\n                    (libc::O_PATH | libc::O_CLOEXEC) as u64,\n                    \"Landlock read/execute path\",\n                )?;\n                let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };\n                if unsafe { libc::fstat(checked.raw(), &mut stat) } == -1 {\n                    return Err(SandboxError::SetupFailed(format!(\n                        \"cannot inspect Landlock read/execute path {}: {}\",\n                        path.display(),\n                        io::Error::last_os_error()\n                    )));\n                }\n                let kind = stat.st_mode & libc::S_IFMT;\n                if kind != libc::S_IFDIR && kind != libc::S_IFREG {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(\n                        \"landlock.read_execute path must name a regular file or directory: {}\",\n                        path.display()\n                    ))));\n                }\n                drop(checked);\n                landlock_read_execute.push(sandbox_relative(path)?);\n            }\n\n            // Keep every launcher-owned source above all target-visible handle\n",
    "linux landlock preparation",
)

replace_one(
    "src/platform/linux.rs",
    "                executable_fd,\n                selected_handles,\n                cancellation_fd,\n",
    "                executable_fd,\n                selected_handles,\n                selected_storage_floor,\n                landlock_read_execute,\n                cancellation_fd,\n",
    "linux landlock prepared init",
)

replace_one(
    "src/platform/linux.rs",
    "        ensure_fd_sanitization_supported()?;\n        ensure_supervision_support(policy.wall_clock_milliseconds, cancellation.is_some())?;\n",
    "        ensure_fd_sanitization_supported()?;\n        ensure_supervision_support(policy.wall_clock_milliseconds, cancellation.is_some())?;\n        ensure_landlock_supported(policy)?;\n",
    "linux landlock preflight call",
)

replace_one(
    "src/platform/linux.rs",
    "    unsafe fn child_exec(\n",
    "    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {\n        if policy.landlock_read_execute.is_empty() {\n            return Ok(());\n        }\n        let abi = unsafe {\n            libc::syscall(\n                SYS_LANDLOCK_CREATE_RULESET,\n                ptr::null::<libc::c_void>(),\n                0usize,\n                LANDLOCK_CREATE_RULESET_VERSION,\n            )\n        };\n        if abi >= 1 {\n            return Ok(());\n        }\n        let error = io::Error::last_os_error();\n        match error.raw_os_error() {\n            Some(libc::ENOSYS | libc::EOPNOTSUPP) => Err(SandboxError::UnsupportedPlatform(\n                format!(\"Landlock read/execute enforcement is unavailable: {error}\"),\n            )),\n            _ => Err(SandboxError::SetupFailed(format!(\n                \"cannot query Landlock ABI: {error}\"\n            ))),\n        }\n    }\n\n    unsafe fn prepare_landlock_ruleset_or_fail(\n        paths: &[CString],\n        root_tree_fd: RawFd,\n        storage_floor: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) -> RawFd {\n        if paths.is_empty() {\n            return -1;\n        }\n\n        let ruleset = LandlockRulesetAttr {\n            handled_access_fs: LANDLOCK_READ_EXECUTE_RIGHTS,\n        };\n        let raw_ruleset_fd = libc::syscall(\n            SYS_LANDLOCK_CREATE_RULESET,\n            &ruleset as *const LandlockRulesetAttr,\n            std::mem::size_of::<LandlockRulesetAttr>(),\n            0u32,\n        );\n        if raw_ruleset_fd == -1 {\n            child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n        }\n        let mut ruleset_fd = raw_ruleset_fd as RawFd;\n        if ruleset_fd < storage_floor {\n            let moved = libc::fcntl(ruleset_fd, libc::F_DUPFD_CLOEXEC, storage_floor);\n            if moved == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n            }\n            if libc::close(ruleset_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n            }\n            ruleset_fd = moved;\n        }\n\n        let path_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        for path in paths {\n            let path_fd = libc::syscall(\n                libc::SYS_openat2,\n                root_tree_fd,\n                path.as_ptr(),\n                &path_how as *const OpenHow,\n                std::mem::size_of::<OpenHow>(),\n            );\n            if path_fd == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let path_fd = path_fd as RawFd;\n            let mut stat = std::mem::zeroed::<libc::stat>();\n            if libc::fstat(path_fd, &mut stat) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let kind = stat.st_mode & libc::S_IFMT;\n            let allowed_access = if kind == libc::S_IFDIR {\n                LANDLOCK_READ_EXECUTE_RIGHTS\n            } else if kind == libc::S_IFREG {\n                LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE\n            } else {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall)\n            };\n            let rule = LandlockPathBeneathAttr {\n                allowed_access,\n                parent_fd: path_fd,\n                reserved: 0,\n            };\n            if libc::syscall(\n                SYS_LANDLOCK_ADD_RULE,\n                ruleset_fd,\n                LANDLOCK_RULE_PATH_BENEATH,\n                &rule as *const LandlockPathBeneathAttr,\n                0u32,\n            ) == -1\n            {\n                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);\n            }\n            if libc::close(path_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n        }\n        ruleset_fd\n    }\n\n    unsafe fn restrict_landlock_or_fail(\n        ruleset_fd: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        if ruleset_fd < 0 {\n            return;\n        }\n        if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) == -1 {\n            child_fail(launch_error, PHASE_LANDLOCK_RESTRICT, error_exit_syscall);\n        }\n        if libc::close(ruleset_fd) == -1 {\n            child_fail(launch_error, PHASE_LANDLOCK_RESTRICT, error_exit_syscall);\n        }\n    }\n\n    unsafe fn child_exec(\n",
    "linux landlock helpers",
)

replace_one(
    "src/platform/linux.rs",
    "        apply_stdio_policy_or_fail(\n            stdio,\n",
    "        let landlock_ruleset_fd = prepare_landlock_ruleset_or_fail(\n            &prepared.landlock_read_execute,\n            root_tree_fd,\n            prepared.selected_storage_floor,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        apply_stdio_policy_or_fail(\n            stdio,\n",
    "linux landlock target preparation",
)

replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {\n            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);\n        }\n\n        let program = libc::sock_fprog {\n",
    "        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {\n            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);\n        }\n        restrict_landlock_or_fail(\n            landlock_ruleset_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        let program = libc::sock_fprog {\n",
    "linux landlock restriction ordering",
)

replace_one(
    "src/platform/linux.rs",
    "            PHASE_VOLUME_ATTACH => \"persistent volume mount attachment\",\n            PHASE_NETWORK_LOOPBACK => \"policy-owned loopback activation\",\n            _ => \"unknown launch phase\",\n",
    "            PHASE_VOLUME_ATTACH => \"persistent volume mount attachment\",\n            PHASE_NETWORK_LOOPBACK => \"policy-owned loopback activation\",\n            PHASE_LANDLOCK_RULESET => \"Landlock ruleset creation\",\n            PHASE_LANDLOCK_PATH => \"Landlock path pin\",\n            PHASE_LANDLOCK_RULE => \"Landlock path-beneath rule installation\",\n            PHASE_LANDLOCK_RESTRICT => \"Landlock self restriction\",\n            _ => \"unknown launch phase\",\n",
    "linux landlock phase labels",
)

# ---------------- raw fixture ----------------
replace_one(
    "tests/fixtures/probe.S",
    "#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n",
    "#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated\n#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n",
    "fixture landlock mode doc",
)

replace_one(
    "tests/fixtures/probe.S",
    "    cmp $112, %al\n    je .brokered_host_loopback\n    cmp $70, %al\n",
    "    cmp $112, %al\n    je .brokered_host_loopback\n    cmp $114, %al\n    je .landlock_read_envelope\n    cmp $70, %al\n",
    "fixture landlock dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    ".forbidden:\n    mov $39, %eax\n",
    ".landlock_read_envelope:\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_allowed_path(%rip), %rsi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail37\n    mov %rax, %r12\n\n    xor %eax, %eax\n    mov %r12, %rdi\n    lea landlock_buffer(%rip), %rsi\n    mov $landlock_allowed_message_len, %edx\n    syscall\n    cmp $landlock_allowed_message_len, %rax\n    jne .fail37\n\n    lea landlock_buffer(%rip), %rdi\n    lea landlock_allowed_message(%rip), %rsi\n    mov $landlock_allowed_message_len, %ecx\n    repe cmpsb\n    jne .fail37\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail37\n\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_denied_path(%rip), %rsi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    cmp $-13, %rax\n    jne .fail37\n\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n    mov $39, %eax\n",
    "fixture landlock behavior",
)

replace_one(
    "tests/fixtures/probe.S",
    ".fail36:\n    mov $36, %edi\n\n.exit:\n",
    ".fail36:\n    mov $36, %edi\n    jmp .exit\n.fail37:\n    mov $37, %edi\n\n.exit:\n",
    "fixture landlock failure",
)

replace_one(
    "tests/fixtures/probe.S",
    "brokered_host_message:\n    .ascii \"brokered-host-loopback-ok\"\n.set brokered_host_message_len, . - brokered_host_message\ndeadline_message:\n",
    "brokered_host_message:\n    .ascii \"brokered-host-loopback-ok\"\n.set brokered_host_message_len, . - brokered_host_message\nlandlock_allowed_path:\n    .asciz \"/landlock-allowed/marker\"\nlandlock_denied_path:\n    .asciz \"/landlock-denied/secret\"\nlandlock_allowed_message:\n    .ascii \"landlock-allowed\\n\"\n.set landlock_allowed_message_len, . - landlock_allowed_message\ndeadline_message:\n",
    "fixture landlock rodata",
)

replace_one(
    "tests/fixtures/probe.S",
    "network_buffer:\n    .skip 32\n\n.section .note.GNU-stack",
    "network_buffer:\n    .skip 32\nlandlock_buffer:\n    .skip 32\n\n.section .note.GNU-stack",
    "fixture landlock buffer",
)

# ---------------- integration test ----------------
replace_one(
    "tests/sandbox.rs",
    "        std::fs::create_dir_all(root.join(\"persist\"))\n            .expect(\"create sandbox writable-volume mountpoint\");\n\n        let output = root.join(\"probe\");\n",
    "        std::fs::create_dir_all(root.join(\"persist\"))\n            .expect(\"create sandbox writable-volume mountpoint\");\n        std::fs::create_dir_all(root.join(\"landlock-allowed\"))\n            .expect(\"create Landlock allowed directory\");\n        std::fs::create_dir_all(root.join(\"landlock-denied\"))\n            .expect(\"create Landlock denied directory\");\n        std::fs::write(root.join(\"landlock-allowed/marker\"), b\"landlock-allowed\\n\")\n            .expect(\"write Landlock allowed marker\");\n        std::fs::write(root.join(\"landlock-denied/secret\"), b\"landlock-secret\\n\")\n            .expect(\"write Landlock denied secret\");\n\n        let output = root.join(\"probe\");\n",
    "integration Landlock fixtures",
)

replace_one(
    "tests/sandbox.rs",
    "        working_dir: PathBuf::from(\"/work\"),\n        loopback_enabled: false,\n",
    "        working_dir: PathBuf::from(\"/work\"),\n        landlock_read_execute: Vec::new(),\n        loopback_enabled: false,\n",
    "integration policy Landlock default",
)

replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {\n",
    "#[test]\nfn landlock_read_execute_envelope_denies_visible_undeclared_path() {\n    let mut confined = policy(\n        \"r\",\n        &[],\n        &[\"execveat\", \"openat\", \"read\", \"close\", \"exit\"],\n    );\n    confined.landlock_read_execute = vec![\n        PathBuf::from(\"/probe\"),\n        PathBuf::from(\"/landlock-allowed\"),\n    ];\n\n    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {\n",
    "integration Landlock test",
)
