from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def replace_section(path: str, start: str, end: str, replacement: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    start_index = text.find(start)
    if start_index < 0:
        raise SystemExit(f"{label}: start marker missing")
    if text.find(start, start_index + 1) >= 0:
        raise SystemExit(f"{label}: start marker is not unique")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{label}: end marker missing")
    p.write_text(text[:start_index] + replacement + text[end_index:])


# TESTS / EXECUTABLE ORACLE FIRST.
replace_one(
    "tests/sandbox.rs",
    "        landlock_read_execute: Vec::new(),\n        loopback_enabled: false,",
    "        landlock_read_execute: Vec::new(),\n        landlock_file_mutate: Vec::new(),\n        loopback_enabled: false,",
    "integration policy Landlock mutation default",
)

replace_one(
    "tests/sandbox.rs",
    '''#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {''',
    '''#[test]\nfn landlock_file_mutation_envelope_narrows_existing_writable_surfaces() {\n    let source = writable_volume_source().to_path_buf();\n    let allowed = source.join("allowed");\n    let denied = source.join("denied");\n    std::fs::create_dir_all(&allowed).expect("create Landlock mutation allowed directory");\n    std::fs::create_dir_all(&denied).expect("create Landlock mutation denied directory");\n    std::fs::write(allowed.join("existing"), b"stale\\n")\n        .expect("seed Landlock mutation truncate fixture");\n    std::fs::write(allowed.join("remove-me"), b"remove-me\\n")\n        .expect("seed Landlock mutation remove fixture");\n    std::fs::write(denied.join("blocked"), b"blocked\\n")\n        .expect("seed Landlock mutation denied remove fixture");\n    let denied_created = denied.join("created");\n    let _ = std::fs::remove_file(&denied_created);\n\n    let mut confined = policy(\n        "m",\n        &[],\n        &["execveat", "openat", "write", "close", "unlink", "exit"],\n    );\n    confined.landlock_read_execute = vec![PathBuf::from("/probe")];\n    confined.landlock_file_mutate =\n        vec![PathBuf::from("/scratch"), PathBuf::from("/persist/allowed")];\n    confined.writable_volume_source = Some(source.clone());\n    confined.writable_volume_target = Some(PathBuf::from("/persist"));\n\n    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));\n    assert_eq!(\n        std::fs::read(allowed.join("existing")).expect("read Landlock-mutated host file"),\n        b"landlock-persistent-write\\n",\n    );\n    assert!(\n        !allowed.join("remove-me").exists(),\n        "declared mutation envelope did not allow REMOVE_FILE"\n    );\n    assert_eq!(\n        std::fs::read(denied.join("blocked")).expect("read denied mutation sentinel"),\n        b"blocked\\n",\n    );\n    assert!(\n        !denied_created.exists(),\n        "Landlock mutation escaped its declared persistent subtree"\n    );\n}\n\n#[test]\nfn landlock_file_mutation_requires_existing_writable_surface() {\n    let mut confined = policy("X", &[], &["execveat", "exit"]);\n    confined.landlock_file_mutate = vec![PathBuf::from("/work")];\n    match run(&confined).unwrap_err() {\n        SandboxError::InvalidPolicy(error) => {\n            assert!(error\n                .to_string()\n                .contains("landlock.file_mutate must be within filesystem.scratch or volume.writable_target"));\n        }\n        other => panic!("unexpected Landlock mutation policy result: {other}"),\n    }\n}\n\n#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {''',
    "Landlock mutation integration regressions",
)

replace_one(
    "tests/fixtures/probe.S",
    "#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM",
    "#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file\n#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM",
    "probe mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $114, %al\n    je .landlock_read_envelope\n    cmp $70, %al",
    "    cmp $114, %al\n    je .landlock_read_envelope\n    cmp $109, %al\n    je .landlock_file_mutation\n    cmp $70, %al",
    "probe mutation dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n''',
    '''    xor %edi, %edi\n    jmp .exit\n\n.landlock_file_mutation:\n    # Private scratch is an existing writable surface; creation must succeed.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_scratch(%rip), %rsi\n    mov $577, %edx\n    mov $384, %r10d\n    syscall\n    test %rax, %rax\n    js .fail38\n    mov %rax, %r12\n\n    mov $1, %eax\n    mov %r12, %rdi\n    lea landlock_mutation_scratch_byte(%rip), %rsi\n    mov $1, %edx\n    syscall\n    cmp $1, %rax\n    jne .fail38\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail38\n\n    # Existing file in the allowed persistent subtree must be writable+truncatable.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_existing(%rip), %rsi\n    mov $513, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail38\n    mov %rax, %r12\n\n    mov $1, %eax\n    mov %r12, %rdi\n    lea landlock_mutation_message(%rip), %rsi\n    mov $landlock_mutation_message_len, %edx\n    syscall\n    cmp $landlock_mutation_message_len, %rax\n    jne .fail38\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail38\n\n    # REMOVE_FILE is independently granted beneath /persist/allowed.\n    mov $87, %eax\n    lea landlock_mutation_remove(%rip), %rdi\n    syscall\n    test %rax, %rax\n    js .fail38\n\n    # The sibling directory is on the same writable mount, so EACCES is Landlock evidence.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_denied_create(%rip), %rsi\n    mov $577, %edx\n    mov $384, %r10d\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    mov $87, %eax\n    lea landlock_mutation_denied_remove(%rip), %rdi\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n''',
    "probe Landlock mutation oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail37:\n    mov $37, %edi\n\n.exit:",
    ".fail37:\n    mov $37, %edi\n    jmp .exit\n.fail38:\n    mov $38, %edi\n\n.exit:",
    "probe mutation failure code",
)
replace_one(
    "tests/fixtures/probe.S",
    '''landlock_allowed_message:\n    .ascii "landlock-allowed\\n"\n.set landlock_allowed_message_len, . - landlock_allowed_message\ndeadline_message:''',
    '''landlock_allowed_message:\n    .ascii "landlock-allowed\\n"\n.set landlock_allowed_message_len, . - landlock_allowed_message\nlandlock_mutation_scratch:\n    .asciz "/scratch/landlock-created"\nlandlock_mutation_scratch_byte:\n    .ascii "s"\nlandlock_mutation_existing:\n    .asciz "/persist/allowed/existing"\nlandlock_mutation_remove:\n    .asciz "/persist/allowed/remove-me"\nlandlock_mutation_denied_create:\n    .asciz "/persist/denied/created"\nlandlock_mutation_denied_remove:\n    .asciz "/persist/denied/blocked"\nlandlock_mutation_message:\n    .ascii "landlock-persistent-write\\n"\n.set landlock_mutation_message_len, . - landlock_mutation_message\ndeadline_message:''',
    "probe mutation paths and message",
)

# POLICY SURFACE / VALIDATION.
replace_one(
    "src/policy.rs",
    "const MAX_LANDLOCK_READ_EXECUTE_PATHS: usize = 32;\nconst MIN_SELECTED_TARGET_FD: u32 = 3;",
    "const MAX_LANDLOCK_READ_EXECUTE_PATHS: usize = 32;\nconst MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MIN_SELECTED_TARGET_FD: u32 = 3;",
    "Landlock mutation path bound",
)
replace_one(
    "src/policy.rs",
    '''    /// Optional Landlock read/execute allowlist. When non-empty, only these\n    /// sandbox paths may be read or executed after trusted setup completes.\n    pub landlock_read_execute: Vec<PathBuf>,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.''',
    '''    /// Optional Landlock read/execute allowlist. When non-empty, only these\n    /// sandbox paths may be read or executed after trusted setup completes.\n    pub landlock_read_execute: Vec<PathBuf>,\n    /// Optional Landlock regular-file mutation allowlist. Each path names a\n    /// directory within an already-writable scratch or persistent-volume surface.\n    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Whether the launcher activates `lo` inside the isolated network namespace.''',
    "SandboxPolicy Landlock mutation field",
)
replace_one(
    "src/policy.rs",
    '''        match (\n            self.host_loopback_tcp_port,\n            self.host_loopback_tcp_target_fd,\n        ) {''',
    '''        if self.landlock_file_mutate.len() > MAX_LANDLOCK_FILE_MUTATE_PATHS {\n            return Err(PolicyError::new(format!(\n                "too many landlock.file_mutate paths: {} > {MAX_LANDLOCK_FILE_MUTATE_PATHS}",\n                self.landlock_file_mutate.len()\n            )));\n        }\n        if !self.landlock_file_mutate.is_empty() {\n            let mut seen = BTreeSet::new();\n            for path in &self.landlock_file_mutate {\n                validate_absolute_path("landlock.file_mutate", path)?;\n                if path == Path::new("/") {\n                    return Err(PolicyError::new(\n                        "landlock.file_mutate must not grant the entire sandbox root",\n                    ));\n                }\n                if !seen.insert(path.clone()) {\n                    return Err(PolicyError::new(format!(\n                        "duplicate landlock.file_mutate path: {}",\n                        path.display()\n                    )));\n                }\n                let in_scratch = self\n                    .scratch_dir\n                    .as_ref()\n                    .map_or(false, |scratch| path == scratch);\n                let in_writable_volume = self\n                    .writable_volume_target\n                    .as_ref()\n                    .map_or(false, |target| path.starts_with(target));\n                if !in_scratch && !in_writable_volume {\n                    return Err(PolicyError::new(\n                        "landlock.file_mutate must be within filesystem.scratch or volume.writable_target",\n                    ));\n                }\n            }\n        }\n\n        match (\n            self.host_loopback_tcp_port,\n            self.host_loopback_tcp_target_fd,\n        ) {''',
    "Landlock mutation validation",
)
replace_one(
    "src/policy.rs",
    "        let mut landlock_read_execute = Vec::new();\n        let mut loopback_enabled = None;",
    "        let mut landlock_read_execute = Vec::new();\n        let mut landlock_file_mutate = Vec::new();\n        let mut loopback_enabled = None;",
    "Landlock mutation parser storage",
)
replace_one(
    "src/policy.rs",
    '''                "working_dir" => set_once(&mut working_dir, value.to_owned(), line_no, key)?,\n                "landlock.read_execute" => landlock_read_execute.push(value.to_owned()),\n                "stdio.stdin" => set_once(''',
    '''                "working_dir" => set_once(&mut working_dir, value.to_owned(), line_no, key)?,\n                "landlock.read_execute" => landlock_read_execute.push(value.to_owned()),\n                "landlock.file_mutate" => landlock_file_mutate.push(value.to_owned()),\n                "stdio.stdin" => set_once(''',
    "Landlock mutation parser key",
)
replace_one(
    "src/policy.rs",
    '''            landlock_read_execute: landlock_read_execute\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            loopback_enabled: loopback_enabled.unwrap_or(false),''',
    '''            landlock_read_execute: landlock_read_execute\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            loopback_enabled: loopback_enabled.unwrap_or(false),''',
    "Landlock mutation policy construction",
)
replace_one(
    "src/policy.rs",
    "        assert!(policy.landlock_read_execute.is_empty());\n        assert_eq!(policy.readonly_volume_source, None);",
    "        assert!(policy.landlock_read_execute.is_empty());\n        assert!(policy.landlock_file_mutate.is_empty());\n        assert_eq!(policy.readonly_volume_source, None);",
    "Landlock mutation default assertion",
)
replace_one(
    "src/policy.rs",
    '''    #[test]\n    fn parses_loopback_networking_mode() {''',
    '''    #[test]\n    fn parses_landlock_file_mutation_paths() {\n        let scratch: SandboxPolicy = format!("{VALID}\\nlandlock.file_mutate = /scratch")\n            .parse()\n            .unwrap();\n        assert_eq!(scratch.landlock_file_mutate, [PathBuf::from("/scratch")]);\n\n        let base = volume_valid();\n        let persistent: SandboxPolicy = format!(\n            "{base}\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /persist\\nlandlock.file_mutate = /persist/allowed"\n        )\n        .parse()\n        .unwrap();\n        assert_eq!(\n            persistent.landlock_file_mutate,\n            [PathBuf::from("/persist/allowed")]\n        );\n    }\n\n    #[test]\n    fn rejects_unsafe_landlock_file_mutation_paths() {\n        let root = format!("{VALID}\\nlandlock.file_mutate = /");\n        assert!(root.parse::<SandboxPolicy>().is_err());\n\n        let relative = format!("{VALID}\\nlandlock.file_mutate = scratch");\n        assert!(relative.parse::<SandboxPolicy>().is_err());\n\n        let duplicate = format!(\n            "{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.file_mutate = /scratch"\n        );\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n\n        let undeclared_surface = format!("{VALID}\\nlandlock.file_mutate = /tmp");\n        let error = undeclared_surface.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains("must be within filesystem.scratch or volume.writable_target"));\n\n        let scratch_subdir = format!("{VALID}\\nlandlock.file_mutate = /scratch/subdir");\n        assert!(scratch_subdir.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_loopback_networking_mode() {''',
    "Landlock mutation policy tests",
)

# LINUX ENFORCEMENT.
replace_one(
    "src/platform/linux.rs",
    '''    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;\n    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;\n    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 =\n        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;''',
    '''    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;\n    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;\n    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;\n    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;\n    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;\n    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;\n    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;\n    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 =\n        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;\n    const LANDLOCK_FILE_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE\n        | LANDLOCK_ACCESS_FS_REMOVE_FILE\n        | LANDLOCK_ACCESS_FS_MAKE_REG\n        | LANDLOCK_ACCESS_FS_TRUNCATE;''',
    "Landlock mutation kernel rights",
)
replace_one(
    "src/platform/linux.rs",
    "        selected_storage_floor: RawFd,\n        landlock_read_execute: Vec<CString>,\n        cancellation_fd: Option<OwnedFd>,",
    "        selected_storage_floor: RawFd,\n        landlock_read_execute: Vec<CString>,\n        landlock_file_mutate: Vec<CString>,\n        cancellation_fd: Option<OwnedFd>,",
    "prepared mutation paths field",
)
replace_one(
    "src/platform/linux.rs",
    '''                landlock_read_execute.push(sandbox_relative(path)?);\n            }\n\n            // Keep every launcher-owned source above all target-visible handle''',
    '''                landlock_read_execute.push(sandbox_relative(path)?);\n            }\n\n            // Mutation paths may live inside the final scratch tmpfs or a mounted\n            // writable persistent volume, so only prepare lexical relative paths\n            // here. The direct target pins the final directory after mount setup.\n            let mut landlock_file_mutate =\n                Vec::with_capacity(policy.landlock_file_mutate.len());\n            for path in &policy.landlock_file_mutate {\n                landlock_file_mutate.push(sandbox_relative(path)?);\n            }\n\n            // Keep every launcher-owned source above all target-visible handle''',
    "prepare mutation path strings",
)
replace_one(
    "src/platform/linux.rs",
    "                selected_storage_floor,\n                landlock_read_execute,\n                cancellation_fd,",
    "                selected_storage_floor,\n                landlock_read_execute,\n                landlock_file_mutate,\n                cancellation_fd,",
    "prepared launch mutation paths",
)

replace_section(
    "src/platform/linux.rs",
    "    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {",
    "    unsafe fn prepare_landlock_ruleset_or_fail(",
    '''    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {\n        if policy.landlock_read_execute.is_empty() && policy.landlock_file_mutate.is_empty() {\n            return Ok(());\n        }\n        let abi = unsafe {\n            libc::syscall(\n                SYS_LANDLOCK_CREATE_RULESET,\n                ptr::null::<libc::c_void>(),\n                0usize,\n                LANDLOCK_CREATE_RULESET_VERSION,\n            )\n        };\n        if abi >= 1 {\n            if !policy.landlock_file_mutate.is_empty() && abi < 3 {\n                return Err(SandboxError::UnsupportedPlatform(format!(\n                    "Landlock file-mutation enforcement requires ABI 3 for TRUNCATE control; kernel reports ABI {abi}"\n                )));\n            }\n            return Ok(());\n        }\n        if abi != -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "Landlock ABI query returned invalid version {abi}"\n            )));\n        }\n        let error = io::Error::last_os_error();\n        match error.raw_os_error() {\n            Some(libc::ENOSYS | libc::EOPNOTSUPP) => Err(SandboxError::UnsupportedPlatform(\n                format!("Landlock enforcement is unavailable: {error}"),\n            )),\n            _ => Err(SandboxError::SetupFailed(format!(\n                "cannot query Landlock ABI: {error}"\n            ))),\n        }\n    }\n\n''',
    "Landlock ABI gate",
)

replace_section(
    "src/platform/linux.rs",
    "    unsafe fn prepare_landlock_ruleset_or_fail(",
    "    unsafe fn restrict_landlock_or_fail(",
    '''    unsafe fn prepare_landlock_ruleset_or_fail(\n        read_execute_paths: &[CString],\n        file_mutate_paths: &[CString],\n        root_tree_fd: RawFd,\n        storage_floor: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) -> RawFd {\n        if read_execute_paths.is_empty() && file_mutate_paths.is_empty() {\n            return -1;\n        }\n\n        let mut handled_access_fs = 0;\n        if !read_execute_paths.is_empty() {\n            handled_access_fs |= LANDLOCK_READ_EXECUTE_RIGHTS;\n        }\n        if !file_mutate_paths.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        let ruleset = LandlockRulesetAttr { handled_access_fs };\n        let raw_ruleset_fd = libc::syscall(\n            SYS_LANDLOCK_CREATE_RULESET,\n            &ruleset as *const LandlockRulesetAttr,\n            std::mem::size_of::<LandlockRulesetAttr>(),\n            0u32,\n        );\n        if raw_ruleset_fd == -1 {\n            child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n        }\n        let mut ruleset_fd = raw_ruleset_fd as RawFd;\n        if ruleset_fd < storage_floor {\n            let moved = libc::fcntl(ruleset_fd, libc::F_DUPFD_CLOEXEC, storage_floor);\n            if moved == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n            }\n            if libc::close(ruleset_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);\n            }\n            ruleset_fd = moved;\n        }\n\n        let path_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        for path in read_execute_paths {\n            let path_fd = libc::syscall(\n                libc::SYS_openat2,\n                root_tree_fd,\n                path.as_ptr(),\n                &path_how as *const OpenHow,\n                std::mem::size_of::<OpenHow>(),\n            );\n            if path_fd == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let path_fd = path_fd as RawFd;\n            let mut stat = std::mem::zeroed::<libc::stat>();\n            if libc::fstat(path_fd, &mut stat) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let kind = stat.st_mode & libc::S_IFMT;\n            let mut allowed_access = if kind == libc::S_IFDIR {\n                LANDLOCK_READ_EXECUTE_RIGHTS\n            } else if kind == libc::S_IFREG {\n                LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE\n            } else {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall)\n            };\n            let also_mutable = file_mutate_paths\n                .iter()\n                .any(|candidate| candidate.as_bytes() == path.as_bytes());\n            if also_mutable {\n                if kind != libc::S_IFDIR {\n                    child_fail_errno(\n                        launch_error,\n                        PHASE_LANDLOCK_PATH,\n                        libc::ENOTDIR,\n                        error_exit_syscall,\n                    );\n                }\n                allowed_access |= LANDLOCK_FILE_MUTATE_RIGHTS;\n            }\n            let rule = LandlockPathBeneathAttr {\n                allowed_access,\n                parent_fd: path_fd,\n                reserved: 0,\n            };\n            if libc::syscall(\n                SYS_LANDLOCK_ADD_RULE,\n                ruleset_fd,\n                LANDLOCK_RULE_PATH_BENEATH,\n                &rule as *const LandlockPathBeneathAttr,\n                0u32,\n            ) == -1\n            {\n                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);\n            }\n            if libc::close(path_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n        }\n\n        let mutation_path_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        for path in file_mutate_paths {\n            if read_execute_paths\n                .iter()\n                .any(|candidate| candidate.as_bytes() == path.as_bytes())\n            {\n                continue;\n            }\n            let path_fd = libc::syscall(\n                libc::SYS_openat2,\n                root_tree_fd,\n                path.as_ptr(),\n                &mutation_path_how as *const OpenHow,\n                std::mem::size_of::<OpenHow>(),\n            );\n            if path_fd == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n            let path_fd = path_fd as RawFd;\n            let rule = LandlockPathBeneathAttr {\n                allowed_access: LANDLOCK_FILE_MUTATE_RIGHTS,\n                parent_fd: path_fd,\n                reserved: 0,\n            };\n            if libc::syscall(\n                SYS_LANDLOCK_ADD_RULE,\n                ruleset_fd,\n                LANDLOCK_RULE_PATH_BENEATH,\n                &rule as *const LandlockPathBeneathAttr,\n                0u32,\n            ) == -1\n            {\n                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);\n            }\n            if libc::close(path_fd) == -1 {\n                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);\n            }\n        }\n        ruleset_fd\n    }\n\n''',
    "Landlock mixed ruleset builder",
)
replace_one(
    "src/platform/linux.rs",
    '''        let landlock_ruleset_fd = prepare_landlock_ruleset_or_fail(\n            &prepared.landlock_read_execute,\n            root_tree_fd,''',
    '''        let landlock_ruleset_fd = prepare_landlock_ruleset_or_fail(\n            &prepared.landlock_read_execute,\n            &prepared.landlock_file_mutate,\n            root_tree_fd,''',
    "Landlock mutation ruleset call",
)
replace_one(
    "src/platform/linux.rs",
    '            "openat" => libc::SYS_openat,\n            "newfstatat" => libc::SYS_newfstatat,',
    '            "openat" => libc::SYS_openat,\n            "unlink" => libc::SYS_unlink,\n            "newfstatat" => libc::SYS_newfstatat,',
    "explicit unlink syscall mapping",
)
