from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: explicit source -> target descriptor capabilities.
replace_one(
    "src/policy.rs",
    "const MAX_SECCOMP_ARG_RULES: usize = 64;\n",
    "const MAX_SECCOMP_ARG_RULES: usize = 64;\nconst MAX_SELECTED_HANDLES: usize = 16;\nconst MIN_SELECTED_TARGET_FD: u32 = 3;\nconst MAX_SELECTED_TARGET_FD: u32 = 63;\n",
    "selected handle constants",
)
replace_one(
    "src/policy.rs",
    '''    /// Explicit disposition for descriptors 0, 1, and 2.\n    pub stdio: StdioPolicy,\n    /// Sandbox path used only when stdout disposition is `Redirect`. The path\n''',
    '''    /// Explicit disposition for descriptors 0, 1, and 2.\n    pub stdio: StdioPolicy,\n    /// Explicit non-stdio descriptor capabilities keyed by target descriptor.\n    /// Each value is an already-open descriptor in the launcher process that\n    /// is pinned before fork and remapped only into the direct target.\n    pub selected_handles: BTreeMap<u32, u32>,\n    /// Sandbox path used only when stdout disposition is `Redirect`. The path\n''',
    "sandbox selected handle field",
)
replace_one(
    "src/policy.rs",
    '''        if self.limits.cpu_seconds == 0\n            || self.limits.address_space_bytes == 0\n            || self.limits.file_size_bytes == 0\n            || self.limits.open_files < 3\n        {\n            return Err(PolicyError::new(\n                "resource limits must be non-zero and open_files must be at least 3",\n            ));\n        }\n\n        if self.seccomp.allowed_syscalls.is_empty() {\n''',
    '''        if self.limits.cpu_seconds == 0\n            || self.limits.address_space_bytes == 0\n            || self.limits.file_size_bytes == 0\n            || self.limits.open_files < 3\n        {\n            return Err(PolicyError::new(\n                "resource limits must be non-zero and open_files must be at least 3",\n            ));\n        }\n\n        if self.selected_handles.len() > MAX_SELECTED_HANDLES {\n            return Err(PolicyError::new(format!(\n                "too many selected handles: {} > {MAX_SELECTED_HANDLES}",\n                self.selected_handles.len()\n            )));\n        }\n        for (target_fd, source_fd) in &self.selected_handles {\n            if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(target_fd) {\n                return Err(PolicyError::new(format!(\n                    "selected handle target fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}"\n                )));\n            }\n            if u64::from(*target_fd) >= self.limits.open_files {\n                return Err(PolicyError::new(format!(\n                    "selected handle target fd {target_fd} must be below limit.open_files {}",\n                    self.limits.open_files\n                )));\n            }\n            if *source_fd > i32::MAX as u32 {\n                return Err(PolicyError::new(format!(\n                    "selected handle source fd exceeds the Linux descriptor range: {source_fd}"\n                )));\n            }\n        }\n\n        if self.seccomp.allowed_syscalls.is_empty() {\n''',
    "selected handle validation",
)
replace_one(
    "src/policy.rs",
    '''        let mut stderr = None;\n        let mut stdout_redirect = None;\n''',
    '''        let mut stderr = None;\n        let mut selected_handles = BTreeMap::new();\n        let mut stdout_redirect = None;\n''',
    "selected handle parser state",
)
replace_one(
    "src/policy.rs",
    '''                "limit.open_files" => set_once(\n                    &mut open_files,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                "seccomp.allow" => {\n''',
    '''                "limit.open_files" => set_once(\n                    &mut open_files,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                _ if key.starts_with("handle.") => {\n                    let target_text = key\n                        .strip_prefix("handle.")\n                        .expect("prefix checked above");\n                    let target_fd = target_text.parse::<u32>().map_err(|_| {\n                        PolicyError::at(\n                            line_no,\n                            "selected handle key must be handle.<target_fd>",\n                        )\n                    })?;\n                    let source_fd = value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(\n                            line_no,\n                            "selected handle source fd must be an unsigned integer",\n                        )\n                    })?;\n                    if selected_handles.insert(target_fd, source_fd).is_some() {\n                        return Err(PolicyError::at(\n                            line_no,\n                            format!("duplicate selected handle target fd: {target_fd}"),\n                        ));\n                    }\n                }\n                "seccomp.allow" => {\n''',
    "selected handle parser arm",
)
replace_one(
    "src/policy.rs",
    '''            stdio: StdioPolicy {\n                stdin: required(stdin, "stdio.stdin")?,\n                stdout: required(stdout, "stdio.stdout")?,\n                stderr: required(stderr, "stdio.stderr")?,\n            },\n            stdout_redirect: stdout_redirect.map(PathBuf::from),\n''',
    '''            stdio: StdioPolicy {\n                stdin: required(stdin, "stdio.stdin")?,\n                stdout: required(stdout, "stdio.stdout")?,\n                stderr: required(stderr, "stdio.stderr")?,\n            },\n            selected_handles,\n            stdout_redirect: stdout_redirect.map(PathBuf::from),\n''',
    "selected handle final policy",
)
replace_one(
    "src/policy.rs",
    '''        assert_eq!(policy.stdio.stderr, StdioMode::Inherit);\n        assert_eq!(policy.stdout_redirect, None);\n''',
    '''        assert_eq!(policy.stdio.stderr, StdioMode::Inherit);\n        assert!(policy.selected_handles.is_empty());\n        assert_eq!(policy.stdout_redirect, None);\n''',
    "selected handle default assertion",
)
replace_one(
    "src/policy.rs",
    '''    #[test]\n    fn rejects_duplicate_syscall() {\n''',
    '''    #[test]\n    fn parses_selected_handle_mapping() {\n        let text = format!("{VALID}\\nhandle.9 = 200");\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.selected_handles.get(&9), Some(&200));\n    }\n\n    #[test]\n    fn rejects_duplicate_selected_handle_target() {\n        let text = format!("{VALID}\\nhandle.9 = 200\\nhandle.9 = 201");\n        assert!(text.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn rejects_selected_handle_target_outside_owned_range_or_rlimit() {\n        for mapping in ["handle.2 = 200", "handle.64 = 200", "handle.32 = 200"] {\n            let text = format!("{VALID}\\n{mapping}");\n            assert!(\n                text.parse::<SandboxPolicy>().is_err(),\n                "accepted invalid mapping {mapping}"\n            );\n        }\n    }\n\n    #[test]\n    fn rejects_selected_handle_source_outside_linux_fd_range() {\n        let text = format!("{VALID}\\nhandle.9 = {}", u32::MAX);\n        assert!(text.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn rejects_too_many_selected_handles() {\n        let mut text = VALID.to_owned();\n        for target_fd in 3..20 {\n            text.push_str(&format!("\\nhandle.{target_fd} = 200"));\n        }\n        assert!(text.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn rejects_duplicate_syscall() {\n''',
    "selected handle policy tests",
)

# Linux runtime: collision-safe storage plane and direct-target-only remap.
replace_one(
    "src/platform/linux.rs",
    '''    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;\n    const FIRST_NON_STDIO_FD: libc::c_uint = 3;\n''',
    '''    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;\n    const FIRST_NON_STDIO_FD: libc::c_uint = 3;\n    const FIRST_SELECTED_STORAGE_FD: RawFd = 64;\n''',
    "selected handle storage constant",
)
replace_one(
    "src/platform/linux.rs",
    '''    const PHASE_DEADLINE_POLL: u32 = 37;\n    const PHASE_HOSTNAME: u32 = 38;\n''',
    '''    const PHASE_DEADLINE_POLL: u32 = 37;\n    const PHASE_HOSTNAME: u32 = 38;\n    const PHASE_SELECTED_HANDLES: u32 = 39;\n''',
    "selected handle phase constant",
)
replace_one(
    "src/platform/linux.rs",
    '''    struct CapturePipe {\n        read_fd: OwnedFd,\n        write_fd: OwnedFd,\n        limit: usize,\n    }\n''',
    '''    struct CapturePipe {\n        read_fd: OwnedFd,\n        write_fd: OwnedFd,\n        limit: usize,\n    }\n\n    struct PreparedSelectedHandle {\n        storage_fd: OwnedFd,\n        target_fd: RawFd,\n    }\n''',
    "prepared selected handle struct",
)
replace_one(
    "src/platform/linux.rs",
    '''    fn move_parent_fd_above_stdio(fd: OwnedFd, label: &str) -> Result<OwnedFd, SandboxError> {\n        if fd.raw() >= FIRST_NON_STDIO_FD as RawFd {\n            return Ok(fd);\n        }\n        let moved = unsafe {\n            libc::fcntl(\n                fd.raw(),\n                libc::F_DUPFD_CLOEXEC,\n                FIRST_NON_STDIO_FD as libc::c_int,\n            )\n        };\n        if moved == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot normalize {label} above standard descriptors: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        drop(fd);\n        Ok(OwnedFd(moved))\n    }\n''',
    '''    fn move_parent_fd_above_stdio(fd: OwnedFd, label: &str) -> Result<OwnedFd, SandboxError> {\n        if fd.raw() >= FIRST_NON_STDIO_FD as RawFd {\n            return Ok(fd);\n        }\n        let moved = unsafe {\n            libc::fcntl(\n                fd.raw(),\n                libc::F_DUPFD_CLOEXEC,\n                FIRST_NON_STDIO_FD as libc::c_int,\n            )\n        };\n        if moved == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot normalize {label} above standard descriptors: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        drop(fd);\n        Ok(OwnedFd(moved))\n    }\n\n    fn move_owned_fd_to_selected_storage(\n        fd: OwnedFd,\n        label: &str,\n    ) -> Result<OwnedFd, SandboxError> {\n        if fd.raw() >= FIRST_SELECTED_STORAGE_FD {\n            return Ok(fd);\n        }\n        let moved = unsafe {\n            libc::fcntl(\n                fd.raw(),\n                libc::F_DUPFD_CLOEXEC,\n                FIRST_SELECTED_STORAGE_FD,\n            )\n        };\n        if moved == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot move {label} into the selected-handle storage plane: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        drop(fd);\n        Ok(OwnedFd(moved))\n    }\n\n    fn pin_selected_handle(\n        source_fd: u32,\n        target_fd: u32,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n        if source_fd > i32::MAX as u32 {\n            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(\n                "selected handle source fd exceeds the Linux descriptor range: {source_fd}"\n            ))));\n        }\n        let source_fd = source_fd as RawFd;\n        let pinned = unsafe {\n            libc::fcntl(\n                source_fd,\n                libc::F_DUPFD_CLOEXEC,\n                FIRST_SELECTED_STORAGE_FD,\n            )\n        };\n        if pinned == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot pin selected handle source fd {source_fd} for target fd {target_fd}: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        let storage_fd = OwnedFd(pinned);\n        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };\n        if unsafe { libc::fstat(storage_fd.raw(), &mut stat) } == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot inspect selected handle source fd {source_fd}: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {\n            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(\n                "selected handle source fd {source_fd} is a directory descriptor"\n            ))));\n        }\n        Ok(PreparedSelectedHandle {\n            storage_fd,\n            target_fd: target_fd as RawFd,\n        })\n    }\n''',
    "selected handle parent helpers",
)
replace_one(
    "src/platform/linux.rs",
    '''        executable_fd: OwnedFd,\n        cwd_relative: CString,\n''',
    '''        executable_fd: OwnedFd,\n        selected_handles: Vec<PreparedSelectedHandle>,\n        cwd_relative: CString,\n''',
    "prepared launch selected handles field",
)
replace_one(
    "src/platform/linux.rs",
    '''            let executable_fd = open_beneath_root(\n                root_fd.raw(),\n                &policy.executable,\n                (libc::O_PATH | libc::O_CLOEXEC) as u64,\n                "executable",\n            )?;\n            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n\n            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n''',
    '''            let executable_fd = open_beneath_root(\n                root_fd.raw(),\n                &policy.executable,\n                (libc::O_PATH | libc::O_CLOEXEC) as u64,\n                "executable",\n            )?;\n            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n            let executable_fd =\n                move_owned_fd_to_selected_storage(executable_fd, "pinned executable")?;\n\n            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());\n            for (target_fd, source_fd) in &policy.selected_handles {\n                selected_handles.push(pin_selected_handle(*source_fd, *target_fd)?);\n            }\n\n            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n''',
    "prepare executable and selected handles",
)
replace_one(
    "src/platform/linux.rs",
    '''                root_path,\n                executable_fd,\n                cwd_relative,\n''',
    '''                root_path,\n                executable_fd,\n                selected_handles,\n                cwd_relative,\n''',
    "prepared launch selected handles init",
)
replace_one(
    "src/platform/linux.rs",
    '''        if pid == 0 {\n            unsafe {\n                child_exec(\n                    &prepared,\n                    policy.stdio,\n                    policy.limits,\n                    &seccomp,\n                    child_control,\n                )\n            }\n        }\n\n        let capture_result = capture.map(|pipe| {\n''',
    '''        if pid == 0 {\n            unsafe {\n                child_exec(\n                    &prepared,\n                    policy.stdio,\n                    policy.limits,\n                    &seccomp,\n                    child_control,\n                )\n            }\n        }\n        // The host parent does not retain launcher-owned duplicates of selected\n        // object capabilities while the target runs. Caller-owned source FDs\n        // remain under caller control.\n        drop(prepared);\n\n        let capture_result = capture.map(|pipe| {\n''',
    "drop prepared handles in host parent",
)
replace_one(
    "src/platform/linux.rs",
    '''        apply_stdio_policy_or_fail(\n            stdio,\n            stdout_redirect_fd,\n            capture_write_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        set_limit_or_fail(\n''',
    '''        apply_stdio_policy_or_fail(\n            stdio,\n            stdout_redirect_fd,\n            capture_write_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n        install_selected_handles_or_fail(\n            &prepared.selected_handles,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        set_limit_or_fail(\n''',
    "install selected handles before limits",
)
replace_one(
    "src/platform/linux.rs",
    '''    unsafe fn set_limit_or_fail(\n        resource: libc::c_uint,\n''',
    '''    unsafe fn install_selected_handles_or_fail(\n        handles: &[PreparedSelectedHandle],\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        for handle in handles {\n            if libc::syscall(\n                libc::SYS_dup3,\n                handle.storage_fd.raw(),\n                handle.target_fd,\n                0u32,\n            ) == -1\n            {\n                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);\n            }\n        }\n        for handle in handles {\n            if libc::close(handle.storage_fd.raw()) == -1 {\n                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);\n            }\n        }\n    }\n\n    unsafe fn set_limit_or_fail(\n        resource: libc::c_uint,\n''',
    "selected handle child installer",
)
replace_one(
    "src/platform/linux.rs",
    '''            PHASE_DEADLINE_POLL => "wall-clock deadline supervision poll",\n            PHASE_HOSTNAME => "UTS hostname installation",\n            _ => "unknown launch phase",\n''',
    '''            PHASE_DEADLINE_POLL => "wall-clock deadline supervision poll",\n            PHASE_HOSTNAME => "UTS hostname installation",\n            PHASE_SELECTED_HANDLES => "selected non-stdio handle installation",\n            _ => "unknown launch phase",\n''',
    "selected handle phase decoding",
)

# Integration harness and executable capability oracle.
replace_one(
    "tests/sandbox.rs",
    '''use std::collections::{BTreeMap, BTreeSet};\nuse std::net::{TcpListener, TcpStream};\nuse std::os::unix::fs::{symlink, PermissionsExt};\n''',
    '''use std::collections::{BTreeMap, BTreeSet};\nuse std::ffi::CString;\nuse std::net::{TcpListener, TcpStream};\nuse std::os::unix::fs::{symlink, PermissionsExt};\nuse std::os::unix::io::{AsRawFd, RawFd};\n''',
    "sandbox fd imports",
)
replace_one(
    "tests/sandbox.rs",
    '''const SCRATCH_BYTES: u64 = 16 * 1024 * 1024;\n\nfn fixture_root() -> &'static Path {\n''',
    '''const SCRATCH_BYTES: u64 = 16 * 1024 * 1024;\n\nstruct TestFd(RawFd);\n\nimpl TestFd {\n    fn raw(&self) -> RawFd {\n        self.0\n    }\n}\n\nimpl Drop for TestFd {\n    fn drop(&mut self) {\n        unsafe {\n            libc::close(self.0);\n        }\n    }\n}\n\nfn duplicate_fd_at_least(fd: RawFd, minimum: RawFd, label: &str) -> TestFd {\n    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };\n    assert!(\n        duplicated >= minimum,\n        "failed to duplicate {label} at or above {minimum}: {}",\n        std::io::Error::last_os_error()\n    );\n    TestFd(duplicated)\n}\n\nfn fixture_root() -> &'static Path {\n''',
    "sandbox test fd helper",
)
replace_one(
    "tests/sandbox.rs",
    '''        stdio: StdioPolicy {\n            stdin: StdioMode::Inherit,\n            stdout: StdioMode::Inherit,\n            stderr: StdioMode::Inherit,\n        },\n        stdout_redirect: None,\n''',
    '''        stdio: StdioPolicy {\n            stdin: StdioMode::Inherit,\n            stdout: StdioMode::Inherit,\n            stderr: StdioMode::Inherit,\n        },\n        selected_handles: BTreeMap::new(),\n        stdout_redirect: None,\n''',
    "sandbox default selected handles",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n''',
    '''#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n    let mut pipe = [-1; 2];\n    assert_eq!(\n        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },\n        0,\n        "create selected-handle pipe"\n    );\n    let read_end = TestFd(pipe[0]);\n    let write_end = TestFd(pipe[1]);\n    let source = duplicate_fd_at_least(read_end.raw(), 200, "selected source");\n    drop(read_end);\n\n    let marker = b"selected-handle-ok";\n    let written = unsafe {\n        libc::write(\n            write_end.raw(),\n            marker.as_ptr().cast::<libc::c_void>(),\n            marker.len(),\n        )\n    };\n    assert_eq!(written, marker.len() as isize, "write selected marker");\n    drop(write_end);\n\n    let null_path = CString::new("/dev/null").unwrap();\n    let null_fd = unsafe { libc::open(null_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };\n    assert!(null_fd >= 0, "open undeclared descriptor fixture");\n    let null_fd = TestFd(null_fd);\n    let undeclared = duplicate_fd_at_least(null_fd.raw(), 220, "undeclared descriptor");\n    drop(null_fd);\n\n    let source_text = source.raw().to_string();\n    let undeclared_text = undeclared.raw().to_string();\n    let mut selected = policy(\n        "G",\n        &[source_text.as_str(), undeclared_text.as_str()],\n        &["execveat", "read", "fcntl", "exit"],\n    );\n    selected.selected_handles.insert(9, source.raw() as u32);\n\n    assert_eq!(run(&selected).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn selected_handle_rejects_directory_source() {\n    let directory = std::fs::File::open(fixture_root()).expect("open directory descriptor");\n    let mut selected = policy("A", &[], &["execveat", "write", "exit"]);\n    selected\n        .selected_handles\n        .insert(9, directory.as_raw_fd() as u32);\n\n    match run(&selected).unwrap_err() {\n        SandboxError::InvalidPolicy(error) => {\n            assert!(error.to_string().contains("directory descriptor"));\n        }\n        other => panic!("unexpected directory-source result: {other}"),\n    }\n}\n\n#[test]\nfn network_namespace_cannot_reach_host_loopback_listener() {\n''',
    "sandbox selected handle integration tests",
)

# Raw target: read only target fd 9, prove original/undeclared descriptors closed.
replace_one(
    "tests/fixtures/probe.S",
    '''#   B assert 64-bit masked seccomp argument filtering on lseek offset\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n''',
    '''#   B assert 64-bit masked seccomp argument filtering on lseek offset\n#   G assert one selected non-stdio handle is remapped without ambient FD leakage\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM\n''',
    "probe selected handle comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $66, %al\n    je .seccomp_argument_filter\n    cmp $70, %al\n''',
    '''    cmp $66, %al\n    je .seccomp_argument_filter\n    cmp $71, %al\n    je .selected_handle\n    cmp $70, %al\n''',
    "probe selected handle dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n''',
    '''    xor %edi, %edi\n    jmp .exit\n\n.selected_handle:\n    mov 24(%rsp), %rdi\n    test %rdi, %rdi\n    je .fail30\n    call .parse_handle_fd\n    mov %eax, %r12d\n    mov 32(%rsp), %rdi\n    test %rdi, %rdi\n    je .fail30\n    call .parse_handle_fd\n    mov %eax, %r13d\n\n    xor %eax, %eax\n    mov $9, %edi\n    lea selected_handle_buffer(%rip), %rsi\n    mov $selected_handle_message_len, %edx\n    syscall\n    cmp $selected_handle_message_len, %rax\n    jne .fail30\n\n    lea selected_handle_buffer(%rip), %rdi\n    lea selected_handle_message(%rip), %rsi\n    mov $selected_handle_message_len, %ecx\n.selected_handle_compare:\n    test %ecx, %ecx\n    je .selected_handle_check_closed\n    movzbl (%rdi), %eax\n    movzbl (%rsi), %edx\n    cmp %dl, %al\n    jne .fail30\n    inc %rdi\n    inc %rsi\n    dec %ecx\n    jmp .selected_handle_compare\n\n.selected_handle_check_closed:\n    mov $72, %eax\n    mov %r12d, %edi\n    mov $1, %esi\n    xor %edx, %edx\n    syscall\n    cmp $-9, %rax\n    jne .fail30\n\n    mov $72, %eax\n    mov %r13d, %edi\n    mov $1, %esi\n    xor %edx, %edx\n    syscall\n    cmp $-9, %rax\n    jne .fail30\n    xor %edi, %edi\n    jmp .exit\n\n.parse_handle_fd:\n    xor %eax, %eax\n    movzbl (%rdi), %edx\n    test %dl, %dl\n    je .fail30\n.parse_handle_fd_loop:\n    movzbl (%rdi), %edx\n    test %dl, %dl\n    je .parse_handle_fd_done\n    sub $48, %edx\n    cmp $9, %edx\n    ja .fail30\n    imul $10, %eax, %eax\n    add %edx, %eax\n    inc %rdi\n    jmp .parse_handle_fd_loop\n.parse_handle_fd_done:\n    ret\n\n.forbidden:\n''',
    "probe selected handle oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    '''.fail29:\n    mov $29, %edi\n\n.exit:\n''',
    '''.fail29:\n    mov $29, %edi\n    jmp .exit\n.fail30:\n    mov $30, %edi\n\n.exit:\n''',
    "probe fail30",
)
replace_one(
    "tests/fixtures/probe.S",
    '''capture_chunk:\n    .ascii "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"\ndeadline_message:\n''',
    '''capture_chunk:\n    .ascii "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"\nselected_handle_message:\n    .ascii "selected-handle-ok"\n.set selected_handle_message_len, . - selected_handle_message\ndeadline_message:\n''',
    "probe selected handle marker",
)
replace_one(
    "tests/fixtures/probe.S",
    '''redirect_buffer:\n    .skip 1\n.balign 16\nuts_buffer:\n''',
    '''redirect_buffer:\n    .skip 1\nselected_handle_buffer:\n    .skip 64\n.balign 16\nuts_buffer:\n''',
    "probe selected handle buffer",
)
