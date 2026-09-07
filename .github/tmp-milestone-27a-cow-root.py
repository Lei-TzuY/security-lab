from pathlib import Path

def replace_one(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

def append_before(path, marker, addition, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(marker)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one marker, got {count}")
    p.write_text(text.replace(marker, addition + marker, 1))

# policy
replace_one("src/policy.rs",
    "const MIN_SCRATCH_BYTES: u64 = 4096;\nconst MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;\n",
    "const MIN_SCRATCH_BYTES: u64 = 4096;\nconst MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;\nconst MIN_COW_ROOT_BYTES: u64 = 4096;\nconst MAX_COW_ROOT_BYTES: u64 = 1024 * 1024 * 1024;\n",
    "cow size constants")
replace_one("src/policy.rs",
    "    /// Host path pinned as the sandbox filesystem root before fork.\n    pub root_dir: PathBuf,\n",
    "    /// Host path pinned as the sandbox filesystem root before fork.\n    pub root_dir: PathBuf,\n    /// Optional byte ceiling for a private tmpfs upper/work backing an\n    /// ephemeral OverlayFS copy-on-write view of `root_dir`.\n    pub cow_root_bytes: Option<u64>,\n",
    "cow policy field")
replace_one("src/policy.rs",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if self.procfs_enabled {",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if let Some(bytes) = self.cow_root_bytes {\n            if !(MIN_COW_ROOT_BYTES..=MAX_COW_ROOT_BYTES).contains(&bytes) {\n                return Err(PolicyError::new(format!(\n                    \"filesystem.cow_root_bytes must be between {MIN_COW_ROOT_BYTES} and {MAX_COW_ROOT_BYTES}\"\n                )));\n            }\n        }\n\n        if self.procfs_enabled {",
    "cow validation")
replace_one("src/policy.rs",
    "        let mut root_dir = None;\n        let mut hostname = None;\n",
    "        let mut root_dir = None;\n        let mut cow_root_bytes = None;\n        let mut hostname = None;\n",
    "cow parser local")
replace_one("src/policy.rs",
    '                "filesystem.root" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,\n',
    '                "filesystem.root" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,\n                "filesystem.cow_root_bytes" => set_once(\n                    &mut cow_root_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n',
    "cow parser key")
replace_one("src/policy.rs",
    '            root_dir: PathBuf::from(required(root_dir, "filesystem.root")?),\n            hostname: required(hostname, "identity.hostname")?,\n',
    '            root_dir: PathBuf::from(required(root_dir, "filesystem.root")?),\n            cow_root_bytes,\n            hostname: required(hostname, "identity.hostname")?,\n',
    "cow constructor")
replace_one("src/policy.rs",
    '        assert_eq!(policy.root_dir, PathBuf::from("/"));\n        assert_eq!(policy.hostname, "security-lab");\n',
    '        assert_eq!(policy.root_dir, PathBuf::from("/"));\n        assert_eq!(policy.cow_root_bytes, None);\n        assert_eq!(policy.hostname, "security-lab");\n',
    "cow parse default assertion")
replace_one("src/policy.rs",
    "    #[test]\n    fn parses_readonly_volume_pair() {",
    '''    #[test]
    fn parses_bounded_copy_on_write_root() {
        let policy: SandboxPolicy =
            format!("{VALID}\\nfilesystem.cow_root_bytes = 16777216")
                .parse()
                .unwrap();
        assert_eq!(policy.cow_root_bytes, Some(16 * 1024 * 1024));

        let too_small =
            format!("{VALID}\\nfilesystem.cow_root_bytes = {}", MIN_COW_ROOT_BYTES - 1);
        assert!(too_small.parse::<SandboxPolicy>().is_err());

        let too_large =
            format!("{VALID}\\nfilesystem.cow_root_bytes = {}", MAX_COW_ROOT_BYTES + 1);
        assert!(too_large.parse::<SandboxPolicy>().is_err());

        let duplicate = format!(
            "{VALID}\\nfilesystem.cow_root_bytes = 4096\\nfilesystem.cow_root_bytes = 8192"
        );
        assert!(duplicate.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn parses_readonly_volume_pair() {''',
    "cow policy tests")

# report / cli json
replace_one("src/report.rs",
    "    pub private_mount_propagation: bool,\n    pub readonly_root: bool,\n    pub chroot: bool,\n",
    "    pub private_mount_propagation: bool,\n    pub readonly_root: bool,\n    /// The final root is an ephemeral OverlayFS view with a launcher-owned,\n    /// bounded private tmpfs upper/work layer over a recursively read-only lower.\n    pub copy_on_write_root: bool,\n    pub chroot: bool,\n",
    "receipt cow field")
replace_one("src/cli_json.rs",
    '    output.push_str(",\\"readonly_root\\":");\n    push_bool(&mut output, report.enforcement.readonly_root);\n    output.push_str(",\\"chroot\\":");\n',
    '    output.push_str(",\\"readonly_root\\":");\n    push_bool(&mut output, report.enforcement.readonly_root);\n    output.push_str(",\\"copy_on_write_root\\":");\n    push_bool(&mut output, report.enforcement.copy_on_write_root);\n    output.push_str(",\\"chroot\\":");\n',
    "cli receipt json")
replace_one("src/cli_json.rs",
    '\\"private_mount_propagation\\":false,\\"readonly_root\\":false,\\"chroot\\":false,',
    '\\"private_mount_propagation\\":false,\\"readonly_root\\":false,\\"copy_on_write_root\\":false,\\"chroot\\":false,',
    "cli exact json test")

# authority manifest
replace_one("src/authority_manifest.rs",
    '    output.push_str(",\\"private_procfs\\":");\n    push_bool(&mut output, policy.procfs_enabled);\n    output.push_str(",\\"scratch\\":");\n',
    '    output.push_str(",\\"private_procfs\\":");\n    push_bool(&mut output, policy.procfs_enabled);\n    output.push_str(",\\"copy_on_write_root_bytes\\":");\n    push_optional_u64(&mut output, policy.cow_root_bytes);\n    output.push_str(",\\"scratch\\":");\n',
    "manifest cow json")
replace_one("src/authority_manifest.rs",
    '    writeln!(&mut output, "root: {}", policy.root_dir.display())\n        .expect("write to String cannot fail");\n    writeln!(\n        &mut output,\n        "private-procfs: {}",\n',
    '    writeln!(&mut output, "root: {}", policy.root_dir.display())\n        .expect("write to String cannot fail");\n    writeln!(\n        &mut output,\n        "copy-on-write-root-bytes: {}",\n        display_optional_u64(policy.cow_root_bytes)\n    )\n    .expect("write to String cannot fail");\n    writeln!(\n        &mut output,\n        "private-procfs: {}",\n',
    "manifest cow human")

# preflight
replace_one("src/policy_preflight.rs",
    "    time_namespace: bool,\n    private_procfs: bool,\n",
    "    time_namespace: bool,\n    private_procfs: bool,\n    copy_on_write_root: bool,\n",
    "preflight requirement field")
replace_one("src/policy_preflight.rs",
    "            private_procfs: policy.procfs_enabled,\n",
    "            private_procfs: policy.procfs_enabled,\n            copy_on_write_root: policy.cow_root_bytes.is_some(),\n",
    "preflight derive cow")
replace_one("src/policy_preflight.rs",
    "    fn private_procfs_status(&self) -> RequirementStatus {\n        if self.requirements.private_procfs {\n            RequirementStatus::Unprobed\n        } else {\n            RequirementStatus::NotRequested\n        }\n    }\n\n    fn mandatory_launch_core_status",
    "    fn private_procfs_status(&self) -> RequirementStatus {\n        if self.requirements.private_procfs {\n            RequirementStatus::Unprobed\n        } else {\n            RequirementStatus::NotRequested\n        }\n    }\n\n    fn copy_on_write_root_status(&self) -> RequirementStatus {\n        if self.requirements.copy_on_write_root {\n            RequirementStatus::Unprobed\n        } else {\n            RequirementStatus::NotRequested\n        }\n    }\n\n    fn mandatory_launch_core_status",
    "preflight cow status")
replace_one("src/policy_preflight.rs",
    "            || self.private_procfs_status() == RequirementStatus::Unprobed\n",
    "            || self.private_procfs_status() == RequirementStatus::Unprobed\n            || self.copy_on_write_root_status() == RequirementStatus::Unprobed\n",
    "preflight cow verdict")
replace_one("src/policy_preflight.rs",
    '        output.push_str("},\\"private_procfs\\":{\\"status\\":\\"");\n        output.push_str(self.private_procfs_status().as_str());\n        output.push_str("\\",\\"reason\\":");\n        if self.requirements.private_procfs {\n            output.push_str("\\"pid_namespace_procfs_mount_requires_real_launch\\"");\n        } else {\n            output.push_str("null");\n        }\n        output.push_str("}}}");\n',
    '        output.push_str("},\\"private_procfs\\":{\\"status\\":\\"");\n        output.push_str(self.private_procfs_status().as_str());\n        output.push_str("\\",\\"reason\\":");\n        if self.requirements.private_procfs {\n            output.push_str("\\"pid_namespace_procfs_mount_requires_real_launch\\"");\n        } else {\n            output.push_str("null");\n        }\n        output.push_str("},\\"copy_on_write_root\\":{\\"status\\":\\"");\n        output.push_str(self.copy_on_write_root_status().as_str());\n        output.push_str("\\",\\"reason\\":");\n        if self.requirements.copy_on_write_root {\n            output.push_str("\\"overlayfs_mount_requires_real_user_mount_namespace\\"");\n        } else {\n            output.push_str("null");\n        }\n        output.push_str("}}}");\n',
    "preflight cow json")
replace_one("src/policy_preflight.rs",
    '        output.push_str("private-procfs: ");\n        output.push_str(self.private_procfs_status().as_str());\n        if self.requirements.private_procfs {\n            output.push_str(" (pid-namespace-procfs-mount-requires-real-launch)");\n        }\n        output.push(\'\\n\');\n        output\n',
    '        output.push_str("private-procfs: ");\n        output.push_str(self.private_procfs_status().as_str());\n        if self.requirements.private_procfs {\n            output.push_str(" (pid-namespace-procfs-mount-requires-real-launch)");\n        }\n        output.push(\'\\n\');\n        output.push_str("copy-on-write-root: ");\n        output.push_str(self.copy_on_write_root_status().as_str());\n        if self.requirements.copy_on_write_root {\n            output.push_str(" (overlayfs-mount-requires-real-user-mount-namespace)");\n        }\n        output.push(\'\\n\');\n        output\n',
    "preflight cow human")
replace_one("src/policy_preflight.rs",
    "                private_procfs: false,\n            }\n",
    "                private_procfs: false,\n                copy_on_write_root: false,\n            }\n",
    "preflight expected requirements")
replace_one("src/policy_preflight.rs",
    '\\"private_procfs\\":{\\"status\\":\\"not_requested\\",\\"reason\\":null}}}"\n',
    '\\"private_procfs\\":{\\"status\\":\\"not_requested\\",\\"reason\\":null},\\"copy_on_write_root\\":{\\"status\\":\\"not_requested\\",\\"reason\\":null}}}"\n',
    "preflight exact json")
replace_one("src/policy_preflight.rs",
    "    #[test]\n    fn derives_highest_requested_landlock_abi_and_supervision_requirements() {",
    '''    #[test]
    fn copy_on_write_root_remains_explicitly_unprobed_without_real_mount_namespace() {
        let policy = policy("filesystem.cow_root_bytes = 16777216");
        let evaluated = evaluate_with_core(&policy, host(None), RequirementStatus::Supported);
        assert_eq!(
            evaluated.copy_on_write_root_status(),
            RequirementStatus::Unprobed
        );
        assert_eq!(evaluated.verdict(), Verdict::Indeterminate);
        assert!(evaluated.to_json().contains(
            "\\\"copy_on_write_root\\\":{\\\"status\\\":\\\"unprobed\\\",\\\"reason\\\":\\\"overlayfs_mount_requires_real_user_mount_namespace\\\"}"
        ));
    }

    #[test]
    fn derives_highest_requested_landlock_abi_and_supervision_requirements() {''',
    "preflight cow test")

# linux constants, bits, phases
replace_one("src/platform/linux.rs",
    "    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;\n",
    "    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;\n    const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;\n    const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;\n    const MOUNT_ATTR_NOEXEC: u64 = 0x0000_0008;\n    const FSOPEN_CLOEXEC: libc::c_uint = 0x0000_0001;\n    const FSMOUNT_CLOEXEC: libc::c_uint = 0x0000_0001;\n    const FSCONFIG_SET_STRING: libc::c_uint = 1;\n    const FSCONFIG_CMD_CREATE: libc::c_uint = 6;\n",
    "mount api constants")
replace_one("src/platform/linux.rs",
    "    const ENFORCEMENT_PRIVATE_PROCFS: u64 = 1 << 12;\n",
    "    const ENFORCEMENT_PRIVATE_PROCFS: u64 = 1 << 12;\n    const ENFORCEMENT_COW_ROOT: u64 = 1 << 13;\n",
    "cow receipt bit")
replace_one("src/platform/linux.rs",
    "        | ENFORCEMENT_SECCOMP\n        | ENFORCEMENT_PRIVATE_PROCFS;\n",
    "        | ENFORCEMENT_SECCOMP\n        | ENFORCEMENT_PRIVATE_PROCFS\n        | ENFORCEMENT_COW_ROOT;\n",
    "known cow receipt bit")
replace_one("src/platform/linux.rs",
    "    const PHASE_PROCFS_PID1_HARDEN: u32 = 58;\n",
    "    const PHASE_PROCFS_PID1_HARDEN: u32 = 58;\n    const PHASE_COW_TMPFS_CREATE: u32 = 59;\n    const PHASE_COW_TMPFS_MOUNT: u32 = 60;\n    const PHASE_COW_UPPER_WORK: u32 = 61;\n    const PHASE_COW_OVERLAY_CREATE: u32 = 62;\n    const PHASE_COW_OVERLAY_MOUNT: u32 = 63;\n    const PHASE_COW_ROOT_ATTACH: u32 = 64;\n",
    "cow launch phases")

# receipt signature/calls
replace_one("src/platform/linux.rs",
    "            false,\n        )\n    }\n\n    fn enforcement_receipt_from_bits_for_policy(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n        procfs_requested: bool,\n    )",
    "            false,\n            false,\n        )\n    }\n\n    fn enforcement_receipt_from_bits_for_policy(\n        bits: u64,\n        time_namespace_requested: bool,\n        landlock_requested: bool,\n        procfs_requested: bool,\n        cow_root_requested: bool,\n    )",
    "receipt decoder signature")
replace_one("src/platform/linux.rs",
    '''        require_predecessor(
            ENFORCEMENT_READONLY_ROOT,
            ENFORCEMENT_PRIVATE_MOUNTS,
            "read-only root",
        )?;
        require_predecessor(ENFORCEMENT_CHROOT, ENFORCEMENT_READONLY_ROOT, "chroot")?;
''',
    '''        require_predecessor(
            ENFORCEMENT_READONLY_ROOT,
            ENFORCEMENT_PRIVATE_MOUNTS,
            "read-only root",
        )?;
        require_predecessor(
            ENFORCEMENT_COW_ROOT,
            ENFORCEMENT_PRIVATE_MOUNTS,
            "copy-on-write root",
        )?;
        let readonly_root = observed(ENFORCEMENT_READONLY_ROOT);
        let copy_on_write_root = observed(ENFORCEMENT_COW_ROOT);
        if readonly_root && copy_on_write_root {
            return Err(SandboxError::SetupFailed(
                "runtime enforcement receipt observed both read-only and copy-on-write final roots"
                    .to_owned(),
            ));
        }
        if copy_on_write_root && !cow_root_requested {
            return Err(SandboxError::SetupFailed(
                "runtime enforcement receipt observed unrequested copy-on-write root".to_owned(),
            ));
        }
        if readonly_root && cow_root_requested {
            return Err(SandboxError::SetupFailed(
                "runtime enforcement receipt observed read-only final root for requested copy-on-write policy"
                    .to_owned(),
            ));
        }
        if observed(ENFORCEMENT_CHROOT) {
            let expected_root = if cow_root_requested {
                copy_on_write_root
            } else {
                readonly_root
            };
            if !expected_root {
                return Err(SandboxError::SetupFailed(
                    "runtime enforcement receipt reached chroot without the requested final-root boundary"
                        .to_owned(),
                ));
            }
        }
''',
    "receipt root semantics")
replace_one("src/platform/linux.rs",
    "            readonly_root: bits & ENFORCEMENT_READONLY_ROOT != 0,\n            chroot: bits & ENFORCEMENT_CHROOT != 0,\n",
    "            readonly_root,\n            copy_on_write_root,\n            chroot: bits & ENFORCEMENT_CHROOT != 0,\n",
    "receipt cow output")
replace_one("src/platform/linux.rs",
    "            policy.procfs_enabled,\n        )\n",
    "            policy.procfs_enabled,\n            policy.cow_root_bytes.is_some(),\n        )\n",
    "decode receipt cow policy")

# prepared field
replace_one("src/platform/linux.rs",
    "        root_fd: OwnedFd,\n        root_path: CString,\n        executable_fd: OwnedFd,\n",
    "        root_fd: OwnedFd,\n        root_path: CString,\n        cow_root_size: Option<CString>,\n        executable_fd: OwnedFd,\n",
    "prepared cow field")
replace_one("src/platform/linux.rs",
    "            let root_path =\n                cstring_bytes(\"filesystem.root\", policy.root_dir.as_os_str().as_bytes())?;\n",
    "            let root_path =\n                cstring_bytes(\"filesystem.root\", policy.root_dir.as_os_str().as_bytes())?;\n            let cow_root_size = policy\n                .cow_root_bytes\n                .map(|bytes| cstring_bytes(\"filesystem.cow_root_bytes\", bytes.to_string().as_bytes()))\n                .transpose()?;\n",
    "prepare cow size")
replace_one("src/platform/linux.rs",
    "                root_fd,\n                root_path,\n                executable_fd,\n",
    "                root_fd,\n                root_path,\n                cow_root_size,\n                executable_fd,\n",
    "prepared cow constructor")

helpers = r'''    unsafe fn close_setup_fd(fd: RawFd) {
        if fd >= 0 {
            libc::close(fd);
        }
    }

    unsafe fn proc_fd_path(fd: RawFd, buffer: &mut [u8; 32]) -> *const libc::c_char {
        const PREFIX: &[u8] = b"/proc/self/fd/";
        let mut index = 0usize;
        while index < PREFIX.len() {
            buffer[index] = PREFIX[index];
            index += 1;
        }

        let mut value = fd as u32;
        let mut digits = [0u8; 10];
        let mut count = 0usize;
        loop {
            digits[count] = b'0' + (value % 10) as u8;
            count += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        while count > 0 {
            count -= 1;
            buffer[index] = digits[count];
            index += 1;
        }
        buffer[index] = 0;
        buffer.as_ptr().cast::<libc::c_char>()
    }

    unsafe fn fsconfig_string_or_fail(
        fsfd: RawFd,
        key: &'static [u8],
        value: *const libc::c_char,
        phase: u32,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        if libc::syscall(
            libc::SYS_fsconfig,
            fsfd,
            FSCONFIG_SET_STRING,
            key.as_ptr().cast::<libc::c_char>(),
            value,
            0,
        ) == -1
        {
            child_fail(launch_error, phase, error_exit_syscall);
        }
    }

    unsafe fn construct_final_root_or_fail(
        prepared: &PreparedLaunch,
        current_root_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        let lower_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_root_fd,
            b".\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if lower_tree_fd == -1 {
            child_fail(launch_error, PHASE_ROOT_CLONE, error_exit_syscall);
        }
        let lower_tree_fd = lower_tree_fd as RawFd;

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            lower_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH | AT_RECURSIVE,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(launch_error, PHASE_ROOT_READONLY, error_exit_syscall);
        }

        let Some(cow_size) = &prepared.cow_root_size else {
            if libc::syscall(
                libc::SYS_move_mount,
                lower_tree_fd,
                b"\0".as_ptr().cast::<libc::c_char>(),
                current_root_fd,
                b"\0".as_ptr().cast::<libc::c_char>(),
                MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
            ) == -1
            {
                child_fail(launch_error, PHASE_ROOT_ATTACH, error_exit_syscall);
            }
            mark_enforcement(launch_error, ENFORCEMENT_READONLY_ROOT);
            return lower_tree_fd;
        };

        let state_fsfd = libc::syscall(
            libc::SYS_fsopen,
            b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
            FSOPEN_CLOEXEC,
        );
        if state_fsfd == -1 {
            child_fail(launch_error, PHASE_COW_TMPFS_CREATE, error_exit_syscall);
        }
        let state_fsfd = state_fsfd as RawFd;
        fsconfig_string_or_fail(state_fsfd, b"size\0", cow_size.as_ptr(),
            PHASE_COW_TMPFS_CREATE, launch_error, error_exit_syscall);
        fsconfig_string_or_fail(state_fsfd, b"mode\0",
            b"0700\0".as_ptr().cast::<libc::c_char>(),
            PHASE_COW_TMPFS_CREATE, launch_error, error_exit_syscall);
        if libc::syscall(
            libc::SYS_fsconfig,
            state_fsfd,
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_COW_TMPFS_CREATE, error_exit_syscall);
        }
        let state_mount_fd = libc::syscall(
            libc::SYS_fsmount,
            state_fsfd,
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
        );
        if state_mount_fd == -1 {
            child_fail(launch_error, PHASE_COW_TMPFS_MOUNT, error_exit_syscall);
        }
        let state_mount_fd = state_mount_fd as RawFd;
        close_setup_fd(state_fsfd);

        if libc::syscall(libc::SYS_mkdirat, state_mount_fd,
            b"upper\0".as_ptr().cast::<libc::c_char>(), 0o700) == -1
        {
            child_fail(launch_error, PHASE_COW_UPPER_WORK, error_exit_syscall);
        }
        if libc::syscall(libc::SYS_mkdirat, state_mount_fd,
            b"work\0".as_ptr().cast::<libc::c_char>(), 0o700) == -1
        {
            child_fail(launch_error, PHASE_COW_UPPER_WORK, error_exit_syscall);
        }
        let upper_fd = libc::syscall(libc::SYS_openat, state_mount_fd,
            b"upper\0".as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0);
        if upper_fd == -1 {
            child_fail(launch_error, PHASE_COW_UPPER_WORK, error_exit_syscall);
        }
        let upper_fd = upper_fd as RawFd;
        let work_fd = libc::syscall(libc::SYS_openat, state_mount_fd,
            b"work\0".as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC, 0);
        if work_fd == -1 {
            child_fail(launch_error, PHASE_COW_UPPER_WORK, error_exit_syscall);
        }
        let work_fd = work_fd as RawFd;

        let mut lower_path_buffer = [0u8; 32];
        let mut upper_path_buffer = [0u8; 32];
        let mut work_path_buffer = [0u8; 32];
        let lower_path = proc_fd_path(lower_tree_fd, &mut lower_path_buffer);
        let upper_path = proc_fd_path(upper_fd, &mut upper_path_buffer);
        let work_path = proc_fd_path(work_fd, &mut work_path_buffer);

        let overlay_fsfd = libc::syscall(
            libc::SYS_fsopen,
            b"overlay\0".as_ptr().cast::<libc::c_char>(),
            FSOPEN_CLOEXEC,
        );
        if overlay_fsfd == -1 {
            child_fail(launch_error, PHASE_COW_OVERLAY_CREATE, error_exit_syscall);
        }
        let overlay_fsfd = overlay_fsfd as RawFd;
        fsconfig_string_or_fail(overlay_fsfd, b"lowerdir\0", lower_path,
            PHASE_COW_OVERLAY_CREATE, launch_error, error_exit_syscall);
        fsconfig_string_or_fail(overlay_fsfd, b"upperdir\0", upper_path,
            PHASE_COW_OVERLAY_CREATE, launch_error, error_exit_syscall);
        fsconfig_string_or_fail(overlay_fsfd, b"workdir\0", work_path,
            PHASE_COW_OVERLAY_CREATE, launch_error, error_exit_syscall);
        if libc::syscall(
            libc::SYS_fsconfig,
            overlay_fsfd,
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_COW_OVERLAY_CREATE, error_exit_syscall);
        }
        let overlay_fd =
            libc::syscall(libc::SYS_fsmount, overlay_fsfd, FSMOUNT_CLOEXEC, 0u64);
        if overlay_fd == -1 {
            child_fail(launch_error, PHASE_COW_OVERLAY_MOUNT, error_exit_syscall);
        }
        let overlay_fd = overlay_fd as RawFd;
        close_setup_fd(overlay_fsfd);

        if libc::syscall(
            libc::SYS_move_mount,
            overlay_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            current_root_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_COW_ROOT_ATTACH, error_exit_syscall);
        }

        close_setup_fd(work_fd);
        close_setup_fd(upper_fd);
        close_setup_fd(state_mount_fd);
        close_setup_fd(lower_tree_fd);
        mark_enforcement(launch_error, ENFORCEMENT_COW_ROOT);
        overlay_fd
    }

'''
append_before("src/platform/linux.rs", "    unsafe fn child_exec(\n", helpers, "insert cow helpers")

old_root_block = r'''        let root_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_root_fd,
            b".\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if root_tree_fd == -1 {
            child_fail(launch_error, PHASE_ROOT_CLONE, seccomp.error_exit_syscall);
        }
        let root_tree_fd = root_tree_fd as RawFd;

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH | AT_RECURSIVE,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_ROOT_READONLY,
                seccomp.error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_move_mount,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            current_root_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_ROOT_ATTACH, seccomp.error_exit_syscall);
        }
        mark_enforcement(launch_error, ENFORCEMENT_READONLY_ROOT);
'''
replace_one("src/platform/linux.rs", old_root_block,
    r'''        let root_tree_fd = construct_final_root_or_fail(
            prepared,
            current_root_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );
''',
    "replace root construction")
replace_one("src/platform/linux.rs",
    "                | PHASE_VOLUME_READONLY\n                | PHASE_VOLUME_ATTACH\n",
    "                | PHASE_VOLUME_READONLY\n                | PHASE_VOLUME_ATTACH\n                | PHASE_COW_TMPFS_CREATE\n                | PHASE_COW_TMPFS_MOUNT\n                | PHASE_COW_UPPER_WORK\n                | PHASE_COW_OVERLAY_CREATE\n                | PHASE_COW_OVERLAY_MOUNT\n                | PHASE_COW_ROOT_ATTACH\n",
    "cow unsupported classification")
replace_one("src/platform/linux.rs",
    '            PHASE_PROCFS_PID1_HARDEN => "private procfs PID1 descriptor-access hardening",\n',
    '            PHASE_PROCFS_PID1_HARDEN => "private procfs PID1 descriptor-access hardening",\n            PHASE_COW_TMPFS_CREATE => "copy-on-write root tmpfs state creation",\n            PHASE_COW_TMPFS_MOUNT => "copy-on-write root tmpfs state mount",\n            PHASE_COW_UPPER_WORK => "copy-on-write root upper/work preparation",\n            PHASE_COW_OVERLAY_CREATE => "copy-on-write root OverlayFS creation",\n            PHASE_COW_OVERLAY_MOUNT => "copy-on-write root OverlayFS mount",\n            PHASE_COW_ROOT_ATTACH => "copy-on-write final root attachment",\n',
    "cow error labels")

# receipt test call sites
replace_one("src/platform/linux.rs",
    "                false,\n                false,\n                false,\n            );\n            assert!(unrequested.is_err());",
    "                false,\n                false,\n                false,\n                false,\n            );\n            assert!(unrequested.is_err());",
    "receipt test 1")
replace_one("src/platform/linux.rs",
    "                false,\n                false,\n                true,\n            );\n            assert!(skipped.is_err());",
    "                false,\n                false,\n                true,\n                false,\n            );\n            assert!(skipped.is_err());",
    "receipt test 2")
replace_one("src/platform/linux.rs",
    "                false,\n                false,\n                true,\n            )\n            .expect(\"requested procfs progression should decode\");",
    "                false,\n                false,\n                true,\n                false,\n            )\n            .expect(\"requested procfs progression should decode\");",
    "receipt test 3")
replace_one("src/platform/linux.rs",
    "        #[test]\n        fn early_control_termination_can_publish_a_valid_partial_receipt() {",
    '''        #[test]
        fn copy_on_write_receipt_is_request_bound_and_mutually_exclusive() {
            let cow_bits = ENFORCEMENT_BASE_NAMESPACES
                | ENFORCEMENT_HOSTNAME
                | ENFORCEMENT_PRIVATE_MOUNTS
                | ENFORCEMENT_COW_ROOT
                | ENFORCEMENT_CHROOT
                | ENFORCEMENT_FD_SANITIZATION
                | ENFORCEMENT_RLIMITS;
            let observed = enforcement_receipt_from_bits_for_policy(
                cow_bits, false, false, false, true,
            )
            .expect("requested COW-root progression should decode");
            assert!(observed.copy_on_write_root);
            assert!(!observed.readonly_root);

            assert!(enforcement_receipt_from_bits_for_policy(
                cow_bits, false, false, false, false,
            )
            .is_err());
            assert!(enforcement_receipt_from_bits_for_policy(
                cow_bits | ENFORCEMENT_READONLY_ROOT,
                false, false, false, true,
            )
            .is_err());
        }

        #[test]
        fn early_control_termination_can_publish_a_valid_partial_receipt() {''',
    "cow receipt tests")

# integration test fixture
replace_one("tests/sandbox.rs",
    '        std::fs::create_dir_all(root.join("landlock-denied"))\n            .expect("create Landlock denied directory");\n',
    '        std::fs::create_dir_all(root.join("landlock-denied"))\n            .expect("create Landlock denied directory");\n        std::fs::create_dir_all(root.join("cow-dir")).expect("create COW root fixture directory");\n        std::fs::write(root.join("cow-base"), b"lower-original\\n")\n            .expect("write COW lower base fixture");\n        std::fs::write(root.join("cow-dir/child"), b"lower-child\\n")\n            .expect("write COW lower child fixture");\n',
    "cow fixture seed")
replace_one("tests/sandbox.rs",
    '        root_dir: fixture_root().to_path_buf(),\n        hostname: "security-lab".to_owned(),\n',
    '        root_dir: fixture_root().to_path_buf(),\n        cow_root_bytes: None,\n        hostname: "security-lab".to_owned(),\n',
    "test policy cow field")
replace_one("tests/sandbox.rs",
    "fn clock_nanos(clock_id: libc::clockid_t) -> i128 {",
    '''#[test]
fn copy_on_write_root_is_ephemeral_and_preserves_host_lower() {
    let root = fixture_root();
    let base = root.join("cow-base");
    let child = root.join("cow-dir/child");
    let created = root.join("cow-new");
    let _ = std::fs::remove_file(&created);
    assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
    assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");

    for _ in 0..2 {
        let mut cow = policy(
            "k",
            &[],
            &["execveat", "openat", "read", "write", "close", "unlink", "exit"],
        );
        cow.cow_root_bytes = Some(SCRATCH_BYTES);
        let report = run_report(&cow).expect("copy-on-write root sandbox failed");
        assert_eq!(report.outcome, ChildOutcome::Exited(0));
        assert!(report.enforcement.copy_on_write_root);
        assert!(!report.enforcement.readonly_root);
        assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
        assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");
        assert!(!created.exists());
    }
}

fn clock_nanos(clock_id: libc::clockid_t) -> i128 {''',
    "cow integration test")

# raw fixture
replace_one("tests/fixtures/probe.S",
    "#   j prove private procfs keeps PID1 metadata visible but seals PID1 control descriptors\n",
    "#   j prove private procfs keeps PID1 metadata visible but seals PID1 control descriptors\n#   k mutate an ephemeral copy-on-write root and verify merged-state behavior\n",
    "cow fixture comment")
replace_one("tests/fixtures/probe.S",
    "    cmp $106, %al\n    je .private_procfs_control_boundary\n",
    "    cmp $106, %al\n    je .private_procfs_control_boundary\n    cmp $107, %al\n    je .copy_on_write_root\n",
    "cow fixture dispatch")
cow_asm = r'''
.copy_on_write_root:
    sub $32, %rsp
    mov $257, %eax
    mov $-100, %edi
    lea cow_base_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov %rax, %r12
    xor %eax, %eax
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $15, %edx
    syscall
    cmp $15, %rax
    jne .fail48_cow_stack
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    lea cow_lower_original(%rip), %rsi
    mov %rsp, %rdi
    mov $15, %ecx
    repe cmpsb
    jne .fail48_cow_stack

    mov $257, %eax
    mov $-100, %edi
    lea cow_base_path(%rip), %rsi
    mov $513, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea cow_replacement(%rip), %rsi
    mov $cow_replacement_len, %edx
    syscall
    cmp $cow_replacement_len, %rax
    jne .fail48_cow_stack
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack

    mov $257, %eax
    mov $-100, %edi
    lea cow_new_path(%rip), %rsi
    mov $193, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea cow_new_message(%rip), %rsi
    mov $cow_new_message_len, %edx
    syscall
    cmp $cow_new_message_len, %rax
    jne .fail48_cow_stack
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack

    mov $87, %eax
    lea cow_child_path(%rip), %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack

    mov $257, %eax
    mov $-100, %edi
    lea cow_base_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov %rax, %r12
    xor %eax, %eax
    mov %r12, %rdi
    mov %rsp, %rsi
    mov $cow_replacement_len, %edx
    syscall
    cmp $cow_replacement_len, %rax
    jne .fail48_cow_stack
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    lea cow_replacement(%rip), %rsi
    mov %rsp, %rdi
    mov $cow_replacement_len, %ecx
    repe cmpsb
    jne .fail48_cow_stack

    mov $257, %eax
    mov $-100, %edi
    lea cow_child_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail48_cow_stack

    add $32, %rsp
    xor %edi, %edi
    jmp .exit

.fail48_cow_stack:
    add $32, %rsp
    jmp .fail48

'''
replace_one("tests/fixtures/probe.S", "\n.forbidden:\n",
    cow_asm + ".forbidden:\n", "cow fixture implementation")
replace_one("tests/fixtures/probe.S",
    'writable_volume_message:\n    .ascii "persistent-write\\n"\n.set writable_volume_message_len, . - writable_volume_message\n',
    '''writable_volume_message:
    .ascii "persistent-write\\n"
.set writable_volume_message_len, . - writable_volume_message
cow_base_path:
    .asciz "/cow-base"
cow_child_path:
    .asciz "/cow-dir/child"
cow_new_path:
    .asciz "/cow-new"
cow_lower_original:
    .ascii "lower-original\\n"
cow_replacement:
    .ascii "cow-replaced\\n"
.set cow_replacement_len, . - cow_replacement
cow_new_message:
    .ascii "cow-new\\n"
.set cow_new_message_len, . - cow_new_message
''',
    "cow fixture data")
