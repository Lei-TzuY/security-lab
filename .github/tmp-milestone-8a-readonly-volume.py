from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# ---------------- policy model / parser / validation ----------------
replace_one(
    "src/policy.rs",
    "    /// Optional absolute path inside `root_dir` replaced by a private writable\n    /// tmpfs after the root mount tree has been made recursively read-only.\n    pub scratch_dir: Option<PathBuf>,\n",
    "    /// Optional trusted host directory exposed read-only at exactly one\n    /// declared sandbox mountpoint. Source and target must be specified together.\n    pub readonly_volume_source: Option<PathBuf>,\n    pub readonly_volume_target: Option<PathBuf>,\n    /// Optional absolute path inside `root_dir` replaced by a private writable\n    /// tmpfs after the root mount tree has been made recursively read-only.\n    pub scratch_dir: Option<PathBuf>,\n",
    "policy fields",
)

replace_one(
    "src/policy.rs",
    "        match (&self.scratch_dir, self.scratch_bytes) {\n",
    "        match (&self.readonly_volume_source, &self.readonly_volume_target) {\n            (None, None) => {}\n            (Some(source), Some(target)) => {\n                validate_absolute_path(\"volume.readonly_source\", source)?;\n                validate_absolute_path(\"volume.readonly_target\", target)?;\n                if target == Path::new(\"/\") {\n                    return Err(PolicyError::new(\n                        \"volume.readonly_target must not replace the sandbox root\",\n                    ));\n                }\n                if self.executable.starts_with(target) || self.working_dir.starts_with(target) {\n                    return Err(PolicyError::new(\n                        \"volume.readonly_target must not contain the executable or working_dir\",\n                    ));\n                }\n                if let Some(scratch) = &self.scratch_dir {\n                    if target.starts_with(scratch) || scratch.starts_with(target) {\n                        return Err(PolicyError::new(\n                            \"volume.readonly_target must not overlap filesystem.scratch\",\n                        ));\n                    }\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"volume.readonly_source and volume.readonly_target must be specified together\",\n                ));\n            }\n        }\n\n        match (&self.scratch_dir, self.scratch_bytes) {\n",
    "volume validation",
)

replace_one(
    "src/policy.rs",
    "        let mut working_dir = None;\n        let mut scratch_dir = None;\n",
    "        let mut working_dir = None;\n        let mut readonly_volume_source = None;\n        let mut readonly_volume_target = None;\n        let mut scratch_dir = None;\n",
    "parser locals",
)

replace_one(
    "src/policy.rs",
    "                \"filesystem.scratch\" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,\n",
    "                \"volume.readonly_source\" => {\n                    set_once(&mut readonly_volume_source, value.to_owned(), line_no, key)?\n                }\n                \"volume.readonly_target\" => {\n                    set_once(&mut readonly_volume_target, value.to_owned(), line_no, key)?\n                }\n                \"filesystem.scratch\" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,\n",
    "parser keys",
)

replace_one(
    "src/policy.rs",
    "            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            scratch_dir: scratch_dir.map(PathBuf::from),\n",
    "            working_dir: PathBuf::from(required(working_dir, \"working_dir\")?),\n            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n            readonly_volume_target: readonly_volume_target.map(PathBuf::from),\n            scratch_dir: scratch_dir.map(PathBuf::from),\n",
    "policy construction",
)

replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.scratch_dir, Some(PathBuf::from(\"/scratch\")));\n",
    "        assert_eq!(policy.readonly_volume_source, None);\n        assert_eq!(policy.readonly_volume_target, None);\n        assert_eq!(policy.scratch_dir, Some(PathBuf::from(\"/scratch\")));\n",
    "complete policy assertions",
)

replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_stdout_redirect_inside_scratch() {\n",
    "    #[test]\n    fn parses_readonly_volume_pair() {\n        let text = format!(\n            \"{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /data\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(\n            policy.readonly_volume_source,\n            Some(PathBuf::from(\"/srv/data\"))\n        );\n        assert_eq!(\n            policy.readonly_volume_target,\n            Some(PathBuf::from(\"/data\"))\n        );\n    }\n\n    #[test]\n    fn rejects_incomplete_or_unsafe_readonly_volume() {\n        let incomplete = format!(\"{VALID}\\nvolume.readonly_source = /srv/data\");\n        assert!(incomplete.parse::<SandboxPolicy>().is_err());\n\n        let root_target = format!(\n            \"{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /\"\n        );\n        assert!(root_target.parse::<SandboxPolicy>().is_err());\n\n        let relative_source = format!(\n            \"{VALID}\\nvolume.readonly_source = relative\\nvolume.readonly_target = /data\"\n        );\n        assert!(relative_source.parse::<SandboxPolicy>().is_err());\n\n        let hides_cwd = format!(\n            \"{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /tmp\"\n        );\n        assert!(hides_cwd.parse::<SandboxPolicy>().is_err());\n\n        let overlaps_scratch = format!(\n            \"{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /scratch/data\"\n        );\n        assert!(overlaps_scratch.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_stdout_redirect_inside_scratch() {\n",
    "volume policy tests",
)

# ---------------- Linux preparation / enforcement ----------------
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_CANCELLATION_PIDFD: u32 = 40;\n    const PHASE_CANCELLATION_POLL: u32 = 41;\n",
    "    const PHASE_CANCELLATION_PIDFD: u32 = 40;\n    const PHASE_CANCELLATION_POLL: u32 = 41;\n    const PHASE_VOLUME_SOURCE_REVALIDATE: u32 = 42;\n    const PHASE_VOLUME_CLONE: u32 = 43;\n    const PHASE_VOLUME_READONLY: u32 = 44;\n    const PHASE_VOLUME_TARGET_PIN: u32 = 45;\n    const PHASE_VOLUME_ATTACH: u32 = 46;\n",
    "volume phases",
)

replace_one(
    "src/platform/linux.rs",
    "        cancellation_fd: Option<OwnedFd>,\n        cwd_relative: CString,\n",
    "        cancellation_fd: Option<OwnedFd>,\n        readonly_volume_source_fd: Option<OwnedFd>,\n        readonly_volume_source_path: Option<CString>,\n        readonly_volume_target_relative: Option<CString>,\n        cwd_relative: CString,\n",
    "prepared volume fields",
)

replace_one(
    "src/platform/linux.rs",
    "            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n            let (scratch_relative, scratch_options) = match (\n",
    "            let (\n                readonly_volume_source_fd,\n                readonly_volume_source_path,\n                readonly_volume_target_relative,\n            ) = match (&policy.readonly_volume_source, &policy.readonly_volume_target) {\n                (Some(source), Some(target)) => {\n                    let source_fd = open_host_directory(source, \"read-only volume source\")?;\n                    let target_check = open_beneath_root(\n                        root_fd.raw(),\n                        target,\n                        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n                        \"read-only volume target\",\n                    )?;\n                    drop(target_check);\n                    let source_path = cstring_bytes(\n                        \"volume.readonly_source\",\n                        source.as_os_str().as_bytes(),\n                    )?;\n                    let target_relative = sandbox_relative(target)?;\n                    (Some(source_fd), Some(source_path), Some(target_relative))\n                }\n                (None, None) => (None, None, None),\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"volume.readonly_source and volume.readonly_target must be specified together\",\n                    )));\n                }\n            };\n\n            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n            let (scratch_relative, scratch_options) = match (\n",
    "prepare volume",
)

replace_one(
    "src/platform/linux.rs",
    "                cancellation_fd,\n                cwd_relative,\n",
    "                cancellation_fd,\n                readonly_volume_source_fd,\n                readonly_volume_source_path,\n                readonly_volume_target_relative,\n                cwd_relative,\n",
    "prepared initializer",
)

replace_one(
    "src/platform/linux.rs",
    "    fn open_beneath_root(\n",
    "    fn open_host_directory(path: &Path, label: &str) -> Result<OwnedFd, SandboxError> {\n        let path = cstring_bytes(label, path.as_os_str().as_bytes())?;\n        let how = OpenHow {\n            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        match openat2(libc::AT_FDCWD, &path, &how) {\n            Ok(fd) => Ok(OwnedFd(fd)),\n            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) => {\n                Err(SandboxError::UnsupportedPlatform(format!(\n                    \"{label} requires Linux openat2 support: {err}\"\n                )))\n            }\n            Err(err) => Err(SandboxError::SetupFailed(format!(\n                \"cannot pin {label} without symlink traversal: {err}\"\n            ))),\n        }\n    }\n\n    fn open_beneath_root(\n",
    "host directory pin helper",
)

replace_one(
    "src/platform/linux.rs",
    "        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {\n            child_fail(launch_error, PHASE_ROOT_FCHDIR, seccomp.error_exit_syscall);\n        }\n\n        if let (Some(scratch), Some(options)) =\n",
    "        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {\n            child_fail(launch_error, PHASE_ROOT_FCHDIR, seccomp.error_exit_syscall);\n        }\n\n        install_readonly_volume_or_fail(\n            prepared,\n            root_tree_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n\n        if let (Some(scratch), Some(options)) =\n",
    "volume installation call",
)

replace_one(
    "src/platform/linux.rs",
    "    unsafe fn open_stdout_redirect_or_fail(\n",
    "    unsafe fn install_readonly_volume_or_fail(\n        prepared: &PreparedLaunch,\n        root_tree_fd: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        let (Some(pinned_source), Some(source_path), Some(target_relative)) = (\n            &prepared.readonly_volume_source_fd,\n            &prepared.readonly_volume_source_path,\n            &prepared.readonly_volume_target_relative,\n        ) else {\n            return;\n        };\n\n        let source_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,\n        };\n        let current_source_fd = libc::syscall(\n            libc::SYS_openat2,\n            libc::AT_FDCWD,\n            source_path.as_ptr(),\n            &source_how as *const OpenHow,\n            std::mem::size_of::<OpenHow>(),\n        );\n        if current_source_fd == -1 {\n            child_fail(\n                launch_error,\n                PHASE_VOLUME_SOURCE_REVALIDATE,\n                error_exit_syscall,\n            );\n        }\n        let current_source_fd = current_source_fd as RawFd;\n        revalidate_fd_identity_or_fail(\n            pinned_source.raw(),\n            current_source_fd,\n            PHASE_VOLUME_SOURCE_REVALIDATE,\n            launch_error,\n            error_exit_syscall,\n        );\n\n        let volume_tree_fd = libc::syscall(\n            libc::SYS_open_tree,\n            current_source_fd,\n            b\".\\0\".as_ptr().cast::<libc::c_char>(),\n            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,\n        );\n        if volume_tree_fd == -1 {\n            child_fail(launch_error, PHASE_VOLUME_CLONE, error_exit_syscall);\n        }\n        let volume_tree_fd = volume_tree_fd as RawFd;\n\n        let volume_attr = MountAttr {\n            attr_set: MOUNT_ATTR_RDONLY,\n            attr_clr: 0,\n            propagation: 0,\n            userns_fd: 0,\n        };\n        if libc::syscall(\n            libc::SYS_mount_setattr,\n            volume_tree_fd,\n            b\"\\0\".as_ptr().cast::<libc::c_char>(),\n            AT_EMPTY_PATH | AT_RECURSIVE,\n            &volume_attr as *const MountAttr,\n            std::mem::size_of::<MountAttr>(),\n        ) == -1\n        {\n            child_fail(launch_error, PHASE_VOLUME_READONLY, error_exit_syscall);\n        }\n\n        let target_how = OpenHow {\n            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,\n            mode: 0,\n            resolve: RESOLVE_BENEATH\n                | RESOLVE_NO_XDEV\n                | RESOLVE_NO_MAGICLINKS\n                | RESOLVE_NO_SYMLINKS,\n        };\n        let target_fd = libc::syscall(\n            libc::SYS_openat2,\n            root_tree_fd,\n            target_relative.as_ptr(),\n            &target_how as *const OpenHow,\n            std::mem::size_of::<OpenHow>(),\n        );\n        if target_fd == -1 {\n            child_fail(launch_error, PHASE_VOLUME_TARGET_PIN, error_exit_syscall);\n        }\n        let target_fd = target_fd as RawFd;\n\n        if libc::syscall(\n            libc::SYS_move_mount,\n            volume_tree_fd,\n            b\"\\0\".as_ptr().cast::<libc::c_char>(),\n            target_fd,\n            b\"\\0\".as_ptr().cast::<libc::c_char>(),\n            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,\n        ) == -1\n        {\n            child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);\n        }\n\n        for fd in [target_fd, volume_tree_fd, current_source_fd] {\n            if libc::close(fd) == -1 {\n                child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);\n            }\n        }\n    }\n\n    unsafe fn open_stdout_redirect_or_fail(\n",
    "volume runtime helper",
)

replace_one(
    "src/platform/linux.rs",
    "    unsafe fn revalidate_root_identity_or_fail(\n        pinned_root_fd: RawFd,\n        current_root_fd: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        let mut pinned = std::mem::zeroed::<libc::stat>();\n        if libc::fstat(pinned_root_fd, &mut pinned) == -1 {\n            child_fail(launch_error, PHASE_ROOT_REVALIDATE, error_exit_syscall);\n        }\n        let mut current = std::mem::zeroed::<libc::stat>();\n        if libc::fstat(current_root_fd, &mut current) == -1 {\n            child_fail(launch_error, PHASE_ROOT_REVALIDATE, error_exit_syscall);\n        }\n        if pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino {\n            child_fail_errno(\n                launch_error,\n                PHASE_ROOT_REVALIDATE,\n                libc::ESTALE,\n                error_exit_syscall,\n            );\n        }\n    }\n",
    "    unsafe fn revalidate_root_identity_or_fail(\n        pinned_root_fd: RawFd,\n        current_root_fd: RawFd,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        revalidate_fd_identity_or_fail(\n            pinned_root_fd,\n            current_root_fd,\n            PHASE_ROOT_REVALIDATE,\n            launch_error,\n            error_exit_syscall,\n        );\n    }\n\n    unsafe fn revalidate_fd_identity_or_fail(\n        pinned_fd: RawFd,\n        current_fd: RawFd,\n        phase: u32,\n        launch_error: *mut LaunchErrorRecord,\n        error_exit_syscall: libc::c_long,\n    ) {\n        let mut pinned = std::mem::zeroed::<libc::stat>();\n        if libc::fstat(pinned_fd, &mut pinned) == -1 {\n            child_fail(launch_error, phase, error_exit_syscall);\n        }\n        let mut current = std::mem::zeroed::<libc::stat>();\n        if libc::fstat(current_fd, &mut current) == -1 {\n            child_fail(launch_error, phase, error_exit_syscall);\n        }\n        if pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino {\n            child_fail_errno(\n                launch_error,\n                phase,\n                libc::ESTALE,\n                error_exit_syscall,\n            );\n        }\n    }\n",
    "generic identity revalidation",
)

replace_one(
    "src/platform/linux.rs",
    "            PHASE_ROOT_CLONE | PHASE_ROOT_READONLY | PHASE_ROOT_ATTACH | PHASE_SCRATCH_MOUNT\n",
    "            PHASE_ROOT_CLONE\n                | PHASE_ROOT_READONLY\n                | PHASE_ROOT_ATTACH\n                | PHASE_SCRATCH_MOUNT\n                | PHASE_VOLUME_CLONE\n                | PHASE_VOLUME_READONLY\n                | PHASE_VOLUME_ATTACH\n",
    "unsupported mount phases",
)

replace_one(
    "src/platform/linux.rs",
    "            PHASE_CANCELLATION_POLL => \"external cancellation supervision poll\",\n            _ => \"unknown launch phase\",\n",
    "            PHASE_CANCELLATION_POLL => \"external cancellation supervision poll\",\n            PHASE_VOLUME_SOURCE_REVALIDATE => \"read-only volume source revalidation\",\n            PHASE_VOLUME_CLONE => \"detached read-only volume mount clone\",\n            PHASE_VOLUME_READONLY => \"recursive read-only volume attributes\",\n            PHASE_VOLUME_TARGET_PIN => \"read-only volume target pin\",\n            PHASE_VOLUME_ATTACH => \"read-only volume mount attachment\",\n            _ => \"unknown launch phase\",\n",
    "volume phase descriptions",
)

# ---------------- integration fixture and oracle ----------------
replace_one(
    "tests/sandbox.rs",
    "        std::fs::create_dir_all(root.join(\"scratch\")).expect(\"create sandbox scratch mountpoint\");\n",
    "        std::fs::create_dir_all(root.join(\"scratch\")).expect(\"create sandbox scratch mountpoint\");\n        std::fs::create_dir_all(root.join(\"data\")).expect(\"create sandbox volume mountpoint\");\n",
    "fixture volume mountpoint",
)

replace_one(
    "tests/sandbox.rs",
    "        working_dir: PathBuf::from(\"/work\"),\n        scratch_dir: Some(PathBuf::from(\"/scratch\")),\n",
    "        working_dir: PathBuf::from(\"/work\"),\n        readonly_volume_source: None,\n        readonly_volume_target: None,\n        scratch_dir: Some(PathBuf::from(\"/scratch\")),\n",
    "integration policy fields",
)

replace_one(
    "tests/sandbox.rs",
    "fn syscall_set(names: &[&str]) -> BTreeSet<String> {\n",
    "fn readonly_volume_source() -> &'static Path {\n    static SOURCE: OnceLock<PathBuf> = OnceLock::new();\n    SOURCE\n        .get_or_init(|| {\n            let source =\n                std::env::temp_dir().join(format!(\"security-lab-volume-{}\", process::id()));\n            let _ = std::fs::remove_dir_all(&source);\n            std::fs::create_dir_all(&source).expect(\"create persistent volume source\");\n            std::fs::write(source.join(\"marker\"), b\"volume-marker\\n\")\n                .expect(\"write persistent volume marker\");\n            source\n        })\n        .as_path()\n}\n\nfn syscall_set(names: &[&str]) -> BTreeSet<String> {\n",
    "volume source fixture",
)

replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n",
    "#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {\n    let source = readonly_volume_source().to_path_buf();\n    let forbidden_write = source.join(\"write-must-fail\");\n    let _ = std::fs::remove_file(&forbidden_write);\n    let marker_before = std::fs::read(source.join(\"marker\")).expect(\"read host volume marker\");\n    let source_argument = source.to_string_lossy().into_owned();\n\n    let mut mounted = policy(\n        \"v\",\n        &[source_argument.as_str()],\n        &[\"execveat\", \"openat\", \"read\", \"close\", \"exit\"],\n    );\n    mounted.readonly_volume_source = Some(source.clone());\n    mounted.readonly_volume_target = Some(PathBuf::from(\"/data\"));\n\n    assert_eq!(run(&mounted).unwrap(), ChildOutcome::Exited(0));\n    assert_eq!(\n        std::fs::read(source.join(\"marker\")).expect(\"read host volume marker after run\"),\n        marker_before,\n        \"sandbox changed persistent volume marker\"\n    );\n    assert!(\n        !forbidden_write.exists(),\n        \"sandbox write escaped the read-only persistent volume\"\n    );\n}\n\n#[test]\nfn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {\n",
    "volume integration test",
)

replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\n",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\n#   v read a declared persistent volume, prove it is read-only, and hide its host source path\n",
    "probe mode comment",
)

replace_one(
    "tests/fixtures/probe.S",
    "    cmp $99, %al\n    je .cancellation_tree\n    jmp .fail2\n",
    "    cmp $99, %al\n    je .cancellation_tree\n    cmp $118, %al\n    je .readonly_volume\n    jmp .fail2\n",
    "probe mode dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    "    ret\n\n.forbidden:\n",
    "    ret\n\n.readonly_volume:\n    mov $257, %eax\n    mov $-100, %edi\n    lea volume_marker_path(%rip), %rsi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail30\n    mov %rax, %r12\n\n    xor %eax, %eax\n    mov %r12, %rdi\n    lea volume_buffer(%rip), %rsi\n    mov $volume_marker_len, %edx\n    syscall\n    cmp $volume_marker_len, %rax\n    jne .fail30\n\n    lea volume_buffer(%rip), %rdi\n    lea volume_marker_expected(%rip), %rsi\n    mov $volume_marker_len, %ecx\n    repe cmpsb\n    jne .fail30\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail30\n\n    mov $257, %eax\n    mov $-100, %edi\n    lea volume_forbidden_write(%rip), %rsi\n    mov $577, %edx\n    mov $384, %r10d\n    syscall\n    cmp $-30, %rax\n    jne .fail30\n\n    mov 24(%rsp), %rsi\n    test %rsi, %rsi\n    je .fail30\n    mov $257, %eax\n    mov $-100, %edi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    cmp $-2, %rax\n    jne .fail30\n\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n",
    "volume raw oracle",
)

replace_one(
    "tests/fixtures/probe.S",
    ".fail29:\n    mov $29, %edi\n\n.exit:\n",
    ".fail29:\n    mov $29, %edi\n    jmp .exit\n.fail30:\n    mov $30, %edi\n\n.exit:\n",
    "volume fail label",
)

replace_one(
    "tests/fixtures/probe.S",
    "deadline_message:\n",
    "volume_marker_path:\n    .asciz \"/data/marker\"\nvolume_forbidden_write:\n    .asciz \"/data/write-must-fail\"\nvolume_marker_expected:\n    .ascii \"volume-marker\\n\"\n.set volume_marker_len, . - volume_marker_expected\ndeadline_message:\n",
    "volume rodata",
)

replace_one(
    "tests/fixtures/probe.S",
    "redirect_buffer:\n    .skip 1\n",
    "redirect_buffer:\n    .skip 1\nvolume_buffer:\n    .skip 32\n",
    "volume buffer",
)
