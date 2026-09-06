from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# ---------------- policy model / validation / parser ----------------
replace_one(
    "src/policy.rs",
    "    pub readonly_volume_source: Option<PathBuf>,\n    pub readonly_volume_target: Option<PathBuf>,\n    /// Optional absolute path inside `root_dir` replaced by a private writable\n",
    "    pub readonly_volume_source: Option<PathBuf>,\n    pub readonly_volume_target: Option<PathBuf>,\n    /// Optional trusted host directory deliberately exposed writable at one\n    /// declared sandbox mountpoint. This grants host mutation authority.\n    pub writable_volume_source: Option<PathBuf>,\n    pub writable_volume_target: Option<PathBuf>,\n    /// Optional absolute path inside `root_dir` replaced by a private writable\n",
    "policy writable fields",
)

validation_anchor = '''            _ => {
                return Err(PolicyError::new(
                    "volume.readonly_source and volume.readonly_target must be specified together",
                ));
            }
        }

        match (&self.scratch_dir, self.scratch_bytes) {
'''
validation_replacement = '''            _ => {
                return Err(PolicyError::new(
                    "volume.readonly_source and volume.readonly_target must be specified together",
                ));
            }
        }

        match (&self.writable_volume_source, &self.writable_volume_target) {
            (None, None) => {}
            (Some(source), Some(target)) => {
                validate_absolute_path("volume.writable_source", source)?;
                validate_absolute_path("volume.writable_target", target)?;
                if source == Path::new("/") {
                    return Err(PolicyError::new(
                        "volume.writable_source must not grant the host root",
                    ));
                }
                if target == Path::new("/") {
                    return Err(PolicyError::new(
                        "volume.writable_target must not replace the sandbox root",
                    ));
                }
                if self.executable.starts_with(target) || self.working_dir.starts_with(target) {
                    return Err(PolicyError::new(
                        "volume.writable_target must not contain the executable or working_dir",
                    ));
                }
                if let Some(scratch) = &self.scratch_dir {
                    if target.starts_with(scratch) || scratch.starts_with(target) {
                        return Err(PolicyError::new(
                            "volume.writable_target must not overlap filesystem.scratch",
                        ));
                    }
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "volume.writable_source and volume.writable_target must be specified together",
                ));
            }
        }

        if let (Some(readonly_source), Some(readonly_target), Some(writable_source), Some(writable_target)) = (
            &self.readonly_volume_source,
            &self.readonly_volume_target,
            &self.writable_volume_source,
            &self.writable_volume_target,
        ) {
            if readonly_target.starts_with(writable_target)
                || writable_target.starts_with(readonly_target)
            {
                return Err(PolicyError::new(
                    "read-only and writable volume targets must not overlap",
                ));
            }
            if readonly_source.starts_with(writable_source)
                || writable_source.starts_with(readonly_source)
            {
                return Err(PolicyError::new(
                    "read-only and writable volume sources must not overlap",
                ));
            }
        }

        match (&self.scratch_dir, self.scratch_bytes) {
'''
replace_one("src/policy.rs", validation_anchor, validation_replacement, "policy writable validation")

replace_one(
    "src/policy.rs",
    "        let mut readonly_volume_source = None;\n        let mut readonly_volume_target = None;\n        let mut scratch_dir = None;\n",
    "        let mut readonly_volume_source = None;\n        let mut readonly_volume_target = None;\n        let mut writable_volume_source = None;\n        let mut writable_volume_target = None;\n        let mut scratch_dir = None;\n",
    "parser writable vars",
)
replace_one(
    "src/policy.rs",
    '''                "volume.readonly_target" => {
                    set_once(&mut readonly_volume_target, value.to_owned(), line_no, key)?
                }
                "filesystem.scratch" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,
''',
    '''                "volume.readonly_target" => {
                    set_once(&mut readonly_volume_target, value.to_owned(), line_no, key)?
                }
                "volume.writable_source" => {
                    set_once(&mut writable_volume_source, value.to_owned(), line_no, key)?
                }
                "volume.writable_target" => {
                    set_once(&mut writable_volume_target, value.to_owned(), line_no, key)?
                }
                "filesystem.scratch" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,
''',
    "parser writable keys",
)
replace_one(
    "src/policy.rs",
    "            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n            readonly_volume_target: readonly_volume_target.map(PathBuf::from),\n            scratch_dir: scratch_dir.map(PathBuf::from),\n",
    "            readonly_volume_source: readonly_volume_source.map(PathBuf::from),\n            readonly_volume_target: readonly_volume_target.map(PathBuf::from),\n            writable_volume_source: writable_volume_source.map(PathBuf::from),\n            writable_volume_target: writable_volume_target.map(PathBuf::from),\n            scratch_dir: scratch_dir.map(PathBuf::from),\n",
    "policy writable construction",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.readonly_volume_source, None);\n        assert_eq!(policy.readonly_volume_target, None);\n        assert_eq!(policy.scratch_dir, Some(PathBuf::from(\"/scratch\")));\n",
    "        assert_eq!(policy.readonly_volume_source, None);\n        assert_eq!(policy.readonly_volume_target, None);\n        assert_eq!(policy.writable_volume_source, None);\n        assert_eq!(policy.writable_volume_target, None);\n        assert_eq!(policy.scratch_dir, Some(PathBuf::from(\"/scratch\")));\n",
    "complete policy writable defaults",
)

policy_test_anchor = '''    #[test]
    fn parses_stdout_redirect_inside_scratch() {
'''
policy_test_insert = '''    #[test]
    fn parses_writable_volume_pair() {
        let text = format!(
            "{VALID}\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /persist"
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(
            policy.writable_volume_source,
            Some(PathBuf::from("/srv/state"))
        );
        assert_eq!(
            policy.writable_volume_target,
            Some(PathBuf::from("/persist"))
        );
    }

    #[test]
    fn rejects_incomplete_or_unsafe_writable_volume() {
        let incomplete = format!("{VALID}\\nvolume.writable_source = /srv/state");
        assert!(incomplete.parse::<SandboxPolicy>().is_err());

        let host_root = format!(
            "{VALID}\\nvolume.writable_source = /\\nvolume.writable_target = /persist"
        );
        assert!(host_root.parse::<SandboxPolicy>().is_err());

        let root_target = format!(
            "{VALID}\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /"
        );
        assert!(root_target.parse::<SandboxPolicy>().is_err());

        let hides_cwd = format!(
            "{VALID}\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /tmp"
        );
        assert!(hides_cwd.parse::<SandboxPolicy>().is_err());

        let overlaps_scratch = format!(
            "{VALID}\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /scratch/state"
        );
        assert!(overlaps_scratch.parse::<SandboxPolicy>().is_err());

        let overlaps_readonly_target = format!(
            "{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /data\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /data/state"
        );
        assert!(overlaps_readonly_target.parse::<SandboxPolicy>().is_err());

        let overlaps_readonly_source = format!(
            "{VALID}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /data\\nvolume.writable_source = /srv/data/state\\nvolume.writable_target = /persist"
        );
        assert!(overlaps_readonly_source.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn parses_stdout_redirect_inside_scratch() {
'''
replace_one("src/policy.rs", policy_test_anchor, policy_test_insert, "policy writable tests")

# ---------------- shared prepared-volume runtime ----------------
replace_one(
    "src/platform/linux.rs",
    '''    struct PreparedSelectedHandle {
        storage_fd: OwnedFd,
        target_fd: RawFd,
    }

    impl CapturePipe {
''',
    '''    struct PreparedSelectedHandle {
        storage_fd: OwnedFd,
        target_fd: RawFd,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VolumeAccess {
        ReadOnly,
        Writable,
    }

    struct PreparedVolume {
        source_fd: OwnedFd,
        source_path: CString,
        target_relative: CString,
        access: VolumeAccess,
    }

    impl CapturePipe {
''',
    "prepared volume type",
)
replace_one(
    "src/platform/linux.rs",
    '''        readonly_volume_source_fd: Option<OwnedFd>,
        readonly_volume_source_path: Option<CString>,
        readonly_volume_target_relative: Option<CString>,
        cwd_relative: CString,
''',
    '''        volumes: Vec<PreparedVolume>,
        cwd_relative: CString,
''',
    "prepared launch volume fields",
)

linux = Path("src/platform/linux.rs")
linux_text = linux.read_text()
old_start = linux_text.find("            let (\n                readonly_volume_source_fd,")
old_end_marker = "            let cwd_relative = sandbox_relative(&policy.working_dir)?;\n"
old_end = linux_text.find(old_end_marker, old_start)
if old_start == -1 or old_end == -1:
    raise SystemExit("prepared volume construction block anchor missing")
volume_prepare = '''            let mut volumes = Vec::with_capacity(2);
            match (&policy.readonly_volume_source, &policy.readonly_volume_target) {
                (Some(source), Some(target)) => volumes.push(prepare_volume(
                    root_fd.raw(),
                    source,
                    target,
                    "volume.readonly_source",
                    "read-only volume source",
                    "read-only volume target",
                    VolumeAccess::ReadOnly,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "volume.readonly_source and volume.readonly_target must be specified together",
                    )));
                }
            }
            match (&policy.writable_volume_source, &policy.writable_volume_target) {
                (Some(source), Some(target)) => volumes.push(prepare_volume(
                    root_fd.raw(),
                    source,
                    target,
                    "volume.writable_source",
                    "writable volume source",
                    "writable volume target",
                    VolumeAccess::Writable,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "volume.writable_source and volume.writable_target must be specified together",
                    )));
                }
            }

'''
linux_text = linux_text[:old_start] + volume_prepare + linux_text[old_end:]
linux.write_text(linux_text)

# Add common pre-fork preparation helper before SharedLaunchState.
replace_one(
    "src/platform/linux.rs",
    "    struct SharedLaunchState {\n",
    '''    fn prepare_volume(
        root_fd: RawFd,
        source: &Path,
        target: &Path,
        source_field: &str,
        source_label: &str,
        target_label: &str,
        access: VolumeAccess,
    ) -> Result<PreparedVolume, SandboxError> {
        let source_fd = open_host_directory(source, source_label)?;
        let target_check = open_beneath_root(
            root_fd,
            target,
            (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            target_label,
        )?;
        drop(target_check);
        Ok(PreparedVolume {
            source_fd,
            source_path: cstring_bytes(source_field, source.as_os_str().as_bytes())?,
            target_relative: sandbox_relative(target)?,
            access,
        })
    }

    struct SharedLaunchState {
''',
    "prepare volume helper",
)
replace_one(
    "src/platform/linux.rs",
    '''                cancellation_fd,
                readonly_volume_source_fd,
                readonly_volume_source_path,
                readonly_volume_target_relative,
                cwd_relative,
''',
    '''                cancellation_fd,
                volumes,
                cwd_relative,
''',
    "prepared launch volume init",
)
replace_one(
    "src/platform/linux.rs",
    '''        install_readonly_volume_or_fail(
            prepared,
            root_tree_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );
''',
    '''        for volume in &prepared.volumes {
            install_volume_or_fail(
                volume,
                root_tree_fd,
                launch_error,
                seccomp.error_exit_syscall,
            );
        }
''',
    "install prepared volumes",
)

linux_text = Path("src/platform/linux.rs").read_text()
helper_start = linux_text.find("    unsafe fn install_readonly_volume_or_fail(")
helper_end = linux_text.find("    unsafe fn open_stdout_redirect_or_fail(", helper_start)
if helper_start == -1 or helper_end == -1:
    raise SystemExit("read-only volume helper boundaries missing")
new_helper = '''    unsafe fn install_volume_or_fail(
        volume: &PreparedVolume,
        root_tree_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let source_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let current_source_fd = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            volume.source_path.as_ptr(),
            &source_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if current_source_fd == -1 {
            child_fail(
                launch_error,
                PHASE_VOLUME_SOURCE_REVALIDATE,
                error_exit_syscall,
            );
        }
        let current_source_fd = current_source_fd as RawFd;
        revalidate_fd_identity_or_fail(
            volume.source_fd.raw(),
            current_source_fd,
            PHASE_VOLUME_SOURCE_REVALIDATE,
            launch_error,
            error_exit_syscall,
        );

        let volume_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_source_fd,
            b".\\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if volume_tree_fd == -1 {
            child_fail(launch_error, PHASE_VOLUME_CLONE, error_exit_syscall);
        }
        let volume_tree_fd = volume_tree_fd as RawFd;

        if volume.access == VolumeAccess::ReadOnly {
            let volume_attr = MountAttr {
                attr_set: MOUNT_ATTR_RDONLY,
                attr_clr: 0,
                propagation: 0,
                userns_fd: 0,
            };
            if libc::syscall(
                libc::SYS_mount_setattr,
                volume_tree_fd,
                b"\\0".as_ptr().cast::<libc::c_char>(),
                AT_EMPTY_PATH | AT_RECURSIVE,
                &volume_attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            ) == -1
            {
                child_fail(launch_error, PHASE_VOLUME_READONLY, error_exit_syscall);
            }
        }

        let target_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let target_fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            volume.target_relative.as_ptr(),
            &target_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if target_fd == -1 {
            child_fail(launch_error, PHASE_VOLUME_TARGET_PIN, error_exit_syscall);
        }
        let target_fd = target_fd as RawFd;

        if libc::syscall(
            libc::SYS_move_mount,
            volume_tree_fd,
            b"\\0".as_ptr().cast::<libc::c_char>(),
            target_fd,
            b"\\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);
        }

        for fd in [target_fd, volume_tree_fd, current_source_fd] {
            if libc::close(fd) == -1 {
                child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);
            }
        }
    }

'''
Path("src/platform/linux.rs").write_text(
    linux_text[:helper_start] + new_helper + linux_text[helper_end:]
)
replace_one(
    "src/platform/linux.rs",
    '''            PHASE_VOLUME_SOURCE_REVALIDATE => "read-only volume source revalidation",
            PHASE_VOLUME_CLONE => "detached read-only volume mount clone",
            PHASE_VOLUME_READONLY => "recursive read-only volume attributes",
            PHASE_VOLUME_TARGET_PIN => "read-only volume target pin",
            PHASE_VOLUME_ATTACH => "read-only volume mount attachment",
''',
    '''            PHASE_VOLUME_SOURCE_REVALIDATE => "persistent volume source revalidation",
            PHASE_VOLUME_CLONE => "detached persistent volume mount clone",
            PHASE_VOLUME_READONLY => "recursive read-only volume attributes",
            PHASE_VOLUME_TARGET_PIN => "persistent volume target pin",
            PHASE_VOLUME_ATTACH => "persistent volume mount attachment",
''',
    "volume phase labels",
)

# ---------------- integration fixture / oracle ----------------
replace_one(
    "tests/sandbox.rs",
    '        std::fs::create_dir_all(root.join("data")).expect("create sandbox volume mountpoint");\n',
    '        std::fs::create_dir_all(root.join("data")).expect("create sandbox volume mountpoint");\n        std::fs::create_dir_all(root.join("persist")).expect("create sandbox writable-volume mountpoint");\n',
    "writable target fixture directory",
)
replace_one(
    "tests/sandbox.rs",
    '''fn syscall_set(names: &[&str]) -> BTreeSet<String> {
''',
    '''fn writable_volume_source() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source =
                std::env::temp_dir().join(format!("security-lab-writable-volume-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(&source).expect("create writable persistent volume source");
            source
        })
        .as_path()
}

fn syscall_set(names: &[&str]) -> BTreeSet<String> {
''',
    "writable source fixture",
)
replace_one(
    "tests/sandbox.rs",
    '''        readonly_volume_source: None,
        readonly_volume_target: None,
        scratch_dir: Some(PathBuf::from("/scratch")),
''',
    '''        readonly_volume_source: None,
        readonly_volume_target: None,
        writable_volume_source: None,
        writable_volume_target: None,
        scratch_dir: Some(PathBuf::from("/scratch")),
''',
    "integration policy writable defaults",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {
''',
    '''#[test]
fn writable_persistent_volume_mutates_only_declared_host_tree() {
    let source = writable_volume_source().to_path_buf();
    let persisted = source.join("persisted");
    let _ = std::fs::remove_file(&persisted);
    let root_forbidden = fixture_root().join("root-write-must-fail");
    let _ = std::fs::remove_file(&root_forbidden);
    let source_argument = source.to_string_lossy().into_owned();

    let mut mounted = policy(
        "w",
        &[source_argument.as_str()],
        &["execveat", "openat", "write", "close", "exit"],
    );
    mounted.writable_volume_source = Some(source.clone());
    mounted.writable_volume_target = Some(PathBuf::from("/persist"));

    assert_eq!(run(&mounted).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(&persisted).expect("read persisted host volume output"),
        b"persistent-write\\n",
    );
    assert!(
        !root_forbidden.exists(),
        "writable volume reopened mutation outside its declared target"
    );
}

#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {
''',
    "writable volume integration test",
)

replace_one(
    "tests/fixtures/probe.S",
    "#   v read a declared persistent volume, prove it is read-only, and hide its host source path\n",
    "#   v read a declared persistent volume, prove it is read-only, and hide its host source path\n#   w write through a declared persistent volume while root and host source paths stay confined\n",
    "writable mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $118, %al
    je .readonly_volume
    cmp $70, %al
''',
    '''    cmp $118, %al
    je .readonly_volume
    cmp $119, %al
    je .writable_volume
    cmp $70, %al
''',
    "writable mode dispatch",
)

probe = Path("tests/fixtures/probe.S")
probe_text = probe.read_text()
insert_at = probe_text.find(".forbidden:\n", probe_text.find(".readonly_volume:\n"))
if insert_at == -1:
    raise SystemExit("writable oracle insertion point missing")
writable_oracle = '''.writable_volume:
    mov $257, %eax
    mov $-100, %edi
    lea writable_volume_output(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail33
    mov %rax, %r12

    mov $1, %eax
    mov %r12, %rdi
    lea writable_volume_message(%rip), %rsi
    mov $writable_volume_message_len, %edx
    syscall
    cmp $writable_volume_message_len, %rax
    jne .fail33

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail33

    mov $257, %eax
    mov $-100, %edi
    lea forbidden_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail33

    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail33
    mov $257, %eax
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail33

    xor %edi, %edi
    jmp .exit

'''
probe.write_text(probe_text[:insert_at] + writable_oracle + probe_text[insert_at:])
replace_one(
    "tests/fixtures/probe.S",
    '''.fail32:
    mov $32, %edi

.exit:
''',
    '''.fail32:
    mov $32, %edi
    jmp .exit
.fail33:
    mov $33, %edi

.exit:
''',
    "writable fail label",
)
replace_one(
    "tests/fixtures/probe.S",
    '''volume_marker_expected:
    .ascii "volume-marker\\n"
.set volume_marker_len, . - volume_marker_expected
deadline_message:
''',
    '''volume_marker_expected:
    .ascii "volume-marker\\n"
.set volume_marker_len, . - volume_marker_expected
writable_volume_output:
    .asciz "/persist/persisted"
writable_volume_message:
    .ascii "persistent-write\\n"
.set writable_volume_message_len, . - writable_volume_message
deadline_message:
''',
    "writable fixture rodata",
)
