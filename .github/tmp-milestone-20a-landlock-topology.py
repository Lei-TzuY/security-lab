from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# Policy surface: topology mutation is an explicit augmentation of an existing
# regular-file mutation envelope, never an independent writable path grant.
replace_one(
    "src/policy.rs",
    "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_DEVICE_IOCTL_PATHS: usize = 32;",
    "const MAX_LANDLOCK_FILE_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_PATH_TOPOLOGY_MUTATE_PATHS: usize = 32;\nconst MAX_LANDLOCK_DEVICE_IOCTL_PATHS: usize = 32;",
    "policy topology max",
)
replace_one(
    "src/policy.rs",
    "    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Optional Landlock device-ioctl allowlist.",
    "    pub landlock_file_mutate: Vec<PathBuf>,\n    /// Optional Landlock directory/symlink/reparent mutation augmentation. Each\n    /// entry must exactly match an existing `landlock_file_mutate` directory.\n    pub landlock_path_topology_mutate: Vec<PathBuf>,\n    /// Optional Landlock device-ioctl allowlist.",
    "policy topology field",
)
needle = '''        if !self.landlock_file_mutate.is_empty() {
            let mut seen = BTreeSet::new();
            for path in &self.landlock_file_mutate {
                validate_absolute_path("landlock.file_mutate", path)?;
                if path == Path::new("/") {
                    return Err(PolicyError::new(
                        "landlock.file_mutate must not grant the entire sandbox root",
                    ));
                }
                if !seen.insert(path.clone()) {
                    return Err(PolicyError::new(format!(
                        "duplicate landlock.file_mutate path: {}",
                        path.display()
                    )));
                }
                let in_scratch = self.scratch_dir.as_ref() == Some(path);
                let in_writable_volume = self
                    .writable_volume_target
                    .as_ref()
                    .is_some_and(|target| path.starts_with(target));
                if !in_scratch && !in_writable_volume {
                    return Err(PolicyError::new(
                        "landlock.file_mutate must be within filesystem.scratch or volume.writable_target",
                    ));
                }
            }
        }
'''
replacement = needle + '''
        if self.landlock_path_topology_mutate.len() > MAX_LANDLOCK_PATH_TOPOLOGY_MUTATE_PATHS {
            return Err(PolicyError::new(format!(
                "too many landlock.path_topology_mutate paths: {} > {MAX_LANDLOCK_PATH_TOPOLOGY_MUTATE_PATHS}",
                self.landlock_path_topology_mutate.len()
            )));
        }
        if !self.landlock_path_topology_mutate.is_empty() {
            let mut seen = BTreeSet::new();
            for path in &self.landlock_path_topology_mutate {
                validate_absolute_path("landlock.path_topology_mutate", path)?;
                if path == Path::new("/") {
                    return Err(PolicyError::new(
                        "landlock.path_topology_mutate must not grant the entire sandbox root",
                    ));
                }
                if !seen.insert(path.clone()) {
                    return Err(PolicyError::new(format!(
                        "duplicate landlock.path_topology_mutate path: {}",
                        path.display()
                    )));
                }
                if !self.landlock_file_mutate.iter().any(|mutable| mutable == path) {
                    return Err(PolicyError::new(
                        "landlock.path_topology_mutate must exactly match a landlock.file_mutate path",
                    ));
                }
            }
        }
'''
replace_one("src/policy.rs", needle, replacement, "policy topology validation")
replace_one(
    "src/policy.rs",
    "        let mut landlock_file_mutate = Vec::new();\n        let mut landlock_device_ioctl = Vec::new();",
    "        let mut landlock_file_mutate = Vec::new();\n        let mut landlock_path_topology_mutate = Vec::new();\n        let mut landlock_device_ioctl = Vec::new();",
    "policy topology parser state",
)
replace_one(
    "src/policy.rs",
    '                "landlock.file_mutate" => landlock_file_mutate.push(value.to_owned()),\n                "landlock.device_ioctl" => landlock_device_ioctl.push(value.to_owned()),',
    '                "landlock.file_mutate" => landlock_file_mutate.push(value.to_owned()),\n                "landlock.path_topology_mutate" => {\n                    landlock_path_topology_mutate.push(value.to_owned())\n                }\n                "landlock.device_ioctl" => landlock_device_ioctl.push(value.to_owned()),',
    "policy topology parser key",
)
replace_one(
    "src/policy.rs",
    "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_device_ioctl:",
    "            landlock_file_mutate: landlock_file_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_path_topology_mutate: landlock_path_topology_mutate\n                .into_iter()\n                .map(PathBuf::from)\n                .collect(),\n            landlock_device_ioctl:",
    "policy topology construction",
)
replace_one(
    "src/policy.rs",
    '''    #[test]
    fn parses_and_rejects_landlock_device_ioctl_paths() {''',
    '''    #[test]
    fn parses_landlock_path_topology_mutation_paths() {
        let policy: SandboxPolicy = format!(
            "{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.path_topology_mutate = /scratch"
        )
        .parse()
        .unwrap();
        assert_eq!(
            policy.landlock_path_topology_mutate,
            [PathBuf::from("/scratch")]
        );
    }

    #[test]
    fn rejects_unanchored_or_unsafe_landlock_path_topology_mutation() {
        for invalid in [
            format!("{VALID}\\nlandlock.path_topology_mutate = /scratch"),
            format!("{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.path_topology_mutate = /"),
            format!("{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.path_topology_mutate = scratch"),
            format!("{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.path_topology_mutate = /scratch/subdir"),
            format!("{VALID}\\nlandlock.file_mutate = /scratch\\nlandlock.path_topology_mutate = /scratch\\nlandlock.path_topology_mutate = /scratch"),
        ] {
            assert!(invalid.parse::<SandboxPolicy>().is_err());
        }

        let mut oversized = VALID.to_owned();
        for index in 0..=MAX_LANDLOCK_PATH_TOPOLOGY_MUTATE_PATHS {
            oversized.push_str(&format!("\\nlandlock.file_mutate = /persist/path-{index}"));
            oversized.push_str(&format!(
                "\\nlandlock.path_topology_mutate = /persist/path-{index}"
            ));
        }
        oversized.push_str("\\nvolume.writable_source = /srv/state\\nvolume.writable_target = /persist");
        assert!(oversized.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn parses_and_rejects_landlock_device_ioctl_paths() {''',
    "policy topology tests",
)

# Runtime: add only directory/symlink/reparent rights and merge them into the
# same final-mounted-tree rules as the matching regular-file mutation path.
replace_one(
    "src/platform/linux.rs",
    "    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;\n    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;\n    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;\n    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;",
    "    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;\n    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;\n    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;\n    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;\n    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;\n    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;\n    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;\n    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;",
    "runtime topology constants",
)
replace_one(
    "src/platform/linux.rs",
    "    const LANDLOCK_FILE_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE\n        | LANDLOCK_ACCESS_FS_REMOVE_FILE\n        | LANDLOCK_ACCESS_FS_MAKE_REG\n        | LANDLOCK_ACCESS_FS_TRUNCATE;",
    "    const LANDLOCK_FILE_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE\n        | LANDLOCK_ACCESS_FS_REMOVE_FILE\n        | LANDLOCK_ACCESS_FS_MAKE_REG\n        | LANDLOCK_ACCESS_FS_TRUNCATE;\n    const LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_REMOVE_DIR\n        | LANDLOCK_ACCESS_FS_MAKE_DIR\n        | LANDLOCK_ACCESS_FS_MAKE_SYM\n        | LANDLOCK_ACCESS_FS_REFER;",
    "runtime topology rights",
)
replace_one(
    "src/platform/linux.rs",
    "        file_mutate: Vec<CString>,\n        device_ioctl: Vec<CString>,",
    "        file_mutate: Vec<CString>,\n        path_topology_mutate: Vec<CString>,\n        device_ioctl: Vec<CString>,",
    "runtime prepared topology field",
)
replace_one(
    "src/platform/linux.rs",
    "            for path in &policy.landlock_file_mutate {\n                landlock_file_mutate.push(sandbox_relative(path)?);\n            }\n            // Device paths",
    "            for path in &policy.landlock_file_mutate {\n                landlock_file_mutate.push(sandbox_relative(path)?);\n            }\n            let mut landlock_path_topology_mutate =\n                Vec::with_capacity(policy.landlock_path_topology_mutate.len());\n            for path in &policy.landlock_path_topology_mutate {\n                landlock_path_topology_mutate.push(sandbox_relative(path)?);\n            }\n            // Device paths",
    "runtime prepare topology paths",
)
replace_one(
    "src/platform/linux.rs",
    "                    file_mutate: landlock_file_mutate,\n                    device_ioctl: landlock_device_ioctl,",
    "                    file_mutate: landlock_file_mutate,\n                    path_topology_mutate: landlock_path_topology_mutate,\n                    device_ioctl: landlock_device_ioctl,",
    "runtime topology init",
)
replace_one(
    "src/platform/linux.rs",
    "            && policy.landlock_file_mutate.is_empty()\n            && policy.landlock_device_ioctl.is_empty()",
    "            && policy.landlock_file_mutate.is_empty()\n            && policy.landlock_path_topology_mutate.is_empty()\n            && policy.landlock_device_ioctl.is_empty()",
    "runtime preflight no-op topology",
)
replace_one(
    "src/platform/linux.rs",
    "            && landlock.file_mutate.is_empty()\n            && landlock.device_ioctl.is_empty()",
    "            && landlock.file_mutate.is_empty()\n            && landlock.path_topology_mutate.is_empty()\n            && landlock.device_ioctl.is_empty()",
    "runtime ruleset no-op topology",
)
replace_one(
    "src/platform/linux.rs",
    "        if !landlock.file_mutate.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        if !landlock.device_ioctl.is_empty() {",
    "        if !landlock.file_mutate.is_empty() {\n            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;\n        }\n        if !landlock.path_topology_mutate.is_empty() {\n            handled_access_fs |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;\n        }\n        if !landlock.device_ioctl.is_empty() {",
    "runtime handled topology rights",
)
replace_one(
    "src/platform/linux.rs",
    "                allowed_access |= LANDLOCK_FILE_MUTATE_RIGHTS;\n            }\n            let rule = LandlockPathBeneathAttr {",
    "                allowed_access |= LANDLOCK_FILE_MUTATE_RIGHTS;\n                if landlock\n                    .path_topology_mutate\n                    .iter()\n                    .any(|candidate| candidate.as_bytes() == path.as_bytes())\n                {\n                    allowed_access |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;\n                }\n            }\n            let rule = LandlockPathBeneathAttr {",
    "runtime combined read topology rights",
)
replace_one(
    "src/platform/linux.rs",
    "            let rule = LandlockPathBeneathAttr {\n                allowed_access: LANDLOCK_FILE_MUTATE_RIGHTS,\n                parent_fd: path_fd,\n                reserved: 0,\n            };",
    "            let mut allowed_access = LANDLOCK_FILE_MUTATE_RIGHTS;\n            if landlock\n                .path_topology_mutate\n                .iter()\n                .any(|candidate| candidate.as_bytes() == path.as_bytes())\n            {\n                allowed_access |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;\n            }\n            let rule = LandlockPathBeneathAttr {\n                allowed_access,\n                parent_fd: path_fd,\n                reserved: 0,\n            };",
    "runtime mutation topology rights",
)
replace_one(
    "src/platform/linux.rs",
    '            "openat" => libc::SYS_openat,\n            "unlink" => libc::SYS_unlink,\n            "truncate" => libc::SYS_truncate,',
    '            "openat" => libc::SYS_openat,\n            "rename" => libc::SYS_rename,\n            "mkdir" => libc::SYS_mkdir,\n            "rmdir" => libc::SYS_rmdir,\n            "unlink" => libc::SYS_unlink,\n            "symlink" => libc::SYS_symlink,\n            "truncate" => libc::SYS_truncate,',
    "runtime topology syscall mapping",
)

# Integration policy helper and a separate persistent source avoid parallel-test
# interference with the existing regular-file mutation oracle.
replace_one(
    "tests/sandbox.rs",
    "        landlock_file_mutate: Vec::new(),\n        landlock_device_ioctl: Vec::new(),",
    "        landlock_file_mutate: Vec::new(),\n        landlock_path_topology_mutate: Vec::new(),\n        landlock_device_ioctl: Vec::new(),",
    "test policy topology field",
)
replace_one(
    "tests/sandbox.rs",
    '''fn syscall_set(names: &[&str]) -> BTreeSet<String> {''',
    '''fn landlock_topology_source() -> &'static Path {
    static SOURCE: OnceLock<PathBuf> = OnceLock::new();
    SOURCE
        .get_or_init(|| {
            let source = std::env::temp_dir()
                .join(format!("security-lab-landlock-topology-{}", process::id()));
            let _ = std::fs::remove_dir_all(&source);
            std::fs::create_dir_all(source.join("allowed/from"))
                .expect("create Landlock topology source directory");
            std::fs::create_dir_all(source.join("allowed/to"))
                .expect("create Landlock topology destination directory");
            std::fs::create_dir_all(source.join("denied"))
                .expect("create Landlock topology denied directory");
            std::fs::write(
                source.join("allowed/from/item"),
                b"landlock-topology-item\\n",
            )
            .expect("seed Landlock topology rename fixture");
            source
        })
        .as_path()
}

fn syscall_set(names: &[&str]) -> BTreeSet<String> {''',
    "topology source helper",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn landlock_file_mutation_requires_existing_writable_surface() {''',
    '''#[test]
fn landlock_path_topology_mutation_is_scoped_to_declared_directory() {
    let source = landlock_topology_source().to_path_buf();
    let allowed = source.join("allowed");
    let denied = source.join("denied");

    let mut confined = policy(
        "h",
        &[],
        &["execveat", "mkdir", "rmdir", "symlink", "rename", "exit"],
    );
    confined.landlock_read_execute = vec![PathBuf::from("/probe")];
    confined.landlock_file_mutate = vec![PathBuf::from("/persist/allowed")];
    confined.landlock_path_topology_mutate = vec![PathBuf::from("/persist/allowed")];
    confined.writable_volume_source = Some(source.clone());
    confined.writable_volume_target = Some(PathBuf::from("/persist"));

    assert_eq!(run(&confined).unwrap(), ChildOutcome::Exited(0));
    assert_eq!(
        std::fs::read(allowed.join("to/item")).expect("read renamed topology fixture"),
        b"landlock-topology-item\\n",
    );
    assert!(!allowed.join("from/item").exists());
    assert_eq!(
        std::fs::read_link(allowed.join("newlink")).expect("read allowed topology symlink"),
        PathBuf::from("topology-target"),
    );
    assert!(!allowed.join("newdir").exists());
    for denied_path in ["newdir", "newlink", "item"] {
        assert!(
            !denied.join(denied_path).exists(),
            "Landlock topology mutation escaped to denied path {denied_path}"
        );
    }
}

#[test]
fn landlock_file_mutation_requires_existing_writable_surface() {''',
    "topology integration test",
)

# Raw-syscall oracle: positive mkdir/symlink/rename/rmdir inside the declared
# envelope and exact EACCES for equivalent sibling/cross-envelope operations.
replace_one(
    "tests/fixtures/probe.S",
    "#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume\n#   h prove Landlock narrows directory/symlink/reparent topology mutation\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "fixture topology mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $109, %al\n    je .landlock_file_mutation\n    cmp $115, %al",
    "    cmp $109, %al\n    je .landlock_file_mutation\n    cmp $104, %al\n    je .landlock_path_topology_mutation\n    cmp $115, %al",
    "fixture topology dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi
    jmp .exit

.landlock_tcp_ports:''',
    '''    xor %edi, %edi
    jmp .exit

.landlock_path_topology_mutation:
    mov $83, %eax
    lea landlock_topology_allowed_dir(%rip), %rdi
    mov $448, %esi
    syscall
    test %rax, %rax
    js .fail47

    mov $88, %eax
    lea landlock_topology_symlink_target(%rip), %rdi
    lea landlock_topology_allowed_link(%rip), %rsi
    syscall
    test %rax, %rax
    js .fail47

    mov $82, %eax
    lea landlock_topology_rename_source(%rip), %rdi
    lea landlock_topology_rename_destination(%rip), %rsi
    syscall
    test %rax, %rax
    js .fail47

    mov $84, %eax
    lea landlock_topology_allowed_dir(%rip), %rdi
    syscall
    test %rax, %rax
    js .fail47

    mov $83, %eax
    lea landlock_topology_denied_dir(%rip), %rdi
    mov $448, %esi
    syscall
    cmp $-13, %rax
    jne .fail47

    mov $88, %eax
    lea landlock_topology_symlink_target(%rip), %rdi
    lea landlock_topology_denied_link(%rip), %rsi
    syscall
    cmp $-13, %rax
    jne .fail47

    mov $82, %eax
    lea landlock_topology_rename_destination(%rip), %rdi
    lea landlock_topology_denied_rename(%rip), %rsi
    syscall
    cmp $-13, %rax
    jne .fail47

    xor %edi, %edi
    jmp .exit

.landlock_tcp_ports:''',
    "fixture topology implementation",
)
replace_one(
    "tests/fixtures/probe.S",
    '''.fail46:
    mov $46, %edi

.exit:''',
    '''.fail46:
    mov $46, %edi
    jmp .exit
.fail47:
    mov $47, %edi

.exit:''',
    "fixture topology failure code",
)
replace_one(
    "tests/fixtures/probe.S",
    '''landlock_mutation_message:
    .ascii "landlock-persistent-write\\n"
.set landlock_mutation_message_len, . - landlock_mutation_message
deadline_message:''',
    '''landlock_mutation_message:
    .ascii "landlock-persistent-write\\n"
.set landlock_mutation_message_len, . - landlock_mutation_message
landlock_topology_allowed_dir:
    .asciz "/persist/allowed/newdir"
landlock_topology_allowed_link:
    .asciz "/persist/allowed/newlink"
landlock_topology_symlink_target:
    .asciz "topology-target"
landlock_topology_rename_source:
    .asciz "/persist/allowed/from/item"
landlock_topology_rename_destination:
    .asciz "/persist/allowed/to/item"
landlock_topology_denied_dir:
    .asciz "/persist/denied/newdir"
landlock_topology_denied_link:
    .asciz "/persist/denied/newlink"
landlock_topology_denied_rename:
    .asciz "/persist/denied/item"
deadline_message:''',
    "fixture topology paths",
)
