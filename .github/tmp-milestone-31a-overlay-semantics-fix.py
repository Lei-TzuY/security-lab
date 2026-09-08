from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Pin OverlayFS behavior that materially affects whether the private upper tree
# is a self-contained change source. Do not inherit host module/config defaults.
replace_one(
    "src/platform/linux.rs",
    '''        fsconfig_string_or_fail(
            overlay_fsfd,
            b"workdir\\0",
            work_path,
            PHASE_COW_OVERLAY_CREATE,
            launch_error,
            error_exit_syscall,
        );
        if libc::syscall(
''',
    '''        fsconfig_string_or_fail(
            overlay_fsfd,
            b"workdir\\0",
            work_path,
            PHASE_COW_OVERLAY_CREATE,
            launch_error,
            error_exit_syscall,
        );
        fsconfig_string_or_fail(
            overlay_fsfd,
            b"metacopy\\0",
            b"off\\0".as_ptr().cast::<libc::c_char>(),
            PHASE_COW_OVERLAY_CREATE,
            launch_error,
            error_exit_syscall,
        );
        fsconfig_string_or_fail(
            overlay_fsfd,
            b"redirect_dir\\0",
            b"nofollow\\0".as_ptr().cast::<libc::c_char>(),
            PHASE_COW_OVERLAY_CREATE,
            launch_error,
            error_exit_syscall,
        );
        if libc::syscall(
''',
    "explicit overlay semantics",
)

# The raw regression needs one metadata-only operation. This only makes fchmod
# available when a policy explicitly names it; it is never auto-granted.
replace_one(
    "src/platform/linux.rs",
    '''            "openat" => libc::SYS_openat,
            "rename" => libc::SYS_rename,
            "mkdir" => libc::SYS_mkdir,
''',
    '''            "openat" => libc::SYS_openat,
            "fchmod" => libc::SYS_fchmod,
            "rename" => libc::SYS_rename,
            "mkdir" => libc::SYS_mkdir,
''',
    "fchmod syscall mapping",
)

# Seed a lower file used only for metadata-copy-up evidence.
replace_one(
    "tests/sandbox.rs",
    '''        std::fs::write(root.join("cow-base"), b"lower-original\\n")
            .expect("write COW lower base fixture");
        std::fs::write(root.join("cow-dir/child"), b"lower-child\\n")
            .expect("write COW lower child fixture");
''',
    '''        std::fs::write(root.join("cow-base"), b"lower-original\\n")
            .expect("write COW lower base fixture");
        std::fs::write(root.join("cow-meta"), b"lower-metadata\\n")
            .expect("write COW lower metadata fixture");
        std::fs::set_permissions(
            root.join("cow-meta"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("set COW lower metadata fixture mode");
        std::fs::write(root.join("cow-dir/child"), b"lower-child\\n")
            .expect("write COW lower child fixture");
''',
    "COW metadata fixture seed",
)

replace_one(
    "tests/sandbox.rs",
    '''    let base = root.join("cow-base");
    let child = root.join("cow-dir/child");
    let created = root.join("cow-new");
    let _ = std::fs::remove_file(&created);
    assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
    assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");
''',
    '''    let base = root.join("cow-base");
    let metadata_only = root.join("cow-meta");
    let child = root.join("cow-dir/child");
    let created = root.join("cow-new");
    let redirected = root.join("cow-renamed");
    let _ = std::fs::remove_file(&created);
    let _ = std::fs::remove_dir_all(&redirected);
    assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
    assert_eq!(std::fs::read(&metadata_only).unwrap(), b"lower-metadata\\n");
    assert_eq!(
        std::fs::metadata(&metadata_only).unwrap().permissions().mode() & 0o7777,
        0o644
    );
    assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");
''',
    "COW metadata fixture assertions",
)

replace_one(
    "tests/sandbox.rs",
    '''                "execveat", "openat", "read", "write", "close", "unlink", "exit",
''',
    '''                "execveat", "openat", "read", "write", "close", "fchmod", "rename", "unlink",
                "exit",
''',
    "COW exact syscall grants",
)

replace_one(
    "tests/sandbox.rs",
    '''        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            CowDiffEntry::UpsertFile { path, mode, bytes }
                if path == b"/cow-new" && *mode == 0o600 && bytes == b"cow-new\\n"
        )));
''',
    '''        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            CowDiffEntry::UpsertFile { path, mode, bytes }
                if path == b"/cow-new" && *mode == 0o600 && bytes == b"cow-new\\n"
        )));
        assert!(diff.entries.iter().any(|entry| matches!(
            entry,
            CowDiffEntry::UpsertFile { path, mode, bytes }
                if path == b"/cow-meta" && *mode == 0o640 && bytes == b"lower-metadata\\n"
        )));
''',
    "COW metadata-only diff evidence",
)

replace_one(
    "tests/sandbox.rs",
    '''        assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
        assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");
        assert!(!created.exists());
''',
    '''        assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");
        assert_eq!(std::fs::read(&metadata_only).unwrap(), b"lower-metadata\\n");
        assert_eq!(
            std::fs::metadata(&metadata_only).unwrap().permissions().mode() & 0o7777,
            0o644
        );
        assert_eq!(std::fs::read(&child).unwrap(), b"lower-child\\n");
        assert!(!created.exists());
        assert!(!redirected.exists());
''',
    "COW host-lower metadata preservation evidence",
)

# Exercise metadata-only copy-up and require lower-directory rename to retain
# EXDEV semantics, proving redirect_dir is not silently encoding topology in
# an xattr the exporter intentionally omits.
replace_one(
    "tests/fixtures/probe.S",
    '''.copy_on_write_root:
    sub $32, %rsp
''',
    '''.copy_on_write_root:
    sub $32, %rsp

    # Metadata-only mutation must still leave a self-contained upper regular
    # file for the post-run exporter (metacopy is forced off by the launcher).
    mov $257, %eax
    mov $-100, %edi
    lea cow_meta_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov %rax, %r13
    mov $91, %eax
    mov %r13, %rdi
    mov $416, %esi
    syscall
    test %rax, %rax
    js .fail48_cow_stack
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail48_cow_stack

    # A lower/merged directory rename must not be represented through an
    # OverlayFS redirect xattr because redirect_dir is forced to nofollow.
    mov $82, %eax
    lea cow_dir_path(%rip), %rdi
    lea cow_renamed_path(%rip), %rsi
    syscall
    cmp $-18, %rax
    jne .fail48_cow_stack
''',
    "COW raw overlay semantics oracle",
)

replace_one(
    "tests/fixtures/probe.S",
    '''cow_base_path:
    .asciz "/cow-base"
cow_child_path:
    .asciz "/cow-dir/child"
cow_new_path:
    .asciz "/cow-new"
''',
    '''cow_base_path:
    .asciz "/cow-base"
cow_meta_path:
    .asciz "/cow-meta"
cow_dir_path:
    .asciz "/cow-dir"
cow_renamed_path:
    .asciz "/cow-renamed"
cow_child_path:
    .asciz "/cow-dir/child"
cow_new_path:
    .asciz "/cow-new"
''',
    "COW raw overlay semantics paths",
)
