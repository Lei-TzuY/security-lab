from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Public contract: preserve replay-relevant Unix permission mode bits for
# regular files and directories, while explicitly not claiming every inode
# metadata family.
replace_one(
    "src/report.rs",
    "pub enum CowDiffEntry {\n    UpsertFile { path: Vec<u8>, bytes: Vec<u8> },\n    EnsureDirectory { path: Vec<u8> },\n    Symlink { path: Vec<u8>, target: Vec<u8> },\n    Remove { path: Vec<u8> },\n    OpaqueDirectory { path: Vec<u8> },\n}\n\n/// Complete bounded change-set for an ephemeral copy-on-write root.",
    "pub enum CowDiffEntry {\n    /// Create or replace a regular file with exact content and Unix permission\n    /// bits (`st_mode & 0o7777`). Ownership, timestamps, and xattrs are not exported.\n    UpsertFile {\n        path: Vec<u8>,\n        mode: u32,\n        bytes: Vec<u8>,\n    },\n    /// Ensure a directory exists with the exported Unix permission bits.\n    EnsureDirectory { path: Vec<u8>, mode: u32 },\n    Symlink { path: Vec<u8>, target: Vec<u8> },\n    Remove { path: Vec<u8> },\n    OpaqueDirectory { path: Vec<u8> },\n}\n\n/// Complete bounded content/topology/permission-mode change-set for the\n/// supported ephemeral COW object classes. Ownership, timestamps, and xattrs\n/// are intentionally outside this replay contract.",
    "CowDiff public metadata contract",
)
replace_one(
    "src/report.rs",
    "/// Present exactly when `filesystem.cow_diff_bytes` requested a complete bounded COW export.",
    "/// Present exactly when `filesystem.cow_diff_bytes` requested the bounded COW content/topology/permission-mode export.",
    "RunReport cow diff contract",
)

# Canonical exporter: file payload becomes mode:u32-le + bytes; directory
# payload becomes exactly mode:u32-le. The existing byte budget therefore
# accounts for metadata as part of the canonical encoding.
replace_one(
    "src/platform/linux_cow_diff.rs",
    "                TAG_FILE => CowDiffEntry::UpsertFile {\n                    path,\n                    bytes: payload.to_vec(),\n                },\n                TAG_DIRECTORY if payload.is_empty() => CowDiffEntry::EnsureDirectory { path },",
    "                TAG_FILE if payload.len() >= 4 => {\n                    let mode = u32::from_le_bytes(\n                        payload[..4]\n                            .try_into()\n                            .expect(\"fixed file mode length\"),\n                    );\n                    CowDiffEntry::UpsertFile {\n                        path,\n                        mode,\n                        bytes: payload[4..].to_vec(),\n                    }\n                }\n                TAG_DIRECTORY if payload.len() == 4 => {\n                    let mode = u32::from_le_bytes(\n                        payload\n                            .try_into()\n                            .expect(\"fixed directory mode length\"),\n                    );\n                    CowDiffEntry::EnsureDirectory { path, mode }\n                }",
    "decode COW mode metadata",
)
replace_one(
    "src/platform/linux_cow_diff.rs",
    "        append_record(state, TAG_DIRECTORY, &path[..path_len], &[])?;",
    "        let mode = (stat.st_mode & 0o7777) as u32;\n        let mode_bytes = mode.to_le_bytes();\n        append_record(state, TAG_DIRECTORY, &path[..path_len], &mode_bytes)?;",
    "export directory mode",
)
replace_one(
    "src/platform/linux_cow_diff.rs",
    "        let result = append_file(state, &path[..path_len], fd, stat.st_size as usize);",
    "        let mode = (stat.st_mode & 0o7777) as u32;\n        let result = append_file(\n            state,\n            &path[..path_len],\n            fd,\n            mode,\n            stat.st_size as usize,\n        );",
    "export file mode",
)
replace_one(
    "src/platform/linux_cow_diff.rs",
    "unsafe fn append_file(\n    state: *mut CowDiffState,\n    path: &[u8],\n    fd: libc::c_int,\n    length: usize,\n) -> Result<(), i32> {\n    let payload = reserve_record(state, TAG_FILE, path, length)?;\n    let mut offset = 0usize;\n    while offset < length {\n        let read = libc::syscall(\n            libc::SYS_pread64,\n            fd,\n            payload.add(offset).cast::<libc::c_void>(),\n            length - offset,\n            offset as libc::off_t,\n        );\n        if read == -1 {\n            let errno = *libc::__errno_location();\n            if errno == libc::EINTR {\n                continue;\n            }\n            return Err(errno);\n        }\n        if read == 0 {\n            return Err(libc::EIO);\n        }\n        offset += read as usize;\n    }\n    commit_record(state, RECORD_HEADER_BYTES + path.len() + length);\n    Ok(())\n}",
    "unsafe fn append_file(\n    state: *mut CowDiffState,\n    path: &[u8],\n    fd: libc::c_int,\n    mode: u32,\n    length: usize,\n) -> Result<(), i32> {\n    let payload_len = 4usize.checked_add(length).ok_or(libc::EFBIG)?;\n    let payload = reserve_record(state, TAG_FILE, path, payload_len)?;\n    let mode_bytes = mode.to_le_bytes();\n    ptr::copy_nonoverlapping(mode_bytes.as_ptr(), payload, mode_bytes.len());\n    let data = payload.add(mode_bytes.len());\n    let mut offset = 0usize;\n    while offset < length {\n        let read = libc::syscall(\n            libc::SYS_pread64,\n            fd,\n            data.add(offset).cast::<libc::c_void>(),\n            length - offset,\n            offset as libc::off_t,\n        );\n        if read == -1 {\n            let errno = *libc::__errno_location();\n            if errno == libc::EINTR {\n                continue;\n            }\n            return Err(errno);\n        }\n        if read == 0 {\n            return Err(libc::EIO);\n        }\n        offset += read as usize;\n    }\n    commit_record(state, RECORD_HEADER_BYTES + path.len() + payload_len);\n    Ok(())\n}",
    "encode file mode metadata",
)

# JSON surface: expose mode as the numeric Unix permission-bit value for file
# and directory records. This makes the public CLI contract replayable without
# guessing the creator umask.
replace_one(
    "src/cli_json.rs",
    "        CowDiffEntry::UpsertFile { bytes, .. } => {\n            output.push_str(\",\\\"data_encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"\");\n            push_hex(output, bytes);\n            output.push('\\\"');\n        }\n        CowDiffEntry::Symlink { target, .. } => {",
    "        CowDiffEntry::UpsertFile { mode, bytes, .. } => {\n            output.push_str(\",\\\"mode\\\":\");\n            write!(output, \"{mode}\").expect(\"write to String cannot fail\");\n            output.push_str(\",\\\"data_encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"\");\n            push_hex(output, bytes);\n            output.push('\\\"');\n        }\n        CowDiffEntry::EnsureDirectory { mode, .. } => {\n            output.push_str(\",\\\"mode\\\":\");\n            write!(output, \"{mode}\").expect(\"write to String cannot fail\");\n        }\n        CowDiffEntry::Symlink { target, .. } => {",
    "serialize COW modes",
)
replace_one(
    "src/cli_json.rs",
    "    use security_lab::{CapturedOutput, EnforcementReceipt, ProcessTreeUsage, RunReport};",
    "    use security_lab::{\n        CapturedOutput, CowDiff, EnforcementReceipt, ProcessTreeUsage, RunReport,\n    };",
    "CLI JSON test imports",
)
replace_one(
    "src/cli_json.rs",
    "    #[test]\n    fn serializes_static_validation_scope_explicitly() {",
    "    #[test]\n    fn serializes_cow_diff_permission_modes() {\n        let report = RunReport {\n            outcome: ChildOutcome::Exited(0),\n            stdout: None,\n            cow_diff: Some(CowDiff {\n                entries: vec![\n                    CowDiffEntry::EnsureDirectory {\n                        path: b\"/state\".to_vec(),\n                        mode: 0o750,\n                    },\n                    CowDiffEntry::UpsertFile {\n                        path: b\"/state/item\".to_vec(),\n                        mode: 0o600,\n                        bytes: b\"ok\".to_vec(),\n                    },\n                ],\n                encoded_bytes: 64,\n            }),\n            reaped_descendants: 0,\n            process_tree_usage: ProcessTreeUsage::default(),\n            enforcement: EnforcementReceipt::default(),\n        };\n        let json = report_json(&report);\n        assert!(json.contains(\"\\\"kind\\\":\\\"ensure_directory\\\",\\\"path_encoding\\\":\\\"hex\\\",\\\"path\\\":\\\"2f7374617465\\\",\\\"mode\\\":488\"));\n        assert!(json.contains(\"\\\"kind\\\":\\\"upsert_file\\\",\\\"path_encoding\\\":\\\"hex\\\",\\\"path\\\":\\\"2f73746174652f6974656d\\\",\\\"mode\\\":384,\\\"data_encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"6f6b\\\"\"));\n    }\n\n    #[test]\n    fn serializes_static_validation_scope_explicitly() {",
    "CLI JSON COW mode regression",
)

# Public integration evidence: the raw fixture already creates /cow-new with
# mode 0600, so require the exported record to preserve exactly that mode.
replace_one(
    "tests/sandbox.rs",
    "            CowDiffEntry::UpsertFile { path, bytes }\n                if path == b\"/cow-base\" && bytes == b\"cow-replaced\\n\"",
    "            CowDiffEntry::UpsertFile { path, bytes, .. }\n                if path == b\"/cow-base\" && bytes == b\"cow-replaced\\n\"",
    "existing COW base match",
)
replace_one(
    "tests/sandbox.rs",
    "            CowDiffEntry::UpsertFile { path, bytes }\n                if path == b\"/cow-new\" && bytes == b\"cow-new\\n\"",
    "            CowDiffEntry::UpsertFile { path, mode, bytes }\n                if path == b\"/cow-new\" && *mode == 0o600 && bytes == b\"cow-new\\n\"",
    "COW created file mode regression",
)
