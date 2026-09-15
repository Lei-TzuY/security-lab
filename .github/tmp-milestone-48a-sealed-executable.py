from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: optional exact SHA-256 restriction on the initial executable image.
replace_one(
    "src/policy.rs",
    "    /// Absolute path interpreted inside `root_dir`.\n    pub executable: PathBuf,\n    pub args: Vec<String>,\n",
    "    /// Absolute path interpreted inside `root_dir`.\n    pub executable: PathBuf,\n    /// Optional exact SHA-256 for the bytes of the initial executable image.\n    /// When present, Linux execution uses a verified sealed memfd copy rather\n    /// than executing the mutable host inode directly.\n    pub executable_sha256: Option<[u8; 32]>,\n    pub args: Vec<String>,\n",
    "policy executable digest field",
)
replace_one(
    "src/policy.rs",
    "        let mut hostname = None;\n        let mut executable = None;\n        let mut args = Vec::new();\n",
    "        let mut hostname = None;\n        let mut executable = None;\n        let mut executable_sha256 = None;\n        let mut args = Vec::new();\n",
    "policy parser digest slot",
)
replace_one(
    "src/policy.rs",
    "                \"executable\" => set_once(&mut executable, value.to_owned(), line_no, key)?,\n                \"arg\" => args.push(value.to_owned()),\n",
    "                \"executable\" => set_once(&mut executable, value.to_owned(), line_no, key)?,\n                \"executable.sha256\" => set_once(\n                    &mut executable_sha256,\n                    parse_sha256(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"arg\" => args.push(value.to_owned()),\n",
    "policy parser digest key",
)
replace_one(
    "src/policy.rs",
    "            hostname: required(hostname, \"identity.hostname\")?,\n            executable: PathBuf::from(required(executable, \"executable\")?),\n            args,\n",
    "            hostname: required(hostname, \"identity.hostname\")?,\n            executable: PathBuf::from(required(executable, \"executable\")?),\n            executable_sha256,\n            args,\n",
    "policy construction digest",
)
replace_one(
    "src/policy.rs",
    "fn parse_u64(value: &str, line_no: usize, key: &str) -> Result<u64, PolicyError> {\n",
    "fn parse_sha256(value: &str, line_no: usize, key: &str) -> Result<[u8; 32], PolicyError> {\n    if value.len() != 64 || !value.is_ascii() {\n        return Err(PolicyError::at(\n            line_no,\n            format!(\"{key} must be exactly 64 hexadecimal characters\"),\n        ));\n    }\n    let nibble = |byte: u8| -> Option<u8> {\n        match byte {\n            b'0'..=b'9' => Some(byte - b'0'),\n            b'a'..=b'f' => Some(byte - b'a' + 10),\n            b'A'..=b'F' => Some(byte - b'A' + 10),\n            _ => None,\n        }\n    };\n    let bytes = value.as_bytes();\n    let mut digest = [0u8; 32];\n    for index in 0..32 {\n        let high = nibble(bytes[index * 2]).ok_or_else(|| {\n            PolicyError::at(line_no, format!(\"{key} must contain only hexadecimal characters\"))\n        })?;\n        let low = nibble(bytes[index * 2 + 1]).ok_or_else(|| {\n            PolicyError::at(line_no, format!(\"{key} must contain only hexadecimal characters\"))\n        })?;\n        digest[index] = (high << 4) | low;\n    }\n    Ok(digest)\n}\n\nfn parse_u64(value: &str, line_no: usize, key: &str) -> Result<u64, PolicyError> {\n",
    "policy digest parser helper",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_complete_policy() {\n",
    "    #[test]\n    fn parses_executable_sha256_and_rejects_malformed_digest() {\n        let hex = \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\";\n        let text = format!(\"{VALID}\\nexecutable.sha256 = {hex}\");\n        let policy: SandboxPolicy = text.parse().unwrap();\n        let mut expected = [0u8; 32];\n        for (index, byte) in expected.iter_mut().enumerate() {\n            *byte = if index % 2 == 0 { 0x01 } else { 0x23 };\n        }\n        assert_eq!(policy.executable_sha256.unwrap().len(), 32);\n\n        let short = format!(\"{VALID}\\nexecutable.sha256 = deadbeef\");\n        assert!(short.parse::<SandboxPolicy>().is_err());\n        let bad = format!(\"{VALID}\\nexecutable.sha256 = {}g\", \"0\".repeat(63));\n        assert!(bad.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_complete_policy() {\n",
    "policy digest parser tests",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.hostname, \"security-lab\");\n",
    "        assert_eq!(policy.hostname, \"security-lab\");\n        assert_eq!(policy.executable_sha256, None);\n",
    "complete policy digest default",
)

# Linux runtime: verify bytes while copying into an executable sealed memfd, then
# execute that immutable copy through the existing execveat(AT_EMPTY_PATH) path.
replace_one(
    "src/platform/linux.rs",
    "    use crate::{\n        CancellationToken, CapturedOutput, ChildOutcome, EnforcementReceipt, PolicyError,\n        ProcessTreeUsage, ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n    };\n",
    "    use crate::{\n        CancellationToken, CapturedOutput, ChildOutcome, EnforcementReceipt, PolicyError,\n        ProcessTreeUsage, ResourceLimits, RunReport, SandboxError, SandboxPolicy,\n    };\n    use sha2::{Digest, Sha256};\n",
    "linux sha2 import",
)
replace_one(
    "src/platform/linux.rs",
    "    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;\n    const CLONE_NEWTIME: libc::c_int = 0x0000_0080;\n",
    "    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;\n    const CLONE_NEWTIME: libc::c_int = 0x0000_0080;\n    const MFD_CLOEXEC: libc::c_uint = 0x0001;\n    const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;\n    const MFD_EXEC: libc::c_uint = 0x0010;\n    const MAX_SEALED_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;\n",
    "linux memfd constants",
)
insert_after = """    fn pin_selected_handle(\n        source_fd: u32,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n"""
p = Path("src/platform/linux.rs")
text = p.read_text()
start = text.find(insert_after)
if start < 0:
    raise SystemExit("linux pin_selected_handle anchor missing")
next_fn = text.find("\n    fn connect_host_tcp_ipv4(", start)
if next_fn < 0:
    raise SystemExit("linux connect_host_tcp_ipv4 anchor missing")
helper = r'''

    fn prepare_verified_executable_image(
        root_fd: RawFd,
        path: &Path,
        pinned: OwnedFd,
        expected_sha256: [u8; 32],
    ) -> Result<OwnedFd, SandboxError> {
        let readable = open_beneath_root(
            root_fd,
            path,
            (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            "executable content",
        )?;
        let mut pinned_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let mut readable_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(pinned.raw(), &mut pinned_stat) } == -1
            || unsafe { libc::fstat(readable.raw(), &mut readable_stat) } == -1
        {
            return Err(SandboxError::SetupFailed(format!(
                "cannot inspect executable identity before sealed copy: {}",
                io::Error::last_os_error()
            )));
        }
        if pinned_stat.st_dev != readable_stat.st_dev || pinned_stat.st_ino != readable_stat.st_ino {
            return Err(SandboxError::SetupFailed(
                "executable identity changed before sealed content copy".to_owned(),
            ));
        }
        if readable_stat.st_size < 0 || readable_stat.st_size as u64 > MAX_SEALED_EXECUTABLE_BYTES {
            return Err(SandboxError::SetupFailed(format!(
                "executable image exceeds sealed-copy byte ceiling of {MAX_SEALED_EXECUTABLE_BYTES}"
            )));
        }

        let name = CString::new("security-lab-executable").expect("fixed memfd name has no NUL");
        let raw_memfd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC,
            )
        };
        if raw_memfd == -1 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EPERM) | Some(libc::EACCES)
            ) {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "executable SHA-256 sealing requires executable memfd support: {error}"
                )))
            } else {
                Err(SandboxError::SetupFailed(format!(
                    "cannot create sealed executable memfd: {error}"
                )))
            };
        }
        let memfd = OwnedFd(raw_memfd as RawFd);
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = unsafe {
                libc::read(
                    readable.raw(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!(
                    "cannot read executable for sealed verification: {error}"
                )));
            }
            if read == 0 {
                break;
            }
            let count = read as usize;
            total = total
                .checked_add(count as u64)
                .ok_or_else(|| SandboxError::SetupFailed("sealed executable byte count overflow".to_owned()))?;
            if total > MAX_SEALED_EXECUTABLE_BYTES {
                return Err(SandboxError::SetupFailed(format!(
                    "executable image exceeds sealed-copy byte ceiling of {MAX_SEALED_EXECUTABLE_BYTES}"
                )));
            }
            hasher.update(&buffer[..count]);
            let mut offset = 0usize;
            while offset < count {
                let written = unsafe {
                    libc::write(
                        memfd.raw(),
                        buffer[offset..count].as_ptr().cast::<libc::c_void>(),
                        count - offset,
                    )
                };
                if written == -1 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(SandboxError::SetupFailed(format!(
                        "cannot populate sealed executable memfd: {error}"
                    )));
                }
                if written == 0 {
                    return Err(SandboxError::SetupFailed(
                        "sealed executable memfd write made no progress".to_owned(),
                    ));
                }
                offset += written as usize;
            }
        }
        if total == 0 {
            return Err(SandboxError::SetupFailed(
                "executable image is empty".to_owned(),
            ));
        }
        let actual: [u8; 32] = hasher.finalize().into();
        if actual != expected_sha256 {
            return Err(SandboxError::SetupFailed(
                "executable SHA-256 does not match executable.sha256 policy".to_owned(),
            ));
        }
        if unsafe { libc::fchmod(memfd.raw(), 0o555) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot set sealed executable memfd mode: {}",
                io::Error::last_os_error()
            )));
        }
        let required_seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(memfd.raw(), libc::F_ADD_SEALS, required_seals) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot seal verified executable memfd: {}",
                io::Error::last_os_error()
            )));
        }
        let observed_seals = unsafe { libc::fcntl(memfd.raw(), libc::F_GET_SEALS) };
        if observed_seals == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot verify executable memfd seals: {}",
                io::Error::last_os_error()
            )));
        }
        if observed_seals & required_seals != required_seals {
            return Err(SandboxError::SetupFailed(
                "verified executable memfd is missing required immutable seals".to_owned(),
            ));
        }
        drop(readable);
        drop(pinned);
        Ok(memfd)
    }
'''
text = text[:next_fn] + helper + text[next_fn:]
p.write_text(text)
replace_one(
    "src/platform/linux.rs",
    "            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n\n            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());\n",
    "            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n            let executable_fd = match policy.executable_sha256 {\n                Some(expected_sha256) => prepare_verified_executable_image(\n                    root_fd.raw(),\n                    &policy.executable,\n                    executable_fd,\n                    expected_sha256,\n                )?,\n                None => executable_fd,\n            };\n\n            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());\n",
    "linux choose sealed executable",
)

# Static authority manifest and delta must reflect the new restriction.
replace_one(
    "src/authority_delta.rs",
    "    compare_exact_incomparable(\n        \"execution.executable\",\n        &baseline.executable,\n        &candidate.executable,\n        &mut changes,\n    );\n",
    "    compare_exact_incomparable(\n        \"execution.executable\",\n        &baseline.executable,\n        &candidate.executable,\n        &mut changes,\n    );\n    compare_optional_restriction(\n        \"execution.executable_sha256\",\n        baseline.executable_sha256,\n        candidate.executable_sha256,\n        &mut changes,\n    );\n",
    "authority delta digest restriction",
)
replace_one(
    "src/authority_manifest.rs",
    "    output.push_str(\",\\\"executable\\\":\");\n    push_path(&mut output, &policy.executable);\n    output.push_str(\",\\\"working_dir\\\":\");\n",
    "    output.push_str(\",\\\"executable\\\":\");\n    push_path(&mut output, &policy.executable);\n    output.push_str(\",\\\"executable_sha256\\\":\");\n    match policy.executable_sha256 {\n        Some(digest) => push_json_string(&mut output, &sha256_hex(digest)),\n        None => output.push_str(\"null\"),\n    }\n    output.push_str(\",\\\"working_dir\\\":\");\n",
    "authority manifest json digest",
)
replace_one(
    "src/authority_manifest.rs",
    "    writeln!(&mut output, \"executable: {}\", policy.executable.display())\n        .expect(\"write to String cannot fail\");\n    writeln!(&mut output, \"working-dir: {}\", policy.working_dir.display())\n",
    "    writeln!(&mut output, \"executable: {}\", policy.executable.display())\n        .expect(\"write to String cannot fail\");\n    writeln!(\n        &mut output,\n        \"executable-sha256: {}\",\n        policy\n            .executable_sha256\n            .map(sha256_hex)\n            .unwrap_or_else(|| \"none\".to_owned())\n    )\n    .expect(\"write to String cannot fail\");\n    writeln!(&mut output, \"working-dir: {}\", policy.working_dir.display())\n",
    "authority manifest human digest",
)
replace_one(
    "src/authority_manifest.rs",
    "fn push_bool(output: &mut String, value: bool) {\n",
    "fn sha256_hex(digest: [u8; 32]) -> String {\n    const HEX: &[u8; 16] = b\"0123456789abcdef\";\n    let mut output = String::with_capacity(64);\n    for byte in digest {\n        output.push(HEX[(byte >> 4) as usize] as char);\n        output.push(HEX[(byte & 0x0f) as usize] as char);\n    }\n    output\n}\n\nfn push_bool(output: &mut String, value: bool) {\n",
    "authority manifest digest formatting",
)

# Read-only configured-filesystem preflight verifies a declared executable digest,
# but does not claim memfd runtime support.
replace_one(
    "src/policy_preflight/configured_filesystem_probe.rs",
    "    use security_lab::SandboxPolicy;\n    use std::ffi::CString;\n",
    "    use security_lab::SandboxPolicy;\n    use sha2::{Digest, Sha256};\n    use std::ffi::CString;\n",
    "preflight sha2 import",
)
replace_one(
    "src/policy_preflight/configured_filesystem_probe.rs",
    "    const RESOLVE_BENEATH: u64 = 0x08;\n",
    "    const RESOLVE_BENEATH: u64 = 0x08;\n    const MAX_EXECUTABLE_DIGEST_BYTES: u64 = 64 * 1024 * 1024;\n",
    "preflight executable digest limit",
)
needle = """        if stat.st_mode & 0o111 == 0 {\n            return ConfiguredFilesystemProbe::unavailable(\"executable_execute_bit\", None);\n        }\n\n"""
addition = r'''        if let Some(expected_sha256) = policy.executable_sha256 {
            let readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_digest_open",
                        Some(error),
                    );
                }
            };
            let mut readable_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(readable.raw(), &mut readable_stat) } != 0 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_digest_stat",
                    Some(errno()),
                );
            }
            if readable_stat.st_dev != stat.st_dev || readable_stat.st_ino != stat.st_ino {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_digest_identity",
                    None,
                );
            }
            if readable_stat.st_size < 0
                || readable_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
            {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_digest_size",
                    None,
                );
            }
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = unsafe {
                    libc::read(
                        readable.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        buffer.len(),
                    )
                };
                if read == -1 {
                    let error = errno();
                    if error == libc::EINTR {
                        continue;
                    }
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_digest_read",
                        Some(error),
                    );
                }
                if read == 0 {
                    break;
                }
                total = match total.checked_add(read as u64) {
                    Some(total) if total <= MAX_EXECUTABLE_DIGEST_BYTES => total,
                    _ => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_digest_size",
                            None,
                        );
                    }
                };
                hasher.update(&buffer[..read as usize]);
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected_sha256 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_digest_mismatch",
                    None,
                );
            }
        }

'''
p = Path("src/policy_preflight/configured_filesystem_probe.rs")
text = p.read_text()
if text.count(needle) != 1:
    raise SystemExit("preflight executable validation anchor mismatch")
p.write_text(text.replace(needle, needle + addition, 1))

# Integration fixture policy helper and deterministic correct/mismatch evidence.
replace_one(
    "tests/sandbox.rs",
    "use security_lab::{\n",
    "use sha2::{Digest, Sha256};\nuse security_lab::{\n",
    "sandbox test sha2 import",
)
replace_one(
    "tests/sandbox.rs",
    "        executable: PathBuf::from(\"/probe\"),\n        args,\n",
    "        executable: PathBuf::from(\"/probe\"),\n        executable_sha256: None,\n        args,\n",
    "sandbox test policy digest default",
)
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn raw_fixture_dispatch_modes_are_unique() {\n",
    "fn fixture_executable_sha256() -> [u8; 32] {\n    let bytes = std::fs::read(fixture_root().join(\"probe\")).expect(\"read raw fixture executable\");\n    Sha256::digest(bytes).into()\n}\n\n#[test]\nfn executable_sha256_runs_verified_sealed_image_and_mismatch_fails_closed() {\n    let mut verified = policy(\"X\", &[], &[\"execveat\", \"exit\"]);\n    verified.executable_sha256 = Some(fixture_executable_sha256());\n    assert_eq!(run(&verified).unwrap(), ChildOutcome::Exited(42));\n\n    let mut mismatch = verified;\n    let mut wrong = mismatch.executable_sha256.expect(\"digest configured\");\n    wrong[0] ^= 0x80;\n    mismatch.executable_sha256 = Some(wrong);\n    match run(&mismatch).unwrap_err() {\n        SandboxError::SetupFailed(message) => {\n            assert!(message.contains(\"executable SHA-256 does not match\"));\n        }\n        other => panic!(\"unexpected executable digest mismatch result: {other}\"),\n    }\n}\n\n#[test]\nfn raw_fixture_dispatch_modes_are_unique() {\n",
    "sandbox executable digest integration test",
)
