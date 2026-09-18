from pathlib import Path

def replace_one(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# Shared strict ELF64/x86_64 PT_INTERP reader. Both the library runtime and
# the CLI preflight compile this same source file in their own crate root.
Path("src/elf_interpreter.rs").write_text(r'''use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const PT_INTERP: u32 = 3;
const PN_XNUM: u16 = 0xffff;
const MAX_INTERPRETER_BYTES: usize = 4096;

#[derive(Debug)]
pub(crate) struct ElfInterpreterError(String);

impl fmt::Display for ElfInterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn pread_exact(fd: RawFd, offset: u64, buffer: &mut [u8]) -> Result<(), ElfInterpreterError> {
    let mut done = 0usize;
    while done < buffer.len() {
        let absolute = offset
            .checked_add(done as u64)
            .ok_or_else(|| ElfInterpreterError("ELF read offset overflow".to_owned()))?;
        if absolute > libc::off_t::MAX as u64 {
            return Err(ElfInterpreterError("ELF read offset exceeds off_t".to_owned()));
        }
        let read = unsafe {
            libc::pread(
                fd,
                buffer[done..].as_mut_ptr().cast::<libc::c_void>(),
                buffer.len() - done,
                absolute as libc::off_t,
            )
        };
        if read == -1 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(ElfInterpreterError(format!("ELF pread failed: {error}")));
        }
        if read == 0 {
            return Err(ElfInterpreterError("ELF file ended unexpectedly".to_owned()));
        }
        done += read as usize;
    }
    Ok(())
}

pub(crate) fn read_elf64_x86_64_pt_interp(
    fd: RawFd,
) -> Result<Option<Vec<u8>>, ElfInterpreterError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } == -1 {
        return Err(ElfInterpreterError(format!(
            "cannot stat ELF image: {}",
            io::Error::last_os_error()
        )));
    }
    if stat.st_size < ELF_HEADER_BYTES as i64 {
        return Err(ElfInterpreterError("ELF image is smaller than its header".to_owned()));
    }
    let file_size = stat.st_size as u64;

    let mut header = [0u8; ELF_HEADER_BYTES];
    pread_exact(fd, 0, &mut header)?;
    if &header[0..4] != b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || read_u16(&header[18..20]) != 62
        || read_u32(&header[20..24]) != 1
    {
        return Err(ElfInterpreterError(
            "expected little-endian ELF64 x86_64 executable image".to_owned(),
        ));
    }

    let phoff = read_u64(&header[32..40]);
    let phentsize = read_u16(&header[54..56]);
    let phnum = read_u16(&header[56..58]);
    if phnum == PN_XNUM {
        return Err(ElfInterpreterError(
            "extended ELF program-header counts are not supported".to_owned(),
        ));
    }
    if phnum == 0 {
        return Ok(None);
    }
    if phentsize as usize != ELF64_PROGRAM_HEADER_BYTES {
        return Err(ElfInterpreterError(format!(
            "unexpected ELF64 program-header size {phentsize}"
        )));
    }
    let table_bytes = u64::from(phnum)
        .checked_mul(ELF64_PROGRAM_HEADER_BYTES as u64)
        .and_then(|bytes| phoff.checked_add(bytes))
        .ok_or_else(|| ElfInterpreterError("ELF program-header table overflow".to_owned()))?;
    if table_bytes > file_size {
        return Err(ElfInterpreterError(
            "ELF program-header table extends beyond the file".to_owned(),
        ));
    }

    let mut found = None;
    for index in 0..u64::from(phnum) {
        let offset = phoff + index * ELF64_PROGRAM_HEADER_BYTES as u64;
        let mut ph = [0u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(fd, offset, &mut ph)?;
        if read_u32(&ph[0..4]) != PT_INTERP {
            continue;
        }
        if found.is_some() {
            return Err(ElfInterpreterError(
                "ELF image contains more than one PT_INTERP segment".to_owned(),
            ));
        }
        let interp_offset = read_u64(&ph[8..16]);
        let interp_size = read_u64(&ph[32..40]);
        if interp_size < 2 || interp_size > MAX_INTERPRETER_BYTES as u64 {
            return Err(ElfInterpreterError(format!(
                "PT_INTERP size {interp_size} is outside 2..={MAX_INTERPRETER_BYTES}"
            )));
        }
        let interp_end = interp_offset
            .checked_add(interp_size)
            .ok_or_else(|| ElfInterpreterError("PT_INTERP range overflow".to_owned()))?;
        if interp_end > file_size {
            return Err(ElfInterpreterError(
                "PT_INTERP extends beyond the ELF image".to_owned(),
            ));
        }
        let mut bytes = vec![0u8; interp_size as usize];
        pread_exact(fd, interp_offset, &mut bytes)?;
        if bytes.last().copied() != Some(0) {
            return Err(ElfInterpreterError(
                "PT_INTERP is not NUL terminated".to_owned(),
            ));
        }
        bytes.pop();
        if bytes.is_empty() || bytes[0] != b'/' || bytes.contains(&0) {
            return Err(ElfInterpreterError(
                "PT_INTERP must be one absolute NUL-free path".to_owned(),
            ));
        }
        found = Some(bytes);
    }
    Ok(found)
}
''')

Path("tests/fixtures/dynamic_probe.S").write_text(r'''.global _start
.section .text
_start:
    # Open the interpreter path after the loader transfers control.
    mov $257, %rax
    mov $-100, %rdi
    lea loader_path(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall
    test %rax, %rax
    js .fail

    mov %rax, %r12

    # F_GET_SEALS must show immutable memfd seals through /loader.
    mov $72, %rax
    mov %r12, %rdi
    mov $1034, %rsi
    xor %rdx, %rdx
    syscall
    test %rax, %rax
    js .fail_close
    mov %rax, %r13
    and $15, %r13
    cmp $15, %r13
    jne .fail_close

    mov $3, %rax
    mov %r12, %rdi
    syscall

    mov $60, %rax
    mov $73, %rdi
    syscall

.fail_close:
    mov $3, %rax
    mov %r12, %rdi
    syscall
.fail:
    mov $60, %rax
    mov $74, %rdi
    syscall

.section .rodata
loader_path:
    .asciz "/loader"
''')

replace_one("src/lib.rs", "mod cancellation;\n", "mod cancellation;\n#[cfg(all(target_os = \"linux\", target_arch = \"x86_64\"))]\nmod elf_interpreter;\n", "lib ELF module")
replace_one("src/main.rs", "mod authority_manifest;\n", "mod authority_manifest;\n#[cfg(all(target_os = \"linux\", target_arch = \"x86_64\"))]\nmod elf_interpreter;\n", "binary ELF module")

# Policy surface.
replace_one(
    "src/policy.rs",
    "    pub executable_sha256: Option<[u8; 32]>,\n    pub args: Vec<String>,",
    "    pub executable_sha256: Option<[u8; 32]>,\n    /// Optional exact PT_INTERP path plus SHA-256 binding for a dynamic ELF loader.\n    /// The pair is valid only with executable.sha256, so the declaring ELF image\n    /// and its interpreter request are both content-bound.\n    pub executable_interpreter: Option<PathBuf>,\n    pub executable_interpreter_sha256: Option<[u8; 32]>,\n    pub args: Vec<String>,",
    "policy fields",
)
replace_one(
    "src/policy.rs",
    "        validate_absolute_path(\"working_dir\", &self.working_dir)?;\n\n        if let Some(bytes) = self.cow_root_bytes {",
    '''        validate_absolute_path("working_dir", &self.working_dir)?;

        match (
            &self.executable_interpreter,
            self.executable_interpreter_sha256,
        ) {
            (None, None) => {}
            (Some(path), Some(_)) => {
                validate_absolute_path("executable.interpreter", path)?;
                if self.executable_sha256.is_none() {
                    return Err(PolicyError::new(
                        "executable.interpreter requires executable.sha256 so PT_INTERP is read from a content-bound main image",
                    ));
                }
                if path == Path::new("/") {
                    return Err(PolicyError::new(
                        "executable.interpreter must not replace the sandbox root",
                    ));
                }
                if path == &self.executable {
                    return Err(PolicyError::new(
                        "executable.interpreter must differ from executable",
                    ));
                }
                let overlaps = |other: &Path| path.starts_with(other) || other.starts_with(path);
                if self.procfs_enabled && overlaps(Path::new("/proc")) {
                    return Err(PolicyError::new(
                        "executable.interpreter must not overlap filesystem.proc",
                    ));
                }
                for (other, label) in [
                    (self.scratch_dir.as_deref(), "filesystem.scratch"),
                    (
                        self.readonly_volume_target.as_deref(),
                        "volume.readonly_target",
                    ),
                    (
                        self.writable_volume_target.as_deref(),
                        "volume.writable_target",
                    ),
                ] {
                    if let Some(other) = other {
                        if overlaps(other) {
                            return Err(PolicyError::new(format!(
                                "executable.interpreter must not overlap {label}"
                            )));
                        }
                    }
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "executable.interpreter and executable.interpreter_sha256 must be specified together",
                ));
            }
        }

        if let Some(bytes) = self.cow_root_bytes {''',
    "policy interpreter validation",
)
replace_one(
    "src/policy.rs",
    "        let mut executable_sha256 = None;\n        let mut args = Vec::new();",
    "        let mut executable_sha256 = None;\n        let mut executable_interpreter = None;\n        let mut executable_interpreter_sha256 = None;\n        let mut args = Vec::new();",
    "policy parser vars",
)
replace_one(
    "src/policy.rs",
    '''                "executable.sha256" => set_once(
                    &mut executable_sha256,
                    parse_sha256(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "arg" => args.push(value.to_owned()),''',
    '''                "executable.sha256" => set_once(
                    &mut executable_sha256,
                    parse_sha256(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "executable.interpreter" => {
                    set_once(&mut executable_interpreter, value.to_owned(), line_no, key)?
                }
                "executable.interpreter_sha256" => set_once(
                    &mut executable_interpreter_sha256,
                    parse_sha256(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "arg" => args.push(value.to_owned()),''',
    "policy parser keys",
)
replace_one(
    "src/policy.rs",
    "            executable_sha256,\n            args,",
    "            executable_sha256,\n            executable_interpreter: executable_interpreter.map(PathBuf::from),\n            executable_interpreter_sha256,\n            args,",
    "policy constructor fields",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.executable_sha256, None);\n        assert!(!policy.loopback_enabled);",
    "        assert_eq!(policy.executable_sha256, None);\n        assert_eq!(policy.executable_interpreter, None);\n        assert_eq!(policy.executable_interpreter_sha256, None);\n        assert!(!policy.loopback_enabled);",
    "policy default assertions",
)
marker = '''    #[test]
    fn parses_complete_policy() {'''
insert = r'''    #[test]
    fn interpreter_binding_requires_complete_content_bound_pair() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let complete = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}"
        );
        let policy: SandboxPolicy = complete.parse().unwrap();
        assert_eq!(
            policy.executable_interpreter,
            Some(PathBuf::from("/loader"))
        );
        assert_eq!(policy.executable_interpreter_sha256, policy.executable_sha256);

        let no_main_digest = format!(
            "{VALID}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}"
        );
        assert!(no_main_digest.parse::<SandboxPolicy>().is_err());

        let missing_digest =
            format!("{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /loader");
        assert!(missing_digest.parse::<SandboxPolicy>().is_err());

        let overlap_scratch = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /scratch/loader\nexecutable.interpreter_sha256 = {digest}"
        );
        assert!(overlap_scratch.parse::<SandboxPolicy>().is_err());
    }

'''
replace_one("src/policy.rs", marker, insert + marker, "policy interpreter tests")

# Static authority surfaces.
replace_one(
    "src/authority_manifest.rs",
    '''    match policy.executable_sha256 {
        Some(digest) => push_json_string(&mut output, &sha256_hex(digest)),
        None => output.push_str("null"),
    }
    output.push_str(",\\"working_dir\\":");''',
    '''    match policy.executable_sha256 {
        Some(digest) => push_json_string(&mut output, &sha256_hex(digest)),
        None => output.push_str("null"),
    }
    output.push_str(",\\"executable_interpreter\\":");
    match &policy.executable_interpreter {
        Some(path) => push_path(&mut output, path),
        None => output.push_str("null"),
    }
    output.push_str(",\\"executable_interpreter_sha256\\":");
    match policy.executable_interpreter_sha256 {
        Some(digest) => push_json_string(&mut output, &sha256_hex(digest)),
        None => output.push_str("null"),
    }
    output.push_str(",\\"working_dir\\":");''',
    "manifest JSON interpreter",
)
replace_one(
    "src/authority_manifest.rs",
    '''    )
    .expect("write to String cannot fail");
    writeln!(&mut output, "working-dir: {}", policy.working_dir.display())''',
    '''    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "executable-interpreter: {}",
        policy
            .executable_interpreter
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_owned())
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "executable-interpreter-sha256: {}",
        policy
            .executable_interpreter_sha256
            .map(sha256_hex)
            .unwrap_or_else(|| "none".to_owned())
    )
    .expect("write to String cannot fail");
    writeln!(&mut output, "working-dir: {}", policy.working_dir.display())''',
    "manifest human interpreter",
)
replace_one(
    "src/authority_delta.rs",
    '''    compare_optional_restriction(
        "execution.executable_sha256",
        baseline.executable_sha256,
        candidate.executable_sha256,
        &mut changes,
    );
    compare_exact_incomparable(''',
    '''    compare_optional_restriction(
        "execution.executable_sha256",
        baseline.executable_sha256,
        candidate.executable_sha256,
        &mut changes,
    );
    compare_optional_restriction(
        "execution.executable_interpreter_binding",
        baseline
            .executable_interpreter
            .as_ref()
            .zip(baseline.executable_interpreter_sha256.as_ref()),
        candidate
            .executable_interpreter
            .as_ref()
            .zip(candidate.executable_interpreter_sha256.as_ref()),
        &mut changes,
    );
    compare_exact_incomparable(''',
    "authority delta interpreter",
)

# CLI manifest/delta regressions.
replace_one(
    "tests/authority_manifest_cli.rs",
    '''    assert!(stdout.contains("\\"executable_sha256\\":\\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\""));
    assert!(stdout.contains("\\"argument_count\\":1,\\"environment_keys\\":[\\"SECRET_TOKEN\\"]"));''',
    '''    assert!(stdout.contains("\\"executable_sha256\\":\\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\\""));
    assert!(stdout.contains("\\"executable_interpreter\\":null"));
    assert!(stdout.contains("\\"executable_interpreter_sha256\\":null"));
    assert!(stdout.contains("\\"argument_count\\":1,\\"environment_keys\\":[\\"SECRET_TOKEN\\"]"));''',
    "manifest CLI null interpreter",
)
delta_marker = '''#[test]
fn execution_identity_change_is_incomparable() {'''
delta_test = r'''#[test]
fn interpreter_binding_is_modeled_as_an_exact_execution_restriction() {
    let root = unique_absent_root("interpreter-binding");
    let baseline_text = base_policy(&root);
    let main_digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let loader_digest = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let changed_digest = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let restricted_text = format!(
        "{baseline_text}executable.sha256 = {main_digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {loader_digest}\n"
    );
    let changed_text = format!(
        "{baseline_text}executable.sha256 = {main_digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {changed_digest}\n"
    );

    let baseline = TempPolicy::new("baseline-interpreter", &format!(
        "{baseline_text}executable.sha256 = {main_digest}\n"
    ));
    let restricted = TempPolicy::new("restricted-interpreter", &restricted_text);
    let changed = TempPolicy::new("changed-interpreter", &changed_text);

    let reduced = run_json(&baseline, &restricted);
    assert_eq!(reduced.status.code(), Some(0));
    let stdout = String::from_utf8(reduced.stdout).expect("utf8 output");
    assert!(stdout.contains(r#""field":"execution.executable_interpreter_binding","class":"reduced""#));

    let widened = run_json(&restricted, &baseline);
    assert_eq!(widened.status.code(), Some(5));
    let stdout = String::from_utf8(widened.stdout).expect("utf8 output");
    assert!(stdout.contains(r#""field":"execution.executable_interpreter_binding","class":"widened""#));

    let incomparable = run_json(&restricted, &changed);
    assert_eq!(incomparable.status.code(), Some(6));
    let stdout = String::from_utf8(incomparable.stdout).expect("utf8 output");
    assert!(stdout.contains(r#""field":"execution.executable_interpreter_binding","class":"incomparable""#));
}

'''
replace_one("tests/authority_delta_cli.rs", delta_marker, delta_test + delta_marker, "delta CLI interpreter")

# Preflight checks the exact declared PT_INTERP and loader digest without launching.
replace_one(
    "src/policy_preflight/configured_filesystem_probe.rs",
    "    use super::ConfiguredFilesystemProbe;\n    use security_lab::SandboxPolicy;",
    "    use super::ConfiguredFilesystemProbe;\n    use crate::elf_interpreter;\n    use security_lab::SandboxPolicy;",
    "preflight ELF import",
)
replace_one(
    "src/policy_preflight/configured_filesystem_probe.rs",
    "    use std::os::unix::ffi::OsStrExt;\n    use std::path::Path;",
    "    use std::os::unix::ffi::OsStrExt;\n    use std::path::Path;",
    "preflight osstr import already present",
)
needle = '''        if let Err(result) =
            require_beneath_directory(root.raw(), &policy.working_dir, "working_dir_open")
        {'''
interp_probe = r'''        if let (Some(interpreter), Some(expected_sha256)) = (
            &policy.executable_interpreter,
            policy.executable_interpreter_sha256,
        ) {
            let executable_readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_elf_open",
                        Some(error),
                    );
                }
            };
            let declared = match elf_interpreter::read_elf64_x86_64_pt_interp(
                executable_readable.raw(),
            ) {
                Ok(Some(path)) => path,
                Ok(None) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_missing",
                        None,
                    );
                }
                Err(_) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_elf",
                        None,
                    );
                }
            };
            if declared.as_slice() != interpreter.as_os_str().as_bytes() {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_path_mismatch",
                    None,
                );
            }

            let loader = match open_beneath(
                root.raw(),
                interpreter,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_open",
                        Some(error),
                    );
                }
            };
            let mut loader_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(loader.raw(), &mut loader_stat) } != 0 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_stat",
                    Some(errno()),
                );
            }
            if loader_stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || loader_stat.st_mode & 0o111 == 0
                || loader_stat.st_size <= 0
                || loader_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
            {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_shape",
                    None,
                );
            }
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = unsafe {
                    libc::read(
                        loader.raw(),
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
                        "executable_interpreter_digest_read",
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
                            "executable_interpreter_digest_size",
                            None,
                        );
                    }
                };
                hasher.update(&buffer[..read as usize]);
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected_sha256 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_digest_mismatch",
                    None,
                );
            }
        }

'''
replace_one("src/policy_preflight/configured_filesystem_probe.rs", needle, interp_probe + needle, "preflight interpreter probe")

# Linux runtime: strict PT_INTERP match, immutable loader memfd, private bind mount.
replace_one(
    "src/platform/linux.rs",
    "    use super::cow_diff::{CowDiffState, SharedCowDiff};",
    "    use super::cow_diff::{CowDiffState, SharedCowDiff};\n    use crate::elf_interpreter;",
    "linux ELF import",
)
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_COW_DIFF_EXPORT: u32 = 65;\n",
    "    const PHASE_COW_DIFF_EXPORT: u32 = 65;\n    const PHASE_INTERPRETER_CLONE: u32 = 66;\n    const PHASE_INTERPRETER_TARGET_PIN: u32 = 67;\n    const PHASE_INTERPRETER_READONLY: u32 = 68;\n    const PHASE_INTERPRETER_ATTACH: u32 = 69;\n",
    "interpreter phases",
)
replace_one(
    "src/platform/linux.rs",
    '''    struct PreparedVolume {
        source_fd: OwnedFd,
        source_path: CString,
        target_relative: CString,
        access: VolumeAccess,
    }
''',
    '''    struct PreparedVolume {
        source_fd: OwnedFd,
        source_path: CString,
        target_relative: CString,
        access: VolumeAccess,
    }

    struct PreparedInterpreter {
        image_fd: OwnedFd,
        target_relative: CString,
    }
''',
    "prepared interpreter struct",
)
# Generalize sealed-image helper labels while preserving main-executable wording.
replace_one(
    "src/platform/linux.rs",
    '''    fn prepare_verified_executable_image(
        root_fd: RawFd,
        path: &Path,
        pinned: OwnedFd,
        expected_sha256: [u8; 32],
    ) -> Result<OwnedFd, SandboxError> {''',
    '''    fn prepare_verified_executable_image(
        root_fd: RawFd,
        path: &Path,
        pinned: OwnedFd,
        expected_sha256: [u8; 32],
        image_label: &str,
        policy_field: &str,
        memfd_name: &str,
    ) -> Result<OwnedFd, SandboxError> {''',
    "sealed helper signature",
)
for old,new,label in [
    ("cannot inspect executable identity before sealed copy", "cannot inspect {image_label} identity before sealed copy", "sealed identity label"),
    ("executable identity changed before sealed content copy", "{image_label} identity changed before sealed content copy", "sealed identity changed label"),
    ("executable image exceeds sealed-copy byte ceiling of {MAX_SEALED_EXECUTABLE_BYTES}", "{image_label} image exceeds sealed-copy byte ceiling of {MAX_SEALED_EXECUTABLE_BYTES}", "sealed size label 1"),
    ("cannot read executable for sealed verification: {error}", "cannot read {image_label} for sealed verification: {error}", "sealed read label"),
    ("sealed executable byte count overflow", "sealed {image_label} byte count overflow", "sealed overflow label"),
    ("executable image is empty", "{image_label} image is empty", "sealed empty label"),
    ("executable SHA-256 does not match executable.sha256 policy", "{image_label} SHA-256 does not match {policy_field} policy", "sealed mismatch label"),
    ("cannot set sealed executable memfd mode", "cannot set sealed {image_label} memfd mode", "sealed chmod label"),
    ("cannot seal verified executable memfd", "cannot seal verified {image_label} memfd", "sealed add seals label"),
    ("cannot verify executable memfd seals", "cannot verify {image_label} memfd seals", "sealed get seals label"),
    ("verified executable memfd is missing required immutable seals", "verified {image_label} memfd is missing required immutable seals", "sealed missing seals label"),
]:
    p=Path("src/platform/linux.rs"); t=p.read_text()
    if t.count(old) < 1:
        raise SystemExit(f"{label}: no match")
    p.write_text(t.replace(old,new))
replace_one(
    "src/platform/linux.rs",
    '''        let name = CString::new("security-lab-executable").expect("fixed memfd name has no NUL");''',
    '''        let name = CString::new(memfd_name).map_err(|_| {
            SandboxError::SetupFailed(format!("invalid sealed {image_label} memfd name"))
        })?;''',
    "sealed memfd name",
)
replace_one(
    "src/platform/linux.rs",
    '''                    "executable SHA-256 sealing requires executable memfd support: {error}"''',
    '''                    "{image_label} SHA-256 sealing requires executable memfd support: {error}"''',
    "sealed support label",
)
# Main call plus interpreter preparation.
replace_one(
    "src/platform/linux.rs",
    '''                Some(expected_sha256) => prepare_verified_executable_image(
                    root_fd.raw(),
                    &policy.executable,
                    executable_fd,
                    expected_sha256,
                )?,''',
    '''                Some(expected_sha256) => prepare_verified_executable_image(
                    root_fd.raw(),
                    &policy.executable,
                    executable_fd,
                    expected_sha256,
                    "executable",
                    "executable.sha256",
                    "security-lab-executable",
                )?,''',
    "main sealed helper call",
)
replace_one(
    "src/platform/linux.rs",
    '''            };

            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());''',
    r'''            };

            let interpreter = match (
                &policy.executable_interpreter,
                policy.executable_interpreter_sha256,
            ) {
                (Some(path), Some(expected_sha256)) => {
                    let declared = elf_interpreter::read_elf64_x86_64_pt_interp(
                        executable_fd.raw(),
                    )
                    .map_err(|error| {
                        SandboxError::SetupFailed(format!(
                            "cannot parse content-bound executable PT_INTERP: {error}"
                        ))
                    })?
                    .ok_or_else(|| {
                        SandboxError::SetupFailed(
                            "executable.interpreter was declared but the content-bound executable has no PT_INTERP"
                                .to_owned(),
                        )
                    })?;
                    if declared.as_slice() != path.as_os_str().as_bytes() {
                        return Err(SandboxError::SetupFailed(format!(
                            "content-bound executable PT_INTERP {:?} does not match executable.interpreter {}",
                            String::from_utf8_lossy(&declared),
                            path.display()
                        )));
                    }
                    let pinned = open_beneath_root(
                        root_fd.raw(),
                        path,
                        (libc::O_PATH | libc::O_CLOEXEC) as u64,
                        "ELF interpreter",
                    )?;
                    validate_executable_fd(pinned.raw(), path)?;
                    let image_fd = prepare_verified_executable_image(
                        root_fd.raw(),
                        path,
                        pinned,
                        expected_sha256,
                        "ELF interpreter",
                        "executable.interpreter_sha256",
                        "security-lab-interpreter",
                    )?;
                    Some(PreparedInterpreter {
                        image_fd,
                        target_relative: sandbox_relative(path)?,
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "executable.interpreter and executable.interpreter_sha256 must be specified together",
                    )));
                }
            };

            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());''',
    "runtime interpreter prepare",
)
replace_one(
    "src/platform/linux.rs",
    "        executable_fd: OwnedFd,\n        selected_handles:",
    "        executable_fd: OwnedFd,\n        interpreter: Option<PreparedInterpreter>,\n        selected_handles:",
    "prepared launch interpreter field",
)
replace_one(
    "src/platform/linux.rs",
    "                executable_fd,\n                selected_handles,",
    "                executable_fd,\n                interpreter,\n                selected_handles,",
    "prepared launch interpreter init",
)
# Install after all mutable overlay mounts but before cwd/chroot.
replace_one(
    "src/platform/linux.rs",
    '''        let stdout_redirect_fd = if let Some(path) = &prepared.stdout_redirect_relative {''',
    '''        if let Some(interpreter) = &prepared.interpreter {
            install_sealed_interpreter_or_fail(
                interpreter,
                root_tree_fd,
                launch_error,
                seccomp.error_exit_syscall,
            );
        }

        let stdout_redirect_fd = if let Some(path) = &prepared.stdout_redirect_relative {''',
    "interpreter install call",
)
install_marker = '''    unsafe fn install_volume_or_fail(
        volume: &PreparedVolume,'''
install_fn = r'''    unsafe fn install_sealed_interpreter_or_fail(
        interpreter: &PreparedInterpreter,
        root_tree_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let interpreter_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            interpreter.image_fd.raw(),
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
        );
        if interpreter_tree_fd == -1 {
            child_fail(launch_error, PHASE_INTERPRETER_CLONE, error_exit_syscall);
        }
        let interpreter_tree_fd = interpreter_tree_fd as RawFd;

        let target_how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let target_fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            interpreter.target_relative.as_ptr(),
            &target_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if target_fd == -1 {
            child_fail(
                launch_error,
                PHASE_INTERPRETER_TARGET_PIN,
                error_exit_syscall,
            );
        }
        let target_fd = target_fd as RawFd;
        let mut target_stat = std::mem::zeroed::<libc::stat>();
        if libc::fstat(target_fd, &mut target_stat) == -1
            || target_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            child_fail(
                launch_error,
                PHASE_INTERPRETER_TARGET_PIN,
                error_exit_syscall,
            );
        }

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            interpreter_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_INTERPRETER_READONLY,
                error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_move_mount,
            interpreter_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            target_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_INTERPRETER_ATTACH,
                error_exit_syscall,
            );
        }
        if libc::close(target_fd) == -1 || libc::close(interpreter_tree_fd) == -1 {
            child_fail(
                launch_error,
                PHASE_INTERPRETER_ATTACH,
                error_exit_syscall,
            );
        }
    }

'''
replace_one("src/platform/linux.rs", install_marker, install_fn + install_marker, "interpreter install helper")
# Phase labels near existing COW labels.
p=Path("src/platform/linux.rs"); text=p.read_text()
phase_anchor='''            PHASE_COW_DIFF_EXPORT => "bounded copy-on-write diff export",'''
if phase_anchor not in text:
    raise SystemExit("phase-name anchor not found")
text=text.replace(
    phase_anchor,
    phase_anchor + '''
            PHASE_INTERPRETER_CLONE => "sealed ELF interpreter detached mount clone",
            PHASE_INTERPRETER_TARGET_PIN => "sealed ELF interpreter target pin",
            PHASE_INTERPRETER_READONLY => "sealed ELF interpreter mount hardening",
            PHASE_INTERPRETER_ATTACH => "sealed ELF interpreter mount attachment",''',
    1,
)
p.write_text(text)

# Integration fixture setup and policy fields.
replace_one(
    "tests/sandbox.rs",
    '''        assert!(status.success(), "failed to assemble raw-syscall fixture");
        root''',
    r'''        assert!(status.success(), "failed to assemble raw-syscall fixture");

        let loader_source = std::fs::canonicalize("/lib64/ld-linux-x86-64.so.2")
            .expect("Ubuntu x86_64 integration tests require the system ELF interpreter");
        let loader_bytes =
            std::fs::read(&loader_source).expect("read system ELF interpreter bytes");
        std::fs::write(root.join("loader"), &loader_bytes)
            .expect("copy ELF interpreter into fixture root");
        std::fs::set_permissions(
            root.join("loader"),
            std::fs::Permissions::from_mode(0o555),
        )
        .expect("make fixture ELF interpreter executable");

        let dynamic_output = root.join("dynamic-probe");
        let dynamic_source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dynamic_probe.S");
        let dynamic_status = Command::new("cc")
            .args([
                "-nostdlib",
                "-fPIE",
                "-pie",
                "-Wl,--build-id=none",
                "-Wl,--dynamic-linker=/loader",
                "-Wl,-e,_start",
                "-o",
            ])
            .arg(&dynamic_output)
            .arg(&dynamic_source)
            .status()
            .expect("Linux x86_64 integration tests require a PIE-capable C toolchain");
        assert!(
            dynamic_status.success(),
            "failed to assemble dynamic PT_INTERP fixture"
        );
        root''',
    "dynamic fixture setup",
)
replace_one(
    "tests/sandbox.rs",
    "        executable_sha256: None,\n        args,",
    "        executable_sha256: None,\n        executable_interpreter: None,\n        executable_interpreter_sha256: None,\n        args,",
    "sandbox policy literal interpreter",
)
replace_one(
    "tests/sandbox.rs",
    '''fn fixture_executable_sha256() -> [u8; 32] {
    let bytes = std::fs::read(fixture_root().join("probe")).expect("read raw fixture executable");
    Sha256::digest(bytes).into()
}
''',
    '''fn fixture_executable_sha256() -> [u8; 32] {
    let bytes = std::fs::read(fixture_root().join("probe")).expect("read raw fixture executable");
    Sha256::digest(bytes).into()
}

fn dynamic_fixture_sha256() -> [u8; 32] {
    let bytes =
        std::fs::read(fixture_root().join("dynamic-probe")).expect("read dynamic fixture");
    Sha256::digest(bytes).into()
}

fn fixture_loader_sha256() -> [u8; 32] {
    let bytes = std::fs::read(fixture_root().join("loader")).expect("read fixture loader");
    Sha256::digest(bytes).into()
}
''',
    "dynamic digest helpers",
)
test_anchor = '''#[test]
fn bootstrap_execveat_is_one_shot_without_persistent_target_grant() {'''
new_tests = r'''#[test]
fn sealed_pt_interp_executes_through_immutable_loader_mount() {
    let loader_before =
        std::fs::read(fixture_root().join("loader")).expect("read host fixture loader before run");
    let mut verified = policy(
        "unused",
        &[],
        &[
            "read",
            "close",
            "fstat",
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "arch_prctl",
            "set_tid_address",
            "set_robust_list",
            "prlimit64",
            "getrandom",
            "openat",
            "newfstatat",
            "pread64",
            "access",
            "madvise",
            "fcntl",
            "exit",
            "exit_group",
        ],
    );
    verified.executable = PathBuf::from("/dynamic-probe");
    verified.executable_sha256 = Some(dynamic_fixture_sha256());
    verified.executable_interpreter = Some(PathBuf::from("/loader"));
    verified.executable_interpreter_sha256 = Some(fixture_loader_sha256());

    assert_eq!(run(&verified).unwrap(), ChildOutcome::Exited(73));
    assert_eq!(
        std::fs::read(fixture_root().join("loader")).expect("read host fixture loader after run"),
        loader_before,
        "sealed interpreter mount must not mutate the host loader copy"
    );
}

#[test]
fn sealed_pt_interp_mismatch_fails_closed_before_target_execution() {
    let mut verified = policy("unused", &[], &["exit"]);
    verified.executable = PathBuf::from("/dynamic-probe");
    verified.executable_sha256 = Some(dynamic_fixture_sha256());
    verified.executable_interpreter = Some(PathBuf::from("/loader"));
    let mut wrong = fixture_loader_sha256();
    wrong[0] ^= 0x80;
    verified.executable_interpreter_sha256 = Some(wrong);

    match run(&verified).unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains(
                "ELF interpreter SHA-256 does not match executable.interpreter_sha256 policy"
            ));
        }
        other => panic!("unexpected interpreter digest mismatch result: {other}"),
    }

    let mut wrong_path = verified;
    wrong_path.executable_interpreter_sha256 = Some(fixture_loader_sha256());
    wrong_path.executable_interpreter = Some(PathBuf::from("/not-the-declared-loader"));
    match run(&wrong_path).unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains("PT_INTERP"));
            assert!(message.contains("does not match executable.interpreter"));
        }
        other => panic!("unexpected PT_INTERP mismatch result: {other}"),
    }
}

'''
replace_one("tests/sandbox.rs", test_anchor, new_tests + test_anchor, "interpreter integration tests")

# The CLI-side modules contain only parser-created SandboxPolicy values, so no
# additional literals need fields. Rust compilation will catch any missed literal.


# Normalize interpolated diagnostics introduced by the generalized sealed-image helper.
p = Path("src/platform/linux.rs")
t = p.read_text()
pairs = [
    ('"{image_label} identity changed before sealed content copy".to_owned()', 'format!("{image_label} identity changed before sealed content copy")'),
    ('"sealed {image_label} byte count overflow".to_owned()', 'format!("sealed {image_label} byte count overflow")'),
    ('"{image_label} image is empty".to_owned()', 'format!("{image_label} image is empty")'),
    ('"{image_label} SHA-256 does not match {policy_field} policy".to_owned()', 'format!("{image_label} SHA-256 does not match {policy_field} policy")'),
    ('"verified {image_label} memfd is missing required immutable seals".to_owned()', 'format!("verified {image_label} memfd is missing required immutable seals")'),
]
for old, new in pairs:
    if old not in t:
        raise SystemExit(f"formatted sealed-image message missing: {old}")
    t = t.replace(old, new, 1)
p.write_text(t)
