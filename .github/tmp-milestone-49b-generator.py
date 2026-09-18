from pathlib import Path
import re

def read(path):
    return Path(path).read_text()

def write(path, text):
    Path(path).write_text(text)

def replace_one(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    return text.replace(old, new, 1)

def replace_regex_one(text, pattern, replacement, label):
    new, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one regex match, got {count}")
    return new

elf_needed = r'''use std::fmt;
use std::io;
use std::os::unix::io::RawFd;

const ELF_HEADER_BYTES: usize = 64;
const ELF64_PROGRAM_HEADER_BYTES: usize = 56;
const ELF64_DYNAMIC_BYTES: usize = 16;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const PN_XNUM: u16 = 0xffff;
const MAX_DYNAMIC_BYTES: u64 = 1024 * 1024;
const MAX_STRING_TABLE_BYTES: u64 = 1024 * 1024;
const MAX_NEEDED_ENTRIES: usize = 128;

#[derive(Debug)]
pub(crate) struct ElfNeededError(String);

impl fmt::Display for ElfNeededError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Copy)]
struct LoadSegment {
    offset: u64,
    vaddr: u64,
    filesz: u64,
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_i64(bytes: &[u8]) -> i64 {
    i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

fn pread_exact(fd: RawFd, offset: u64, buffer: &mut [u8]) -> Result<(), ElfNeededError> {
    let mut done = 0usize;
    while done < buffer.len() {
        let absolute = offset
            .checked_add(done as u64)
            .ok_or_else(|| ElfNeededError("ELF read offset overflow".to_owned()))?;
        if absolute > libc::off_t::MAX as u64 {
            return Err(ElfNeededError("ELF read offset exceeds off_t".to_owned()));
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
            return Err(ElfNeededError(format!("ELF pread failed: {error}")));
        }
        if read == 0 {
            return Err(ElfNeededError("ELF file ended unexpectedly".to_owned()));
        }
        done += read as usize;
    }
    Ok(())
}

fn validate_range(offset: u64, size: u64, file_size: u64, label: &str) -> Result<(), ElfNeededError> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| ElfNeededError(format!("{label} range overflow")))?;
    if end > file_size {
        return Err(ElfNeededError(format!("{label} extends beyond the ELF image")));
    }
    Ok(())
}

pub(crate) fn read_elf64_x86_64_dt_needed(
    fd: RawFd,
) -> Result<Vec<Vec<u8>>, ElfNeededError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut stat) } == -1 {
        return Err(ElfNeededError(format!(
            "cannot stat ELF image: {}",
            io::Error::last_os_error()
        )));
    }
    if stat.st_size < ELF_HEADER_BYTES as i64 {
        return Err(ElfNeededError("ELF image is smaller than its header".to_owned()));
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
        return Err(ElfNeededError(
            "expected little-endian ELF64 x86_64 image".to_owned(),
        ));
    }

    let phoff = read_u64(&header[32..40]);
    let phentsize = read_u16(&header[54..56]);
    let phnum = read_u16(&header[56..58]);
    if phnum == PN_XNUM {
        return Err(ElfNeededError(
            "extended ELF program-header counts are not supported".to_owned(),
        ));
    }
    if phnum == 0 {
        return Ok(Vec::new());
    }
    if phentsize as usize != ELF64_PROGRAM_HEADER_BYTES {
        return Err(ElfNeededError(format!(
            "unexpected ELF64 program-header size {phentsize}"
        )));
    }
    let ph_table_size = u64::from(phnum)
        .checked_mul(ELF64_PROGRAM_HEADER_BYTES as u64)
        .ok_or_else(|| ElfNeededError("ELF program-header table overflow".to_owned()))?;
    validate_range(phoff, ph_table_size, file_size, "ELF program-header table")?;

    let mut loads = Vec::new();
    let mut dynamic = None;
    for index in 0..u64::from(phnum) {
        let offset = phoff + index * ELF64_PROGRAM_HEADER_BYTES as u64;
        let mut ph = [0u8; ELF64_PROGRAM_HEADER_BYTES];
        pread_exact(fd, offset, &mut ph)?;
        let kind = read_u32(&ph[0..4]);
        let file_offset = read_u64(&ph[8..16]);
        let vaddr = read_u64(&ph[16..24]);
        let filesz = read_u64(&ph[32..40]);
        if kind == PT_LOAD {
            validate_range(file_offset, filesz, file_size, "PT_LOAD")?;
            loads.push(LoadSegment {
                offset: file_offset,
                vaddr,
                filesz,
            });
        } else if kind == PT_DYNAMIC {
            if dynamic.is_some() {
                return Err(ElfNeededError(
                    "ELF image contains more than one PT_DYNAMIC segment".to_owned(),
                ));
            }
            if filesz == 0
                || filesz > MAX_DYNAMIC_BYTES
                || filesz % ELF64_DYNAMIC_BYTES as u64 != 0
            {
                return Err(ElfNeededError(
                    "PT_DYNAMIC has an invalid bounded size".to_owned(),
                ));
            }
            validate_range(file_offset, filesz, file_size, "PT_DYNAMIC")?;
            dynamic = Some((file_offset, filesz));
        }
    }

    let Some((dynamic_offset, dynamic_size)) = dynamic else {
        return Ok(Vec::new());
    };
    let mut needed_offsets = Vec::new();
    let mut strtab_vaddr = None;
    let mut strtab_size = None;
    let mut terminated = false;
    for index in 0..(dynamic_size / ELF64_DYNAMIC_BYTES as u64) {
        let mut entry = [0u8; ELF64_DYNAMIC_BYTES];
        pread_exact(
            fd,
            dynamic_offset + index * ELF64_DYNAMIC_BYTES as u64,
            &mut entry,
        )?;
        let tag = read_i64(&entry[0..8]);
        let value = read_u64(&entry[8..16]);
        match tag {
            DT_NULL => {
                terminated = true;
                break;
            }
            DT_NEEDED => {
                if needed_offsets.len() >= MAX_NEEDED_ENTRIES {
                    return Err(ElfNeededError(
                        "too many DT_NEEDED entries".to_owned(),
                    ));
                }
                needed_offsets.push(value);
            }
            DT_STRTAB => {
                if strtab_vaddr.replace(value).is_some() {
                    return Err(ElfNeededError(
                        "ELF image contains multiple DT_STRTAB entries".to_owned(),
                    ));
                }
            }
            DT_STRSZ => {
                if strtab_size.replace(value).is_some() {
                    return Err(ElfNeededError(
                        "ELF image contains multiple DT_STRSZ entries".to_owned(),
                    ));
                }
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(ElfNeededError("PT_DYNAMIC has no DT_NULL terminator".to_owned()));
    }
    if needed_offsets.is_empty() {
        return Ok(Vec::new());
    }

    let strtab_vaddr =
        strtab_vaddr.ok_or_else(|| ElfNeededError("DT_NEEDED requires DT_STRTAB".to_owned()))?;
    let strtab_size =
        strtab_size.ok_or_else(|| ElfNeededError("DT_NEEDED requires DT_STRSZ".to_owned()))?;
    if strtab_size == 0 || strtab_size > MAX_STRING_TABLE_BYTES {
        return Err(ElfNeededError("DT_STRTAB size is outside the bounded range".to_owned()));
    }

    let mut strtab_offset = None;
    for load in loads {
        let Some(delta) = strtab_vaddr.checked_sub(load.vaddr) else {
            continue;
        };
        if delta <= load.filesz && strtab_size <= load.filesz.saturating_sub(delta) {
            strtab_offset = load.offset.checked_add(delta);
            if strtab_offset.is_none() {
                return Err(ElfNeededError("DT_STRTAB file offset overflow".to_owned()));
            }
            break;
        }
    }
    let strtab_offset =
        strtab_offset.ok_or_else(|| ElfNeededError("DT_STRTAB is not backed by one PT_LOAD".to_owned()))?;
    validate_range(strtab_offset, strtab_size, file_size, "DT_STRTAB")?;

    let mut strings = vec![0u8; strtab_size as usize];
    pread_exact(fd, strtab_offset, &mut strings)?;
    let mut result = Vec::with_capacity(needed_offsets.len());
    for needed in needed_offsets {
        if needed >= strtab_size {
            return Err(ElfNeededError(
                "DT_NEEDED string offset is outside DT_STRTAB".to_owned(),
            ));
        }
        let tail = &strings[needed as usize..];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| ElfNeededError("DT_NEEDED string is not NUL terminated".to_owned()))?;
        if end == 0 {
            return Err(ElfNeededError("DT_NEEDED string is empty".to_owned()));
        }
        result.push(tail[..end].to_vec());
    }
    Ok(result)
}
''';
Path("src/elf_needed.rs").write_text(elf_needed)

# Module wiring.
for path in ["src/lib.rs", "src/main.rs"]:
    text = read(path)
    anchor = '#[cfg(all(target_os = "linux", target_arch = "x86_64"))]\nmod elf_interpreter;\n'
    text = replace_one(
        text,
        anchor,
        anchor + '#[cfg(all(target_os = "linux", target_arch = "x86_64"))]\nmod elf_needed;\n',
        f"{path} elf_needed module",
    )
    write(path, text)

# Policy surface, parser, validation and unit regression.
path = "src/policy.rs"
text = read(path)
text = replace_one(
    text,
    '    pub executable_interpreter: Option<PathBuf>,\n    pub executable_interpreter_sha256: Option<[u8; 32]>,\n',
    '    pub executable_interpreter: Option<PathBuf>,\n    pub executable_interpreter_sha256: Option<[u8; 32]>,\n'
    '    /// Optional one direct absolute path-qualified DT_NEEDED dependency plus\n'
    '    /// exact SHA-256. Valid only when both the main executable and PT_INTERP\n'
    '    /// loader are content-bound, so the dependency is selected by sealed code.\n'
    '    pub executable_needed: Option<PathBuf>,\n'
    '    pub executable_needed_sha256: Option<[u8; 32]>,\n',
    "policy fields",
)
validation = r'''
        match (&self.executable_needed, self.executable_needed_sha256) {
            (None, None) => {}
            (Some(path), Some(_)) => {
                validate_absolute_path("executable.needed", path)?;
                if self.executable_sha256.is_none()
                    || self.executable_interpreter.is_none()
                    || self.executable_interpreter_sha256.is_none()
                {
                    return Err(PolicyError::new(
                        "executable.needed requires content-bound executable.sha256 and executable.interpreter binding",
                    ));
                }
                if path == Path::new("/") {
                    return Err(PolicyError::new(
                        "executable.needed must not replace the sandbox root",
                    ));
                }
                if path == &self.executable
                    || self.executable_interpreter.as_ref() == Some(path)
                {
                    return Err(PolicyError::new(
                        "executable.needed must differ from executable and executable.interpreter",
                    ));
                }
                #[cfg(unix)]
                if path.as_os_str().as_bytes().contains(&b'$') {
                    return Err(PolicyError::new(
                        "executable.needed must not contain dynamic-linker $ tokens",
                    ));
                }
                let overlaps = |other: &Path| path.starts_with(other) || other.starts_with(path);
                if self.procfs_enabled && overlaps(Path::new("/proc")) {
                    return Err(PolicyError::new(
                        "executable.needed must not overlap filesystem.proc",
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
                                "executable.needed must not overlap {label}"
                            )));
                        }
                    }
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "executable.needed and executable.needed_sha256 must be specified together",
                ));
            }
        }

'''
text = replace_one(
    text,
    '        if let Some(bytes) = self.cow_root_bytes {\n',
    validation + '        if let Some(bytes) = self.cow_root_bytes {\n',
    "needed validation",
)
text = replace_one(
    text,
    '        let mut executable_interpreter_sha256 = None;\n',
    '        let mut executable_interpreter_sha256 = None;\n'
    '        let mut executable_needed = None;\n'
    '        let mut executable_needed_sha256 = None;\n',
    "needed parser variables",
)
text = replace_one(
    text,
    '                "executable.interpreter_sha256" => set_once(\n'
    '                    &mut executable_interpreter_sha256,\n'
    '                    parse_sha256(value, line_no, key)?,\n'
    '                    line_no,\n'
    '                    key,\n'
    '                )?,\n',
    '                "executable.interpreter_sha256" => set_once(\n'
    '                    &mut executable_interpreter_sha256,\n'
    '                    parse_sha256(value, line_no, key)?,\n'
    '                    line_no,\n'
    '                    key,\n'
    '                )?,\n'
    '                "executable.needed" => {\n'
    '                    set_once(&mut executable_needed, value.to_owned(), line_no, key)?\n'
    '                }\n'
    '                "executable.needed_sha256" => set_once(\n'
    '                    &mut executable_needed_sha256,\n'
    '                    parse_sha256(value, line_no, key)?,\n'
    '                    line_no,\n'
    '                    key,\n'
    '                )?,\n',
    "needed parser keys",
)
text = replace_one(
    text,
    '            executable_interpreter: executable_interpreter.map(PathBuf::from),\n'
    '            executable_interpreter_sha256,\n'
    '            args,\n',
    '            executable_interpreter: executable_interpreter.map(PathBuf::from),\n'
    '            executable_interpreter_sha256,\n'
    '            executable_needed: executable_needed.map(PathBuf::from),\n'
    '            executable_needed_sha256,\n'
    '            args,\n',
    "needed policy construction",
)
needed_policy_test = r'''
    #[test]
    fn direct_needed_binding_requires_sealed_main_and_interpreter() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let complete = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}\nexecutable.needed = /dependency\nexecutable.needed_sha256 = {digest}"
        );
        let policy: SandboxPolicy = complete.parse().unwrap();
        assert_eq!(policy.executable_needed, Some(PathBuf::from("/dependency")));
        assert_eq!(policy.executable_needed_sha256, policy.executable_sha256);

        let no_interpreter = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.needed = /dependency\nexecutable.needed_sha256 = {digest}"
        );
        assert!(no_interpreter.parse::<SandboxPolicy>().is_err());

        let tokenized = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}\nexecutable.needed = /lib/$LIB/dependency\nexecutable.needed_sha256 = {digest}"
        );
        assert!(tokenized.parse::<SandboxPolicy>().is_err());

        let incomplete = format!(
            "{VALID}\nexecutable.sha256 = {digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}\nexecutable.needed = /dependency"
        );
        assert!(incomplete.parse::<SandboxPolicy>().is_err());
    }

'''
text = replace_one(
    text,
    '    #[test]\n    fn parses_stdout_redirect_inside_scratch() {\n',
    needed_policy_test + '    #[test]\n    fn parses_stdout_redirect_inside_scratch() {\n',
    "needed policy unit test",
)
write(path, text)

# Add default None fields to direct SandboxPolicy literals across Rust tests/helpers.
for candidate in Path(".").rglob("*.rs"):
    if candidate.as_posix() == "src/policy.rs":
        continue
    source = candidate.read_text()
    if "executable_interpreter_sha256: None," not in source:
        continue
    source = source.replace(
        "executable_interpreter_sha256: None,\n",
        "executable_interpreter_sha256: None,\n"
        "        executable_needed: None,\n"
        "        executable_needed_sha256: None,\n",
    )
    candidate.write_text(source)

# Authority manifest JSON/human surfaces.
path = "src/authority_manifest.rs"
text = read(path)
text = replace_one(
    text,
    '    output.push_str(",\\"working_dir\\":");\n',
    '    output.push_str(",\\"executable_needed\\":");\n'
    '    match &policy.executable_needed {\n'
    '        Some(path) => push_path(&mut output, path),\n'
    '        None => output.push_str("null"),\n'
    '    }\n'
    '    output.push_str(",\\"executable_needed_sha256\\":");\n'
    '    match policy.executable_needed_sha256 {\n'
    '        Some(digest) => push_json_string(&mut output, &sha256_hex(digest)),\n'
    '        None => output.push_str("null"),\n'
    '    }\n'
    '    output.push_str(",\\"working_dir\\":");\n',
    "authority manifest json",
)
human_anchor = r'''    writeln!(&mut output, "working-dir: {}", policy.working_dir.display())
        .expect("write to String cannot fail");
'''
human_needed = r'''    writeln!(
        &mut output,
        "executable-needed: {}",
        policy
            .executable_needed
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_owned())
    )
    .expect("write to String cannot fail");
    writeln!(
        &mut output,
        "executable-needed-sha256: {}",
        policy
            .executable_needed_sha256
            .map(sha256_hex)
            .unwrap_or_else(|| "none".to_owned())
    )
    .expect("write to String cannot fail");
'''
text = replace_one(text, human_anchor, human_needed + human_anchor, "authority manifest human")
write(path, text)

# Authority delta models the path+digest pair as one exact optional restriction.
path = "src/authority_delta.rs"
text = read(path)
anchor = r'''    compare_exact_incomparable(
        "execution.arguments",
'''
addition = r'''    compare_optional_restriction(
        "execution.executable_needed_binding",
        baseline
            .executable_needed
            .as_ref()
            .zip(baseline.executable_needed_sha256.as_ref()),
        candidate
            .executable_needed
            .as_ref()
            .zip(candidate.executable_needed_sha256.as_ref()),
        &mut changes,
    );
'''
text = replace_one(text, anchor, addition + anchor, "authority delta needed")
write(path, text)

# Linux runtime: parse DT_NEEDED from sealed main and mount sealed dependency at exact path.
path = "src/platform/linux.rs"
text = read(path)
text = replace_one(
    text,
    '    use crate::elf_interpreter;\n',
    '    use crate::elf_interpreter;\n    use crate::elf_needed;\n',
    "linux elf_needed import",
)
text = replace_one(
    text,
    '    const PHASE_INTERPRETER_ATTACH: u32 = 72;\n',
    '    const PHASE_INTERPRETER_ATTACH: u32 = 72;\n'
    '    const PHASE_NEEDED_TMPFS_CREATE: u32 = 73;\n'
    '    const PHASE_NEEDED_TMPFS_MOUNT: u32 = 74;\n'
    '    const PHASE_NEEDED_COPY: u32 = 75;\n'
    '    const PHASE_NEEDED_CLONE: u32 = 76;\n'
    '    const PHASE_NEEDED_TARGET_PIN: u32 = 77;\n'
    '    const PHASE_NEEDED_READONLY: u32 = 78;\n'
    '    const PHASE_NEEDED_ATTACH: u32 = 79;\n',
    "needed launch phases",
)
text = replace_one(
    text,
    '    struct PreparedInterpreter {\n'
    '        image_fd: OwnedFd,\n'
    '        target_relative: CString,\n'
    '    }\n',
    '    struct PreparedSealedMount {\n'
    '        image_fd: OwnedFd,\n'
    '        target_relative: CString,\n'
    '    }\n\n'
    '    #[derive(Clone, Copy)]\n'
    '    struct SealedMountPhases {\n'
    '        tmpfs_create: u32,\n'
    '        tmpfs_mount: u32,\n'
    '        copy: u32,\n'
    '        clone: u32,\n'
    '        target_pin: u32,\n'
    '        readonly: u32,\n'
    '        attach: u32,\n'
    '    }\n\n'
    '    const INTERPRETER_MOUNT_PHASES: SealedMountPhases = SealedMountPhases {\n'
    '        tmpfs_create: PHASE_INTERPRETER_TMPFS_CREATE,\n'
    '        tmpfs_mount: PHASE_INTERPRETER_TMPFS_MOUNT,\n'
    '        copy: PHASE_INTERPRETER_COPY,\n'
    '        clone: PHASE_INTERPRETER_CLONE,\n'
    '        target_pin: PHASE_INTERPRETER_TARGET_PIN,\n'
    '        readonly: PHASE_INTERPRETER_READONLY,\n'
    '        attach: PHASE_INTERPRETER_ATTACH,\n'
    '    };\n'
    '    const NEEDED_MOUNT_PHASES: SealedMountPhases = SealedMountPhases {\n'
    '        tmpfs_create: PHASE_NEEDED_TMPFS_CREATE,\n'
    '        tmpfs_mount: PHASE_NEEDED_TMPFS_MOUNT,\n'
    '        copy: PHASE_NEEDED_COPY,\n'
    '        clone: PHASE_NEEDED_CLONE,\n'
    '        target_pin: PHASE_NEEDED_TARGET_PIN,\n'
    '        readonly: PHASE_NEEDED_READONLY,\n'
    '        attach: PHASE_NEEDED_ATTACH,\n'
    '    };\n',
    "generic sealed mount state",
)
text = text.replace("PreparedInterpreter", "PreparedSealedMount")
text = replace_one(
    text,
    '        interpreter: Option<PreparedSealedMount>,\n'
    '        selected_handles: Vec<PreparedSelectedHandle>,\n',
    '        interpreter: Option<PreparedSealedMount>,\n'
    '        dependency: Option<PreparedSealedMount>,\n'
    '        selected_handles: Vec<PreparedSelectedHandle>,\n',
    "prepared dependency field",
)
dependency_prepare = r'''
            let dependency = match (
                &policy.executable_needed,
                policy.executable_needed_sha256,
            ) {
                (Some(path), Some(expected_sha256)) => {
                    let needed = elf_needed::read_elf64_x86_64_dt_needed(executable_fd.raw())
                        .map_err(|error| {
                            SandboxError::SetupFailed(format!(
                                "cannot parse content-bound executable DT_NEEDED: {error}"
                            ))
                        })?;
                    let matches = needed
                        .iter()
                        .filter(|entry| entry.as_slice() == path.as_os_str().as_bytes())
                        .count();
                    if matches != 1 {
                        return Err(SandboxError::SetupFailed(format!(
                            "content-bound executable must contain exactly one DT_NEEDED entry matching executable.needed {}",
                            path.display()
                        )));
                    }
                    let pinned = open_beneath_root(
                        root_fd.raw(),
                        path,
                        (libc::O_PATH | libc::O_CLOEXEC) as u64,
                        "ELF direct dependency",
                    )?;
                    validate_executable_fd(pinned.raw(), path)?;
                    let image_fd = prepare_verified_executable_image(
                        root_fd.raw(),
                        path,
                        pinned,
                        expected_sha256,
                        "ELF direct dependency",
                        "executable.needed_sha256",
                        "security-lab-needed",
                    )?;
                    Some(PreparedSealedMount {
                        image_fd,
                        target_relative: sandbox_relative(path)?,
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "executable.needed and executable.needed_sha256 must be specified together",
                    )));
                }
            };

'''
text = replace_one(
    text,
    '            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());\n',
    dependency_prepare + '            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());\n',
    "runtime needed preparation",
)
text = replace_one(
    text,
    '                interpreter,\n'
    '                selected_handles,\n',
    '                interpreter,\n'
    '                dependency,\n'
    '                selected_handles,\n',
    "prepared dependency initialization",
)
text = replace_one(
    text,
    '        if let Some(interpreter) = &prepared.interpreter {\n'
    '            install_sealed_interpreter_or_fail(\n'
    '                interpreter,\n'
    '                root_tree_fd,\n'
    '                launch_error,\n'
    '                seccomp.error_exit_syscall,\n'
    '            );\n'
    '        }\n',
    '        if let Some(interpreter) = &prepared.interpreter {\n'
    '            install_sealed_image_or_fail(\n'
    '                interpreter,\n'
    '                INTERPRETER_MOUNT_PHASES,\n'
    '                root_tree_fd,\n'
    '                launch_error,\n'
    '                seccomp.error_exit_syscall,\n'
    '            );\n'
    '        }\n'
    '        if let Some(dependency) = &prepared.dependency {\n'
    '            install_sealed_image_or_fail(\n'
    '                dependency,\n'
    '                NEEDED_MOUNT_PHASES,\n'
    '                root_tree_fd,\n'
    '                launch_error,\n'
    '                seccomp.error_exit_syscall,\n'
    '            );\n'
    '        }\n',
    "child sealed mounts",
)

generic_mount = r'''    unsafe fn copy_sealed_image_or_fail(
        source_fd: RawFd,
        destination_fd: RawFd,
        copy_phase: u32,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let mut stat = std::mem::zeroed::<libc::stat>();
        if libc::fstat(source_fd, &mut stat) == -1 || stat.st_size <= 0 {
            child_fail(launch_error, copy_phase, error_exit_syscall);
        }
        let total = stat.st_size as u64;
        let mut offset = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        while offset < total {
            let wanted = std::cmp::min(buffer.len() as u64, total - offset) as usize;
            let read = loop {
                let result = libc::pread(
                    source_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    wanted,
                    offset as libc::off_t,
                );
                if result == -1 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                break result;
            };
            if read <= 0 {
                if read == 0 {
                    child_fail_errno(launch_error, copy_phase, libc::EIO, error_exit_syscall);
                }
                child_fail(launch_error, copy_phase, error_exit_syscall);
            }
            let mut written = 0usize;
            while written < read as usize {
                let result = libc::write(
                    destination_fd,
                    buffer[written..read as usize].as_ptr().cast::<libc::c_void>(),
                    read as usize - written,
                );
                if result == -1 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                if result <= 0 {
                    if result == 0 {
                        child_fail_errno(launch_error, copy_phase, libc::EIO, error_exit_syscall);
                    }
                    child_fail(launch_error, copy_phase, error_exit_syscall);
                }
                written += result as usize;
            }
            offset += read as u64;
        }
    }

    unsafe fn install_sealed_image_or_fail(
        image: &PreparedSealedMount,
        phases: SealedMountPhases,
        root_tree_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let fsfd = libc::syscall(
            libc::SYS_fsopen,
            b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
            FSOPEN_CLOEXEC,
        );
        if fsfd == -1 {
            child_fail(launch_error, phases.tmpfs_create, error_exit_syscall);
        }
        let fsfd = fsfd as RawFd;
        fsconfig_string_or_fail(
            fsfd,
            b"size\0",
            b"68157440\0".as_ptr().cast::<libc::c_char>(),
            phases.tmpfs_create,
            launch_error,
            error_exit_syscall,
        );
        fsconfig_string_or_fail(
            fsfd,
            b"mode\0",
            b"0700\0".as_ptr().cast::<libc::c_char>(),
            phases.tmpfs_create,
            launch_error,
            error_exit_syscall,
        );
        if libc::syscall(
            libc::SYS_fsconfig,
            fsfd,
            FSCONFIG_CMD_CREATE,
            ptr::null::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            0,
        ) == -1
        {
            child_fail(launch_error, phases.tmpfs_create, error_exit_syscall);
        }
        let state_mount_fd = libc::syscall(
            libc::SYS_fsmount,
            fsfd,
            FSMOUNT_CLOEXEC,
            MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
        );
        if state_mount_fd == -1 {
            child_fail(launch_error, phases.tmpfs_mount, error_exit_syscall);
        }
        let state_mount_fd = state_mount_fd as RawFd;
        close_setup_fd(fsfd);

        let image_fd = libc::syscall(
            libc::SYS_openat,
            state_mount_fd,
            b"image\0".as_ptr().cast::<libc::c_char>(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o700,
        );
        if image_fd == -1 {
            child_fail(launch_error, phases.copy, error_exit_syscall);
        }
        let image_fd = image_fd as RawFd;
        copy_sealed_image_or_fail(
            image.image_fd.raw(),
            image_fd,
            phases.copy,
            launch_error,
            error_exit_syscall,
        );
        if libc::close(image_fd) == -1 {
            child_fail(launch_error, phases.copy, error_exit_syscall);
        }

        let image_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            state_mount_fd,
            b"image\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC,
        );
        if image_tree_fd == -1 {
            child_fail(launch_error, phases.clone, error_exit_syscall);
        }
        let image_tree_fd = image_tree_fd as RawFd;

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
            image.target_relative.as_ptr(),
            &target_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if target_fd == -1 {
            child_fail(launch_error, phases.target_pin, error_exit_syscall);
        }
        let target_fd = target_fd as RawFd;
        let mut target_stat = std::mem::zeroed::<libc::stat>();
        if libc::fstat(target_fd, &mut target_stat) == -1
            || target_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        {
            child_fail(launch_error, phases.target_pin, error_exit_syscall);
        }

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            image_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(launch_error, phases.readonly, error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_move_mount,
            image_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            target_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, phases.attach, error_exit_syscall);
        }
        close_setup_fd(target_fd);
        close_setup_fd(image_tree_fd);
        close_setup_fd(state_mount_fd);
    }

'''
text = replace_regex_one(
    text,
    r'    unsafe fn copy_sealed_interpreter_image_or_fail\(.*?\n    unsafe fn install_volume_or_fail\(',
    generic_mount + '    unsafe fn install_volume_or_fail(',
    "generic sealed mount functions",
)
text = replace_one(
    text,
    '                | PHASE_INTERPRETER_ATTACH\n',
    '                | PHASE_INTERPRETER_ATTACH\n'
    '                | PHASE_NEEDED_TMPFS_CREATE\n'
    '                | PHASE_NEEDED_TMPFS_MOUNT\n'
    '                | PHASE_NEEDED_CLONE\n'
    '                | PHASE_NEEDED_READONLY\n'
    '                | PHASE_NEEDED_ATTACH\n',
    "needed unsupported mount phases",
)
text = replace_one(
    text,
    '            PHASE_INTERPRETER_ATTACH => "sealed ELF interpreter mount attachment",\n',
    '            PHASE_INTERPRETER_ATTACH => "sealed ELF interpreter mount attachment",\n'
    '            PHASE_NEEDED_TMPFS_CREATE => "sealed ELF DT_NEEDED tmpfs creation",\n'
    '            PHASE_NEEDED_TMPFS_MOUNT => "sealed ELF DT_NEEDED tmpfs mount",\n'
    '            PHASE_NEEDED_COPY => "sealed ELF DT_NEEDED private copy",\n'
    '            PHASE_NEEDED_CLONE => "sealed ELF DT_NEEDED detached file clone",\n'
    '            PHASE_NEEDED_TARGET_PIN => "sealed ELF DT_NEEDED target pin",\n'
    '            PHASE_NEEDED_READONLY => "sealed ELF DT_NEEDED mount hardening",\n'
    '            PHASE_NEEDED_ATTACH => "sealed ELF DT_NEEDED mount attachment",\n',
    "needed phase labels",
)
write(path, text)

# Configured-filesystem read-only preflight for direct dependency.
path = "src/policy_preflight/configured_filesystem_probe.rs"
text = read(path)
# The import is inside the Linux implementation section.
if "use crate::elf_interpreter;" in text:
    text = replace_one(
        text,
        "use crate::elf_interpreter;\n",
        "use crate::elf_interpreter;\nuse crate::elf_needed;\n",
        "preflight elf_needed import",
    )
else:
    raise SystemExit("preflight elf_interpreter import not found")
needed_preflight = r'''
        if let (Some(dependency), Some(expected_sha256)) = (
            &policy.executable_needed,
            policy.executable_needed_sha256,
        ) {
            let executable_readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_elf_open",
                        Some(error),
                    );
                }
            };
            let needed = match elf_needed::read_elf64_x86_64_dt_needed(executable_readable.raw()) {
                Ok(needed) => needed,
                Err(_) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_elf",
                        None,
                    );
                }
            };
            let matches = needed
                .iter()
                .filter(|entry| entry.as_slice() == dependency.as_os_str().as_bytes())
                .count();
            if matches != 1 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_path_mismatch",
                    None,
                );
            }

            let object = match open_beneath(
                root.raw(),
                dependency,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_open",
                        Some(error),
                    );
                }
            };
            let mut object_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(object.raw(), &mut object_stat) } != 0 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_stat",
                    Some(errno()),
                );
            }
            if object_stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || object_stat.st_mode & 0o111 == 0
                || object_stat.st_size <= 0
                || object_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
            {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_shape",
                    None,
                );
            }
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = unsafe {
                    libc::read(
                        object.raw(),
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
                        "executable_needed_digest_read",
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
                            "executable_needed_digest_size",
                            None,
                        );
                    }
                };
                hasher.update(&buffer[..read as usize]);
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected_sha256 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_digest_mismatch",
                    None,
                );
            }
        }

'''
text = replace_one(
    text,
    '        if let Err(result) =\n            require_beneath_directory(root.raw(), &policy.working_dir, "working_dir_open")\n',
    needed_preflight +
    '        if let Err(result) =\n            require_beneath_directory(root.raw(), &policy.working_dir, "working_dir_open")\n',
    "needed preflight block",
)
write(path, text)

# Deterministic direct shared-object fixture and runtime regressions.
Path("tests/fixtures/needed_dependency.S").write_text(r'''.text
.globl sealed_dependency_value
.type sealed_dependency_value,@function
sealed_dependency_value:
    mov $91, %eax
    ret
.size sealed_dependency_value, .-sealed_dependency_value

.section .note.GNU-stack,"",@progbits
''')
Path("tests/fixtures/dynamic_needed_probe.S").write_text(r'''.text
.globl _start
.extern sealed_dependency_value
.type _start,@function
_start:
    call sealed_dependency_value@PLT
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
''')

path = "tests/sandbox.rs"
text = read(path)
fixture_add = r'''
        let dependency_output = root.join("dependency");
        let dependency_source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/needed_dependency.S");
        let dependency_status = Command::new("cc")
            .args([
                "-nostdlib",
                "-shared",
                "-fPIC",
                "-Wl,--build-id=none",
                "-Wl,-soname,/dependency",
                "-o",
            ])
            .arg(&dependency_output)
            .arg(&dependency_source)
            .status()
            .expect("Linux x86_64 integration tests require shared-object linker support");
        assert!(
            dependency_status.success(),
            "failed to assemble path-qualified DT_NEEDED fixture dependency"
        );
        std::fs::set_permissions(&dependency_output, std::fs::Permissions::from_mode(0o555))
            .expect("make fixture DT_NEEDED dependency executable");

        let dynamic_needed_output = root.join("dynamic-needed-probe");
        let dynamic_needed_source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dynamic_needed_probe.S");
        let dynamic_needed_status = Command::new("cc")
            .args([
                "-nostdlib",
                "-fPIE",
                "-pie",
                "-Wl,--build-id=none",
                "-Wl,--dynamic-linker=/loader",
                "-Wl,-e,_start",
                "-o",
            ])
            .arg(&dynamic_needed_output)
            .arg(&dynamic_needed_source)
            .arg(&dependency_output)
            .status()
            .expect("Linux x86_64 integration tests require PIE shared-object linking");
        assert!(
            dynamic_needed_status.success(),
            "failed to assemble path-qualified DT_NEEDED dynamic fixture"
        );
'''
text = replace_one(
    text,
    '        root\n    })\n    .as_path()\n',
    fixture_add + '        root\n    })\n    .as_path()\n',
    "dynamic needed fixture build",
)
hash_add = r'''
fn dynamic_needed_fixture_sha256() -> [u8; 32] {
    let bytes =
        std::fs::read(fixture_root().join("dynamic-needed-probe")).expect("read needed fixture");
    Sha256::digest(bytes).into()
}

fn fixture_needed_sha256() -> [u8; 32] {
    let bytes = std::fs::read(fixture_root().join("dependency")).expect("read fixture dependency");
    Sha256::digest(bytes).into()
}

'''
text = replace_one(
    text,
    'fn fixture_loader_sha256() -> [u8; 32] {\n',
    hash_add + 'fn fixture_loader_sha256() -> [u8; 32] {\n',
    "needed hash helpers",
)
needed_tests = r'''
#[test]
fn sealed_path_qualified_dt_needed_executes_through_immutable_dependency_mount() {
    let dependency_before = std::fs::read(fixture_root().join("dependency"))
        .expect("read host fixture dependency before run");
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
            "exit",
            "exit_group",
        ],
    );
    verified.executable = PathBuf::from("/dynamic-needed-probe");
    verified.executable_sha256 = Some(dynamic_needed_fixture_sha256());
    verified.executable_interpreter = Some(PathBuf::from("/loader"));
    verified.executable_interpreter_sha256 = Some(fixture_loader_sha256());
    verified.executable_needed = Some(PathBuf::from("/dependency"));
    verified.executable_needed_sha256 = Some(fixture_needed_sha256());

    assert_eq!(run(&verified).unwrap(), ChildOutcome::Exited(91));
    assert_eq!(
        std::fs::read(fixture_root().join("dependency"))
            .expect("read host fixture dependency after run"),
        dependency_before,
        "sealed DT_NEEDED mount must not mutate the host dependency copy"
    );
}

#[test]
fn sealed_path_qualified_dt_needed_mismatch_fails_closed_before_target_execution() {
    let mut verified = policy("unused", &[], &["exit"]);
    verified.executable = PathBuf::from("/dynamic-needed-probe");
    verified.executable_sha256 = Some(dynamic_needed_fixture_sha256());
    verified.executable_interpreter = Some(PathBuf::from("/loader"));
    verified.executable_interpreter_sha256 = Some(fixture_loader_sha256());
    verified.executable_needed = Some(PathBuf::from("/dependency"));
    let mut wrong = fixture_needed_sha256();
    wrong[0] ^= 0x80;
    verified.executable_needed_sha256 = Some(wrong);

    match run(&verified).unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains(
                "ELF direct dependency SHA-256 does not match executable.needed_sha256 policy"
            ));
        }
        other => panic!("unexpected DT_NEEDED digest mismatch result: {other}"),
    }

    let mut wrong_path = verified;
    wrong_path.executable_needed_sha256 = Some(fixture_needed_sha256());
    wrong_path.executable_needed = Some(PathBuf::from("/not-the-needed-object"));
    match run(&wrong_path).unwrap_err() {
        SandboxError::SetupFailed(message) => {
            assert!(message.contains("DT_NEEDED"));
            assert!(message.contains("exactly one"));
        }
        other => panic!("unexpected DT_NEEDED path mismatch result: {other}"),
    }
}

'''
text = replace_one(
    text,
    '#[test]\nfn bootstrap_execveat_is_one_shot_without_persistent_target_grant() {\n',
    needed_tests + '#[test]\nfn bootstrap_execveat_is_one_shot_without_persistent_target_grant() {\n',
    "needed runtime tests",
)
write(path, text)

# Manifest regressions expose null fields for ordinary policy.
path = "tests/authority_manifest_cli.rs"
text = read(path)
text = replace_one(
    text,
    '    assert!(stdout.contains("\\"executable_interpreter_sha256\\":null"));\n',
    '    assert!(stdout.contains("\\"executable_interpreter_sha256\\":null"));\n'
    '    assert!(stdout.contains("\\"executable_needed\\":null"));\n'
    '    assert!(stdout.contains("\\"executable_needed_sha256\\":null"));\n',
    "manifest needed assertions",
)
write(path, text)

# Delta regression: adding/removing/changing the direct dependency binding has exact restriction semantics.
path = "tests/authority_delta_cli.rs"
text = read(path)
needle = '#[test]\nfn copy_on_write_root_is_modeled_as_ephemeral_write_authority() {\n'
delta_test = r'''
#[test]
fn direct_needed_binding_is_modeled_as_an_exact_execution_restriction() {
    let root = unique_absent_root("needed-binding");
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let second = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let sealed = format!(
        "{}executable.sha256 = {digest}\nexecutable.interpreter = /loader\nexecutable.interpreter_sha256 = {digest}\n",
        base_policy(&root)
    );
    let restricted_text = format!(
        "{sealed}executable.needed = /dependency\nexecutable.needed_sha256 = {digest}\n"
    );
    let changed_text = format!(
        "{sealed}executable.needed = /dependency\nexecutable.needed_sha256 = {second}\n"
    );
    let baseline = TempPolicy::new("baseline", &sealed);
    let restricted = TempPolicy::new("restricted", &restricted_text);
    let changed = TempPolicy::new("changed", &changed_text);

    let reduced = run_json(&baseline, &restricted);
    assert_eq!(reduced.status.code(), Some(0));
    let stdout = String::from_utf8(reduced.stdout).expect("utf8 output");
    assert!(stdout.contains("\"field\":\"execution.executable_needed_binding\",\"class\":\"reduced\""));

    let widened = run_json(&restricted, &baseline);
    assert_eq!(widened.status.code(), Some(5));
    let stdout = String::from_utf8(widened.stdout).expect("utf8 output");
    assert!(stdout.contains("\"field\":\"execution.executable_needed_binding\",\"class\":\"widened\""));

    let incomparable = run_json(&restricted, &changed);
    assert_eq!(incomparable.status.code(), Some(6));
    let stdout = String::from_utf8(incomparable.stdout).expect("utf8 output");
    assert!(stdout.contains("\"field\":\"execution.executable_needed_binding\",\"class\":\"incomparable\""));
}

'''
text = replace_one(text, needle, delta_test + needle, "delta needed regression")
write(path, text)
