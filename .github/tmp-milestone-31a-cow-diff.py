from pathlib import Path
import re


def replace_one(path, old, new, label):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def replace_all(path, old, new, label, minimum=1):
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count < minimum:
        raise SystemExit(f"{label}: expected at least {minimum} matches, got {count}")
    p.write_text(text.replace(old, new))

cow_module = r'''use crate::{CowDiff, CowDiffEntry, SandboxError};
use std::io;
use std::ptr;

const RECORD_HEADER_BYTES: usize = 11;
const CANONICAL_MAGIC_BYTES: usize = 6;
const PATH_BYTES_MAX: usize = 4096;
const DIRENT_BUFFER_BYTES: usize = 8192;
const TAG_FILE: u8 = 1;
const TAG_DIRECTORY: u8 = 2;
const TAG_SYMLINK: u8 = 3;
const TAG_REMOVE: u8 = 4;
const TAG_OPAQUE_DIRECTORY: u8 = 5;

#[repr(C)]
pub(super) struct CowDiffState {
    used: u64,
    capacity: u64,
}

pub(super) struct SharedCowDiff {
    state: *mut CowDiffState,
    mapping_len: usize,
}

impl SharedCowDiff {
    pub(super) fn new(limit: u64) -> io::Result<Self> {
        let payload_capacity = limit
            .checked_sub(CANONICAL_MAGIC_BYTES as u64)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let mapping_len = std::mem::size_of::<CowDiffState>()
            .checked_add(payload_capacity as usize)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        let mapping = unsafe {
            libc::mmap(
                ptr::null_mut(),
                mapping_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let state = mapping.cast::<CowDiffState>();
        unsafe {
            ptr::write_volatile(
                state,
                CowDiffState {
                    used: 0,
                    capacity: payload_capacity,
                },
            );
        }
        Ok(Self { state, mapping_len })
    }

    pub(super) fn raw(&self) -> *mut CowDiffState {
        self.state
    }

    pub(super) fn snapshot(&self) -> Result<CowDiff, SandboxError> {
        let used = unsafe { ptr::read_volatile(ptr::addr_of!((*self.state).used)) } as usize;
        let capacity = unsafe { ptr::read_volatile(ptr::addr_of!((*self.state).capacity)) } as usize;
        if used > capacity {
            return Err(SandboxError::SetupFailed(
                "copy-on-write diff exporter published an invalid byte count".to_owned(),
            ));
        }
        let bytes = unsafe {
            std::slice::from_raw_parts(
                self.state.add(1).cast::<u8>(),
                used,
            )
        };
        let mut offset = 0usize;
        let mut entries = Vec::new();
        while offset < bytes.len() {
            if bytes.len() - offset < RECORD_HEADER_BYTES {
                return Err(SandboxError::SetupFailed(
                    "copy-on-write diff exporter published a truncated record header".to_owned(),
                ));
            }
            let tag = bytes[offset];
            let path_len = u16::from_le_bytes([bytes[offset + 1], bytes[offset + 2]]) as usize;
            let payload_len = u64::from_le_bytes(
                bytes[offset + 3..offset + 11]
                    .try_into()
                    .expect("fixed diff record length"),
            ) as usize;
            offset += RECORD_HEADER_BYTES;
            let end_path = offset.checked_add(path_len).ok_or_else(|| {
                SandboxError::SetupFailed("copy-on-write diff path length overflow".to_owned())
            })?;
            let end_payload = end_path.checked_add(payload_len).ok_or_else(|| {
                SandboxError::SetupFailed("copy-on-write diff payload length overflow".to_owned())
            })?;
            if end_payload > bytes.len() {
                return Err(SandboxError::SetupFailed(
                    "copy-on-write diff exporter published a truncated record".to_owned(),
                ));
            }
            let mut path = Vec::with_capacity(path_len.saturating_add(1));
            path.push(b'/');
            path.extend_from_slice(&bytes[offset..end_path]);
            let payload = &bytes[end_path..end_payload];
            let entry = match tag {
                TAG_FILE => CowDiffEntry::UpsertFile {
                    path,
                    bytes: payload.to_vec(),
                },
                TAG_DIRECTORY if payload.is_empty() => CowDiffEntry::EnsureDirectory { path },
                TAG_SYMLINK => CowDiffEntry::Symlink {
                    path,
                    target: payload.to_vec(),
                },
                TAG_REMOVE if payload.is_empty() => CowDiffEntry::Remove { path },
                TAG_OPAQUE_DIRECTORY if payload.is_empty() => {
                    CowDiffEntry::OpaqueDirectory { path }
                }
                _ => {
                    return Err(SandboxError::SetupFailed(
                        "copy-on-write diff exporter published an unknown record".to_owned(),
                    ));
                }
            };
            entries.push(entry);
            offset = end_payload;
        }
        entries.sort_by(|left, right| {
            entry_path(left)
                .cmp(entry_path(right))
                .then_with(|| entry_rank(left).cmp(&entry_rank(right)))
        });
        Ok(CowDiff {
            entries,
            encoded_bytes: (CANONICAL_MAGIC_BYTES + used) as u64,
        })
    }
}

impl Drop for SharedCowDiff {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.state.cast::<libc::c_void>(), self.mapping_len);
        }
    }
}

fn entry_path(entry: &CowDiffEntry) -> &[u8] {
    match entry {
        CowDiffEntry::UpsertFile { path, .. }
        | CowDiffEntry::EnsureDirectory { path }
        | CowDiffEntry::Symlink { path, .. }
        | CowDiffEntry::Remove { path }
        | CowDiffEntry::OpaqueDirectory { path } => path,
    }
}

fn entry_rank(entry: &CowDiffEntry) -> u8 {
    match entry {
        CowDiffEntry::EnsureDirectory { .. } => 0,
        CowDiffEntry::OpaqueDirectory { .. } => 1,
        CowDiffEntry::UpsertFile { .. } => 2,
        CowDiffEntry::Symlink { .. } => 3,
        CowDiffEntry::Remove { .. } => 4,
    }
}

pub(super) unsafe fn export_upper(
    upper_path_fd: libc::c_int,
    state: *mut CowDiffState,
) -> Result<(), i32> {
    if upper_path_fd < 0 || state.is_null() {
        return Err(libc::EINVAL);
    }
    ptr::write_volatile(ptr::addr_of_mut!((*state).used), 0);
    let root_fd = libc::syscall(
        libc::SYS_openat,
        upper_path_fd,
        b".\0".as_ptr().cast::<libc::c_char>(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    );
    if root_fd == -1 {
        return Err(*libc::__errno_location());
    }
    let root_fd = root_fd as libc::c_int;
    if is_opaque_directory(root_fd)? {
        append_record(state, TAG_OPAQUE_DIRECTORY, &[], &[])?;
    }
    let mut path = [0u8; PATH_BYTES_MAX];
    let result = walk_directory(root_fd, state, &mut path, 0);
    let close_result = libc::close(root_fd);
    if let Err(errno) = result {
        return Err(errno);
    }
    if close_result == -1 {
        return Err(*libc::__errno_location());
    }
    Ok(())
}

unsafe fn walk_directory(
    directory_fd: libc::c_int,
    state: *mut CowDiffState,
    path: &mut [u8; PATH_BYTES_MAX],
    path_len: usize,
) -> Result<(), i32> {
    let mut buffer = [0u8; DIRENT_BUFFER_BYTES];
    loop {
        let count = libc::syscall(
            libc::SYS_getdents64,
            directory_fd,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
        );
        if count == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        if count == 0 {
            return Ok(());
        }
        let count = count as usize;
        let mut offset = 0usize;
        while offset < count {
            if count - offset < 19 {
                return Err(libc::EIO);
            }
            let record = buffer.as_ptr().add(offset);
            let reclen = u16::from_ne_bytes([*record.add(16), *record.add(17)]) as usize;
            if reclen < 20 || offset + reclen > count {
                return Err(libc::EIO);
            }
            let name_start = offset + 19;
            let name_region = &buffer[name_start..offset + reclen];
            let Some(name_len) = name_region.iter().position(|byte| *byte == 0) else {
                return Err(libc::EIO);
            };
            let name = &name_region[..name_len];
            if name != b"." && name != b".." {
                let previous_len = path_len;
                let mut next_len = path_len;
                if next_len != 0 {
                    if next_len >= path.len() {
                        return Err(libc::ENAMETOOLONG);
                    }
                    path[next_len] = b'/';
                    next_len += 1;
                }
                if name.len() > path.len().saturating_sub(next_len) {
                    return Err(libc::ENAMETOOLONG);
                }
                path[next_len..next_len + name.len()].copy_from_slice(name);
                next_len += name.len();
                let name_ptr = buffer.as_ptr().add(name_start).cast::<libc::c_char>();
                export_entry(directory_fd, name_ptr, state, path, next_len)?;
                for byte in &mut path[previous_len..next_len] {
                    *byte = 0;
                }
            }
            offset += reclen;
        }
    }
}

unsafe fn export_entry(
    directory_fd: libc::c_int,
    name: *const libc::c_char,
    state: *mut CowDiffState,
    path: &mut [u8; PATH_BYTES_MAX],
    path_len: usize,
) -> Result<(), i32> {
    let mut stat = std::mem::zeroed::<libc::stat>();
    if libc::syscall(
        libc::SYS_newfstatat,
        directory_fd,
        name,
        &mut stat as *mut libc::stat,
        libc::AT_SYMLINK_NOFOLLOW,
    ) == -1
    {
        return Err(*libc::__errno_location());
    }
    let kind = stat.st_mode & libc::S_IFMT;
    if kind == libc::S_IFCHR && stat.st_rdev == 0 {
        return append_record(state, TAG_REMOVE, &path[..path_len], &[]);
    }
    if kind == libc::S_IFDIR {
        let fd = libc::syscall(
            libc::SYS_openat,
            directory_fd,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        );
        if fd == -1 {
            return Err(*libc::__errno_location());
        }
        let fd = fd as libc::c_int;
        append_record(state, TAG_DIRECTORY, &path[..path_len], &[])?;
        if is_opaque_directory(fd)? {
            append_record(state, TAG_OPAQUE_DIRECTORY, &path[..path_len], &[])?;
        }
        let result = walk_directory(fd, state, path, path_len);
        let close_result = libc::close(fd);
        if let Err(errno) = result {
            return Err(errno);
        }
        if close_result == -1 {
            return Err(*libc::__errno_location());
        }
        return Ok(());
    }
    if kind == libc::S_IFREG {
        let fd = libc::syscall(
            libc::SYS_openat,
            directory_fd,
            name,
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0,
        );
        if fd == -1 {
            return Err(*libc::__errno_location());
        }
        let fd = fd as libc::c_int;
        if has_whiteout_xattr(fd)? {
            let close_result = libc::close(fd);
            if close_result == -1 {
                return Err(*libc::__errno_location());
            }
            return append_record(state, TAG_REMOVE, &path[..path_len], &[]);
        }
        if stat.st_size < 0 {
            let _ = libc::close(fd);
            return Err(libc::EIO);
        }
        let result = append_file(state, &path[..path_len], fd, stat.st_size as usize);
        let close_result = libc::close(fd);
        if let Err(errno) = result {
            return Err(errno);
        }
        if close_result == -1 {
            return Err(*libc::__errno_location());
        }
        return Ok(());
    }
    if kind == libc::S_IFLNK {
        let mut target = [0u8; PATH_BYTES_MAX];
        let length = libc::syscall(
            libc::SYS_readlinkat,
            directory_fd,
            name,
            target.as_mut_ptr(),
            target.len(),
        );
        if length == -1 {
            return Err(*libc::__errno_location());
        }
        if length as usize == target.len() {
            return Err(libc::ENAMETOOLONG);
        }
        return append_record(
            state,
            TAG_SYMLINK,
            &path[..path_len],
            &target[..length as usize],
        );
    }
    Err(libc::EOPNOTSUPP)
}

unsafe fn append_file(
    state: *mut CowDiffState,
    path: &[u8],
    fd: libc::c_int,
    length: usize,
) -> Result<(), i32> {
    let payload = reserve_record(state, TAG_FILE, path, length)?;
    let mut offset = 0usize;
    while offset < length {
        let read = libc::syscall(
            libc::SYS_pread64,
            fd,
            payload.add(offset).cast::<libc::c_void>(),
            length - offset,
            offset as libc::off_t,
        );
        if read == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
        if read == 0 {
            return Err(libc::EIO);
        }
        offset += read as usize;
    }
    commit_record(state, RECORD_HEADER_BYTES + path.len() + length);
    Ok(())
}

unsafe fn append_record(
    state: *mut CowDiffState,
    tag: u8,
    path: &[u8],
    payload: &[u8],
) -> Result<(), i32> {
    let destination = reserve_record(state, tag, path, payload.len())?;
    ptr::copy_nonoverlapping(payload.as_ptr(), destination, payload.len());
    commit_record(state, RECORD_HEADER_BYTES + path.len() + payload.len());
    Ok(())
}

unsafe fn reserve_record(
    state: *mut CowDiffState,
    tag: u8,
    path: &[u8],
    payload_len: usize,
) -> Result<*mut u8, i32> {
    if path.len() > u16::MAX as usize {
        return Err(libc::ENAMETOOLONG);
    }
    let used = ptr::read_volatile(ptr::addr_of!((*state).used)) as usize;
    let capacity = ptr::read_volatile(ptr::addr_of!((*state).capacity)) as usize;
    let record_len = RECORD_HEADER_BYTES
        .checked_add(path.len())
        .and_then(|value| value.checked_add(payload_len))
        .ok_or(libc::EFBIG)?;
    if record_len > capacity.saturating_sub(used) {
        return Err(libc::EFBIG);
    }
    let output = state.add(1).cast::<u8>().add(used);
    *output = tag;
    let path_len = (path.len() as u16).to_le_bytes();
    ptr::copy_nonoverlapping(path_len.as_ptr(), output.add(1), path_len.len());
    let payload_len_bytes = (payload_len as u64).to_le_bytes();
    ptr::copy_nonoverlapping(payload_len_bytes.as_ptr(), output.add(3), payload_len_bytes.len());
    ptr::copy_nonoverlapping(path.as_ptr(), output.add(RECORD_HEADER_BYTES), path.len());
    Ok(output.add(RECORD_HEADER_BYTES + path.len()))
}

unsafe fn commit_record(state: *mut CowDiffState, record_len: usize) {
    let used = ptr::read_volatile(ptr::addr_of!((*state).used));
    ptr::write_volatile(
        ptr::addr_of_mut!((*state).used),
        used + record_len as u64,
    );
}

unsafe fn has_whiteout_xattr(fd: libc::c_int) -> Result<bool, i32> {
    has_xattr(fd, b"trusted.overlay.whiteout\0")
        .or_else(|errno| if errno == libc::EPERM { Ok(false) } else { Err(errno) })
        .and_then(|trusted| {
            if trusted {
                Ok(true)
            } else {
                has_xattr(fd, b"user.overlay.whiteout\0")
            }
        })
}

unsafe fn is_opaque_directory(fd: libc::c_int) -> Result<bool, i32> {
    for name in [b"trusted.overlay.opaque\0".as_slice(), b"user.overlay.opaque\0".as_slice()] {
        let mut value = [0u8; 1];
        let result = libc::syscall(
            libc::SYS_fgetxattr,
            fd,
            name.as_ptr().cast::<libc::c_char>(),
            value.as_mut_ptr(),
            value.len(),
        );
        if result >= 0 {
            return Ok(result == 1 && value[0] == b'y');
        }
        let errno = *libc::__errno_location();
        if errno != libc::ENODATA && errno != libc::EOPNOTSUPP && errno != libc::EPERM {
            return Err(errno);
        }
    }
    Ok(false)
}

unsafe fn has_xattr(fd: libc::c_int, name: &[u8]) -> Result<bool, i32> {
    let result = libc::syscall(
        libc::SYS_fgetxattr,
        fd,
        name.as_ptr().cast::<libc::c_char>(),
        ptr::null_mut::<libc::c_void>(),
        0usize,
    );
    if result >= 0 {
        return Ok(true);
    }
    let errno = *libc::__errno_location();
    if errno == libc::ENODATA || errno == libc::EOPNOTSUPP {
        Ok(false)
    } else {
        Err(errno)
    }
}
'''
Path("src/platform/linux_cow_diff.rs").write_text(cow_module)

# Public report model.
replace_one(
    "src/report.rs",
    "/// Kernel resource usage attributed to the terminated/waited-for sandbox process tree.\n",
    '''/// One deterministic copy-on-write root change exported after launcher-owned tree teardown.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub enum CowDiffEntry {\n    UpsertFile { path: Vec<u8>, bytes: Vec<u8> },\n    EnsureDirectory { path: Vec<u8> },\n    Symlink { path: Vec<u8>, target: Vec<u8> },\n    Remove { path: Vec<u8> },\n    OpaqueDirectory { path: Vec<u8> },\n}\n\n/// Complete bounded change-set for an ephemeral copy-on-write root.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct CowDiff {\n    pub entries: Vec<CowDiffEntry>,\n    /// Bytes consumed by the canonical internal change-set encoding.\n    pub encoded_bytes: u64,\n}\n\n/// Kernel resource usage attributed to the terminated/waited-for sandbox process tree.\n''',
    "report cow diff types",
)
replace_one(
    "src/report.rs",
    "    pub stdout: Option<CapturedOutput>,\n",
    "    pub stdout: Option<CapturedOutput>,\n    /// Present exactly when `filesystem.cow_diff_bytes` requested a complete bounded COW export.\n    pub cow_diff: Option<CowDiff>,\n",
    "report cow diff field",
)
replace_one(
    "src/lib.rs",
    "pub use report::{CapturedOutput, ChildOutcome, EnforcementReceipt, ProcessTreeUsage, RunReport};",
    "pub use report::{CapturedOutput, ChildOutcome, CowDiff, CowDiffEntry, EnforcementReceipt, ProcessTreeUsage, RunReport};",
    "lib cow diff export",
)

# Policy: bounded opt-in export only with COW root.
replace_one(
    "src/policy.rs",
    "const MAX_COW_ROOT_BYTES: u64 = 1024 * 1024 * 1024;\n",
    "const MAX_COW_ROOT_BYTES: u64 = 1024 * 1024 * 1024;\nconst MIN_COW_DIFF_BYTES: u64 = 64;\nconst MAX_COW_DIFF_BYTES: u64 = 16 * 1024 * 1024;\n",
    "policy cow diff constants",
)
replace_one(
    "src/policy.rs",
    "    pub cow_root_bytes: Option<u64>,\n",
    "    pub cow_root_bytes: Option<u64>,\n    /// Optional complete post-run export ceiling for the private COW upper tree.\n    /// Valid only when `cow_root_bytes` is also configured.\n    pub cow_diff_bytes: Option<u64>,\n",
    "policy cow diff field",
)
replace_one(
    "src/policy.rs",
    "        if let Some(bytes) = self.cow_root_bytes {\n            if !(MIN_COW_ROOT_BYTES..=MAX_COW_ROOT_BYTES).contains(&bytes) {\n                return Err(PolicyError::new(format!(\n                    \"filesystem.cow_root_bytes must be between {MIN_COW_ROOT_BYTES} and {MAX_COW_ROOT_BYTES}\"\n                )));\n            }\n        }\n\n",
    "        if let Some(bytes) = self.cow_root_bytes {\n            if !(MIN_COW_ROOT_BYTES..=MAX_COW_ROOT_BYTES).contains(&bytes) {\n                return Err(PolicyError::new(format!(\n                    \"filesystem.cow_root_bytes must be between {MIN_COW_ROOT_BYTES} and {MAX_COW_ROOT_BYTES}\"\n                )));\n            }\n        }\n        if let Some(bytes) = self.cow_diff_bytes {\n            if self.cow_root_bytes.is_none() {\n                return Err(PolicyError::new(\n                    \"filesystem.cow_diff_bytes requires filesystem.cow_root_bytes\",\n                ));\n            }\n            if !(MIN_COW_DIFF_BYTES..=MAX_COW_DIFF_BYTES).contains(&bytes) {\n                return Err(PolicyError::new(format!(\n                    \"filesystem.cow_diff_bytes must be between {MIN_COW_DIFF_BYTES} and {MAX_COW_DIFF_BYTES}\"\n                )));\n            }\n        }\n\n",
    "policy cow diff validation",
)
replace_one(
    "src/policy.rs",
    "        let mut cow_root_bytes = None;\n",
    "        let mut cow_root_bytes = None;\n        let mut cow_diff_bytes = None;\n",
    "policy parser variable",
)
replace_one(
    "src/policy.rs",
    "                \"filesystem.cow_root_bytes\" => set_once(\n                    &mut cow_root_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n",
    "                \"filesystem.cow_root_bytes\" => set_once(\n                    &mut cow_root_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n                \"filesystem.cow_diff_bytes\" => set_once(\n                    &mut cow_diff_bytes,\n                    parse_u64(value, line_no, key)?,\n                    line_no,\n                    key,\n                )?,\n",
    "policy parser key",
)
replace_one(
    "src/policy.rs",
    "            cow_root_bytes,\n            hostname:",
    "            cow_root_bytes,\n            cow_diff_bytes,\n            hostname:",
    "policy parsed constructor",
)
replace_one(
    "src/policy.rs",
    "        assert_eq!(policy.cow_root_bytes, None);\n",
    "        assert_eq!(policy.cow_root_bytes, None);\n        assert_eq!(policy.cow_diff_bytes, None);\n",
    "policy complete assertion",
)
replace_one(
    "src/policy.rs",
    "    #[test]\n    fn parses_readonly_volume_pair() {",
    '''    #[test]\n    fn parses_bounded_copy_on_write_diff_export() {\n        let policy: SandboxPolicy = format!(\n            "{VALID}\\nfilesystem.cow_root_bytes = 16777216\\nfilesystem.cow_diff_bytes = 4096"\n        )\n        .parse()\n        .unwrap();\n        assert_eq!(policy.cow_diff_bytes, Some(4096));\n\n        let without_cow = format!("{VALID}\\nfilesystem.cow_diff_bytes = 4096");\n        assert!(without_cow.parse::<SandboxPolicy>().is_err());\n\n        let too_small = format!(\n            "{VALID}\\nfilesystem.cow_root_bytes = 16777216\\nfilesystem.cow_diff_bytes = {}",\n            MIN_COW_DIFF_BYTES - 1\n        );\n        assert!(too_small.parse::<SandboxPolicy>().is_err());\n    }\n\n    #[test]\n    fn parses_readonly_volume_pair() {''',
    "policy cow diff unit test",
)

# Add cow_diff_bytes to every direct SandboxPolicy literal currently using cow_root_bytes.
for p in Path(".").rglob("*.rs"):
    if p.as_posix() == "src/policy.rs":
        continue
    text = p.read_text()
    updated = re.sub(
        r"(?m)^(\s*)cow_root_bytes: ([^\n]+),$",
        r"\1cow_root_bytes: \2,\n\1cow_diff_bytes: None,",
        text,
    )
    if updated != text:
        p.write_text(updated)

# Linux module and launch wiring.
replace_one(
    "src/platform/linux.rs",
    '#[cfg(target_arch = "x86_64")]\n#[path = "linux_pid_lifecycle.rs"]\nmod pid_lifecycle;\n',
    '#[cfg(target_arch = "x86_64")]\n#[path = "linux_pid_lifecycle.rs"]\nmod pid_lifecycle;\n#[cfg(target_arch = "x86_64")]\n#[path = "linux_cow_diff.rs"]\nmod cow_diff;\n',
    "linux cow module",
)
replace_one(
    "src/platform/linux.rs",
    "    use super::pid_lifecycle::{\n",
    "    use super::cow_diff::{CowDiffState, SharedCowDiff};\n    use super::pid_lifecycle::{\n",
    "linux cow imports",
)
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_COW_ROOT_ATTACH: u32 = 64;\n",
    "    const PHASE_COW_ROOT_ATTACH: u32 = 64;\n    const PHASE_COW_DIFF_EXPORT: u32 = 65;\n",
    "linux cow diff phase",
)
replace_one(
    "src/platform/linux.rs",
    "        cow_root_size: Option<CString>,\n",
    "        cow_root_size: Option<CString>,\n        cow_diff_requested: bool,\n",
    "prepared cow diff flag",
)
replace_one(
    "src/platform/linux.rs",
    "                root_path,\n                cow_root_size,\n                executable_fd,",
    "                root_path,\n                cow_root_size,\n                cow_diff_requested: policy.cow_diff_bytes.is_some(),\n                executable_fd,",
    "prepared cow diff init",
)
replace_one(
    "src/platform/linux.rs",
    "        capture_write_fd: RawFd,\n        output_limit_fd: RawFd,\n",
    "        capture_write_fd: RawFd,\n        output_limit_fd: RawFd,\n        cow_diff_state: *mut CowDiffState,\n",
    "child control cow state",
)
replace_one(
    "src/platform/linux.rs",
    "        let lifecycle = SharedTargetLifecycle::new().map_err(|err| {\n            SandboxError::SetupFailed(format!(\n                \"cannot allocate shared target lifecycle state: {err}\"\n            ))\n        })?;\n",
    "        let lifecycle = SharedTargetLifecycle::new().map_err(|err| {\n            SandboxError::SetupFailed(format!(\n                \"cannot allocate shared target lifecycle state: {err}\"\n            ))\n        })?;\n        let cow_diff = policy\n            .cow_diff_bytes\n            .map(SharedCowDiff::new)\n            .transpose()\n            .map_err(|err| {\n                SandboxError::SetupFailed(format!(\n                    \"cannot allocate bounded copy-on-write diff state: {err}\"\n                ))\n            })?;\n",
    "host shared cow diff",
)
replace_one(
    "src/platform/linux.rs",
    "            output_limit_fd,\n            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),\n",
    "            output_limit_fd,\n            cow_diff_state: cow_diff.as_ref().map_or(ptr::null_mut(), SharedCowDiff::raw),\n            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),\n",
    "child control cow pointer",
)
replace_all(
    "src/platform/linux.rs",
    "                stdout: None,\n                reaped_descendants:",
    "                stdout: None,\n                cow_diff: None,\n                reaped_descendants:",
    "error report cow diff",
    minimum=1,
)
replace_one(
    "src/platform/linux.rs",
    "        let outcome = resolve_lifecycle_outcome(&lifecycle_record, output_limit_observed)?;\n        Ok(RunReport {\n            outcome,\n            stdout,\n",
    "        let outcome = resolve_lifecycle_outcome(&lifecycle_record, output_limit_observed)?;\n        let cow_diff = cow_diff.as_ref().map(SharedCowDiff::snapshot).transpose()?;\n        Ok(RunReport {\n            outcome,\n            stdout,\n            cow_diff,\n",
    "final report cow diff",
)
replace_one(
    "src/platform/linux.rs",
    "            output_limit_fd,\n            wall_clock_milliseconds,\n        } = control;",
    "            output_limit_fd,\n            cow_diff_state,\n            wall_clock_milliseconds,\n        } = control;",
    "child control destructure",
)
replace_one(
    "src/platform/linux.rs",
    "    ) -> RawFd {\n        let lower_tree_fd = libc::syscall(\n",
    "    ) -> (RawFd, RawFd) {\n        let lower_tree_fd = libc::syscall(\n",
    "constructed root return signature",
)
replace_one(
    "src/platform/linux.rs",
    "            close_setup_fd(current_root_fd);\n            mark_enforcement(launch_error, ENFORCEMENT_READONLY_ROOT);\n            return lower_tree_fd;\n",
    "            close_setup_fd(current_root_fd);\n            mark_enforcement(launch_error, ENFORCEMENT_READONLY_ROOT);\n            return (lower_tree_fd, -1);\n",
    "readonly root tuple",
)
replace_one(
    "src/platform/linux.rs",
    "        close_setup_fd(work_fd);\n        close_setup_fd(upper_fd);\n        close_setup_fd(state_mount_fd);\n        close_setup_fd(lower_tree_fd);\n        mark_enforcement(launch_error, ENFORCEMENT_COW_ROOT);\n        overlay_fd\n",
    "        close_setup_fd(work_fd);\n        let retained_upper_fd = if prepared.cow_diff_requested {\n            upper_fd\n        } else {\n            close_setup_fd(upper_fd);\n            -1\n        };\n        close_setup_fd(state_mount_fd);\n        close_setup_fd(lower_tree_fd);\n        mark_enforcement(launch_error, ENFORCEMENT_COW_ROOT);\n        (overlay_fd, retained_upper_fd)\n",
    "retain cow upper for exporter",
)
replace_one(
    "src/platform/linux.rs",
    "        let root_tree_fd = construct_final_root_or_fail(\n            prepared,\n            current_root_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n",
    "        let (root_tree_fd, cow_upper_fd) = construct_final_root_or_fail(\n            prepared,\n            current_root_fd,\n            launch_error,\n            seccomp.error_exit_syscall,\n        );\n",
    "constructed root destructure",
)
replace_one(
    "src/platform/linux.rs",
    "            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),\n            output_limit_fd,\n            TargetSupervisionPhases {",
    "            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),\n            output_limit_fd,\n            cow_upper_fd,\n            cow_diff_state,\n            TargetSupervisionPhases {",
    "lifecycle cow arguments",
)
replace_one(
    "src/platform/linux.rs",
    "                usage: PHASE_PROCESS_TREE_USAGE,\n            },",
    "                usage: PHASE_PROCESS_TREE_USAGE,\n                cow_diff_export: PHASE_COW_DIFF_EXPORT,\n            },",
    "cow diff lifecycle phase",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_COW_ROOT_ATTACH => \"copy-on-write final root attachment\",\n",
    "            PHASE_COW_ROOT_ATTACH => \"copy-on-write final root attachment\",\n            PHASE_COW_DIFF_EXPORT => \"bounded copy-on-write diff export\",\n",
    "cow diff phase name",
)

# PID1 owns upper fd; target never receives it; export after tree teardown.
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "use std::io;\n",
    "use super::cow_diff::{self, CowDiffState};\nuse std::io;\n",
    "lifecycle cow import",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    pub(super) usage: u32,\n}",
    "    pub(super) usage: u32,\n    pub(super) cow_diff_export: u32,\n}",
    "lifecycle phase field",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    output_limit_fd: libc::c_int,\n    phases: TargetSupervisionPhases,\n",
    "    output_limit_fd: libc::c_int,\n    cow_upper_fd: libc::c_int,\n    cow_diff_state: *mut CowDiffState,\n    phases: TargetSupervisionPhases,\n",
    "lifecycle signature",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "        for control_fd in [cancellation_fd, output_limit_fd] {\n",
    "        for control_fd in [cancellation_fd, output_limit_fd, cow_upper_fd] {\n",
    "target closes cow upper",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    if let Err(errno) = close_nonstdio_except(cancellation_fd, output_limit_fd) {\n",
    "    if let Err(errno) = close_nonstdio_except(cancellation_fd, output_limit_fd, cow_upper_fd) {\n",
    "pid1 keeps cow upper",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    let (user_cpu_micros, system_cpu_micros, max_child_rss_kib) = match collect_process_tree_usage()\n    {\n        Ok(usage) => usage,\n        Err(errno) => fail_errno(launch_error, phases.usage, errno),\n    };\n\n",
    "    let (user_cpu_micros, system_cpu_micros, max_child_rss_kib) = match collect_process_tree_usage()\n    {\n        Ok(usage) => usage,\n        Err(errno) => fail_errno(launch_error, phases.usage, errno),\n    };\n    if !cow_diff_state.is_null() {\n        if cow_upper_fd < 3 {\n            fail_errno(launch_error, phases.cow_diff_export, libc::EINVAL);\n        }\n        if let Err(errno) = cow_diff::export_upper(cow_upper_fd, cow_diff_state) {\n            fail_errno(launch_error, phases.cow_diff_export, errno);\n        }\n    }\n    if cow_upper_fd >= 3 && libc::close(cow_upper_fd) == -1 {\n        fail(launch_error, phases.close);\n    }\n\n",
    "post-tree cow export",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "unsafe fn close_nonstdio_except(keep_a: libc::c_int, keep_b: libc::c_int) -> Result<(), i32> {\n    let mut keep = [keep_a, keep_b];\n",
    "unsafe fn close_nonstdio_except(\n    keep_a: libc::c_int,\n    keep_b: libc::c_int,\n    keep_c: libc::c_int,\n) -> Result<(), i32> {\n    let mut keep = [keep_a, keep_b, keep_c];\n",
    "close except third fd",
)

# CLI JSON exposes structured deterministic entries as raw-byte hex.
replace_one(
    "src/cli_json.rs",
    "use security_lab::{ChildOutcome, RunReport, SandboxError};",
    "use security_lab::{ChildOutcome, CowDiffEntry, RunReport, SandboxError};",
    "cli cow import",
)
replace_one(
    "src/cli_json.rs",
    "    output.push_str(\",\\\"reaped_descendants\\\":\");\n",
    '''    output.push_str(",\\\"cow_diff\\\":");\n    match &report.cow_diff {\n        Some(diff) => {\n            output.push_str("{\\\"encoded_bytes\\\":");\n            write!(&mut output, "{}", diff.encoded_bytes).expect("write to String cannot fail");\n            output.push_str(",\\\"entries\\\":[");\n            for (index, entry) in diff.entries.iter().enumerate() {\n                if index != 0 { output.push(','); }\n                push_cow_diff_entry(&mut output, entry);\n            }\n            output.push_str("]}");\n        }\n        None => output.push_str("null"),\n    }\n    output.push_str(",\\\"reaped_descendants\\\":");\n''',
    "cli cow diff output",
)
replace_one(
    "src/cli_json.rs",
    "fn push_bool(output: &mut String, value: bool) {\n",
    '''fn push_cow_diff_entry(output: &mut String, entry: &CowDiffEntry) {\n    let (kind, path) = match entry {\n        CowDiffEntry::UpsertFile { path, .. } => ("upsert_file", path),\n        CowDiffEntry::EnsureDirectory { path } => ("ensure_directory", path),\n        CowDiffEntry::Symlink { path, .. } => ("symlink", path),\n        CowDiffEntry::Remove { path } => ("remove", path),\n        CowDiffEntry::OpaqueDirectory { path } => ("opaque_directory", path),\n    };\n    output.push_str("{\\\"kind\\\":");\n    push_json_string(output, kind);\n    output.push_str(",\\\"path_encoding\\\":\\\"hex\\\",\\\"path\\\":\\\"");\n    push_hex(output, path);\n    output.push('\\\"');\n    match entry {\n        CowDiffEntry::UpsertFile { bytes, .. } => {\n            output.push_str(",\\\"data_encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"");\n            push_hex(output, bytes);\n            output.push('\\\"');\n        }\n        CowDiffEntry::Symlink { target, .. } => {\n            output.push_str(",\\\"target_encoding\\\":\\\"hex\\\",\\\"target\\\":\\\"");\n            push_hex(output, target);\n            output.push('\\\"');\n        }\n        _ => {}\n    }\n    output.push('}');\n}\n\nfn push_bool(output: &mut String, value: bool) {\n''',
    "cli cow diff helper",
)
replace_all(
    "src/cli_json.rs",
    "            stdout: Some(CapturedOutput {",
    "            stdout: Some(CapturedOutput {",
    "cli initializer anchor",
)
# Direct report literals need the new field.
p = Path("src/cli_json.rs")
text = p.read_text()
text = text.replace(
    "            }),\n            reaped_descendants:",
    "            }),\n            cow_diff: None,\n            reaped_descendants:",
)
p.write_text(text)
# Exact JSON test gains null field.
p = Path("src/cli_json.rs")
text = p.read_text().replace(
    '\\"truncated\\\":true},\\\"reaped_descendants\\\":3',
    '\\"truncated\\\":true},\\\"cow_diff\\\":null,\\\"reaped_descendants\\\":3',
)
p.write_text(text)

# Static authority surfaces.
replace_one(
    "src/authority_manifest.rs",
    "    output.push_str(\",\\\"copy_on_write_root_bytes\\\":\");\n    push_optional_u64(&mut output, policy.cow_root_bytes);\n",
    "    output.push_str(\",\\\"copy_on_write_root_bytes\\\":\");\n    push_optional_u64(&mut output, policy.cow_root_bytes);\n    output.push_str(\",\\\"copy_on_write_diff_bytes\\\":\");\n    push_optional_u64(&mut output, policy.cow_diff_bytes);\n",
    "manifest json cow diff",
)
replace_one(
    "src/authority_manifest.rs",
    "        display_optional_u64(policy.cow_root_bytes)\n    )\n    .expect(\"write to String cannot fail\");\n",
    "        display_optional_u64(policy.cow_root_bytes)\n    )\n    .expect(\"write to String cannot fail\");\n    writeln!(\n        &mut output,\n        \"copy-on-write-diff-bytes: {}\",\n        display_optional_u64(policy.cow_diff_bytes)\n    )\n    .expect(\"write to String cannot fail\");\n",
    "manifest human cow diff",
)
replace_one(
    "src/authority_delta.rs",
    "    compare_copy_on_write_root(baseline, candidate, &mut changes);\n",
    "    compare_copy_on_write_root(baseline, candidate, &mut changes);\n    compare_copy_on_write_diff(baseline, candidate, &mut changes);\n",
    "delta cow diff call",
)
replace_one(
    "src/authority_delta.rs",
    "fn compare_scratch(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {\n",
    '''fn compare_copy_on_write_diff(\n    baseline: &SandboxPolicy,\n    candidate: &SandboxPolicy,\n    changes: &mut Vec<Change>,\n) {\n    match (baseline.cow_diff_bytes, candidate.cow_diff_bytes) {\n        (None, None) => {}\n        (None, Some(_)) => push_change(\n            "filesystem.copy_on_write_diff_export",\n            DeltaClass::Widened,\n            changes,\n        ),\n        (Some(_), None) => push_change(\n            "filesystem.copy_on_write_diff_export",\n            DeltaClass::Reduced,\n            changes,\n        ),\n        (Some(base), Some(new)) => push_change(\n            "filesystem.copy_on_write_diff_bytes",\n            classify_allowance(base, new),\n            changes,\n        ),\n    }\n}\n\nfn compare_scratch(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {\n''',
    "delta cow diff function",
)

# Integration evidence: canonical content diff + fail-closed export ceiling.
replace_one(
    "tests/sandbox.rs",
    "    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, ResourceLimits,\n",
    "    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, CowDiffEntry, ResourceLimits,\n",
    "tests cow diff import",
)
replace_one(
    "tests/sandbox.rs",
    "        cow.cow_root_bytes = Some(SCRATCH_BYTES);\n        let report = run_report(&cow).expect(\"copy-on-write root sandbox failed\");\n",
    "        cow.cow_root_bytes = Some(SCRATCH_BYTES);\n        cow.cow_diff_bytes = Some(4096);\n        let report = run_report(&cow).expect(\"copy-on-write root sandbox failed\");\n",
    "enable cow diff evidence",
)
replace_one(
    "tests/sandbox.rs",
    "        assert!(report.enforcement.copy_on_write_root);\n        assert!(!report.enforcement.readonly_root);\n        assert_eq!(std::fs::read(&base).unwrap(), b\"lower-original\\n\");\n",
    '''        assert!(report.enforcement.copy_on_write_root);\n        assert!(!report.enforcement.readonly_root);\n        let diff = report.cow_diff.expect("requested COW diff export");\n        assert!(diff.entries.iter().any(|entry| matches!(\n            entry,\n            CowDiffEntry::UpsertFile { path, bytes }\n                if path == b"/cow-base" && bytes == b"cow-replaced\\n"\n        )));\n        assert!(diff.entries.iter().any(|entry| matches!(\n            entry,\n            CowDiffEntry::UpsertFile { path, bytes }\n                if path == b"/cow-new" && bytes == b"cow-new\\n"\n        )));\n        assert!(diff.entries.iter().any(|entry| matches!(\n            entry,\n            CowDiffEntry::Remove { path } if path == b"/cow-dir/child"\n        )));\n        assert!(diff.encoded_bytes <= 4096);\n        assert_eq!(std::fs::read(&base).unwrap(), b"lower-original\\n");\n''',
    "assert cow diff evidence",
)
replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {",
    '''#[test]\nfn copy_on_write_diff_export_fails_closed_when_budget_is_too_small() {\n    let mut cow = policy(\n        "z",\n        &[],\n        &["execveat", "openat", "read", "write", "close", "unlink", "exit"],\n    );\n    cow.cow_root_bytes = Some(SCRATCH_BYTES);\n    cow.cow_diff_bytes = Some(64);\n    match run_report(&cow).expect_err("undersized COW diff budget must fail closed") {\n        SandboxError::SetupFailed(message) => {\n            assert!(message.contains("bounded copy-on-write diff export"));\n        }\n        other => panic!("unexpected COW diff overflow result: {other}"),\n    }\n}\n\n#[test]\nfn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {''',
    "cow diff overflow test",
)

# Report literals outside CLI/Linux get default None via broad direct literal insertion where needed.
for p in Path(".").rglob("*.rs"):
    if p.as_posix() in {"src/report.rs", "src/platform/linux.rs", "src/cli_json.rs"}:
        continue
    text = p.read_text()
    if "RunReport {" in text:
        text = text.replace(
            "            stdout: None,\n            reaped_descendants:",
            "            stdout: None,\n            cow_diff: None,\n            reaped_descendants:",
        )
        p.write_text(text)
