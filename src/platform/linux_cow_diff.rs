use crate::{CowDiff, CowDiffEntry, SandboxError};
use std::io;
use std::ptr;

const RECORD_HEADER_BYTES: usize = 11;
const CANONICAL_MAGIC_BYTES: usize = 6;
const PATH_BYTES_MAX: usize = 4096;
const DIRENT_BUFFER_BYTES: usize = 8192;
const MAX_EXPORT_DEPTH: usize = 64;
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
        let capacity =
            unsafe { ptr::read_volatile(ptr::addr_of!((*self.state).capacity)) } as usize;
        if used > capacity {
            return Err(SandboxError::SetupFailed(
                "copy-on-write diff exporter published an invalid byte count".to_owned(),
            ));
        }
        let bytes = unsafe { std::slice::from_raw_parts(self.state.add(1).cast::<u8>(), used) };
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
    let result = walk_directory(root_fd, state, &mut path, 0, 0);
    let close_result = libc::close(root_fd);
    result?;
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
    depth: usize,
) -> Result<(), i32> {
    if depth > MAX_EXPORT_DEPTH {
        return Err(libc::ELOOP);
    }
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
                export_entry(directory_fd, name_ptr, state, path, next_len, depth)?;
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
    depth: usize,
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
        let result = walk_directory(fd, state, path, path_len, depth + 1);
        let close_result = libc::close(fd);
        result?;
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
        result?;
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
    ptr::copy_nonoverlapping(
        payload_len_bytes.as_ptr(),
        output.add(3),
        payload_len_bytes.len(),
    );
    ptr::copy_nonoverlapping(path.as_ptr(), output.add(RECORD_HEADER_BYTES), path.len());
    Ok(output.add(RECORD_HEADER_BYTES + path.len()))
}

unsafe fn commit_record(state: *mut CowDiffState, record_len: usize) {
    let used = ptr::read_volatile(ptr::addr_of!((*state).used));
    ptr::write_volatile(ptr::addr_of_mut!((*state).used), used + record_len as u64);
}

unsafe fn has_whiteout_xattr(fd: libc::c_int) -> Result<bool, i32> {
    has_xattr(fd, b"trusted.overlay.whiteout\0")
        .or_else(|errno| {
            if errno == libc::EPERM {
                Ok(false)
            } else {
                Err(errno)
            }
        })
        .and_then(|trusted| {
            if trusted {
                Ok(true)
            } else {
                has_xattr(fd, b"user.overlay.whiteout\0")
            }
        })
}

unsafe fn is_opaque_directory(fd: libc::c_int) -> Result<bool, i32> {
    for name in [
        b"trusted.overlay.opaque\0".as_slice(),
        b"user.overlay.opaque\0".as_slice(),
    ] {
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
