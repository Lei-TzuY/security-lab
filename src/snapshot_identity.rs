use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::path::Path;

const MAX_IDENTITY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_IDENTITY_NODES: u64 = 100_000;
const CANONICAL_MAGIC: &[u8] = b"security-lab-snapshot-sha256-v1\0";

/// Explicit work limits for canonical snapshot identity calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotIdentityLimits {
    /// Maximum canonical bytes hashed, including file contents and symlink targets.
    pub max_bytes: u64,
    /// Maximum filesystem nodes included in the identity, including the root directory.
    pub max_nodes: u64,
}

/// Canonical SHA-256 identity for the supported snapshot object model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotIdentity {
    pub sha256: [u8; 32],
    pub encoded_bytes: u64,
    pub nodes: u64,
}

impl SnapshotIdentity {
    pub fn sha256_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(64);
        for byte in self.sha256 {
            write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
        }
        text
    }
}

#[derive(Debug)]
pub enum SnapshotIdentityError {
    InvalidInput(String),
    BudgetExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    UnsupportedPlatform(String),
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for SnapshotIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid snapshot identity input: {message}"),
            Self::BudgetExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                f,
                "snapshot identity {resource} budget exceeded: limit={limit} attempted={attempted}"
            ),
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported snapshot identity platform: {message}")
            }
            Self::Io { phase, source } => {
                write!(f, "snapshot identity failed during {phase}: {source}")
            }
        }
    }
}

impl Error for SnapshotIdentityError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Hash one trusted, stable snapshot tree using the Milestone 33A canonical object model.
///
/// The digest commits to sorted path bytes, node type, regular-file/directory Unix
/// permission bits, regular-file bytes, and symlink target bytes. It intentionally
/// excludes UID/GID ownership, timestamps, xattrs/ACLs, hard-link identity, and
/// unsupported special nodes. The caller must not treat this digest as authenticity
/// evidence without an independent trusted binding (for example a signature).
pub fn snapshot_sha256(
    root: &Path,
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotIdentity, SnapshotIdentityError> {
    validate_limits(limits)?;
    #[cfg(target_os = "linux")]
    {
        linux::snapshot_sha256(root, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(SnapshotIdentityError::UnsupportedPlatform(
            "canonical snapshot identity currently requires Linux fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

fn validate_limits(limits: SnapshotIdentityLimits) -> Result<(), SnapshotIdentityError> {
    if limits.max_bytes == 0 || limits.max_bytes > MAX_IDENTITY_BYTES {
        return Err(SnapshotIdentityError::InvalidInput(format!(
            "max_bytes must be between 1 and {MAX_IDENTITY_BYTES}"
        )));
    }
    if limits.max_nodes == 0 || limits.max_nodes > MAX_IDENTITY_NODES {
        return Err(SnapshotIdentityError::InvalidInput(format!(
            "max_nodes must be between 1 and {MAX_IDENTITY_NODES}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;

    const MAX_RELATIVE_PATH_BYTES: usize = 4096;
    const MAX_SYMLINK_TARGET_BYTES: usize = 4095;
    const MAX_TREE_DEPTH: usize = 64;
    const DIRENT_BUFFER_BYTES: usize = 8192;

    struct Fd(RawFd);

    impl Fd {
        fn raw(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    struct CanonicalHasher {
        hasher: Sha256,
        limits: SnapshotIdentityLimits,
        encoded_bytes: u64,
        nodes: u64,
    }

    impl CanonicalHasher {
        fn new(limits: SnapshotIdentityLimits) -> Result<Self, SnapshotIdentityError> {
            let mut value = Self {
                hasher: Sha256::new(),
                limits,
                encoded_bytes: 0,
                nodes: 0,
            };
            value.update(CANONICAL_MAGIC)?;
            Ok(value)
        }

        fn consume_node(&mut self) -> Result<(), SnapshotIdentityError> {
            let attempted = self.nodes.checked_add(1).ok_or_else(|| {
                SnapshotIdentityError::InvalidInput("node accounting overflow".to_owned())
            })?;
            if attempted > self.limits.max_nodes {
                return Err(SnapshotIdentityError::BudgetExceeded {
                    resource: "node",
                    limit: self.limits.max_nodes,
                    attempted,
                });
            }
            self.nodes = attempted;
            Ok(())
        }

        fn update(&mut self, bytes: &[u8]) -> Result<(), SnapshotIdentityError> {
            let attempted = self
                .encoded_bytes
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    SnapshotIdentityError::InvalidInput("byte accounting overflow".to_owned())
                })?;
            if attempted > self.limits.max_bytes {
                return Err(SnapshotIdentityError::BudgetExceeded {
                    resource: "byte",
                    limit: self.limits.max_bytes,
                    attempted,
                });
            }
            self.hasher.update(bytes);
            self.encoded_bytes = attempted;
            Ok(())
        }

        fn record_prefix(&mut self, tag: u8, path: &[u8]) -> Result<(), SnapshotIdentityError> {
            let path_len = u32::try_from(path.len()).map_err(|_| {
                SnapshotIdentityError::InvalidInput("snapshot path length overflow".to_owned())
            })?;
            self.update(&[tag])?;
            self.update(&path_len.to_le_bytes())?;
            self.update(path)
        }

        fn record_directory(
            &mut self,
            path: &[u8],
            mode: u32,
        ) -> Result<(), SnapshotIdentityError> {
            self.consume_node()?;
            self.record_prefix(b'D', path)?;
            self.update(&mode.to_le_bytes())
        }

        fn begin_file(
            &mut self,
            path: &[u8],
            mode: u32,
            length: u64,
        ) -> Result<(), SnapshotIdentityError> {
            self.consume_node()?;
            self.record_prefix(b'F', path)?;
            self.update(&mode.to_le_bytes())?;
            self.update(&length.to_le_bytes())
        }

        fn record_symlink(
            &mut self,
            path: &[u8],
            target: &[u8],
        ) -> Result<(), SnapshotIdentityError> {
            let target_len = u32::try_from(target.len()).map_err(|_| {
                SnapshotIdentityError::InvalidInput("symlink target length overflow".to_owned())
            })?;
            self.consume_node()?;
            self.record_prefix(b'L', path)?;
            self.update(&target_len.to_le_bytes())?;
            self.update(target)
        }

        fn finish(self) -> SnapshotIdentity {
            let digest = self.hasher.finalize();
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&digest);
            SnapshotIdentity {
                sha256,
                encoded_bytes: self.encoded_bytes,
                nodes: self.nodes,
            }
        }
    }

    pub(super) fn snapshot_sha256(
        root: &Path,
        limits: SnapshotIdentityLimits,
    ) -> Result<SnapshotIdentity, SnapshotIdentityError> {
        if !root.is_absolute() {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot root must be an absolute host path".to_owned(),
            ));
        }
        let canonical = fs::canonicalize(root)
            .map_err(|source| io_error("canonicalize snapshot root", source))?;
        let root_fd = open_directory_path(&canonical, "open snapshot root")?;
        let root_stat = stat_fd(root_fd.raw(), "stat snapshot root")?;
        if root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot root is not a directory".to_owned(),
            ));
        }

        let mut identity = CanonicalHasher::new(limits)?;
        identity.record_directory(b"/", (root_stat.st_mode & 0o7777) as u32)?;
        hash_directory(root_fd.raw(), &[], 0, &mut identity)?;
        Ok(identity.finish())
    }

    fn hash_directory(
        directory_fd: RawFd,
        relative: &[u8],
        depth: usize,
        identity: &mut CanonicalHasher,
    ) -> Result<(), SnapshotIdentityError> {
        if depth > MAX_TREE_DEPTH {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot exceeds the 64-level identity depth ceiling".to_owned(),
            ));
        }
        for name in read_directory_names(directory_fd)? {
            let child_relative = join_relative(relative, &name)?;
            let absolute_path = absolute_snapshot_path(&child_relative);
            let name_c = CString::new(name).expect("directory entry has no embedded NUL");
            let stat = stat_entry(directory_fd, name_c.as_c_str())?;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let child = open_child_directory(directory_fd, name_c.as_c_str())?;
                    let current = stat_fd(child.raw(), "stat opened snapshot directory")?;
                    if current.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(SnapshotIdentityError::InvalidInput(
                            "snapshot directory changed type during identity scan".to_owned(),
                        ));
                    }
                    identity.record_directory(
                        &absolute_path,
                        (current.st_mode & 0o7777) as u32,
                    )?;
                    hash_directory(child.raw(), &child_relative, depth + 1, identity)?;
                }
                libc::S_IFREG => {
                    hash_regular_file(
                        directory_fd,
                        name_c.as_c_str(),
                        &absolute_path,
                        identity,
                    )?;
                }
                libc::S_IFLNK => {
                    hash_symlink(
                        directory_fd,
                        name_c.as_c_str(),
                        &absolute_path,
                        identity,
                    )?;
                }
                _ => {
                    return Err(SnapshotIdentityError::InvalidInput(format!(
                        "snapshot contains unsupported node kind at {}",
                        String::from_utf8_lossy(&absolute_path)
                    )));
                }
            }
        }
        Ok(())
    }

    fn hash_regular_file(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        identity: &mut CanonicalHasher,
    ) -> Result<(), SnapshotIdentityError> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(
                "open snapshot regular file",
                io::Error::last_os_error(),
            ));
        }
        let fd = Fd(fd);
        let stat = stat_fd(fd.raw(), "stat opened snapshot regular file")?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < 0 {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot regular file changed type or has invalid size during identity scan"
                    .to_owned(),
            ));
        }
        let length = stat.st_size as u64;
        identity.begin_file(path, (stat.st_mode & 0o7777) as u32, length)?;

        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let request = std::cmp::min(remaining, buffer.len() as u64) as usize;
            let count = loop {
                let count = unsafe {
                    libc::read(
                        fd.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        request,
                    )
                };
                if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break count;
            };
            if count == -1 {
                return Err(io_error(
                    "read snapshot regular file",
                    io::Error::last_os_error(),
                ));
            }
            if count == 0 {
                return Err(SnapshotIdentityError::InvalidInput(
                    "snapshot regular file shrank during identity scan".to_owned(),
                ));
            }
            identity.update(&buffer[..count as usize])?;
            remaining -= count as u64;
        }

        let mut extra = [0u8; 1];
        let extra_count = loop {
            let count = unsafe {
                libc::read(
                    fd.raw(),
                    extra.as_mut_ptr().cast::<libc::c_void>(),
                    extra.len(),
                )
            };
            if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break count;
        };
        if extra_count == -1 {
            return Err(io_error(
                "verify snapshot regular file length",
                io::Error::last_os_error(),
            ));
        }
        if extra_count != 0 {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot regular file grew during identity scan".to_owned(),
            ));
        }
        Ok(())
    }

    fn hash_symlink(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        identity: &mut CanonicalHasher,
    ) -> Result<(), SnapshotIdentityError> {
        let mut target = [0u8; MAX_SYMLINK_TARGET_BYTES + 1];
        let count = unsafe {
            libc::readlinkat(
                parent_fd,
                name.as_ptr(),
                target.as_mut_ptr().cast::<libc::c_char>(),
                target.len(),
            )
        };
        if count == -1 {
            return Err(io_error(
                "read snapshot symlink",
                io::Error::last_os_error(),
            ));
        }
        let count = count as usize;
        if count == target.len() {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot symlink target exceeds 4095 bytes".to_owned(),
            ));
        }
        identity.record_symlink(path, &target[..count])
    }

    fn open_directory_path(
        path: &Path,
        phase: &'static str,
    ) -> Result<Fd, SnapshotIdentityError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            SnapshotIdentityError::InvalidInput(format!("{phase} path contains an embedded NUL"))
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(phase, io::Error::last_os_error()));
        }
        Ok(Fd(fd))
    }

    fn open_child_directory(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
    ) -> Result<Fd, SnapshotIdentityError> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(
                "open snapshot child directory",
                io::Error::last_os_error(),
            ));
        }
        Ok(Fd(fd))
    }

    fn stat_fd(fd: RawFd, phase: &'static str) -> Result<libc::stat, SnapshotIdentityError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut stat) } == -1 {
            return Err(io_error(phase, io::Error::last_os_error()));
        }
        Ok(stat)
    }

    fn stat_entry(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
    ) -> Result<libc::stat, SnapshotIdentityError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                parent_fd,
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            return Err(io_error(
                "stat snapshot entry",
                io::Error::last_os_error(),
            ));
        }
        Ok(stat)
    }

    fn read_directory_names(directory_fd: RawFd) -> Result<Vec<Vec<u8>>, SnapshotIdentityError> {
        if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
            return Err(io_error(
                "rewind snapshot directory enumeration",
                io::Error::last_os_error(),
            ));
        }
        let mut names = Vec::new();
        let mut buffer = [0u8; DIRENT_BUFFER_BYTES];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("enumerate snapshot directory", error));
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            let mut offset = 0usize;
            while offset < count {
                if count - offset < 19 {
                    return Err(SnapshotIdentityError::InvalidInput(
                        "snapshot directory enumeration returned a truncated dirent".to_owned(),
                    ));
                }
                let record = unsafe { buffer.as_ptr().add(offset) };
                let reclen =
                    unsafe { u16::from_ne_bytes([*record.add(16), *record.add(17)]) as usize };
                if reclen < 20 || offset + reclen > count {
                    return Err(SnapshotIdentityError::InvalidInput(
                        "snapshot directory enumeration returned an invalid record length"
                            .to_owned(),
                    ));
                }
                let name_region = &buffer[offset + 19..offset + reclen];
                let name_len = name_region
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| {
                        SnapshotIdentityError::InvalidInput(
                            "snapshot directory enumeration returned an unterminated name"
                                .to_owned(),
                        )
                    })?;
                let name = &name_region[..name_len];
                if name != b"." && name != b".." {
                    names.push(name.to_vec());
                }
                offset += reclen;
            }
        }
        names.sort();
        Ok(names)
    }

    fn join_relative(parent: &[u8], name: &[u8]) -> Result<Vec<u8>, SnapshotIdentityError> {
        let extra = usize::from(!parent.is_empty());
        let length = parent
            .len()
            .checked_add(extra)
            .and_then(|value| value.checked_add(name.len()))
            .ok_or_else(|| {
                SnapshotIdentityError::InvalidInput("snapshot path length overflow".to_owned())
            })?;
        if length > MAX_RELATIVE_PATH_BYTES {
            return Err(SnapshotIdentityError::InvalidInput(
                "snapshot path exceeds the 4096-byte relative path ceiling".to_owned(),
            ));
        }
        let mut result = Vec::with_capacity(length);
        result.extend_from_slice(parent);
        if !parent.is_empty() {
            result.push(b'/');
        }
        result.extend_from_slice(name);
        Ok(result)
    }

    fn absolute_snapshot_path(relative: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(relative.len() + 1);
        result.push(b'/');
        result.extend_from_slice(relative);
        result
    }

    fn io_error(phase: &'static str, source: io::Error) -> SnapshotIdentityError {
        SnapshotIdentityError::Io { phase, source }
    }
}
