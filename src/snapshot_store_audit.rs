use crate::snapshot_archive::{
    snapshot_archive_identity, SnapshotArchiveError, SnapshotArchiveLimits,
};
use crate::snapshot_identity::SnapshotIdentity;
use std::error::Error;
use std::fmt;
use std::path::{Component, Path};

/// Explicit work limits for one read-only content-addressed store audit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreAuditLimits {
    /// Maximum non-dot directory entries examined in `objects/`.
    pub max_entries: u64,
    /// Maximum aggregate archive bytes read across all validated objects.
    pub max_total_archive_bytes: u64,
    /// Existing per-object archive validation limits.
    pub archive: SnapshotArchiveLimits,
}

/// Aggregate result of a successful read-only store integrity pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreAuditReport {
    pub objects: u64,
    pub archive_bytes: u64,
}

#[derive(Debug)]
pub enum SnapshotStoreAuditError {
    InvalidInput(String),
    BudgetExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    InvalidObjectName {
        name: String,
    },
    UnsafeObject {
        name: String,
        reason: &'static str,
    },
    IdentityMismatch {
        name: String,
        expected: SnapshotIdentity,
        actual: SnapshotIdentity,
    },
    Archive {
        name: String,
        source: SnapshotArchiveError,
    },
    UnsupportedPlatform(String),
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
}

impl fmt::Display for SnapshotStoreAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid snapshot store audit input: {message}"),
            Self::BudgetExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                f,
                "snapshot store audit {resource} budget exceeded: limit={limit} attempted={attempted}"
            ),
            Self::InvalidObjectName { name } => {
                write!(f, "snapshot store audit found invalid object name {name:?}")
            }
            Self::UnsafeObject { name, reason } => write!(
                f,
                "snapshot store audit rejected object {name:?}: {reason}"
            ),
            Self::IdentityMismatch {
                name,
                expected,
                actual,
            } => write!(
                f,
                "snapshot store audit identity mismatch for {name:?}: expected {}-{}-{} actual {}-{}-{}",
                expected.sha256_hex(),
                expected.encoded_bytes,
                expected.nodes,
                actual.sha256_hex(),
                actual.encoded_bytes,
                actual.nodes
            ),
            Self::Archive { name, source } => {
                write!(f, "snapshot store audit archive validation failed for {name:?}: {source}")
            }
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported snapshot store audit platform: {message}")
            }
            Self::Io { phase, source } => {
                write!(f, "snapshot store audit failed during {phase}: {source}")
            }
        }
    }
}

impl Error for SnapshotStoreAuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Archive { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Audit every object entry observed in the bounded content-addressed store.
///
/// The audit is strictly read-only. On Linux it opens the store root and
/// `objects/` with `O_NOFOLLOW`, enumerates through the already-open directory,
/// opens each object fd-relative with `O_NOFOLLOW`, requires a single-link
/// read-only regular file, applies explicit entry/aggregate-byte budgets, parses
/// the canonical object filename, validates the complete archive, and requires
/// the archive-derived [`SnapshotIdentity`] to equal the filename identity.
///
/// This is an integrity pass over a quiescent/cooperatively serialized store; it
/// does not lock out independent concurrent publishers and does not delete,
/// repair, quarantine, or garbage-collect anything.
pub fn audit_snapshot_store(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError> {
    validate_store_root(store_root)?;
    validate_limits(limits)?;

    #[cfg(target_os = "linux")]
    {
        linux::audit(store_root, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, limits);
        Err(SnapshotStoreAuditError::UnsupportedPlatform(
            "snapshot-store integrity audit currently requires Linux fd-relative directory enumeration and O_NOFOLLOW object access"
                .to_owned(),
        ))
    }
}

fn validate_store_root(store_root: &Path) -> Result<(), SnapshotStoreAuditError> {
    if !store_root.is_absolute() {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "store_root must be absolute".to_owned(),
        ));
    }
    if store_root == Path::new("/") {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "store_root must not be host /".to_owned(),
        ));
    }
    if store_root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "store_root must not contain '..'".to_owned(),
        ));
    }
    Ok(())
}

fn validate_limits(limits: SnapshotStoreAuditLimits) -> Result<(), SnapshotStoreAuditError> {
    if limits.max_entries == 0 {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "max_entries must be non-zero".to_owned(),
        ));
    }
    if limits.max_total_archive_bytes == 0 {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "max_total_archive_bytes must be non-zero".to_owned(),
        ));
    }
    if limits.archive.max_archive_bytes == 0
        || limits.archive.max_identity_bytes == 0
        || limits.archive.max_nodes == 0
    {
        return Err(SnapshotStoreAuditError::InvalidInput(
            "archive limits must all be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn parse_object_filename(name: &[u8]) -> Result<SnapshotIdentity, SnapshotStoreAuditError> {
    const SUFFIX: &[u8] = b".slarchive";
    if !name.ends_with(SUFFIX) {
        return Err(invalid_name(name));
    }
    let stem = &name[..name.len() - SUFFIX.len()];
    let mut parts = stem.split(|byte| *byte == b'-');
    let digest = parts.next().ok_or_else(|| invalid_name(name))?;
    let encoded = parts.next().ok_or_else(|| invalid_name(name))?;
    let nodes = parts.next().ok_or_else(|| invalid_name(name))?;
    if parts.next().is_some() || digest.len() != 64 {
        return Err(invalid_name(name));
    }

    let mut sha256 = [0u8; 32];
    for (index, chunk) in digest.chunks_exact(2).enumerate() {
        let high = lower_hex_nibble(chunk[0]).ok_or_else(|| invalid_name(name))?;
        let low = lower_hex_nibble(chunk[1]).ok_or_else(|| invalid_name(name))?;
        sha256[index] = (high << 4) | low;
    }
    let encoded_bytes = parse_canonical_decimal(encoded).ok_or_else(|| invalid_name(name))?;
    let nodes = parse_canonical_decimal(nodes).ok_or_else(|| invalid_name(name))?;
    Ok(SnapshotIdentity {
        sha256,
        encoded_bytes,
        nodes,
    })
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn parse_canonical_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || (bytes.len() > 1 && bytes[0] == b'0') {
        return None;
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add(u64::from(*byte - b'0'))?;
    }
    Some(value)
}

fn invalid_name(name: &[u8]) -> SnapshotStoreAuditError {
    SnapshotStoreAuditError::InvalidObjectName {
        name: String::from_utf8_lossy(name).into_owned(),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        audit_archive, invalid_name, parse_object_filename, SnapshotStoreAuditError,
        SnapshotStoreAuditLimits, SnapshotStoreAuditReport,
    };
    use std::ffi::{CStr, CString};
    use std::mem::MaybeUninit;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    struct OwnedFd(RawFd);

    impl OwnedFd {
        fn raw(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    struct DirStream(*mut libc::DIR);

    impl DirStream {
        fn fd(&self) -> Result<RawFd, SnapshotStoreAuditError> {
            let fd = unsafe { libc::dirfd(self.0) };
            if fd < 0 {
                return Err(io_error(
                    "query objects directory descriptor",
                    std::io::Error::last_os_error(),
                ));
            }
            Ok(fd)
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    pub(super) fn audit(
        store_root: &Path,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError> {
        let root = open_store_root(store_root)?;
        let Some(objects) = open_objects_stream(root.raw())? else {
            return Ok(SnapshotStoreAuditReport {
                objects: 0,
                archive_bytes: 0,
            });
        };
        let objects_fd = objects.fd()?;
        let mut entries_seen = 0u64;
        let mut object_count = 0u64;
        let mut total_bytes = 0u64;

        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(objects.0) };
            if entry.is_null() {
                let errno = unsafe { *libc::__errno_location() };
                if errno != 0 {
                    return Err(io_error(
                        "enumerate snapshot store objects",
                        std::io::Error::from_raw_os_error(errno),
                    ));
                }
                break;
            }

            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            entries_seen =
                entries_seen
                    .checked_add(1)
                    .ok_or(SnapshotStoreAuditError::BudgetExceeded {
                        resource: "entry",
                        limit: limits.max_entries,
                        attempted: u64::MAX,
                    })?;
            if entries_seen > limits.max_entries {
                return Err(SnapshotStoreAuditError::BudgetExceeded {
                    resource: "entry",
                    limit: limits.max_entries,
                    attempted: entries_seen,
                });
            }

            let expected = parse_object_filename(name)?;
            let name_text = String::from_utf8_lossy(name).into_owned();
            let name_c = CString::new(name).map_err(|_| invalid_name(name))?;
            let object = open_object(objects_fd, &name_c, &name_text)?;
            let size = require_safe_object(object.raw(), &name_text)?;
            if size > limits.archive.max_archive_bytes {
                return Err(SnapshotStoreAuditError::BudgetExceeded {
                    resource: "per-object byte",
                    limit: limits.archive.max_archive_bytes,
                    attempted: size,
                });
            }
            let attempted_total =
                total_bytes
                    .checked_add(size)
                    .ok_or(SnapshotStoreAuditError::BudgetExceeded {
                        resource: "aggregate byte",
                        limit: limits.max_total_archive_bytes,
                        attempted: u64::MAX,
                    })?;
            if attempted_total > limits.max_total_archive_bytes {
                return Err(SnapshotStoreAuditError::BudgetExceeded {
                    resource: "aggregate byte",
                    limit: limits.max_total_archive_bytes,
                    attempted: attempted_total,
                });
            }

            let size_usize = usize::try_from(size).map_err(|_| {
                SnapshotStoreAuditError::InvalidInput(
                    "stored object is too large for this process address space".to_owned(),
                )
            })?;
            let mut archive = vec![0u8; size_usize];
            read_exact(object.raw(), &mut archive, &name_text)?;
            let mut extra = [0u8; 1];
            if retry_read(object.raw(), &mut extra)? != 0 {
                return Err(SnapshotStoreAuditError::UnsafeObject {
                    name: name_text,
                    reason: "object length changed while it was audited",
                });
            }
            let actual = audit_archive(&archive, limits.archive, &name_text)?;
            if actual != expected {
                return Err(SnapshotStoreAuditError::IdentityMismatch {
                    name: name_text,
                    expected,
                    actual,
                });
            }
            total_bytes = attempted_total;
            object_count += 1;
        }

        Ok(SnapshotStoreAuditReport {
            objects: object_count,
            archive_bytes: total_bytes,
        })
    }

    fn open_store_root(store_root: &Path) -> Result<OwnedFd, SnapshotStoreAuditError> {
        let path = CString::new(store_root.as_os_str().as_bytes()).map_err(|_| {
            SnapshotStoreAuditError::InvalidInput("store_root contains NUL".to_owned())
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io_error(
                "open snapshot store root",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(OwnedFd(fd))
    }

    fn open_objects_stream(root_fd: RawFd) -> Result<Option<DirStream>, SnapshotStoreAuditError> {
        let name = CString::new("objects").expect("static objects name has no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(io_error("open snapshot store objects directory", error));
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(io_error("open objects directory stream", error));
        }
        Ok(Some(DirStream(stream)))
    }

    fn open_object(
        objects_fd: RawFd,
        name: &CString,
        name_text: &str,
    ) -> Result<OwnedFd, SnapshotStoreAuditError> {
        let fd = unsafe {
            libc::openat(
                objects_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENXIO) | Some(libc::ENODEV)
            ) {
                return Err(SnapshotStoreAuditError::UnsafeObject {
                    name: name_text.to_owned(),
                    reason: "entry is not a directly openable regular file",
                });
            }
            return Err(io_error("open snapshot store object", error));
        }
        Ok(OwnedFd(fd))
    }

    fn require_safe_object(fd: RawFd, name: &str) -> Result<u64, SnapshotStoreAuditError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io_error(
                "stat snapshot store object",
                std::io::Error::last_os_error(),
            ));
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(SnapshotStoreAuditError::UnsafeObject {
                name: name.to_owned(),
                reason: "entry is not a regular file",
            });
        }
        if stat.st_nlink != 1 {
            return Err(SnapshotStoreAuditError::UnsafeObject {
                name: name.to_owned(),
                reason: "object has more than one hard link",
            });
        }
        if stat.st_mode & 0o222 != 0 {
            return Err(SnapshotStoreAuditError::UnsafeObject {
                name: name.to_owned(),
                reason: "object retains write permission bits",
            });
        }
        if stat.st_size < 0 {
            return Err(SnapshotStoreAuditError::UnsafeObject {
                name: name.to_owned(),
                reason: "object has a negative size",
            });
        }
        Ok(stat.st_size as u64)
    }

    fn read_exact(fd: RawFd, bytes: &mut [u8], name: &str) -> Result<(), SnapshotStoreAuditError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let read = unsafe {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                    bytes.len() - offset,
                )
            };
            if read == 0 {
                return Err(SnapshotStoreAuditError::UnsafeObject {
                    name: name.to_owned(),
                    reason: "object became shorter while it was audited",
                });
            }
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("read snapshot store object", error));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn retry_read(fd: RawFd, bytes: &mut [u8]) -> Result<usize, SnapshotStoreAuditError> {
        loop {
            let read =
                unsafe { libc::read(fd, bytes.as_mut_ptr().cast::<libc::c_void>(), bytes.len()) };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(io_error("check snapshot store object length", error));
        }
    }

    fn io_error(phase: &'static str, source: std::io::Error) -> SnapshotStoreAuditError {
        SnapshotStoreAuditError::Io { phase, source }
    }
}

fn audit_archive(
    archive: &[u8],
    limits: SnapshotArchiveLimits,
    name: &str,
) -> Result<SnapshotIdentity, SnapshotStoreAuditError> {
    snapshot_archive_identity(archive, limits).map_err(|source| SnapshotStoreAuditError::Archive {
        name: name.to_owned(),
        source,
    })
}
