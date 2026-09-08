use crate::snapshot_archive::{
    materialize_snapshot_archive_ed25519_atomic, snapshot_archive_identity, SnapshotArchiveError,
    SnapshotArchiveLimits, SnapshotArchiveMaterializeReport,
};
use crate::snapshot_identity::SnapshotIdentity;
use crate::snapshot_signature::{
    verify_snapshot_identity_ed25519, SnapshotEd25519Error, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES,
    SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Result of an authenticated content-addressed object insertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStorePutReport {
    pub identity: SnapshotIdentity,
    pub archive_bytes: u64,
    /// `true` when this call published a new object, `false` when an exact
    /// immutable object already occupied the same content address.
    pub inserted: bool,
}

#[derive(Debug)]
pub enum SnapshotStoreError {
    InvalidInput(String),
    Archive(SnapshotArchiveError),
    Signature(SnapshotEd25519Error),
    ObjectNotFound { identity: SnapshotIdentity },
    ObjectConflict { identity: SnapshotIdentity },
    UnsupportedPlatform(String),
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    CleanupFailed {
        primary: String,
        cleanup: String,
    },
}

impl fmt::Display for SnapshotStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid snapshot store input: {message}"),
            Self::Archive(source) => write!(f, "snapshot store archive validation failed: {source}"),
            Self::Signature(source) => {
                write!(f, "snapshot store signature verification failed: {source}")
            }
            Self::ObjectNotFound { identity } => write!(
                f,
                "snapshot store object not found: {}-{}-{}",
                identity.sha256_hex(),
                identity.encoded_bytes,
                identity.nodes
            ),
            Self::ObjectConflict { identity } => write!(
                f,
                "snapshot store object conflicts with content address: {}-{}-{}",
                identity.sha256_hex(),
                identity.encoded_bytes,
                identity.nodes
            ),
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported snapshot store platform: {message}")
            }
            Self::Io { phase, source } => {
                write!(f, "snapshot store failed during {phase}: {source}")
            }
            Self::CleanupFailed { primary, cleanup } => write!(
                f,
                "snapshot store failed ({primary}) and temporary-object cleanup also failed ({cleanup})"
            ),
        }
    }
}

impl Error for SnapshotStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Archive(source) => Some(source),
            Self::Signature(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotArchiveError> for SnapshotStoreError {
    fn from(value: SnapshotArchiveError) -> Self {
        Self::Archive(value)
    }
}

impl From<SnapshotEd25519Error> for SnapshotStoreError {
    fn from(value: SnapshotEd25519Error) -> Self {
        Self::Signature(value)
    }
}

/// Return the deterministic relative object path used by the bounded store.
///
/// The complete canonical identity tuple is encoded in the object name rather
/// than the digest alone, preserving the byte/node accounting covered by the
/// existing Ed25519 signature message.
pub fn snapshot_store_object_path(store_root: &Path, identity: SnapshotIdentity) -> PathBuf {
    store_root.join("objects").join(object_filename(identity))
}

/// Validate and authenticate one frozen canonical archive before publishing it
/// into a trusted host-local content-addressed object store.
///
/// Objects are keyed by the complete canonical identity tuple. Publication is
/// no-replace and failure-atomic at the final rename boundary. If an object is
/// already present at the same key, it is accepted as a deduplicated hit only
/// after its type, read-only mode, exact length, and every archive byte match the
/// supplied artifact. This does not claim fsync-backed crash durability or
/// protection from a privileged hostile writer that controls the store root.
pub fn store_snapshot_archive_ed25519_atomic(
    store_root: &Path,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotStorePutReport, SnapshotStoreError> {
    validate_store_root(store_root)?;
    let identity = snapshot_archive_identity(archive, limits)?;
    verify_snapshot_identity_ed25519(identity, public_key, expected_signature)?;

    #[cfg(target_os = "linux")]
    {
        linux::store(store_root, archive, identity)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, archive, identity);
        Err(SnapshotStoreError::UnsupportedPlatform(
            "content-addressed snapshot storage currently requires Linux fd-relative filesystem operations and renameat2"
                .to_owned(),
        ))
    }
}

/// Load one exact content-addressed archive object, require that its canonical
/// identity still matches the requested key, strictly verify the supplied
/// Ed25519 evidence again, and only then enter the existing failure-atomic
/// materialization path.
pub fn materialize_snapshot_store_object_ed25519_atomic(
    store_root: &Path,
    identity: SnapshotIdentity,
    destination: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchiveMaterializeReport, SnapshotStoreError> {
    validate_store_root(store_root)?;
    #[cfg(target_os = "linux")]
    let archive = linux::read_object(store_root, identity, limits.max_archive_bytes)?;
    #[cfg(not(target_os = "linux"))]
    let archive: Vec<u8> = {
        let _ = (store_root, identity, limits);
        return Err(SnapshotStoreError::UnsupportedPlatform(
            "content-addressed snapshot storage currently requires Linux fd-relative filesystem operations"
                .to_owned(),
        ));
    };

    let actual = snapshot_archive_identity(&archive, limits)?;
    if actual != identity {
        return Err(SnapshotStoreError::ObjectConflict { identity });
    }
    verify_snapshot_identity_ed25519(actual, public_key, expected_signature)?;
    materialize_snapshot_archive_ed25519_atomic(
        &archive,
        destination,
        public_key,
        expected_signature,
        limits,
    )
    .map_err(SnapshotStoreError::from)
}

fn validate_store_root(store_root: &Path) -> Result<(), SnapshotStoreError> {
    if !store_root.is_absolute() {
        return Err(SnapshotStoreError::InvalidInput(
            "store_root must be absolute".to_owned(),
        ));
    }
    if store_root == Path::new("/") {
        return Err(SnapshotStoreError::InvalidInput(
            "store_root must not be host /".to_owned(),
        ));
    }
    if store_root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SnapshotStoreError::InvalidInput(
            "store_root must not contain '..'".to_owned(),
        ));
    }
    Ok(())
}

fn object_filename(identity: SnapshotIdentity) -> String {
    format!(
        "{}-{}-{}.slarchive",
        identity.sha256_hex(),
        identity.encoded_bytes,
        identity.nodes
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{object_filename, SnapshotIdentity, SnapshotStoreError, SnapshotStorePutReport};
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    const RENAME_NOREPLACE: libc::c_uint = 1;
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

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

    pub(super) fn store(
        store_root: &Path,
        archive: &[u8],
        identity: SnapshotIdentity,
    ) -> Result<SnapshotStorePutReport, SnapshotStoreError> {
        let root = open_store_root(store_root)?;
        let objects = ensure_objects_dir(root.raw())?;
        let final_name = cstring_text(&object_filename(identity), "object filename")?;

        if let Some(existing) = open_existing(objects.raw(), &final_name)? {
            require_existing_matches(existing.raw(), archive, identity)?;
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: false,
            });
        }

        let (temp, temp_name) = create_temp(objects.raw())?;
        if let Err(primary) = write_and_seal(temp.raw(), archive) {
            drop(temp);
            return cleanup_after_error(objects.raw(), &temp_name, primary);
        }
        drop(temp);

        let renamed = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                objects.raw(),
                temp_name.as_ptr(),
                objects.raw(),
                final_name.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if renamed == 0 {
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: true,
            });
        }

        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            unlink_temp(objects.raw(), &temp_name).map_err(|cleanup| {
                SnapshotStoreError::CleanupFailed {
                    primary: "content-addressed object raced with another publisher".to_owned(),
                    cleanup: cleanup.to_string(),
                }
            })?;
            let existing = open_existing(objects.raw(), &final_name)?.ok_or_else(|| {
                SnapshotStoreError::Io {
                    phase: "open raced content-addressed object",
                    source: std::io::Error::from_raw_os_error(libc::ENOENT),
                }
            })?;
            require_existing_matches(existing.raw(), archive, identity)?;
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: false,
            });
        }

        let primary = if error.raw_os_error() == Some(libc::ENOSYS) {
            SnapshotStoreError::UnsupportedPlatform(
                "renameat2(RENAME_NOREPLACE) is required for snapshot-store publication".to_owned(),
            )
        } else {
            SnapshotStoreError::Io {
                phase: "publish content-addressed object",
                source: error,
            }
        };
        cleanup_after_error(objects.raw(), &temp_name, primary)
    }

    pub(super) fn read_object(
        store_root: &Path,
        identity: SnapshotIdentity,
        max_archive_bytes: u64,
    ) -> Result<Vec<u8>, SnapshotStoreError> {
        let root = open_store_root(store_root)?;
        let objects = open_objects_dir(root.raw())?;
        let final_name = cstring_text(&object_filename(identity), "object filename")?;
        let object = open_existing(objects.raw(), &final_name)?
            .ok_or(SnapshotStoreError::ObjectNotFound { identity })?;
        let stat = require_regular_readonly(object.raw(), identity)?;
        if stat.st_size < 0 {
            return Err(SnapshotStoreError::ObjectConflict { identity });
        }
        let size = stat.st_size as u64;
        if size > max_archive_bytes {
            return Err(SnapshotStoreError::Archive(
                crate::snapshot_archive::SnapshotArchiveError::BudgetExceeded {
                    resource: "byte",
                    limit: max_archive_bytes,
                    attempted: size,
                },
            ));
        }
        let size = usize::try_from(size).map_err(|_| SnapshotStoreError::InvalidInput(
            "stored object is too large for this process address space".to_owned(),
        ))?;
        let mut archive = vec![0u8; size];
        read_exact(object.raw(), &mut archive, identity)?;
        let mut extra = [0u8; 1];
        let read = retry_read(object.raw(), &mut extra)?;
        if read != 0 {
            return Err(SnapshotStoreError::ObjectConflict { identity });
        }
        Ok(archive)
    }

    fn open_store_root(store_root: &Path) -> Result<OwnedFd, SnapshotStoreError> {
        let path = CString::new(store_root.as_os_str().as_bytes()).map_err(|_| {
            SnapshotStoreError::InvalidInput("store_root contains NUL".to_owned())
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase: "open store root",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(OwnedFd(fd))
    }

    fn ensure_objects_dir(root_fd: RawFd) -> Result<OwnedFd, SnapshotStoreError> {
        let name = cstring_text("objects", "objects directory")?;
        let created = unsafe { libc::mkdirat(root_fd, name.as_ptr(), 0o700) };
        if created != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(SnapshotStoreError::Io {
                    phase: "create objects directory",
                    source: error,
                });
            }
        }
        open_objects_dir(root_fd)
    }

    fn open_objects_dir(root_fd: RawFd) -> Result<OwnedFd, SnapshotStoreError> {
        let name = cstring_text("objects", "objects directory")?;
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase: "open objects directory",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(OwnedFd(fd))
    }

    fn open_existing(
        objects_fd: RawFd,
        name: &CString,
    ) -> Result<Option<OwnedFd>, SnapshotStoreError> {
        let fd = unsafe {
            libc::openat(
                objects_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            return Ok(Some(OwnedFd(fd)));
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(SnapshotStoreError::Io {
                phase: "open content-addressed object",
                source: error,
            })
        }
    }

    fn create_temp(objects_fd: RawFd) -> Result<(OwnedFd, CString), SnapshotStoreError> {
        for _ in 0..128 {
            let id = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = cstring_text(
                &format!(".tmp-{}-{id}", std::process::id()),
                "temporary object filename",
            )?;
            let fd = unsafe {
                libc::openat(
                    objects_fd,
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd >= 0 {
                return Ok((OwnedFd(fd), name));
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EEXIST) {
                return Err(SnapshotStoreError::Io {
                    phase: "create temporary object",
                    source: error,
                });
            }
        }
        Err(SnapshotStoreError::Io {
            phase: "create temporary object",
            source: std::io::Error::from_raw_os_error(libc::EEXIST),
        })
    }

    fn write_and_seal(fd: RawFd, archive: &[u8]) -> Result<(), SnapshotStoreError> {
        let mut offset = 0usize;
        while offset < archive.len() {
            let written = unsafe {
                libc::write(
                    fd,
                    archive[offset..].as_ptr().cast::<libc::c_void>(),
                    archive.len() - offset,
                )
            };
            if written < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SnapshotStoreError::Io {
                    phase: "write temporary object",
                    source: error,
                });
            }
            if written == 0 {
                return Err(SnapshotStoreError::Io {
                    phase: "write temporary object",
                    source: std::io::Error::from_raw_os_error(libc::EIO),
                });
            }
            offset += written as usize;
        }
        if unsafe { libc::fchmod(fd, 0o444) } != 0 {
            return Err(SnapshotStoreError::Io {
                phase: "seal temporary object read-only",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn require_existing_matches(
        fd: RawFd,
        archive: &[u8],
        identity: SnapshotIdentity,
    ) -> Result<(), SnapshotStoreError> {
        let stat = require_regular_readonly(fd, identity)?;
        if stat.st_size < 0 || stat.st_size as u64 != archive.len() as u64 {
            return Err(SnapshotStoreError::ObjectConflict { identity });
        }
        let mut offset = 0usize;
        let mut buffer = [0u8; 8192];
        while offset < archive.len() {
            let wanted = std::cmp::min(buffer.len(), archive.len() - offset);
            let read = retry_read(fd, &mut buffer[..wanted])?;
            if read == 0 || buffer[..read] != archive[offset..offset + read] {
                return Err(SnapshotStoreError::ObjectConflict { identity });
            }
            offset += read;
        }
        let mut extra = [0u8; 1];
        if retry_read(fd, &mut extra)? != 0 {
            return Err(SnapshotStoreError::ObjectConflict { identity });
        }
        Ok(())
    }

    fn require_regular_readonly(
        fd: RawFd,
        identity: SnapshotIdentity,
    ) -> Result<libc::stat, SnapshotStoreError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(SnapshotStoreError::Io {
                phase: "inspect content-addressed object",
                source: std::io::Error::last_os_error(),
            });
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_mode & 0o222 != 0 {
            return Err(SnapshotStoreError::ObjectConflict { identity });
        }
        Ok(stat)
    }

    fn read_exact(
        fd: RawFd,
        buffer: &mut [u8],
        identity: SnapshotIdentity,
    ) -> Result<(), SnapshotStoreError> {
        let mut offset = 0usize;
        while offset < buffer.len() {
            let read = retry_read(fd, &mut buffer[offset..])?;
            if read == 0 {
                return Err(SnapshotStoreError::ObjectConflict { identity });
            }
            offset += read;
        }
        Ok(())
    }

    fn retry_read(fd: RawFd, buffer: &mut [u8]) -> Result<usize, SnapshotStoreError> {
        loop {
            let read = unsafe {
                libc::read(
                    fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read >= 0 {
                return Ok(read as usize);
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SnapshotStoreError::Io {
                phase: "read content-addressed object",
                source: error,
            });
        }
    }

    fn unlink_temp(objects_fd: RawFd, temp_name: &CString) -> Result<(), std::io::Error> {
        if unsafe { libc::unlinkat(objects_fd, temp_name.as_ptr(), 0) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn cleanup_after_error<T>(
        objects_fd: RawFd,
        temp_name: &CString,
        primary: SnapshotStoreError,
    ) -> Result<T, SnapshotStoreError> {
        match unlink_temp(objects_fd, temp_name) {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(SnapshotStoreError::CleanupFailed {
                primary: primary.to_string(),
                cleanup: cleanup.to_string(),
            }),
        }
    }

    fn cstring_text(text: &str, label: &str) -> Result<CString, SnapshotStoreError> {
        CString::new(text.as_bytes()).map_err(|_| {
            SnapshotStoreError::InvalidInput(format!("{label} unexpectedly contains NUL"))
        })
    }
}