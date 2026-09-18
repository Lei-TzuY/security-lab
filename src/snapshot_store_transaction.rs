use crate::snapshot_archive::SnapshotArchiveLimits;
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_store::{SnapshotStoreError, SnapshotStorePutReport};
use crate::snapshot_store_audit::{
    audit_snapshot_store, SnapshotStoreAuditError, SnapshotStoreAuditLimits,
    SnapshotStoreAuditReport,
};
use crate::snapshot_store_durable::store_snapshot_archive_ed25519_durable;
use crate::snapshot_store_inventory::{
    snapshot_store_inventory_identity, verify_snapshot_store_inventory_identity,
    SnapshotStoreInventoryError, SnapshotStoreInventoryIdentity,
};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Cooperative access mode for one host-local snapshot store.
///
/// Read transactions take a shared advisory lock on the store-root directory;
/// write transactions take an exclusive advisory lock on that same inode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotStoreTransactionMode {
    Read,
    Write,
}

impl fmt::Display for SnapshotStoreTransactionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
        }
    }
}

#[derive(Debug)]
pub enum SnapshotStoreTransactionError {
    InvalidInput(String),
    LockContended {
        requested: SnapshotStoreTransactionMode,
    },
    InventoryConflict {
        expected: SnapshotStoreInventoryIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
    UnsupportedPlatform(String),
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    Store(SnapshotStoreError),
    Audit(SnapshotStoreAuditError),
    Inventory(SnapshotStoreInventoryError),
}

impl fmt::Display for SnapshotStoreTransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(f, "invalid snapshot store transaction input: {message}")
            }
            Self::LockContended { requested } => write!(
                f,
                "snapshot store {requested} transaction lock is contended"
            ),
            Self::InventoryConflict { expected, actual } => write!(
                f,
                "snapshot store inventory changed before guarded write: expected {} objects={} bytes={} actual {} objects={} bytes={}",
                expected.sha256_hex(),
                expected.objects,
                expected.archive_bytes,
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
            Self::UnsupportedPlatform(message) => {
                write!(
                    f,
                    "unsupported snapshot store transaction platform: {message}"
                )
            }
            Self::Io { phase, source } => {
                write!(
                    f,
                    "snapshot store transaction failed during {phase}: {source}"
                )
            }
            Self::Store(source) => write!(f, "snapshot store transaction write failed: {source}"),
            Self::Audit(source) => write!(f, "snapshot store transaction audit failed: {source}"),
            Self::Inventory(source) => {
                write!(f, "snapshot store transaction inventory failed: {source}")
            }
        }
    }
}

impl Error for SnapshotStoreTransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Store(source) => Some(source),
            Self::Audit(source) => Some(source),
            Self::Inventory(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotStoreError> for SnapshotStoreTransactionError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::Store(value)
    }
}

impl From<SnapshotStoreAuditError> for SnapshotStoreTransactionError {
    fn from(value: SnapshotStoreAuditError) -> Self {
        Self::Audit(value)
    }
}

impl From<SnapshotStoreInventoryError> for SnapshotStoreTransactionError {
    fn from(value: SnapshotStoreInventoryError) -> Self {
        Self::Inventory(value)
    }
}

/// Shared cooperative transaction for a pre-existing snapshot-store root.
///
/// The advisory lock remains held until this value is dropped. Every method on
/// this value executes while that shared lock is live, so cooperating writers
/// using [`SnapshotStoreWriteTransaction`] cannot publish during the audit or
/// inventory pass.
pub struct SnapshotStoreReadTransaction {
    store_root: PathBuf,
    #[cfg(target_os = "linux")]
    _lock: linux::StoreLock,
}

impl SnapshotStoreReadTransaction {
    /// Acquire a blocking shared transaction lock.
    pub fn begin(store_root: &Path) -> Result<Self, SnapshotStoreTransactionError> {
        Self::acquire(store_root, false)
    }

    /// Try to acquire a shared transaction lock without waiting.
    pub fn try_begin(store_root: &Path) -> Result<Self, SnapshotStoreTransactionError> {
        Self::acquire(store_root, true)
    }

    pub fn audit(
        &self,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreAuditReport, SnapshotStoreTransactionError> {
        Ok(audit_snapshot_store(&self.store_root, limits)?)
    }

    pub fn inventory_identity(
        &self,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreInventoryIdentity, SnapshotStoreTransactionError> {
        Ok(snapshot_store_inventory_identity(&self.store_root, limits)?)
    }

    pub fn verify_inventory_identity(
        &self,
        expected: SnapshotStoreInventoryIdentity,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreAuditReport, SnapshotStoreTransactionError> {
        Ok(verify_snapshot_store_inventory_identity(
            &self.store_root,
            expected,
            limits,
        )?)
    }

    fn acquire(
        store_root: &Path,
        nonblocking: bool,
    ) -> Result<Self, SnapshotStoreTransactionError> {
        validate_store_root(store_root)?;
        #[cfg(target_os = "linux")]
        {
            let lock = linux::lock_store_root(
                store_root,
                SnapshotStoreTransactionMode::Read,
                nonblocking,
            )?;
            Ok(Self {
                store_root: store_root.to_path_buf(),
                _lock: lock,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (store_root, nonblocking);
            Err(SnapshotStoreTransactionError::UnsupportedPlatform(
                "cooperative snapshot-store transactions currently require Linux flock on the store-root directory"
                    .to_owned(),
            ))
        }
    }
}

/// Exclusive cooperative transaction for authenticated durable publication.
///
/// The advisory lock remains held until this value is dropped. Participating
/// readers using [`SnapshotStoreReadTransaction`] therefore observe either the
/// inventory before this transaction or the inventory after its durable store
/// operation, never a cooperating publication while their shared transaction is
/// live.
pub struct SnapshotStoreWriteTransaction {
    store_root: PathBuf,
    #[cfg(target_os = "linux")]
    _lock: linux::StoreLock,
}

impl SnapshotStoreWriteTransaction {
    /// Acquire a blocking exclusive transaction lock.
    pub fn begin(store_root: &Path) -> Result<Self, SnapshotStoreTransactionError> {
        Self::acquire(store_root, false)
    }

    /// Try to acquire an exclusive transaction lock without waiting.
    pub fn try_begin(store_root: &Path) -> Result<Self, SnapshotStoreTransactionError> {
        Self::acquire(store_root, true)
    }

    /// Recompute the complete audited inventory while the exclusive store
    /// transaction lock is held. This is useful for obtaining a successor token
    /// before releasing the write transaction.
    pub fn inventory_identity(
        &self,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreInventoryIdentity, SnapshotStoreTransactionError> {
        Ok(snapshot_store_inventory_identity(&self.store_root, limits)?)
    }

    /// Authenticated durable publication while the exclusive store transaction
    /// lock is held.
    pub fn store_ed25519_durable(
        &self,
        archive: &[u8],
        public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
        limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotStorePutReport, SnapshotStoreTransactionError> {
        Ok(store_snapshot_archive_ed25519_durable(
            &self.store_root,
            archive,
            public_key,
            expected_signature,
            limits,
        )?)
    }

    /// Optimistic guarded durable publication. The complete audited store
    /// inventory is compared with a caller-retained expected identity while the
    /// exclusive transaction lock is held. A mismatch is a typed conflict and
    /// returns before the supplied archive reaches the publication path.
    ///
    /// Participating writers can therefore use a previously observed inventory
    /// identity as a compare-and-swap style precondition without weakening the
    /// existing authenticated, no-replace, fsync-backed object publication.
    pub fn store_ed25519_durable_if_inventory(
        &self,
        expected_inventory: SnapshotStoreInventoryIdentity,
        inventory_limits: SnapshotStoreAuditLimits,
        archive: &[u8],
        public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
        limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotStorePutReport, SnapshotStoreTransactionError> {
        let actual_inventory =
            snapshot_store_inventory_identity(&self.store_root, inventory_limits)?;
        if actual_inventory != expected_inventory {
            return Err(SnapshotStoreTransactionError::InventoryConflict {
                expected: expected_inventory,
                actual: actual_inventory,
            });
        }
        self.store_ed25519_durable(archive, public_key, expected_signature, limits)
    }

    fn acquire(
        store_root: &Path,
        nonblocking: bool,
    ) -> Result<Self, SnapshotStoreTransactionError> {
        validate_store_root(store_root)?;
        #[cfg(target_os = "linux")]
        {
            let lock = linux::lock_store_root(
                store_root,
                SnapshotStoreTransactionMode::Write,
                nonblocking,
            )?;
            Ok(Self {
                store_root: store_root.to_path_buf(),
                _lock: lock,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (store_root, nonblocking);
            Err(SnapshotStoreTransactionError::UnsupportedPlatform(
                "cooperative snapshot-store transactions currently require Linux flock on the store-root directory"
                    .to_owned(),
            ))
        }
    }
}

fn validate_store_root(store_root: &Path) -> Result<(), SnapshotStoreTransactionError> {
    if !store_root.is_absolute() {
        return Err(SnapshotStoreTransactionError::InvalidInput(
            "store_root must be absolute".to_owned(),
        ));
    }
    if store_root == Path::new("/") {
        return Err(SnapshotStoreTransactionError::InvalidInput(
            "store_root must not be host /".to_owned(),
        ));
    }
    if store_root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SnapshotStoreTransactionError::InvalidInput(
            "store_root must not contain '..'".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{SnapshotStoreTransactionError, SnapshotStoreTransactionMode};
    use std::ffi::CString;
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

    pub(super) struct StoreLock {
        _fd: OwnedFd,
    }

    pub(super) fn lock_store_root(
        store_root: &Path,
        mode: SnapshotStoreTransactionMode,
        nonblocking: bool,
    ) -> Result<StoreLock, SnapshotStoreTransactionError> {
        let path = CString::new(store_root.as_os_str().as_bytes()).map_err(|_| {
            SnapshotStoreTransactionError::InvalidInput("store_root contains NUL".to_owned())
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreTransactionError::Io {
                phase: "open snapshot store root for transaction lock",
                source: std::io::Error::last_os_error(),
            });
        }
        let fd = OwnedFd(fd);
        let mut operation = match mode {
            SnapshotStoreTransactionMode::Read => libc::LOCK_SH,
            SnapshotStoreTransactionMode::Write => libc::LOCK_EX,
        };
        if nonblocking {
            operation |= libc::LOCK_NB;
        }
        if unsafe { libc::flock(fd.raw(), operation) } != 0 {
            let source = std::io::Error::last_os_error();
            if nonblocking && source.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(SnapshotStoreTransactionError::LockContended { requested: mode });
            }
            return Err(SnapshotStoreTransactionError::Io {
                phase: "acquire snapshot store transaction lock",
                source,
            });
        }
        Ok(StoreLock { _fd: fd })
    }
}
