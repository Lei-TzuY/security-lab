use crate::snapshot_archive::SnapshotArchiveLimits;
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_store::SnapshotStorePutReport;
use crate::snapshot_store_audit::SnapshotStoreAuditLimits;
use crate::snapshot_store_inventory::SnapshotStoreInventoryIdentity;
use crate::snapshot_store_transaction::{
    SnapshotStoreReadTransaction, SnapshotStoreTransactionError, SnapshotStoreWriteTransaction,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const HEAD_STATE_DOMAIN: &[u8] = b"security-lab-snapshot-store-head-state-v1\0";
const HEAD_STATE_MAGIC: [u8; 8] = *b"SLHDST1\0";
const HEAD_STATE_HEADER_BYTES: usize = 64;
const HEAD_STATE_MAC_BYTES: usize = 32;
const HEAD_STATE_BYTES: usize = HEAD_STATE_HEADER_BYTES + HEAD_STATE_MAC_BYTES;
const HEAD_STATE_FILE: &str = "snapshot-store-head";
const HEAD_STATE_LOCK: &str = ".snapshot-store-head.lock";
pub const SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES: usize = 32;

/// Host-held authentication key for the independently persisted store head.
///
/// The key authenticates the state file. Rollback protection is relative to an
/// intact state root kept outside the snapshot store; restoring both roots to a
/// coordinated older filesystem snapshot remains outside this laboratory claim.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadStateKey([u8; SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES]);

impl SnapshotStoreHeadStateKey {
    pub fn new(bytes: [u8; SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SnapshotStoreHeadStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnapshotStoreHeadStateKey([REDACTED])")
    }
}

/// Authenticated, host-persisted accepted head for one snapshot store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadStateIdentity {
    pub generation: u64,
    pub inventory: SnapshotStoreInventoryIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadPutReport {
    pub put: SnapshotStorePutReport,
    pub previous: SnapshotStoreHeadStateIdentity,
    pub successor: SnapshotStoreHeadStateIdentity,
}

#[derive(Debug)]
pub enum SnapshotStoreHeadStateError {
    InvalidInput(String),
    UnsupportedPlatform(String),
    NotInitialized,
    AlreadyInitialized {
        persisted: SnapshotStoreHeadStateIdentity,
    },
    AuthenticationFailed,
    InvalidState(String),
    StoreDiverged {
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    Transaction(SnapshotStoreTransactionError),
}

impl fmt::Display for SnapshotStoreHeadStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(f, "invalid snapshot store head-state input: {message}")
            }
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported snapshot store head-state platform: {message}")
            }
            Self::NotInitialized => f.write_str("snapshot store head state is not initialized"),
            Self::AlreadyInitialized { persisted } => write!(
                f,
                "snapshot store head state is already initialized at generation {} inventory {} objects={} bytes={}",
                persisted.generation,
                persisted.inventory.sha256_hex(),
                persisted.inventory.objects,
                persisted.inventory.archive_bytes,
            ),
            Self::AuthenticationFailed => {
                f.write_str("snapshot store head-state authentication failed")
            }
            Self::InvalidState(message) => write!(f, "invalid snapshot store head state: {message}"),
            Self::StoreDiverged { anchored, actual } => write!(
                f,
                "snapshot store diverged from authenticated head generation {}: anchored {} objects={} bytes={} actual {} objects={} bytes={}",
                anchored.generation,
                anchored.inventory.sha256_hex(),
                anchored.inventory.objects,
                anchored.inventory.archive_bytes,
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
            Self::Io { phase, source } => {
                write!(f, "snapshot store head state failed during {phase}: {source}")
            }
            Self::Transaction(source) => {
                write!(f, "snapshot store head-state transaction failed: {source}")
            }
        }
    }
}

impl Error for SnapshotStoreHeadStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Transaction(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotStoreTransactionError> for SnapshotStoreHeadStateError {
    fn from(value: SnapshotStoreTransactionError) -> Self {
        Self::Transaction(value)
    }
}

pub fn snapshot_store_head_state_path(state_root: &Path) -> PathBuf {
    state_root.join(HEAD_STATE_FILE)
}

/// Establish generation 1 from the complete audited store inventory.
///
/// The state root and store root must be configured as disjoint host paths. A
/// shared store transaction is held while the initial inventory is derived, and
/// the authenticated state is fsync-backed before success is returned.
pub fn initialize_snapshot_store_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    inventory_limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = "linux")]
    {
        linux::initialize(state_root, state_key, store_root, inventory_limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, store_root, inventory_limits);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated store-head state currently requires Linux flock, fsync, and fd-relative state publication"
                .to_owned(),
        ))
    }
}

/// Load and authenticate the persisted head without inspecting the store.
pub fn load_snapshot_store_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
    validate_root("state_root", state_root)?;
    #[cfg(target_os = "linux")]
    {
        linux::load(state_root, state_key)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated store-head state currently requires Linux flock and fd-relative state access"
                .to_owned(),
        ))
    }
}

/// Require the complete audited store inventory to equal the authenticated
/// persisted head while a cooperative shared store transaction is held.
pub fn verify_snapshot_store_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    inventory_limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = "linux")]
    {
        linux::verify(state_root, state_key, store_root, inventory_limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, store_root, inventory_limits);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated store-head verification currently requires Linux flock and cooperative snapshot-store transactions"
                .to_owned(),
        ))
    }
}

/// Authenticated durable store publication guarded by an independently persisted
/// whole-store head.
///
/// The head-state lock is acquired before the exclusive store transaction. The
/// current store inventory must exactly equal the authenticated persisted head
/// before the supplied archive enters the publication path. A newly inserted
/// object is then audited into a successor inventory and the successor head is
/// durably published before success is returned, while the store write lock is
/// still held. Exact deduplication leaves the head generation unchanged.
///
/// Store publication and head-state publication are two durable resources, not
/// one crash-atomic transaction. If the store advances but the later state write
/// cannot complete, this call returns an error and subsequent head verification
/// fails closed on the resulting inventory mismatch.
pub fn store_snapshot_archive_ed25519_durable_with_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    inventory_limits: SnapshotStoreAuditLimits,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    archive_limits: SnapshotArchiveLimits,
) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = "linux")]
    {
        linux::store(
            state_root,
            state_key,
            store_root,
            inventory_limits,
            archive,
            public_key,
            expected_signature,
            archive_limits,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            state_root,
            state_key,
            store_root,
            inventory_limits,
            archive,
            public_key,
            expected_signature,
            archive_limits,
        );
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated durable store-head publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions"
                .to_owned(),
        ))
    }
}

fn validate_roots(state_root: &Path, store_root: &Path) -> Result<(), SnapshotStoreHeadStateError> {
    validate_root("state_root", state_root)?;
    validate_root("store_root", store_root)?;
    if state_root.starts_with(store_root) || store_root.starts_with(state_root) {
        return Err(SnapshotStoreHeadStateError::InvalidInput(
            "state_root and store_root configured paths must not overlap".to_owned(),
        ));
    }
    Ok(())
}

fn validate_root(label: &str, root: &Path) -> Result<(), SnapshotStoreHeadStateError> {
    if !root.is_absolute() {
        return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
            "{label} must be absolute"
        )));
    }
    if root == Path::new("/") {
        return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
            "{label} must not be host /"
        )));
    }
    if root
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
            "{label} must not contain '..'"
        )));
    }
    Ok(())
}

fn encode_state(
    identity: SnapshotStoreHeadStateIdentity,
    state_key: &SnapshotStoreHeadStateKey,
) -> [u8; HEAD_STATE_BYTES] {
    let mut bytes = [0u8; HEAD_STATE_BYTES];
    bytes[0..8].copy_from_slice(&HEAD_STATE_MAGIC);
    bytes[8..16].copy_from_slice(&identity.generation.to_le_bytes());
    bytes[16..48].copy_from_slice(&identity.inventory.sha256);
    bytes[48..56].copy_from_slice(&identity.inventory.objects.to_le_bytes());
    bytes[56..64].copy_from_slice(&identity.inventory.archive_bytes.to_le_bytes());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_STATE_DOMAIN);
    mac.update(&bytes[..HEAD_STATE_HEADER_BYTES]);
    bytes[HEAD_STATE_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn decode_state(
    bytes: &[u8; HEAD_STATE_BYTES],
    state_key: &SnapshotStoreHeadStateKey,
) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_STATE_DOMAIN);
    mac.update(&bytes[..HEAD_STATE_HEADER_BYTES]);
    mac.verify_slice(&bytes[HEAD_STATE_HEADER_BYTES..])
        .map_err(|_| SnapshotStoreHeadStateError::AuthenticationFailed)?;

    if bytes[0..8] != HEAD_STATE_MAGIC {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "unexpected store-head magic/version".to_owned(),
        ));
    }
    let generation = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .expect("fixed store-head generation width"),
    );
    if generation == 0 {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "store-head generation must be non-zero".to_owned(),
        ));
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[16..48]);
    let objects = u64::from_le_bytes(
        bytes[48..56]
            .try_into()
            .expect("fixed store-head object-count width"),
    );
    let archive_bytes = u64::from_le_bytes(
        bytes[56..64]
            .try_into()
            .expect("fixed store-head archive-byte width"),
    );
    Ok(SnapshotStoreHeadStateIdentity {
        generation,
        inventory: SnapshotStoreInventoryIdentity {
            sha256,
            objects,
            archive_bytes,
        },
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        decode_state, encode_state, SnapshotArchiveLimits, SnapshotStoreAuditLimits,
        SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity,
        SnapshotStoreHeadStateKey, SnapshotStoreInventoryIdentity, SnapshotStoreReadTransaction,
        SnapshotStoreWriteTransaction, HEAD_STATE_BYTES, HEAD_STATE_FILE, HEAD_STATE_LOCK,
        SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
    };
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    const RENAME_NOREPLACE: libc::c_uint = 1;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

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

    struct StateGuard {
        root: OwnedFd,
        _lock: OwnedFd,
    }

    pub(super) fn initialize(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        if let Some(persisted) = read_state_optional(guard.root.raw(), state_key)? {
            return Err(SnapshotStoreHeadStateError::AlreadyInitialized { persisted });
        }

        let reader = SnapshotStoreReadTransaction::begin(store_root)?;
        let inventory = reader.inventory_identity(inventory_limits)?;
        let identity = SnapshotStoreHeadStateIdentity {
            generation: 1,
            inventory,
        };
        write_state(guard.root.raw(), state_key, identity, false)?;
        Ok(identity)
    }

    pub(super) fn load(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_SH)?;
        read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)
    }

    pub(super) fn verify(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_SH)?;
        let anchored = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        let reader = SnapshotStoreReadTransaction::begin(store_root)?;
        let actual = reader.inventory_identity(inventory_limits)?;
        require_inventory(anchored, actual)?;
        Ok(anchored)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn store(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
        archive: &[u8],
        public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
        archive_limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        let previous = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        if previous.generation == u64::MAX {
            return Err(SnapshotStoreHeadStateError::InvalidState(
                "store-head generation is exhausted".to_owned(),
            ));
        }

        let writer = SnapshotStoreWriteTransaction::begin(store_root)?;
        let actual = writer.inventory_identity(inventory_limits)?;
        require_inventory(previous, actual)?;

        let put = writer.store_ed25519_durable(
            archive,
            public_key,
            expected_signature,
            archive_limits,
        )?;
        if !put.inserted {
            return Ok(SnapshotStoreHeadPutReport {
                put,
                previous,
                successor: previous,
            });
        }

        let successor_inventory = writer.inventory_identity(inventory_limits)?;
        let successor = SnapshotStoreHeadStateIdentity {
            generation: previous.generation + 1,
            inventory: successor_inventory,
        };
        write_state(guard.root.raw(), state_key, successor, true)?;
        Ok(SnapshotStoreHeadPutReport {
            put,
            previous,
            successor,
        })
    }

    fn require_inventory(
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        if anchored.inventory != actual {
            return Err(SnapshotStoreHeadStateError::StoreDiverged { anchored, actual });
        }
        Ok(())
    }

    fn lock_state(state_root: &Path, operation: libc::c_int) -> Result<StateGuard, SnapshotStoreHeadStateError> {
        let root = open_root(state_root)?;
        let lock = open_lock(root.raw())?;
        if unsafe { libc::flock(lock.raw(), operation) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "lock snapshot store head state",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(StateGuard { root, _lock: lock })
    }

    fn open_root(state_root: &Path) -> Result<OwnedFd, SnapshotStoreHeadStateError> {
        let path = cstring_path(state_root, "state_root")?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "open snapshot store head-state root",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(OwnedFd(fd))
    }

    fn open_lock(root_fd: RawFd) -> Result<OwnedFd, SnapshotStoreHeadStateError> {
        let name = CString::new(HEAD_STATE_LOCK).expect("fixed lock filename contains no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "open snapshot store head-state lock",
                source: std::io::Error::last_os_error(),
            });
        }
        let fd = OwnedFd(fd);
        require_regular_single_link(fd.raw(), "validate snapshot store head-state lock")?;
        Ok(fd)
    }

    fn read_state_optional(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
    ) -> Result<Option<SnapshotStoreHeadStateIdentity>, SnapshotStoreHeadStateError> {
        let name = CString::new(HEAD_STATE_FILE).expect("fixed state filename contains no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "open snapshot store head state",
                source,
            });
        }
        let fd = OwnedFd(fd);
        let stat = require_regular_single_link(fd.raw(), "validate snapshot store head state")?;
        if stat.st_size != HEAD_STATE_BYTES as libc::off_t {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "state file length {} does not equal {HEAD_STATE_BYTES}",
                stat.st_size
            )));
        }
        let mut bytes = [0u8; HEAD_STATE_BYTES];
        read_exact(fd.raw(), &mut bytes)?;
        Ok(Some(decode_state(&bytes, state_key)?))
    }

    fn write_state(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
        identity: SnapshotStoreHeadStateIdentity,
        replace: bool,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        let bytes = encode_state(identity, state_key);
        let (temp_fd, temp_name) = create_temp(root_fd)?;
        if let Err(error) = write_all(temp_fd.raw(), &bytes) {
            unlink_temp(root_fd, &temp_name);
            return Err(error);
        }
        if unsafe { libc::fsync(temp_fd.raw()) } != 0 {
            let source = std::io::Error::last_os_error();
            unlink_temp(root_fd, &temp_name);
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync temporary snapshot store head state",
                source,
            });
        }
        drop(temp_fd);

        let state_name = CString::new(HEAD_STATE_FILE).expect("fixed state filename contains no NUL");
        let rename_result = if replace {
            unsafe { libc::renameat(root_fd, temp_name.as_ptr(), root_fd, state_name.as_ptr()) }
        } else {
            unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    root_fd,
                    temp_name.as_ptr(),
                    root_fd,
                    state_name.as_ptr(),
                    RENAME_NOREPLACE,
                ) as libc::c_int
            }
        };
        if rename_result != 0 {
            let source = std::io::Error::last_os_error();
            unlink_temp(root_fd, &temp_name);
            if !replace && source.raw_os_error() == Some(libc::EEXIST) {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "head state appeared while initialization lock was held".to_owned(),
                ));
            }
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "publish snapshot store head state",
                source,
            });
        }
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync snapshot store head-state directory",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn create_temp(root_fd: RawFd) -> Result<(OwnedFd, CString), SnapshotStoreHeadStateError> {
        for _ in 0..32 {
            let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(
                ".snapshot-store-head.tmp.{}.{}",
                unsafe { libc::getpid() },
                serial
            ))
            .expect("generated temporary filename contains no NUL");
            let fd = unsafe {
                libc::openat(
                    root_fd,
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
                let fd = OwnedFd(fd);
                require_regular_single_link(fd.raw(), "validate temporary snapshot store head state")?;
                return Ok((fd, name));
            }
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::EEXIST) {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "create temporary snapshot store head state",
                    source,
                });
            }
        }
        Err(SnapshotStoreHeadStateError::InvalidState(
            "exhausted temporary snapshot store head-state names".to_owned(),
        ))
    }

    fn require_regular_single_link(
        fd: RawFd,
        phase: &'static str,
    ) -> Result<libc::stat, SnapshotStoreHeadStateError> {
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase,
                source: std::io::Error::last_os_error(),
            });
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "{phase}: descriptor is not a regular file"
            )));
        }
        if stat.st_nlink != 1 {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "{phase}: regular file must have exactly one link"
            )));
        }
        Ok(stat)
    }

    fn read_exact(fd: RawFd, bytes: &mut [u8]) -> Result<(), SnapshotStoreHeadStateError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let read = unsafe {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast::<libc::c_void>(),
                    bytes.len() - offset,
                )
            };
            if read < 0 {
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "read snapshot store head state",
                    source,
                });
            }
            if read == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "snapshot store head state ended early".to_owned(),
                ));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn write_all(fd: RawFd, bytes: &[u8]) -> Result<(), SnapshotStoreHeadStateError> {
        let mut offset = 0usize;
        while offset < bytes.len() {
            let written = unsafe {
                libc::write(
                    fd,
                    bytes[offset..].as_ptr().cast::<libc::c_void>(),
                    bytes.len() - offset,
                )
            };
            if written < 0 {
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "write temporary snapshot store head state",
                    source,
                });
            }
            if written == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "temporary snapshot store head-state write made no progress".to_owned(),
                ));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn unlink_temp(root_fd: RawFd, name: &CString) {
        unsafe {
            libc::unlinkat(root_fd, name.as_ptr(), 0);
        }
    }

    fn cstring_path(path: &Path, label: &str) -> Result<CString, SnapshotStoreHeadStateError> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            SnapshotStoreHeadStateError::InvalidInput(format!("{label} contains NUL"))
        })
    }
}
