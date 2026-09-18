use crate::snapshot_archive::SnapshotArchiveLimits;
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_trust::{
    materialize_snapshot_store_object_trusted_ed25519_atomic,
    store_snapshot_archive_trusted_ed25519_durable, SnapshotTrustError, SnapshotTrustKeyId,
    SnapshotTrustPolicy, SnapshotTrustPolicyIdentity, SnapshotTrustedMaterializeReport,
    SnapshotTrustedStorePutReport, SNAPSHOT_TRUST_MAX_KEYS,
};
use crate::SnapshotIdentity;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};

const TRUST_STATE_DOMAIN: &[u8] = b"security-lab-snapshot-trust-state-v1\0";
const TRUST_STATE_MAGIC: [u8; 8] = *b"SLTRST1\0";
const TRUST_STATE_HEADER_BYTES: usize = 56;
const TRUST_STATE_MAC_BYTES: usize = 32;
const TRUST_STATE_BYTES: usize = TRUST_STATE_HEADER_BYTES + TRUST_STATE_MAC_BYTES;
const TRUST_STATE_FILE: &str = "trust-state";
const TRUST_STATE_LOCK: &str = ".trust-state.lock";
pub const SNAPSHOT_TRUST_STATE_KEY_BYTES: usize = 32;

/// Host-held authentication key for the persisted trust-policy identity.
///
/// This key protects the integrity of the state file. Rollback protection is
/// relative to an intact trusted state directory: this mechanism does not claim
/// resistance to a privileged actor who can restore the entire directory to an
/// older filesystem snapshot or disclose this key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustStateKey([u8; SNAPSHOT_TRUST_STATE_KEY_BYTES]);

impl SnapshotTrustStateKey {
    pub fn new(bytes: [u8; SNAPSHOT_TRUST_STATE_KEY_BYTES]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SNAPSHOT_TRUST_STATE_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for SnapshotTrustStateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SnapshotTrustStateKey([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustStateReceipt {
    pub policy: SnapshotTrustPolicyIdentity,
}

/// One persisted trust-state authority reused by state-backed snapshot operations.
///
/// The context binds the host-owned authenticated state location/key to the exact
/// caller-supplied trust-policy snapshot. Each operation still reopens, locks,
/// authenticates, and compares persisted state before touching snapshot storage.
pub struct SnapshotTrustStateContext<'a> {
    state_root: &'a Path,
    state_key: &'a SnapshotTrustStateKey,
    policy: &'a SnapshotTrustPolicy,
}

impl<'a> SnapshotTrustStateContext<'a> {
    pub fn new(
        state_root: &'a Path,
        state_key: &'a SnapshotTrustStateKey,
        policy: &'a SnapshotTrustPolicy,
    ) -> Self {
        Self {
            state_root,
            state_key,
            policy,
        }
    }
}

#[derive(Debug)]
pub enum SnapshotTrustStateError {
    UnsupportedPlatform(String),
    NotInitialized,
    AlreadyInitialized {
        persisted: SnapshotTrustPolicyIdentity,
    },
    AuthenticationFailed,
    InvalidState(String),
    StalePolicy {
        persisted: SnapshotTrustPolicyIdentity,
        supplied: SnapshotTrustPolicyIdentity,
    },
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    Trust(SnapshotTrustError),
}

impl fmt::Display for SnapshotTrustStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(message) => write!(f, "unsupported platform: {message}"),
            Self::NotInitialized => f.write_str("snapshot trust state is not initialized"),
            Self::AlreadyInitialized { persisted } => write!(
                f,
                "snapshot trust state is already initialized at generation {} ({})",
                persisted.generation,
                persisted.sha256_hex()
            ),
            Self::AuthenticationFailed => {
                f.write_str("snapshot trust state authentication failed")
            }
            Self::InvalidState(message) => write!(f, "invalid snapshot trust state: {message}"),
            Self::StalePolicy {
                persisted,
                supplied,
            } => write!(
                f,
                "supplied snapshot trust policy generation {} ({}) does not match persisted generation {} ({})",
                supplied.generation,
                supplied.sha256_hex(),
                persisted.generation,
                persisted.sha256_hex()
            ),
            Self::Io { phase, source } => write!(f, "{phase}: {source}"),
            Self::Trust(source) => write!(f, "snapshot trust decision failed: {source}"),
        }
    }
}

impl Error for SnapshotTrustStateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Trust(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotTrustError> for SnapshotTrustStateError {
    fn from(value: SnapshotTrustError) -> Self {
        Self::Trust(value)
    }
}

pub fn snapshot_trust_state_path(state_root: &Path) -> PathBuf {
    state_root.join(TRUST_STATE_FILE)
}

/// Initialize one host-owned authenticated trust-state identity.
///
/// Initialization is idempotent for the exact same policy identity. On Linux,
/// the state is written to a fresh temporary file, fsynced, atomically installed
/// without replacing an existing state, and the containing directory is then
/// fsynced before success is returned.
pub fn initialize_snapshot_trust_state(
    state_root: &Path,
    state_key: &SnapshotTrustStateKey,
    policy: &SnapshotTrustPolicy,
) -> Result<SnapshotTrustStateReceipt, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        linux::initialize(state_root, state_key, policy.identity())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, policy);
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust state currently requires Linux flock, fsync, and fd-relative atomic publication"
                .to_owned(),
        ))
    }
}

/// Load and authenticate the exact currently persisted policy identity.
pub fn load_snapshot_trust_state_identity(
    state_root: &Path,
    state_key: &SnapshotTrustStateKey,
) -> Result<SnapshotTrustPolicyIdentity, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        linux::load_identity(state_root, state_key)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key);
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust state currently requires Linux flock and fd-relative state access"
                .to_owned(),
        ))
    }
}

/// Persist one policy rotation while rejecting stale writers.
///
/// The successor is always constructed through the existing 41A `rotate()`
/// transition, so revoked-key reactivation and non-advancing generations remain
/// fail-closed. An exclusive advisory lock linearizes cooperating writers and
/// state-backed operations. Repeating the exact transition after an ambiguous
/// publication acknowledgement converges successfully when the persisted state
/// already equals the computed successor identity.
pub fn rotate_snapshot_trust_state(
    state_root: &Path,
    state_key: &SnapshotTrustStateKey,
    current_policy: &SnapshotTrustPolicy,
    next_generation: u64,
    new_active_keys: Vec<[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES]>,
    revoke: &[SnapshotTrustKeyId],
) -> Result<SnapshotTrustPolicy, SnapshotTrustStateError> {
    let next_policy = current_policy.rotate(next_generation, new_active_keys, revoke)?;
    #[cfg(target_os = "linux")]
    {
        linux::rotate(
            state_root,
            state_key,
            current_policy.identity(),
            &next_policy,
        )?;
        Ok(next_policy)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, current_policy, next_policy);
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust rotation currently requires Linux flock, fsync, and fd-relative atomic publication"
                .to_owned(),
        ))
    }
}

/// Require the supplied policy to equal authenticated host-owned state before
/// allowing any snapshot-store access. A shared lock is held through the entire
/// durable store operation, so a cooperating rotation cannot overtake an
/// operation after the persisted-policy gate has accepted it.
pub fn store_snapshot_archive_persisted_trust_ed25519_durable(
    context: &SnapshotTrustStateContext<'_>,
    store_root: &Path,
    archive: &[u8],
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedStorePutReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(
            context.state_root,
            context.state_key,
            context.policy.identity(),
        )?;
        Ok(store_snapshot_archive_trusted_ed25519_durable(
            store_root,
            archive,
            context.policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            context,
            store_root,
            archive,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}

/// State-backed counterpart to trusted atomic materialization. The persisted
/// policy gate runs before store-object inspection and remains locked until the
/// materializer returns.
pub fn materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
    context: &SnapshotTrustStateContext<'_>,
    store_root: &Path,
    identity: SnapshotIdentity,
    destination: &Path,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedMaterializeReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(
            context.state_root,
            context.state_key,
            context.policy.identity(),
        )?;
        Ok(materialize_snapshot_store_object_trusted_ed25519_atomic(
            store_root,
            identity,
            destination,
            context.policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            context,
            store_root,
            identity,
            destination,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}

fn encode_state(
    identity: SnapshotTrustPolicyIdentity,
    state_key: &SnapshotTrustStateKey,
) -> [u8; TRUST_STATE_BYTES] {
    let mut bytes = [0u8; TRUST_STATE_BYTES];
    bytes[0..8].copy_from_slice(&TRUST_STATE_MAGIC);
    bytes[8..16].copy_from_slice(&identity.generation.to_le_bytes());
    bytes[16..48].copy_from_slice(&identity.sha256);
    bytes[48..52].copy_from_slice(&identity.keys.to_le_bytes());
    // bytes 52..56 are reserved and remain zero.

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(TRUST_STATE_DOMAIN);
    mac.update(&bytes[..TRUST_STATE_HEADER_BYTES]);
    bytes[TRUST_STATE_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn decode_state(
    bytes: &[u8; TRUST_STATE_BYTES],
    state_key: &SnapshotTrustStateKey,
) -> Result<SnapshotTrustPolicyIdentity, SnapshotTrustStateError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(TRUST_STATE_DOMAIN);
    mac.update(&bytes[..TRUST_STATE_HEADER_BYTES]);
    mac.verify_slice(&bytes[TRUST_STATE_HEADER_BYTES..])
        .map_err(|_| SnapshotTrustStateError::AuthenticationFailed)?;

    if bytes[0..8] != TRUST_STATE_MAGIC {
        return Err(SnapshotTrustStateError::InvalidState(
            "unexpected trust-state magic/version".to_owned(),
        ));
    }
    if bytes[52..56] != [0u8; 4] {
        return Err(SnapshotTrustStateError::InvalidState(
            "reserved trust-state bytes are non-zero".to_owned(),
        ));
    }

    let generation = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .expect("fixed trust-state generation width"),
    );
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[16..48]);
    let keys = u32::from_le_bytes(
        bytes[48..52]
            .try_into()
            .expect("fixed trust-state key-count width"),
    );
    if generation == 0 {
        return Err(SnapshotTrustStateError::InvalidState(
            "persisted policy generation must be non-zero".to_owned(),
        ));
    }
    if keys == 0 || keys as usize > SNAPSHOT_TRUST_MAX_KEYS {
        return Err(SnapshotTrustStateError::InvalidState(format!(
            "persisted key count {keys} is outside 1..={SNAPSHOT_TRUST_MAX_KEYS}"
        )));
    }
    Ok(SnapshotTrustPolicyIdentity {
        generation,
        sha256,
        keys,
    })
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{
        decode_state, encode_state, SnapshotTrustPolicy, SnapshotTrustPolicyIdentity,
        SnapshotTrustStateError, SnapshotTrustStateKey, SnapshotTrustStateReceipt,
        TRUST_STATE_BYTES, TRUST_STATE_FILE, TRUST_STATE_LOCK,
    };
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    const RENAME_NOREPLACE: libc::c_uint = 1;
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    pub(super) struct StateGuard {
        _lock: OwnedFd,
    }

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

    pub(super) fn initialize(
        state_root: &Path,
        state_key: &SnapshotTrustStateKey,
        identity: SnapshotTrustPolicyIdentity,
    ) -> Result<SnapshotTrustStateReceipt, SnapshotTrustStateError> {
        let root = open_root(state_root)?;
        let lock = open_lock(root.raw())?;
        lock_fd(lock.raw(), libc::LOCK_EX)?;

        if let Some((persisted, state_fd)) = read_state_optional(root.raw(), state_key)? {
            if persisted == identity {
                sync_fd(state_fd.raw(), "sync existing snapshot trust state")?;
                sync_fd(root.raw(), "sync snapshot trust state directory")?;
                return Ok(SnapshotTrustStateReceipt { policy: persisted });
            }
            return Err(SnapshotTrustStateError::AlreadyInitialized { persisted });
        }

        publish_state(root.raw(), identity, state_key, true)?;
        Ok(SnapshotTrustStateReceipt { policy: identity })
    }

    pub(super) fn load_identity(
        state_root: &Path,
        state_key: &SnapshotTrustStateKey,
    ) -> Result<SnapshotTrustPolicyIdentity, SnapshotTrustStateError> {
        let root = open_root(state_root)?;
        let lock = open_lock(root.raw())?;
        lock_fd(lock.raw(), libc::LOCK_SH)?;
        let (identity, _) = read_state_optional(root.raw(), state_key)?
            .ok_or(SnapshotTrustStateError::NotInitialized)?;
        Ok(identity)
    }

    pub(super) fn rotate(
        state_root: &Path,
        state_key: &SnapshotTrustStateKey,
        current: SnapshotTrustPolicyIdentity,
        next_policy: &SnapshotTrustPolicy,
    ) -> Result<(), SnapshotTrustStateError> {
        let next = next_policy.identity();
        let root = open_root(state_root)?;
        let lock = open_lock(root.raw())?;
        lock_fd(lock.raw(), libc::LOCK_EX)?;
        let (persisted, state_fd) = read_state_optional(root.raw(), state_key)?
            .ok_or(SnapshotTrustStateError::NotInitialized)?;

        if persisted == next {
            sync_fd(state_fd.raw(), "sync converged snapshot trust state")?;
            sync_fd(root.raw(), "sync snapshot trust state directory")?;
            return Ok(());
        }
        if persisted != current {
            return Err(SnapshotTrustStateError::StalePolicy {
                persisted,
                supplied: current,
            });
        }

        publish_state(root.raw(), next, state_key, false)
    }

    pub(super) fn lock_shared_and_validate(
        state_root: &Path,
        state_key: &SnapshotTrustStateKey,
        supplied: SnapshotTrustPolicyIdentity,
    ) -> Result<StateGuard, SnapshotTrustStateError> {
        let root = open_root(state_root)?;
        let lock = open_lock(root.raw())?;
        lock_fd(lock.raw(), libc::LOCK_SH)?;
        let (persisted, _) = read_state_optional(root.raw(), state_key)?
            .ok_or(SnapshotTrustStateError::NotInitialized)?;
        if persisted != supplied {
            return Err(SnapshotTrustStateError::StalePolicy {
                persisted,
                supplied,
            });
        }
        Ok(StateGuard { _lock: lock })
    }

    fn open_root(state_root: &Path) -> Result<OwnedFd, SnapshotTrustStateError> {
        let path = CString::new(state_root.as_os_str().as_bytes()).map_err(|_| {
            SnapshotTrustStateError::InvalidState("state_root contains NUL".to_owned())
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io_error(
                "open snapshot trust state directory",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(OwnedFd(fd))
    }

    fn open_lock(root_fd: RawFd) -> Result<OwnedFd, SnapshotTrustStateError> {
        let name = CString::new(TRUST_STATE_LOCK).expect("static lock filename has no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io_error(
                "open snapshot trust state lock",
                std::io::Error::last_os_error(),
            ));
        }
        let fd = OwnedFd(fd);
        require_regular(fd.raw(), "stat snapshot trust state lock", None)?;
        Ok(fd)
    }

    fn lock_fd(fd: RawFd, operation: libc::c_int) -> Result<(), SnapshotTrustStateError> {
        loop {
            if unsafe { libc::flock(fd, operation) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(io_error("lock snapshot trust state", error));
        }
    }

    fn read_state_optional(
        root_fd: RawFd,
        state_key: &SnapshotTrustStateKey,
    ) -> Result<Option<(SnapshotTrustPolicyIdentity, OwnedFd)>, SnapshotTrustStateError> {
        let name = CString::new(TRUST_STATE_FILE).expect("static state filename has no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(io_error("open snapshot trust state", error));
        }
        let fd = OwnedFd(fd);
        require_regular(
            fd.raw(),
            "stat snapshot trust state",
            Some(TRUST_STATE_BYTES as i64),
        )?;
        let mut bytes = [0u8; TRUST_STATE_BYTES];
        read_exact(fd.raw(), &mut bytes)?;
        let identity = decode_state(&bytes, state_key)?;
        Ok(Some((identity, fd)))
    }

    fn require_regular(
        fd: RawFd,
        phase: &'static str,
        exact_size: Option<i64>,
    ) -> Result<(), SnapshotTrustStateError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } != 0 {
            return Err(io_error(phase, std::io::Error::last_os_error()));
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG {
            return Err(SnapshotTrustStateError::InvalidState(
                "snapshot trust state path is not a regular file".to_owned(),
            ));
        }
        if let Some(expected) = exact_size {
            if stat.st_size != expected {
                return Err(SnapshotTrustStateError::InvalidState(format!(
                    "snapshot trust state size {} does not equal expected {expected}",
                    stat.st_size
                )));
            }
        }
        Ok(())
    }

    fn read_exact(fd: RawFd, bytes: &mut [u8]) -> Result<(), SnapshotTrustStateError> {
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
                return Err(SnapshotTrustStateError::InvalidState(
                    "snapshot trust state reached EOF early".to_owned(),
                ));
            }
            if read < 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("read snapshot trust state", error));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn publish_state(
        root_fd: RawFd,
        identity: SnapshotTrustPolicyIdentity,
        state_key: &SnapshotTrustStateKey,
        no_replace: bool,
    ) -> Result<(), SnapshotTrustStateError> {
        let bytes = encode_state(identity, state_key);
        let temp_name = unique_temp_name();
        let temp = create_temp(root_fd, &temp_name)?;
        let result = (|| {
            write_all(temp.raw(), &bytes)?;
            sync_fd(temp.raw(), "sync snapshot trust state temp file")?;
            install_temp(root_fd, &temp_name, no_replace)?;
            sync_fd(root_fd, "sync snapshot trust state directory")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = unlink_temp(root_fd, &temp_name);
        }
        result
    }

    fn unique_temp_name() -> CString {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        CString::new(format!(
            ".trust-state.tmp.{}.{}",
            std::process::id(),
            sequence
        ))
        .expect("generated trust-state temp filename has no NUL")
    }

    fn create_temp(root_fd: RawFd, name: &CString) -> Result<OwnedFd, SnapshotTrustStateError> {
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(io_error(
                "create snapshot trust state temp file",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(OwnedFd(fd))
    }

    fn write_all(fd: RawFd, bytes: &[u8]) -> Result<(), SnapshotTrustStateError> {
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
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("write snapshot trust state temp file", error));
            }
            if written == 0 {
                return Err(SnapshotTrustStateError::InvalidState(
                    "snapshot trust state write made no progress".to_owned(),
                ));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn install_temp(
        root_fd: RawFd,
        temp_name: &CString,
        no_replace: bool,
    ) -> Result<(), SnapshotTrustStateError> {
        let state_name = CString::new(TRUST_STATE_FILE).expect("static state filename has no NUL");
        if no_replace {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    root_fd,
                    temp_name.as_ptr(),
                    root_fd,
                    state_name.as_ptr(),
                    RENAME_NOREPLACE,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    return Err(SnapshotTrustStateError::InvalidState(
                        "snapshot trust state appeared during locked initialization".to_owned(),
                    ));
                }
                return Err(io_error("install initial snapshot trust state", error));
            }
        } else if unsafe {
            libc::renameat(root_fd, temp_name.as_ptr(), root_fd, state_name.as_ptr())
        } != 0
        {
            return Err(io_error(
                "replace snapshot trust state",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn unlink_temp(root_fd: RawFd, temp_name: &CString) -> Result<(), SnapshotTrustStateError> {
        if unsafe { libc::unlinkat(root_fd, temp_name.as_ptr(), 0) } != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(io_error("remove snapshot trust state temp file", error));
            }
        }
        Ok(())
    }

    fn sync_fd(fd: RawFd, phase: &'static str) -> Result<(), SnapshotTrustStateError> {
        if unsafe { libc::fsync(fd) } != 0 {
            return Err(io_error(phase, std::io::Error::last_os_error()));
        }
        Ok(())
    }

    fn io_error(phase: &'static str, source: std::io::Error) -> SnapshotTrustStateError {
        SnapshotTrustStateError::Io { phase, source }
    }
}
