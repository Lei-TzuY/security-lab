use crate::snapshot_archive::SnapshotArchiveLimits;
use crate::snapshot_identity::SnapshotIdentity;
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_store::{
    validate_snapshot_archive_ed25519, SnapshotStoreError, SnapshotStorePutReport,
};
use crate::snapshot_store_audit::SnapshotStoreAuditLimits;
use crate::snapshot_store_inventory::{
    projected_snapshot_store_batch_inventory_identity, projected_snapshot_store_inventory_identity,
    SnapshotStoreInventoryIdentity,
};
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
const HEAD_PENDING_DOMAIN: &[u8] = b"security-lab-snapshot-store-head-pending-v2\0";
const HEAD_PENDING_MAGIC: [u8; 8] = *b"SLHPND2\0";
const HEAD_PENDING_HEADER_BYTES: usize = 176;
const HEAD_PENDING_MAC_BYTES: usize = 32;
const HEAD_PENDING_BYTES: usize = HEAD_PENDING_HEADER_BYTES + HEAD_PENDING_MAC_BYTES;
const HEAD_PENDING_FILE: &str = "snapshot-store-head-pending";
const HEAD_BATCH_PENDING_DOMAIN: &[u8] =
    b"security-lab-snapshot-store-head-batch-pending-v1\0";
const HEAD_BATCH_PENDING_MAGIC: [u8; 8] = *b"SLHBPN1\0";
const HEAD_BATCH_PENDING_FIXED_BYTES: usize = 128;
const HEAD_BATCH_PENDING_ENTRY_BYTES: usize = 208;
const HEAD_BATCH_PENDING_HEADER_BYTES: usize =
    HEAD_BATCH_PENDING_FIXED_BYTES + SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS * HEAD_BATCH_PENDING_ENTRY_BYTES;
const HEAD_BATCH_PENDING_MAC_BYTES: usize = 32;
const HEAD_BATCH_PENDING_BYTES: usize =
    HEAD_BATCH_PENDING_HEADER_BYTES + HEAD_BATCH_PENDING_MAC_BYTES;
const HEAD_BATCH_PENDING_FILE: &str = "snapshot-store-head-batch-pending";
const HEAD_BATCH_STAGE_PREFIX: &str = "snapshot-store-head-batch-stage-";
pub const SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES: usize = 32;
pub const SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS: usize = 16;

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

    /// Recover an authenticated pending publication and return the exact head
    /// identity after convergence.
    ///
    /// Single-object recovery accepts only the exact predecessor or successor.
    /// Batch recovery additionally accepts only authenticated intermediate
    /// inventories committed by the batch journal, validates every durable
    /// staged archive before replay, and then converges to the exact successor.
    /// Arbitrary observed store inventories are never promoted to head state.
    pub fn recover_pending_publication(
        &self,
        state_root: &Path,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        validate_roots(state_root, store_root)?;
        #[cfg(target_os = "linux")]
        {
            linux::recover(state_root, self, store_root, inventory_limits)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (state_root, store_root, inventory_limits);
            Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
                "authenticated store-head recovery currently requires Linux flock, fsync, and cooperative snapshot-store transactions"
                    .to_owned(),
            ))
        }
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
struct SnapshotStoreHeadPendingIntent {
    previous: SnapshotStoreHeadStateIdentity,
    successor: SnapshotStoreHeadStateIdentity,
    candidate_identity: SnapshotIdentity,
    candidate_archive_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotStoreHeadValidatedBatchItem {
    identity: SnapshotIdentity,
    archive_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotStoreHeadBatchPendingEntry {
    identity: SnapshotIdentity,
    archive_bytes: u64,
    public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    signature: [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    preexisting: bool,
    after_inventory: Option<SnapshotStoreInventoryIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotStoreHeadBatchPendingIntent {
    previous: SnapshotStoreHeadStateIdentity,
    successor: SnapshotStoreHeadStateIdentity,
    entries: Vec<SnapshotStoreHeadBatchPendingEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadPutReport {
    pub put: SnapshotStorePutReport,
    pub previous: SnapshotStoreHeadStateIdentity,
    pub successor: SnapshotStoreHeadStateIdentity,
}

/// Inputs for one authenticated durable publication guarded by the persisted
/// whole-store head.
pub struct SnapshotStoreHeadPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

pub struct SnapshotStoreHeadBatchItem<'a> {
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

pub struct SnapshotStoreHeadBatchPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub items: &'a [SnapshotStoreHeadBatchItem<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStoreHeadBatchPutReport {
    pub puts: Vec<SnapshotStorePutReport>,
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
    RecoveryRequired {
        previous: SnapshotStoreHeadStateIdentity,
        successor: SnapshotStoreHeadStateIdentity,
    },
    PendingStateDiverged {
        previous: Box<SnapshotStoreHeadStateIdentity>,
        successor: Box<SnapshotStoreHeadStateIdentity>,
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
    BatchItemInvalid {
        index: usize,
        source: Box<SnapshotStoreError>,
    },
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    Transaction(Box<SnapshotStoreTransactionError>),
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
            Self::RecoveryRequired {
                previous,
                successor,
            } => write!(
                f,
                "snapshot store head recovery is required: pending generation {} inventory {} -> generation {} inventory {}",
                previous.generation,
                previous.inventory.sha256_hex(),
                successor.generation,
                successor.inventory.sha256_hex(),
            ),
            Self::PendingStateDiverged {
                previous,
                successor,
                anchored,
                actual,
            } => write!(
                f,
                "snapshot store pending publication diverged: pending generation {} inventory {} -> generation {} inventory {}, persisted generation {} inventory {}, actual store {} objects={} bytes={}",
                previous.generation,
                previous.inventory.sha256_hex(),
                successor.generation,
                successor.inventory.sha256_hex(),
                anchored.generation,
                anchored.inventory.sha256_hex(),
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
            Self::BatchItemInvalid { index, source } => write!(
                f,
                "snapshot store head-state batch item {index} failed prevalidation: {source}"
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
            Self::BatchItemInvalid { source, .. } => Some(source.as_ref()),
            Self::Io { source, .. } => Some(source),
            Self::Transaction(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl From<SnapshotStoreTransactionError> for SnapshotStoreHeadStateError {
    fn from(value: SnapshotStoreTransactionError) -> Self {
        Self::Transaction(Box::new(value))
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
    request: SnapshotStoreHeadPublishRequest<'_>,
) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = "linux")]
    {
        linux::store(state_root, state_key, store_root, request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, store_root, request);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated durable store-head publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions"
                .to_owned(),
        ))
    }
}

/// Bounded multi-object publication under one authenticated store-head generation.
///
/// Every archive/signature pair is completely validated before either state or
/// store filesystem mutation is attempted. The head-state lock and exclusive
/// store transaction remain held across the whole publication loop, so
/// cooperating readers observe the inventory before or after a successful
/// batch, not an intermediate member. A successful batch advances the head at
/// most once; an all-deduplicated batch leaves it unchanged.
///
/// This is not a crash-atomic all-or-nothing filesystem transaction. If a later
/// object/durability operation fails after an earlier member was published, the
/// call returns an error and the unchanged authenticated head makes that
/// partial store advancement detectable as divergence.
pub fn store_snapshot_archives_ed25519_durable_with_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    request: SnapshotStoreHeadBatchPublishRequest<'_>,
) -> Result<SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    let validated = validate_batch_request(&request)?;
    #[cfg(target_os = "linux")]
    {
        linux::store_batch(state_root, state_key, store_root, request, &validated)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, store_root, request, validated);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated durable store-head batch publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions"
                .to_owned(),
        ))
    }
}

fn validate_batch_request(
    request: &SnapshotStoreHeadBatchPublishRequest<'_>,
) -> Result<Vec<SnapshotStoreHeadValidatedBatchItem>, SnapshotStoreHeadStateError> {
    if request.items.is_empty() {
        return Err(SnapshotStoreHeadStateError::InvalidInput(
            "batch publication requires at least one item".to_owned(),
        ));
    }
    if request.items.len() > SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS {
        return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
            "batch publication accepts at most {SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS} items"
        )));
    }

    let mut validated = Vec::with_capacity(request.items.len());
    let mut staged_archive_bytes = 0u64;
    for (index, item) in request.items.iter().enumerate() {
        let identity = validate_snapshot_archive_ed25519(
            item.archive,
            item.public_key,
            item.expected_signature,
            item.archive_limits,
        )
        .map_err(|source| SnapshotStoreHeadStateError::BatchItemInvalid {
            index,
            source: Box::new(source),
        })?;
        if let Some(first_index) = validated
            .iter()
            .position(|existing: &SnapshotStoreHeadValidatedBatchItem| existing.identity == identity)
        {
            return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
                "batch item {index} duplicates canonical identity from item {first_index}"
            )));
        }
        let archive_bytes = u64::try_from(item.archive.len()).map_err(|_| {
            SnapshotStoreHeadStateError::InvalidInput(format!(
                "batch item {index} archive length does not fit u64"
            ))
        })?;
        staged_archive_bytes = staged_archive_bytes.checked_add(archive_bytes).ok_or_else(|| {
            SnapshotStoreHeadStateError::InvalidInput(
                "batch staged archive-byte accounting overflow".to_owned(),
            )
        })?;
        if staged_archive_bytes > request.inventory_limits.max_total_archive_bytes {
            return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
                "batch staged archive bytes exceed inventory aggregate budget: limit={} attempted={staged_archive_bytes}",
                request.inventory_limits.max_total_archive_bytes
            )));
        }
        validated.push(SnapshotStoreHeadValidatedBatchItem {
            identity,
            archive_bytes,
        });
    }
    Ok(validated)
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

fn encode_pending(
    intent: SnapshotStoreHeadPendingIntent,
    state_key: &SnapshotStoreHeadStateKey,
) -> [u8; HEAD_PENDING_BYTES] {
    let mut bytes = [0u8; HEAD_PENDING_BYTES];
    bytes[0..8].copy_from_slice(&HEAD_PENDING_MAGIC);
    encode_identity_fields(&mut bytes[8..64], intent.previous);
    encode_identity_fields(&mut bytes[64..120], intent.successor);
    bytes[120..152].copy_from_slice(&intent.candidate_identity.sha256);
    bytes[152..160].copy_from_slice(&intent.candidate_identity.encoded_bytes.to_le_bytes());
    bytes[160..168].copy_from_slice(&intent.candidate_identity.nodes.to_le_bytes());
    bytes[168..176].copy_from_slice(&intent.candidate_archive_bytes.to_le_bytes());

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_PENDING_DOMAIN);
    mac.update(&bytes[..HEAD_PENDING_HEADER_BYTES]);
    bytes[HEAD_PENDING_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn decode_pending(
    bytes: &[u8; HEAD_PENDING_BYTES],
    state_key: &SnapshotStoreHeadStateKey,
) -> Result<SnapshotStoreHeadPendingIntent, SnapshotStoreHeadStateError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_PENDING_DOMAIN);
    mac.update(&bytes[..HEAD_PENDING_HEADER_BYTES]);
    mac.verify_slice(&bytes[HEAD_PENDING_HEADER_BYTES..])
        .map_err(|_| SnapshotStoreHeadStateError::AuthenticationFailed)?;

    if bytes[0..8] != HEAD_PENDING_MAGIC {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "unexpected pending store-head magic/version".to_owned(),
        ));
    }
    let previous = decode_identity_fields(&bytes[8..64])?;
    let successor = decode_identity_fields(&bytes[64..120])?;
    let mut candidate_sha256 = [0u8; 32];
    candidate_sha256.copy_from_slice(&bytes[120..152]);
    let candidate_identity = SnapshotIdentity {
        sha256: candidate_sha256,
        encoded_bytes: u64::from_le_bytes(
            bytes[152..160]
                .try_into()
                .expect("fixed pending candidate encoded-byte width"),
        ),
        nodes: u64::from_le_bytes(
            bytes[160..168]
                .try_into()
                .expect("fixed pending candidate node-count width"),
        ),
    };
    let candidate_archive_bytes = u64::from_le_bytes(
        bytes[168..176]
            .try_into()
            .expect("fixed pending candidate archive-byte width"),
    );
    let expected_generation = previous.generation.checked_add(1).ok_or_else(|| {
        SnapshotStoreHeadStateError::InvalidState(
            "pending predecessor generation is exhausted".to_owned(),
        )
    })?;
    if successor.generation != expected_generation {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "pending successor generation must advance exactly once".to_owned(),
        ));
    }
    if successor.inventory.objects
        != previous.inventory.objects.checked_add(1).ok_or_else(|| {
            SnapshotStoreHeadStateError::InvalidState(
                "pending predecessor object count is exhausted".to_owned(),
            )
        })?
    {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "pending successor must add exactly one object".to_owned(),
        ));
    }
    if candidate_archive_bytes == 0 {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "pending candidate archive bytes must be non-zero".to_owned(),
        ));
    }
    let expected_archive_bytes = previous
        .inventory
        .archive_bytes
        .checked_add(candidate_archive_bytes)
        .ok_or_else(|| {
            SnapshotStoreHeadStateError::InvalidState(
                "pending successor archive-byte accounting overflow".to_owned(),
            )
        })?;
    if successor.inventory.archive_bytes != expected_archive_bytes {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "pending successor archive bytes must equal predecessor plus candidate archive bytes"
                .to_owned(),
        ));
    }
    Ok(SnapshotStoreHeadPendingIntent {
        previous,
        successor,
        candidate_identity,
        candidate_archive_bytes,
    })
}

fn encode_batch_pending(
    intent: &SnapshotStoreHeadBatchPendingIntent,
    state_key: &SnapshotStoreHeadStateKey,
) -> [u8; HEAD_BATCH_PENDING_BYTES] {
    debug_assert!(!intent.entries.is_empty());
    debug_assert!(intent.entries.len() <= SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS);
    let mut bytes = [0u8; HEAD_BATCH_PENDING_BYTES];
    bytes[0..8].copy_from_slice(&HEAD_BATCH_PENDING_MAGIC);
    encode_identity_fields(&mut bytes[8..64], intent.previous);
    encode_identity_fields(&mut bytes[64..120], intent.successor);
    bytes[120..128].copy_from_slice(&(intent.entries.len() as u64).to_le_bytes());

    for (index, entry) in intent.entries.iter().enumerate() {
        let offset = HEAD_BATCH_PENDING_FIXED_BYTES + index * HEAD_BATCH_PENDING_ENTRY_BYTES;
        let slot = &mut bytes[offset..offset + HEAD_BATCH_PENDING_ENTRY_BYTES];
        slot[0..32].copy_from_slice(&entry.identity.sha256);
        slot[32..40].copy_from_slice(&entry.identity.encoded_bytes.to_le_bytes());
        slot[40..48].copy_from_slice(&entry.identity.nodes.to_le_bytes());
        slot[48..56].copy_from_slice(&entry.archive_bytes.to_le_bytes());
        slot[56..88].copy_from_slice(&entry.public_key);
        slot[88..152].copy_from_slice(&entry.signature);
        slot[152] = u8::from(entry.preexisting);
        if let Some(after) = entry.after_inventory {
            encode_inventory_fields(&mut slot[160..208], after);
        }
    }

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_BATCH_PENDING_DOMAIN);
    mac.update(&bytes[..HEAD_BATCH_PENDING_HEADER_BYTES]);
    bytes[HEAD_BATCH_PENDING_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn decode_batch_pending(
    bytes: &[u8; HEAD_BATCH_PENDING_BYTES],
    state_key: &SnapshotStoreHeadStateKey,
) -> Result<SnapshotStoreHeadBatchPendingIntent, SnapshotStoreHeadStateError> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(state_key.as_bytes())
        .expect("fixed-size HMAC key is always accepted");
    mac.update(HEAD_BATCH_PENDING_DOMAIN);
    mac.update(&bytes[..HEAD_BATCH_PENDING_HEADER_BYTES]);
    mac.verify_slice(&bytes[HEAD_BATCH_PENDING_HEADER_BYTES..])
        .map_err(|_| SnapshotStoreHeadStateError::AuthenticationFailed)?;

    if bytes[0..8] != HEAD_BATCH_PENDING_MAGIC {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "unexpected batch pending store-head magic/version".to_owned(),
        ));
    }
    let previous = decode_identity_fields(&bytes[8..64])?;
    let successor = decode_identity_fields(&bytes[64..120])?;
    let count_u64 = u64::from_le_bytes(
        bytes[120..128]
            .try_into()
            .expect("fixed batch pending item-count width"),
    );
    let count = usize::try_from(count_u64).map_err(|_| {
        SnapshotStoreHeadStateError::InvalidState(
            "batch pending item count does not fit usize".to_owned(),
        )
    })?;
    if count == 0 || count > SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS {
        return Err(SnapshotStoreHeadStateError::InvalidState(format!(
            "batch pending item count must be between 1 and {SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS}"
        )));
    }
    let expected_generation = previous.generation.checked_add(1).ok_or_else(|| {
        SnapshotStoreHeadStateError::InvalidState(
            "batch pending predecessor generation is exhausted".to_owned(),
        )
    })?;
    if successor.generation != expected_generation {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "batch pending successor generation must advance exactly once".to_owned(),
        ));
    }

    let mut entries = Vec::with_capacity(count);
    let mut expected_objects = previous.inventory.objects;
    let mut expected_archive_bytes = previous.inventory.archive_bytes;
    let mut last_after = None;
    for index in 0..count {
        let offset = HEAD_BATCH_PENDING_FIXED_BYTES + index * HEAD_BATCH_PENDING_ENTRY_BYTES;
        let slot = &bytes[offset..offset + HEAD_BATCH_PENDING_ENTRY_BYTES];
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&slot[0..32]);
        let identity = SnapshotIdentity {
            sha256,
            encoded_bytes: u64::from_le_bytes(
                slot[32..40]
                    .try_into()
                    .expect("fixed batch pending encoded-byte width"),
            ),
            nodes: u64::from_le_bytes(
                slot[40..48]
                    .try_into()
                    .expect("fixed batch pending node-count width"),
            ),
        };
        let archive_bytes = u64::from_le_bytes(
            slot[48..56]
                .try_into()
                .expect("fixed batch pending archive-byte width"),
        );
        if identity.encoded_bytes == 0 || identity.nodes == 0 || archive_bytes == 0 {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "batch pending item {index} has zero identity/archive accounting"
            )));
        }
        if entries
            .iter()
            .any(|existing: &SnapshotStoreHeadBatchPendingEntry| existing.identity == identity)
        {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "batch pending item {index} duplicates an earlier canonical identity"
            )));
        }
        let mut public_key = [0u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES];
        public_key.copy_from_slice(&slot[56..88]);
        let mut signature = [0u8; SNAPSHOT_ED25519_SIGNATURE_BYTES];
        signature.copy_from_slice(&slot[88..152]);
        let preexisting = match slot[152] {
            0 => false,
            1 => true,
            _ => {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch pending item {index} has invalid preexisting flag"
                )))
            }
        };
        if slot[153..160].iter().any(|byte| *byte != 0) {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "batch pending item {index} has non-zero reserved bytes"
            )));
        }
        let after_inventory = if preexisting {
            if slot[160..208].iter().any(|byte| *byte != 0) {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch pending preexisting item {index} must not carry an intermediate inventory"
                )));
            }
            None
        } else {
            expected_objects = expected_objects.checked_add(1).ok_or_else(|| {
                SnapshotStoreHeadStateError::InvalidState(
                    "batch pending predecessor object count is exhausted".to_owned(),
                )
            })?;
            expected_archive_bytes = expected_archive_bytes
                .checked_add(archive_bytes)
                .ok_or_else(|| {
                    SnapshotStoreHeadStateError::InvalidState(
                        "batch pending successor archive-byte accounting overflow".to_owned(),
                    )
                })?;
            let after = decode_inventory_fields(&slot[160..208])?;
            if after.objects != expected_objects || after.archive_bytes != expected_archive_bytes {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch pending item {index} intermediate inventory counters are inconsistent"
                )));
            }
            last_after = Some(after);
            Some(after)
        };
        entries.push(SnapshotStoreHeadBatchPendingEntry {
            identity,
            archive_bytes,
            public_key,
            signature,
            preexisting,
            after_inventory,
        });
    }

    let used = HEAD_BATCH_PENDING_FIXED_BYTES + count * HEAD_BATCH_PENDING_ENTRY_BYTES;
    if bytes[used..HEAD_BATCH_PENDING_HEADER_BYTES]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "unused batch pending entry bytes must be zero".to_owned(),
        ));
    }
    let final_after = last_after.ok_or_else(|| {
        SnapshotStoreHeadStateError::InvalidState(
            "batch pending intent must contain at least one new object".to_owned(),
        )
    })?;
    if final_after != successor.inventory {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "batch pending final intermediate inventory must equal successor".to_owned(),
        ));
    }

    Ok(SnapshotStoreHeadBatchPendingIntent {
        previous,
        successor,
        entries,
    })
}

fn encode_inventory_fields(bytes: &mut [u8], identity: SnapshotStoreInventoryIdentity) {
    debug_assert_eq!(bytes.len(), 48);
    bytes[0..32].copy_from_slice(&identity.sha256);
    bytes[32..40].copy_from_slice(&identity.objects.to_le_bytes());
    bytes[40..48].copy_from_slice(&identity.archive_bytes.to_le_bytes());
}

fn decode_inventory_fields(
    bytes: &[u8],
) -> Result<SnapshotStoreInventoryIdentity, SnapshotStoreHeadStateError> {
    if bytes.len() != 48 {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "invalid batch pending inventory width".to_owned(),
        ));
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[0..32]);
    Ok(SnapshotStoreInventoryIdentity {
        sha256,
        objects: u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .expect("fixed batch pending inventory object-count width"),
        ),
        archive_bytes: u64::from_le_bytes(
            bytes[40..48]
                .try_into()
                .expect("fixed batch pending inventory archive-byte width"),
        ),
    })
}

fn encode_identity_fields(bytes: &mut [u8], identity: SnapshotStoreHeadStateIdentity) {
    debug_assert_eq!(bytes.len(), 56);
    bytes[0..8].copy_from_slice(&identity.generation.to_le_bytes());
    bytes[8..40].copy_from_slice(&identity.inventory.sha256);
    bytes[40..48].copy_from_slice(&identity.inventory.objects.to_le_bytes());
    bytes[48..56].copy_from_slice(&identity.inventory.archive_bytes.to_le_bytes());
}

fn decode_identity_fields(
    bytes: &[u8],
) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
    if bytes.len() != 56 {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "invalid pending store-head identity width".to_owned(),
        ));
    }
    let generation = u64::from_le_bytes(
        bytes[0..8]
            .try_into()
            .expect("fixed pending generation width"),
    );
    if generation == 0 {
        return Err(SnapshotStoreHeadStateError::InvalidState(
            "pending store-head generation must be non-zero".to_owned(),
        ));
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[8..40]);
    let objects = u64::from_le_bytes(
        bytes[40..48]
            .try_into()
            .expect("fixed pending object-count width"),
    );
    let archive_bytes = u64::from_le_bytes(
        bytes[48..56]
            .try_into()
            .expect("fixed pending archive-byte width"),
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
        decode_batch_pending, decode_pending, decode_state, encode_batch_pending, encode_pending,
        encode_state, projected_snapshot_store_batch_inventory_identity,
        projected_snapshot_store_inventory_identity, validate_snapshot_archive_ed25519,
        SnapshotStoreAuditLimits, SnapshotStoreHeadBatchPendingEntry,
        SnapshotStoreHeadBatchPendingIntent, SnapshotStoreHeadBatchPublishRequest,
        SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadPendingIntent,
        SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError,
        SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey,
        SnapshotStoreHeadValidatedBatchItem, SnapshotStoreInventoryIdentity,
        SnapshotStoreReadTransaction, SnapshotStoreTransactionError, SnapshotStoreWriteTransaction,
        HEAD_BATCH_PENDING_BYTES, HEAD_BATCH_PENDING_FILE, HEAD_BATCH_STAGE_PREFIX,
        HEAD_PENDING_BYTES, HEAD_PENDING_FILE, HEAD_STATE_BYTES, HEAD_STATE_FILE, HEAD_STATE_LOCK,
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
        require_no_pending(guard.root.raw(), state_key)?;
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
        require_no_pending(guard.root.raw(), state_key)?;
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
        require_no_pending(guard.root.raw(), state_key)?;
        let anchored = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        let reader = SnapshotStoreReadTransaction::begin(store_root)?;
        let actual = reader.inventory_identity(inventory_limits)?;
        require_inventory(anchored, actual)?;
        Ok(anchored)
    }

    pub(super) fn store(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        request: SnapshotStoreHeadPublishRequest<'_>,
    ) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        require_no_pending(guard.root.raw(), state_key)?;
        let previous = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        if previous.generation == u64::MAX {
            return Err(SnapshotStoreHeadStateError::InvalidState(
                "store-head generation is exhausted".to_owned(),
            ));
        }

        let candidate_identity = validate_snapshot_archive_ed25519(
            request.archive,
            request.public_key,
            request.expected_signature,
            request.archive_limits,
        )
        .map_err(|source| {
            SnapshotStoreHeadStateError::Transaction(Box::new(
                SnapshotStoreTransactionError::Store(source),
            ))
        })?;
        let candidate_archive_bytes = u64::try_from(request.archive.len()).map_err(|_| {
            SnapshotStoreHeadStateError::InvalidInput(
                "snapshot archive length does not fit u64".to_owned(),
            )
        })?;

        let writer = SnapshotStoreWriteTransaction::begin(store_root)?;
        let (current, projected) = projected_snapshot_store_inventory_identity(
            store_root,
            request.inventory_limits,
            candidate_identity,
            candidate_archive_bytes,
        )
        .map_err(|source| {
            SnapshotStoreHeadStateError::Transaction(Box::new(
                SnapshotStoreTransactionError::Inventory(source),
            ))
        })?;
        require_inventory(previous, current)?;

        if projected == current {
            let put = writer.store_ed25519_durable(
                request.archive,
                request.public_key,
                request.expected_signature,
                request.archive_limits,
            )?;
            if put.inserted {
                let actual = writer.inventory_identity(request.inventory_limits)?;
                return Err(SnapshotStoreHeadStateError::StoreDiverged {
                    anchored: previous,
                    actual,
                });
            }
            return Ok(SnapshotStoreHeadPutReport {
                put,
                previous,
                successor: previous,
            });
        }

        let successor = SnapshotStoreHeadStateIdentity {
            generation: previous.generation + 1,
            inventory: projected,
        };
        let pending = SnapshotStoreHeadPendingIntent {
            previous,
            successor,
            candidate_identity,
            candidate_archive_bytes,
        };
        write_pending(guard.root.raw(), state_key, pending)?;

        let put = writer.store_ed25519_durable(
            request.archive,
            request.public_key,
            request.expected_signature,
            request.archive_limits,
        )?;
        let actual = writer.inventory_identity(request.inventory_limits)?;
        if actual != successor.inventory {
            return Err(SnapshotStoreHeadStateError::PendingStateDiverged {
                previous: Box::new(previous),
                successor: Box::new(successor),
                anchored: previous,
                actual,
            });
        }

        write_state(guard.root.raw(), state_key, successor, true)?;
        clear_pending(guard.root.raw())?;
        Ok(SnapshotStoreHeadPutReport {
            put,
            previous,
            successor,
        })
    }

    pub(super) fn store_batch(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        request: SnapshotStoreHeadBatchPublishRequest<'_>,
        validated: &[SnapshotStoreHeadValidatedBatchItem],
    ) -> Result<SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        require_no_pending(guard.root.raw(), state_key)?;
        let previous = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        if previous.generation == u64::MAX {
            return Err(SnapshotStoreHeadStateError::InvalidState(
                "store-head generation is exhausted".to_owned(),
            ));
        }

        let writer = SnapshotStoreWriteTransaction::begin(store_root)?;
        let candidates: Vec<_> = validated
            .iter()
            .map(|item| (item.identity, item.archive_bytes))
            .collect();
        let (current, projected, after_each) =
            projected_snapshot_store_batch_inventory_identity(
                store_root,
                request.inventory_limits,
                &candidates,
            )
            .map_err(|source| {
                SnapshotStoreHeadStateError::Transaction(Box::new(
                    SnapshotStoreTransactionError::Inventory(source),
                ))
            })?;
        require_inventory(previous, current)?;

        let mut puts: Vec<Option<crate::snapshot_store::SnapshotStorePutReport>> =
            vec![None; request.items.len()];
        for (index, ((item, validated_item), after)) in request
            .items
            .iter()
            .zip(validated.iter())
            .zip(after_each.iter())
            .enumerate()
        {
            if after.is_none() {
                let put = writer.store_ed25519_durable(
                    item.archive,
                    item.public_key,
                    item.expected_signature,
                    item.archive_limits,
                )?;
                if put.inserted
                    || put.identity != validated_item.identity
                    || put.archive_bytes != validated_item.archive_bytes
                {
                    let actual = writer.inventory_identity(request.inventory_limits)?;
                    return Err(SnapshotStoreHeadStateError::StoreDiverged {
                        anchored: previous,
                        actual,
                    });
                }
                puts[index] = Some(put);
            }
        }

        if projected == current {
            return Ok(SnapshotStoreHeadBatchPutReport {
                puts: puts
                    .into_iter()
                    .map(|put| put.expect("all-deduplicated batch preflights every item"))
                    .collect(),
                previous,
                successor: previous,
            });
        }

        let successor = SnapshotStoreHeadStateIdentity {
            generation: previous.generation + 1,
            inventory: projected,
        };
        let entries = request
            .items
            .iter()
            .zip(validated.iter())
            .zip(after_each.iter())
            .map(|((item, validated_item), after)| SnapshotStoreHeadBatchPendingEntry {
                identity: validated_item.identity,
                archive_bytes: validated_item.archive_bytes,
                public_key: *item.public_key,
                signature: *item.expected_signature,
                preexisting: after.is_none(),
                after_inventory: *after,
            })
            .collect();
        let pending = SnapshotStoreHeadBatchPendingIntent {
            previous,
            successor,
            entries,
        };
        write_batch_pending(guard.root.raw(), state_key, &pending)?;
        write_batch_stages(guard.root.raw(), &request)?;

        for (index, ((item, validated_item), after)) in request
            .items
            .iter()
            .zip(validated.iter())
            .zip(after_each.iter())
            .enumerate()
        {
            let Some(expected_after) = after else {
                continue;
            };
            let put = writer.store_ed25519_durable(
                item.archive,
                item.public_key,
                item.expected_signature,
                item.archive_limits,
            )?;
            if put.identity != validated_item.identity
                || put.archive_bytes != validated_item.archive_bytes
            {
                let actual = writer.inventory_identity(request.inventory_limits)?;
                return Err(batch_pending_diverged(&pending, previous, actual));
            }
            puts[index] = Some(put);
            let actual = writer.inventory_identity(request.inventory_limits)?;
            if actual != *expected_after {
                return Err(batch_pending_diverged(&pending, previous, actual));
            }
        }

        let actual = writer.inventory_identity(request.inventory_limits)?;
        if actual != successor.inventory {
            return Err(batch_pending_diverged(&pending, previous, actual));
        }
        write_state(guard.root.raw(), state_key, successor, true)?;
        clear_batch_recovery_files(guard.root.raw(), pending.entries.len())?;

        Ok(SnapshotStoreHeadBatchPutReport {
            puts: puts
                .into_iter()
                .map(|put| put.expect("every batch item has a publication report"))
                .collect(),
            previous,
            successor,
        })
    }

    pub(super) fn recover(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        let anchored = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        let writer = SnapshotStoreWriteTransaction::begin(store_root)?;
        let actual = writer.inventory_identity(inventory_limits)?;
        let single = read_pending_optional(guard.root.raw(), state_key)?;
        let batch = read_batch_pending_optional(guard.root.raw(), state_key)?;

        match (single, batch) {
            (Some(_), Some(_)) => Err(SnapshotStoreHeadStateError::InvalidState(
                "single-object and batch pending publications coexist".to_owned(),
            )),
            (Some(pending), None) => {
                recover_single(guard.root.raw(), state_key, &writer, inventory_limits, anchored, actual, pending)
            }
            (None, Some(pending)) => recover_batch(
                guard.root.raw(),
                state_key,
                &writer,
                inventory_limits,
                anchored,
                actual,
                pending,
            ),
            (None, None) => {
                require_inventory(anchored, actual)?;
                Ok(anchored)
            }
        }
    }

    fn recover_single(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
        writer: &SnapshotStoreWriteTransaction,
        inventory_limits: SnapshotStoreAuditLimits,
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
        pending: SnapshotStoreHeadPendingIntent,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        if anchored == pending.previous && actual == pending.previous.inventory {
            clear_pending(root_fd)?;
            return Ok(anchored);
        }

        if anchored == pending.previous && actual == pending.successor.inventory {
            writer
                .sync_object_durable(pending.candidate_identity, pending.candidate_archive_bytes)?;
            let durable_actual = writer.inventory_identity(inventory_limits)?;
            if durable_actual != pending.successor.inventory {
                return Err(SnapshotStoreHeadStateError::PendingStateDiverged {
                    previous: Box::new(pending.previous),
                    successor: Box::new(pending.successor),
                    anchored,
                    actual: durable_actual,
                });
            }
            write_state(root_fd, state_key, pending.successor, true)?;
            clear_pending(root_fd)?;
            return Ok(pending.successor);
        }

        if anchored == pending.successor && actual == pending.successor.inventory {
            clear_pending(root_fd)?;
            return Ok(anchored);
        }

        Err(SnapshotStoreHeadStateError::PendingStateDiverged {
            previous: Box::new(pending.previous),
            successor: Box::new(pending.successor),
            anchored,
            actual,
        })
    }

    fn recover_batch(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
        writer: &SnapshotStoreWriteTransaction,
        inventory_limits: SnapshotStoreAuditLimits,
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
        pending: SnapshotStoreHeadBatchPendingIntent,
    ) -> Result<SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateError> {
        if anchored == pending.previous && actual == pending.previous.inventory {
            clear_batch_recovery_files(root_fd, pending.entries.len())?;
            return Ok(anchored);
        }

        if anchored == pending.successor && actual == pending.successor.inventory {
            clear_batch_recovery_files(root_fd, pending.entries.len())?;
            return Ok(anchored);
        }

        if anchored != pending.previous {
            return Err(batch_pending_diverged(&pending, anchored, actual));
        }

        let mut observed_new = None;
        let mut new_count = 0usize;
        for entry in &pending.entries {
            if let Some(after) = entry.after_inventory {
                new_count += 1;
                if after == actual {
                    observed_new = Some(new_count);
                }
            }
        }
        let Some(observed_new) = observed_new else {
            return Err(batch_pending_diverged(&pending, anchored, actual));
        };

        let staged = read_and_validate_batch_stages(root_fd, &pending, inventory_limits)?;
        let mut replay_new = 0usize;
        for (index, (entry, archive)) in pending.entries.iter().zip(staged.iter()).enumerate() {
            let put = writer.store_ed25519_durable(
                archive,
                &entry.public_key,
                &entry.signature,
                inventory_limits.archive,
            )?;
            if put.identity != entry.identity || put.archive_bytes != entry.archive_bytes {
                let actual = writer.inventory_identity(inventory_limits)?;
                return Err(batch_pending_diverged(&pending, anchored, actual));
            }
            if entry.preexisting {
                if put.inserted {
                    let actual = writer.inventory_identity(inventory_limits)?;
                    return Err(batch_pending_diverged(&pending, anchored, actual));
                }
                continue;
            }

            replay_new += 1;
            if replay_new <= observed_new {
                if put.inserted {
                    let actual = writer.inventory_identity(inventory_limits)?;
                    return Err(batch_pending_diverged(&pending, anchored, actual));
                }
                continue;
            }

            let expected_after = entry.after_inventory.ok_or_else(|| {
                SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch pending item {index} lost its intermediate inventory"
                ))
            })?;
            let actual = writer.inventory_identity(inventory_limits)?;
            if actual != expected_after {
                return Err(batch_pending_diverged(&pending, anchored, actual));
            }
        }

        let durable_actual = writer.inventory_identity(inventory_limits)?;
        if durable_actual != pending.successor.inventory {
            return Err(batch_pending_diverged(&pending, anchored, durable_actual));
        }
        write_state(root_fd, state_key, pending.successor, true)?;
        clear_batch_recovery_files(root_fd, pending.entries.len())?;
        Ok(pending.successor)
    }

    fn batch_pending_diverged(
        pending: &SnapshotStoreHeadBatchPendingIntent,
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    ) -> SnapshotStoreHeadStateError {
        SnapshotStoreHeadStateError::PendingStateDiverged {
            previous: Box::new(pending.previous),
            successor: Box::new(pending.successor),
            anchored,
            actual,
        }
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

    fn require_no_pending(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        let single = read_pending_optional(root_fd, state_key)?;
        let batch = read_batch_pending_optional(root_fd, state_key)?;
        match (single, batch) {
            (Some(_), Some(_)) => Err(SnapshotStoreHeadStateError::InvalidState(
                "single-object and batch pending publications coexist".to_owned(),
            )),
            (Some(pending), None) => Err(SnapshotStoreHeadStateError::RecoveryRequired {
                previous: pending.previous,
                successor: pending.successor,
            }),
            (None, Some(pending)) => Err(SnapshotStoreHeadStateError::RecoveryRequired {
                previous: pending.previous,
                successor: pending.successor,
            }),
            (None, None) => Ok(()),
        }
    }

    fn read_pending_optional(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
    ) -> Result<Option<SnapshotStoreHeadPendingIntent>, SnapshotStoreHeadStateError> {
        let name = CString::new(HEAD_PENDING_FILE).expect("fixed pending filename contains no NUL");
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
                phase: "open pending snapshot store head publication",
                source,
            });
        }
        let fd = OwnedFd(fd);
        let stat = require_regular_single_link(
            fd.raw(),
            "validate pending snapshot store head publication",
        )?;
        if stat.st_size != HEAD_PENDING_BYTES as libc::off_t {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "pending state file length {} does not equal {HEAD_PENDING_BYTES}",
                stat.st_size
            )));
        }
        let mut bytes = [0u8; HEAD_PENDING_BYTES];
        read_exact_pending(fd.raw(), &mut bytes)?;
        Ok(Some(decode_pending(&bytes, state_key)?))
    }

    fn read_batch_pending_optional(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
    ) -> Result<Option<SnapshotStoreHeadBatchPendingIntent>, SnapshotStoreHeadStateError> {
        let name =
            CString::new(HEAD_BATCH_PENDING_FILE).expect("fixed batch pending filename has no NUL");
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
                phase: "open batch pending snapshot store head publication",
                source,
            });
        }
        let fd = OwnedFd(fd);
        let stat = require_regular_single_link(
            fd.raw(),
            "validate batch pending snapshot store head publication",
        )?;
        if stat.st_size != HEAD_BATCH_PENDING_BYTES as libc::off_t {
            return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                "batch pending state file length {} does not equal {HEAD_BATCH_PENDING_BYTES}",
                stat.st_size
            )));
        }
        let mut bytes = [0u8; HEAD_BATCH_PENDING_BYTES];
        read_exact_named(
            fd.raw(),
            &mut bytes,
            "read batch pending snapshot store head publication",
            "batch pending snapshot store head publication ended early",
        )?;
        Ok(Some(decode_batch_pending(&bytes, state_key)?))
    }

    fn write_batch_pending(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
        pending: &SnapshotStoreHeadBatchPendingIntent,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        let name =
            CString::new(HEAD_BATCH_PENDING_FILE).expect("fixed batch pending filename has no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EEXIST) {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "batch pending store-head publication appeared while state lock was held"
                        .to_owned(),
                ));
            }
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "create batch pending snapshot store head publication",
                source,
            });
        }
        let fd = OwnedFd(fd);
        require_regular_single_link(
            fd.raw(),
            "validate batch pending snapshot store head publication",
        )?;
        let bytes = encode_batch_pending(pending, state_key);
        write_all_named(
            fd.raw(),
            &bytes,
            "write batch pending snapshot store head publication",
            "batch pending snapshot store head publication write made no progress",
        )?;
        if unsafe { libc::fsync(fd.raw()) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync batch pending snapshot store head publication",
                source: std::io::Error::last_os_error(),
            });
        }
        drop(fd);
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after batch pending publication",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn batch_stage_name(index: usize) -> CString {
        CString::new(format!("{HEAD_BATCH_STAGE_PREFIX}{index:02}"))
            .expect("fixed batch stage filename has no NUL")
    }

    fn write_batch_stages(
        root_fd: RawFd,
        request: &SnapshotStoreHeadBatchPublishRequest<'_>,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        for (index, item) in request.items.iter().enumerate() {
            let name = batch_stage_name(index);
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
            if fd < 0 {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "create durable batch recovery stage",
                    source: std::io::Error::last_os_error(),
                });
            }
            let fd = OwnedFd(fd);
            require_regular_single_link(fd.raw(), "validate durable batch recovery stage")?;
            write_all_named(
                fd.raw(),
                item.archive,
                "write durable batch recovery stage",
                "durable batch recovery stage write made no progress",
            )?;
            if unsafe { libc::fchmod(fd.raw(), 0o400) } != 0 {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "seal durable batch recovery stage read-only",
                    source: std::io::Error::last_os_error(),
                });
            }
            if unsafe { libc::fsync(fd.raw()) } != 0 {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "fsync durable batch recovery stage",
                    source: std::io::Error::last_os_error(),
                });
            }
        }
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after batch recovery staging",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn read_and_validate_batch_stages(
        root_fd: RawFd,
        pending: &SnapshotStoreHeadBatchPendingIntent,
        inventory_limits: SnapshotStoreAuditLimits,
    ) -> Result<Vec<Vec<u8>>, SnapshotStoreHeadStateError> {
        let mut total = 0u64;
        let mut staged = Vec::with_capacity(pending.entries.len());
        for (index, entry) in pending.entries.iter().enumerate() {
            total = total.checked_add(entry.archive_bytes).ok_or_else(|| {
                SnapshotStoreHeadStateError::InvalidState(
                    "batch staged archive-byte accounting overflow".to_owned(),
                )
            })?;
            if total > inventory_limits.max_total_archive_bytes
                || entry.archive_bytes > inventory_limits.archive.max_archive_bytes
            {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch pending item {index} exceeds recovery archive-byte budgets"
                )));
            }
            let name = batch_stage_name(index);
            let fd = unsafe {
                libc::openat(
                    root_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "open durable batch recovery stage",
                    source: std::io::Error::last_os_error(),
                });
            }
            let fd = OwnedFd(fd);
            let stat = require_regular_single_link(fd.raw(), "validate durable batch recovery stage")?;
            if stat.st_size < 0
                || stat.st_size as u64 != entry.archive_bytes
                || (stat.st_mode & 0o222) != 0
            {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch recovery stage {index} has unexpected shape, writability, or length"
                )));
            }
            let size = usize::try_from(entry.archive_bytes).map_err(|_| {
                SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch recovery stage {index} length does not fit usize"
                ))
            })?;
            let mut archive = Vec::new();
            archive.try_reserve_exact(size).map_err(|_| {
                SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch recovery stage {index} allocation failed"
                ))
            })?;
            archive.resize(size, 0);
            read_exact_named(
                fd.raw(),
                &mut archive,
                "read durable batch recovery stage",
                "durable batch recovery stage ended early",
            )?;
            let identity = validate_snapshot_archive_ed25519(
                &archive,
                &entry.public_key,
                &entry.signature,
                inventory_limits.archive,
            )
            .map_err(|source| {
                SnapshotStoreHeadStateError::Transaction(Box::new(
                    SnapshotStoreTransactionError::Store(source),
                ))
            })?;
            if identity != entry.identity {
                return Err(SnapshotStoreHeadStateError::InvalidState(format!(
                    "batch recovery stage {index} canonical identity changed"
                )));
            }
            staged.push(archive);
        }
        Ok(staged)
    }

    fn clear_batch_recovery_files(
        root_fd: RawFd,
        count: usize,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        for index in 0..count {
            let name = batch_stage_name(index);
            if unsafe { libc::unlinkat(root_fd, name.as_ptr(), 0) } != 0 {
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() != Some(libc::ENOENT) {
                    return Err(SnapshotStoreHeadStateError::Io {
                        phase: "remove completed batch recovery stage",
                        source,
                    });
                }
            }
        }
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after batch stage removal",
                source: std::io::Error::last_os_error(),
            });
        }

        let name =
            CString::new(HEAD_BATCH_PENDING_FILE).expect("fixed batch pending filename has no NUL");
        if unsafe { libc::unlinkat(root_fd, name.as_ptr(), 0) } != 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() != Some(libc::ENOENT) {
                return Err(SnapshotStoreHeadStateError::Io {
                    phase: "remove completed batch pending publication",
                    source,
                });
            }
        }
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after batch pending removal",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn write_pending(
        root_fd: RawFd,
        state_key: &SnapshotStoreHeadStateKey,
        pending: SnapshotStoreHeadPendingIntent,
    ) -> Result<(), SnapshotStoreHeadStateError> {
        let name = CString::new(HEAD_PENDING_FILE).expect("fixed pending filename contains no NUL");
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            let source = std::io::Error::last_os_error();
            if source.raw_os_error() == Some(libc::EEXIST) {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "pending store-head publication appeared while state lock was held".to_owned(),
                ));
            }
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "create pending snapshot store head publication",
                source,
            });
        }
        let fd = OwnedFd(fd);
        require_regular_single_link(fd.raw(), "validate pending snapshot store head publication")?;
        let bytes = encode_pending(pending, state_key);
        if let Err(error) = write_all_pending(fd.raw(), &bytes) {
            unsafe {
                libc::unlinkat(root_fd, name.as_ptr(), 0);
            }
            return Err(error);
        }
        if unsafe { libc::fsync(fd.raw()) } != 0 {
            let source = std::io::Error::last_os_error();
            unsafe {
                libc::unlinkat(root_fd, name.as_ptr(), 0);
            }
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync pending snapshot store head publication",
                source,
            });
        }
        drop(fd);
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after pending publication",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn clear_pending(root_fd: RawFd) -> Result<(), SnapshotStoreHeadStateError> {
        let name = CString::new(HEAD_PENDING_FILE).expect("fixed pending filename contains no NUL");
        if unsafe { libc::unlinkat(root_fd, name.as_ptr(), 0) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "remove completed snapshot store head pending publication",
                source: std::io::Error::last_os_error(),
            });
        }
        if unsafe { libc::fsync(root_fd) } != 0 {
            return Err(SnapshotStoreHeadStateError::Io {
                phase: "fsync head-state directory after pending removal",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn lock_state(
        state_root: &Path,
        operation: libc::c_int,
    ) -> Result<StateGuard, SnapshotStoreHeadStateError> {
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

        let state_name =
            CString::new(HEAD_STATE_FILE).expect("fixed state filename contains no NUL");
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
                require_regular_single_link(
                    fd.raw(),
                    "validate temporary snapshot store head state",
                )?;
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

    fn read_exact_named(
        fd: RawFd,
        bytes: &mut [u8],
        phase: &'static str,
        eof_message: &'static str,
    ) -> Result<(), SnapshotStoreHeadStateError> {
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
                return Err(SnapshotStoreHeadStateError::Io { phase, source });
            }
            if read == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    eof_message.to_owned(),
                ));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn write_all_named(
        fd: RawFd,
        bytes: &[u8],
        phase: &'static str,
        zero_message: &'static str,
    ) -> Result<(), SnapshotStoreHeadStateError> {
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
                return Err(SnapshotStoreHeadStateError::Io { phase, source });
            }
            if written == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    zero_message.to_owned(),
                ));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn read_exact_pending(fd: RawFd, bytes: &mut [u8]) -> Result<(), SnapshotStoreHeadStateError> {
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
                    phase: "read pending snapshot store head publication",
                    source,
                });
            }
            if read == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "pending snapshot store head publication ended early".to_owned(),
                ));
            }
            offset += read as usize;
        }
        Ok(())
    }

    fn write_all_pending(fd: RawFd, bytes: &[u8]) -> Result<(), SnapshotStoreHeadStateError> {
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
                    phase: "write pending snapshot store head publication",
                    source,
                });
            }
            if written == 0 {
                return Err(SnapshotStoreHeadStateError::InvalidState(
                    "pending snapshot store head publication write made no progress".to_owned(),
                ));
            }
            offset += written as usize;
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
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| SnapshotStoreHeadStateError::InvalidInput(format!("{label} contains NUL")))
    }
}
