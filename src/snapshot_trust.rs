use crate::snapshot_archive::{SnapshotArchiveLimits, SnapshotArchiveMaterializeReport};
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_store::{
    materialize_snapshot_store_object_ed25519_atomic, SnapshotStoreError, SnapshotStorePutReport,
};
use crate::snapshot_store_durable::store_snapshot_archive_ed25519_durable;
use crate::SnapshotIdentity;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::path::Path;

const SNAPSHOT_TRUST_KEY_DOMAIN: &[u8] = b"security-lab-snapshot-trust-key-v1\0";
const SNAPSHOT_TRUST_POLICY_DOMAIN: &[u8] = b"security-lab-snapshot-trust-policy-v1\0";
pub const SNAPSHOT_TRUST_MAX_KEYS: usize = 64;

/// Stable domain-separated identity for one Ed25519 verifying key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SnapshotTrustKeyId([u8; 32]);

impl SnapshotTrustKeyId {
    pub fn from_public_key(public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(SNAPSHOT_TRUST_KEY_DOMAIN);
        hasher.update(public_key);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex_bytes(&self.0)
    }
}

impl fmt::Display for SnapshotTrustKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lifecycle state of one key inside one explicit trust-policy snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotTrustKeyState {
    Active,
    Revoked,
}

impl SnapshotTrustKeyState {
    fn tag(self) -> u8 {
        match self {
            Self::Active => 1,
            Self::Revoked => 2,
        }
    }
}

/// One Ed25519 public key plus its explicit lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustKey {
    pub public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub state: SnapshotTrustKeyState,
}

impl SnapshotTrustKey {
    pub fn active(public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self {
            public_key,
            state: SnapshotTrustKeyState::Active,
        }
    }

    pub fn revoked(public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES]) -> Self {
        Self {
            public_key,
            state: SnapshotTrustKeyState::Revoked,
        }
    }

    pub fn key_id(&self) -> SnapshotTrustKeyId {
        SnapshotTrustKeyId::from_public_key(&self.public_key)
    }
}

/// Deterministic identity for an exact trust-policy generation and key-state set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustPolicyIdentity {
    pub generation: u64,
    pub sha256: [u8; 32],
    pub keys: u32,
}

impl SnapshotTrustPolicyIdentity {
    pub fn sha256_hex(&self) -> String {
        hex_bytes(&self.sha256)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SnapshotTrustRecord {
    id: SnapshotTrustKeyId,
    key: SnapshotTrustKey,
}

/// Bounded explicit signer policy for authenticated snapshot operations.
///
/// `generation` and the complete sorted key/state set are hashed into a
/// deterministic policy identity. Rotation keeps old keys and can move them to
/// `Revoked` while adding new active keys. This object does not persist or
/// authenticate itself and therefore does not provide anti-rollback: callers
/// remain responsible for choosing the policy snapshot they trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotTrustPolicy {
    generation: u64,
    records: Vec<SnapshotTrustRecord>,
    identity: SnapshotTrustPolicyIdentity,
}

impl SnapshotTrustPolicy {
    pub fn new(
        generation: u64,
        keys: Vec<SnapshotTrustKey>,
    ) -> Result<Self, SnapshotTrustError> {
        if generation == 0 {
            return Err(SnapshotTrustError::InvalidGeneration);
        }
        if keys.is_empty() {
            return Err(SnapshotTrustError::EmptyPolicy);
        }
        if keys.len() > SNAPSHOT_TRUST_MAX_KEYS {
            return Err(SnapshotTrustError::TooManyKeys {
                limit: SNAPSHOT_TRUST_MAX_KEYS,
                attempted: keys.len(),
            });
        }

        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            let id = key.key_id();
            VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| SnapshotTrustError::InvalidPublicKey { key_id: id })?;
            records.push(SnapshotTrustRecord { id, key });
        }
        records.sort_by_key(|record| record.id);
        for pair in records.windows(2) {
            if pair[0].id == pair[1].id {
                return Err(SnapshotTrustError::DuplicateKey {
                    key_id: pair[0].id,
                });
            }
        }

        let identity = policy_identity(generation, &records);
        Ok(Self {
            generation,
            records,
            identity,
        })
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn identity(&self) -> SnapshotTrustPolicyIdentity {
        self.identity
    }

    pub fn key_state(&self, key_id: SnapshotTrustKeyId) -> Option<SnapshotTrustKeyState> {
        self.find_record(key_id).map(|record| record.key.state)
    }

    /// Produce a later policy generation by revoking known keys and adding new
    /// active keys. Revoked keys cannot be reactivated through this transition.
    ///
    /// The generation must strictly increase, but no persistent monotonic state
    /// is claimed: a caller could still supply an older policy object later.
    pub fn rotate(
        &self,
        next_generation: u64,
        new_active_keys: Vec<[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES]>,
        revoke: &[SnapshotTrustKeyId],
    ) -> Result<Self, SnapshotTrustError> {
        if next_generation <= self.generation {
            return Err(SnapshotTrustError::NonAdvancingGeneration {
                current: self.generation,
                requested: next_generation,
            });
        }

        let mut keys: Vec<SnapshotTrustKey> =
            self.records.iter().map(|record| record.key).collect();
        for key_id in revoke {
            let record = self
                .records
                .iter()
                .find(|record| record.id == *key_id)
                .ok_or(SnapshotTrustError::UnknownRevocation { key_id: *key_id })?;
            let slot = keys
                .iter_mut()
                .find(|key| key.public_key == record.key.public_key)
                .expect("rotation keys are cloned from policy records");
            slot.state = SnapshotTrustKeyState::Revoked;
        }

        for public_key in new_active_keys {
            let id = SnapshotTrustKeyId::from_public_key(&public_key);
            if let Some(existing) = self.find_record(id) {
                return Err(match existing.key.state {
                    SnapshotTrustKeyState::Active => SnapshotTrustError::DuplicateKey { key_id: id },
                    SnapshotTrustKeyState::Revoked => {
                        SnapshotTrustError::RevokedKeyReactivation { key_id: id }
                    }
                });
            }
            keys.push(SnapshotTrustKey::active(public_key));
        }

        Self::new(next_generation, keys)
    }

    fn resolve_active(
        &self,
        signer: SnapshotTrustKeyId,
    ) -> Result<&[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES], SnapshotTrustError> {
        let record = self
            .find_record(signer)
            .ok_or(SnapshotTrustError::UnknownSigner { key_id: signer })?;
        match record.key.state {
            SnapshotTrustKeyState::Active => Ok(&record.key.public_key),
            SnapshotTrustKeyState::Revoked => {
                Err(SnapshotTrustError::RevokedSigner { key_id: signer })
            }
        }
    }

    fn find_record(&self, key_id: SnapshotTrustKeyId) -> Option<&SnapshotTrustRecord> {
        self.records
            .binary_search_by_key(&key_id, |record| record.id)
            .ok()
            .map(|index| &self.records[index])
    }
}

/// Auditable trust decision attached to a successful operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustDecision {
    pub policy: SnapshotTrustPolicyIdentity,
    pub signer: SnapshotTrustKeyId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustedStorePutReport {
    pub store: SnapshotStorePutReport,
    pub trust: SnapshotTrustDecision,
}

#[derive(Debug)]
pub struct SnapshotTrustedMaterializeReport {
    pub materialization: SnapshotArchiveMaterializeReport,
    pub trust: SnapshotTrustDecision,
}

#[derive(Debug)]
pub enum SnapshotTrustError {
    InvalidGeneration,
    NonAdvancingGeneration { current: u64, requested: u64 },
    EmptyPolicy,
    TooManyKeys { limit: usize, attempted: usize },
    InvalidPublicKey { key_id: SnapshotTrustKeyId },
    DuplicateKey { key_id: SnapshotTrustKeyId },
    UnknownRevocation { key_id: SnapshotTrustKeyId },
    RevokedKeyReactivation { key_id: SnapshotTrustKeyId },
    UnknownSigner { key_id: SnapshotTrustKeyId },
    RevokedSigner { key_id: SnapshotTrustKeyId },
    Store(SnapshotStoreError),
}

impl fmt::Display for SnapshotTrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGeneration => f.write_str("snapshot trust generation must be non-zero"),
            Self::NonAdvancingGeneration { current, requested } => write!(
                f,
                "snapshot trust rotation must advance generation beyond {current}, got {requested}"
            ),
            Self::EmptyPolicy => f.write_str("snapshot trust policy must contain at least one key"),
            Self::TooManyKeys { limit, attempted } => write!(
                f,
                "snapshot trust policy key count {attempted} exceeds limit {limit}"
            ),
            Self::InvalidPublicKey { key_id } => {
                write!(f, "snapshot trust key {key_id} is not a valid Ed25519 public key")
            }
            Self::DuplicateKey { key_id } => {
                write!(f, "snapshot trust policy contains duplicate key {key_id}")
            }
            Self::UnknownRevocation { key_id } => {
                write!(f, "snapshot trust rotation cannot revoke unknown key {key_id}")
            }
            Self::RevokedKeyReactivation { key_id } => write!(
                f,
                "snapshot trust rotation cannot reactivate revoked key {key_id}"
            ),
            Self::UnknownSigner { key_id } => {
                write!(f, "snapshot signer {key_id} is not trusted by this policy")
            }
            Self::RevokedSigner { key_id } => {
                write!(f, "snapshot signer {key_id} is revoked by this policy")
            }
            Self::Store(source) => write!(f, "trusted snapshot store operation failed: {source}"),
        }
    }
}

impl Error for SnapshotTrustError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Store(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotStoreError> for SnapshotTrustError {
    fn from(value: SnapshotStoreError) -> Self {
        Self::Store(value)
    }
}

/// Resolve an active signer through the explicit trust policy before touching
/// the store, then reuse the authenticated durable publication path.
pub fn store_snapshot_archive_trusted_ed25519_durable(
    store_root: &Path,
    archive: &[u8],
    trust_policy: &SnapshotTrustPolicy,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedStorePutReport, SnapshotTrustError> {
    let public_key = trust_policy.resolve_active(signer)?;
    let store = store_snapshot_archive_ed25519_durable(
        store_root,
        archive,
        public_key,
        expected_signature,
        limits,
    )?;
    Ok(SnapshotTrustedStorePutReport {
        store,
        trust: SnapshotTrustDecision {
            policy: trust_policy.identity(),
            signer,
        },
    })
}

/// Resolve an active signer before store-object inspection, then reuse the
/// identity re-derivation, strict Ed25519 verification, and atomic materializer.
pub fn materialize_snapshot_store_object_trusted_ed25519_atomic(
    store_root: &Path,
    identity: SnapshotIdentity,
    destination: &Path,
    trust_policy: &SnapshotTrustPolicy,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedMaterializeReport, SnapshotTrustError> {
    let public_key = trust_policy.resolve_active(signer)?;
    let materialization = materialize_snapshot_store_object_ed25519_atomic(
        store_root,
        identity,
        destination,
        public_key,
        expected_signature,
        limits,
    )?;
    Ok(SnapshotTrustedMaterializeReport {
        materialization,
        trust: SnapshotTrustDecision {
            policy: trust_policy.identity(),
            signer,
        },
    })
}

fn policy_identity(
    generation: u64,
    records: &[SnapshotTrustRecord],
) -> SnapshotTrustPolicyIdentity {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_TRUST_POLICY_DOMAIN);
    hasher.update(generation.to_le_bytes());
    hasher.update((records.len() as u32).to_le_bytes());
    for record in records {
        hasher.update(record.id.as_bytes());
        hasher.update([record.key.state.tag()]);
        hasher.update(record.key.public_key);
    }
    let digest = hasher.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest);
    SnapshotTrustPolicyIdentity {
        generation,
        sha256,
        keys: records.len() as u32,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn public(seed: u8) -> [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES] {
        SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    #[test]
    fn policy_identity_is_order_independent_and_state_sensitive() {
        let a = public(0x11);
        let b = public(0x22);
        let first = SnapshotTrustPolicy::new(
            7,
            vec![SnapshotTrustKey::active(a), SnapshotTrustKey::revoked(b)],
        )
        .unwrap();
        let reordered = SnapshotTrustPolicy::new(
            7,
            vec![SnapshotTrustKey::revoked(b), SnapshotTrustKey::active(a)],
        )
        .unwrap();
        assert_eq!(first.identity(), reordered.identity());

        let different_state = SnapshotTrustPolicy::new(
            7,
            vec![SnapshotTrustKey::active(a), SnapshotTrustKey::active(b)],
        )
        .unwrap();
        assert_ne!(first.identity(), different_state.identity());

        let different_generation = SnapshotTrustPolicy::new(
            8,
            vec![SnapshotTrustKey::active(a), SnapshotTrustKey::revoked(b)],
        )
        .unwrap();
        assert_ne!(first.identity(), different_generation.identity());
    }

    #[test]
    fn rotation_revokes_old_key_adds_new_key_and_never_reactivates() {
        let a = public(0x31);
        let b = public(0x32);
        let a_id = SnapshotTrustKeyId::from_public_key(&a);
        let b_id = SnapshotTrustKeyId::from_public_key(&b);
        let first = SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(a)]).unwrap();
        let rotated = first.rotate(2, vec![b], &[a_id]).unwrap();
        assert_eq!(rotated.key_state(a_id), Some(SnapshotTrustKeyState::Revoked));
        assert_eq!(rotated.key_state(b_id), Some(SnapshotTrustKeyState::Active));
        assert!(matches!(
            rotated.resolve_active(a_id),
            Err(SnapshotTrustError::RevokedSigner { key_id }) if key_id == a_id
        ));
        assert!(rotated.resolve_active(b_id).is_ok());
        assert!(matches!(
            rotated.rotate(2, Vec::new(), &[]),
            Err(SnapshotTrustError::NonAdvancingGeneration { .. })
        ));
        assert!(matches!(
            rotated.rotate(3, vec![a], &[]),
            Err(SnapshotTrustError::RevokedKeyReactivation { key_id }) if key_id == a_id
        ));
    }

    #[test]
    fn duplicate_and_unknown_revocation_fail_closed() {
        let a = public(0x41);
        let a_id = SnapshotTrustKeyId::from_public_key(&a);
        assert!(matches!(
            SnapshotTrustPolicy::new(
                1,
                vec![SnapshotTrustKey::active(a), SnapshotTrustKey::revoked(a)]
            ),
            Err(SnapshotTrustError::DuplicateKey { key_id }) if key_id == a_id
        ));
        let policy = SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(a)]).unwrap();
        let unknown = SnapshotTrustKeyId::from_public_key(&public(0x42));
        assert!(matches!(
            policy.rotate(2, Vec::new(), &[unknown]),
            Err(SnapshotTrustError::UnknownRevocation { key_id }) if key_id == unknown
        ));
    }
}
