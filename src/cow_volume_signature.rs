use crate::{
    publish_cow_volume_diff_atomic, CowDiffApplyLimits, CowDiffEntry, CowVolumeDiff,
    CowVolumePublicationError, CowVolumePublicationReport, SnapshotTrustDecision,
    SnapshotTrustError, SnapshotTrustKeyId, SnapshotTrustPolicy, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES,
    SNAPSHOT_ED25519_SIGNATURE_BYTES, SNAPSHOT_ED25519_SIGNING_KEY_BYTES,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::path::Path;

const COW_VOLUME_EVIDENCE_DOMAIN: &[u8] = b"security-lab-cow-volume-publication-evidence-v1\0";
const COW_VOLUME_SIGNATURE_DOMAIN: &[u8] = b"security-lab-cow-volume-publication-ed25519-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowVolumeEd25519Signature {
    pub evidence_sha256: [u8; 32],
    pub public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub signature: [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
}

#[derive(Debug)]
pub enum CowVolumeEd25519Error {
    UnboundDiff,
    IncompleteBinding,
    InvalidPublicKey,
    EvidenceDigestMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    VerificationFailed,
}

impl fmt::Display for CowVolumeEd25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnboundDiff => f.write_str(
                "COW volume Ed25519 evidence requires a launch-time base identity binding",
            ),
            Self::IncompleteBinding => {
                f.write_str("COW volume Ed25519 evidence has inconsistent base identity evidence")
            }
            Self::InvalidPublicKey => f.write_str("COW volume Ed25519 public key is invalid"),
            Self::EvidenceDigestMismatch { .. } => {
                f.write_str("COW volume Ed25519 evidence digest does not match the report")
            }
            Self::VerificationFailed => f.write_str("COW volume Ed25519 verification failed"),
        }
    }
}

impl Error for CowVolumeEd25519Error {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CowVolumeTrustedPublicationReport {
    pub publication: CowVolumePublicationReport,
    pub trust: SnapshotTrustDecision,
    pub evidence_sha256: [u8; 32],
}

#[derive(Debug)]
pub enum CowVolumeTrustedPublicationError {
    Trust(SnapshotTrustError),
    Signature(CowVolumeEd25519Error),
    Publication(CowVolumePublicationError),
}

impl fmt::Display for CowVolumeTrustedPublicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trust(source) => write!(f, "trusted COW publication signer rejected: {source}"),
            Self::Signature(source) => {
                write!(f, "trusted COW publication signature rejected: {source}")
            }
            Self::Publication(source) => write!(f, "trusted COW publication failed: {source}"),
        }
    }
}

impl Error for CowVolumeTrustedPublicationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Trust(source) => Some(source),
            Self::Signature(source) => Some(source),
            Self::Publication(source) => Some(source),
        }
    }
}

impl From<SnapshotTrustError> for CowVolumeTrustedPublicationError {
    fn from(source: SnapshotTrustError) -> Self {
        Self::Trust(source)
    }
}

impl From<CowVolumeEd25519Error> for CowVolumeTrustedPublicationError {
    fn from(source: CowVolumeEd25519Error) -> Self {
        Self::Signature(source)
    }
}

impl From<CowVolumePublicationError> for CowVolumeTrustedPublicationError {
    fn from(source: CowVolumePublicationError) -> Self {
        Self::Publication(source)
    }
}

/// Sign the complete guarded COW publication evidence under one caller-supplied
/// Ed25519 signing seed.
///
/// The signed evidence commits to exact source and sandbox-target pathname
/// bytes, launch-time canonical base identity and its limits, the reported
/// canonical diff accounting, and every diff entry including paths, modes,
/// file bytes, symlink targets, removals, and opaque-directory records.
pub fn sign_cow_volume_diff_ed25519(
    volume_diff: &CowVolumeDiff,
    signing_key: &[u8; SNAPSHOT_ED25519_SIGNING_KEY_BYTES],
) -> Result<CowVolumeEd25519Signature, CowVolumeEd25519Error> {
    let evidence_sha256 = cow_volume_evidence_sha256(volume_diff)?;
    let signing_key = SigningKey::from_bytes(signing_key);
    let signature = signing_key
        .sign(&signature_message(evidence_sha256))
        .to_bytes();
    Ok(CowVolumeEd25519Signature {
        evidence_sha256,
        public_key: signing_key.verifying_key().to_bytes(),
        signature,
    })
}

/// Strictly verify that one Ed25519 signature authenticates the exact guarded
/// COW publication evidence supplied by `volume_diff`.
pub fn verify_cow_volume_diff_ed25519(
    volume_diff: &CowVolumeDiff,
    evidence: &CowVolumeEd25519Signature,
) -> Result<[u8; 32], CowVolumeEd25519Error> {
    let actual = cow_volume_evidence_sha256(volume_diff)?;
    if actual != evidence.evidence_sha256 {
        return Err(CowVolumeEd25519Error::EvidenceDigestMismatch {
            expected: evidence.evidence_sha256,
            actual,
        });
    }
    let verifying_key = VerifyingKey::from_bytes(&evidence.public_key)
        .map_err(|_| CowVolumeEd25519Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(&evidence.signature);
    verifying_key
        .verify_strict(&signature_message(actual), &signature)
        .map_err(|_| CowVolumeEd25519Error::VerificationFailed)?;
    Ok(actual)
}

/// Resolve the signer through an explicit bounded trust policy, strictly verify
/// the exact COW publication evidence, and only then enter the 76A guarded
/// publication path.
///
/// Unknown or revoked signers and signature failures happen before base or
/// destination filesystem inspection. A successful signature does not replace
/// 76A's source-path, current-base, materialized-base, replay, or no-replace
/// publication gates.
pub fn publish_cow_volume_diff_trusted_ed25519_atomic(
    base: &Path,
    destination: &Path,
    volume_diff: &CowVolumeDiff,
    evidence: &CowVolumeEd25519Signature,
    trust_policy: &SnapshotTrustPolicy,
    signer: SnapshotTrustKeyId,
    replay_limits: CowDiffApplyLimits,
) -> Result<CowVolumeTrustedPublicationReport, CowVolumeTrustedPublicationError> {
    let trusted_public_key = trust_policy.resolve_active(signer)?;
    if trusted_public_key != &evidence.public_key {
        return Err(CowVolumeEd25519Error::VerificationFailed.into());
    }
    let evidence_sha256 = verify_cow_volume_diff_ed25519(volume_diff, evidence)?;
    let publication =
        publish_cow_volume_diff_atomic(base, destination, volume_diff, replay_limits)?;
    Ok(CowVolumeTrustedPublicationReport {
        publication,
        trust: SnapshotTrustDecision {
            policy: trust_policy.identity(),
            signer,
        },
        evidence_sha256,
    })
}

fn cow_volume_evidence_sha256(
    volume_diff: &CowVolumeDiff,
) -> Result<[u8; 32], CowVolumeEd25519Error> {
    let (base_identity, limits) =
        match (volume_diff.base_identity, volume_diff.base_identity_limits) {
            (Some(identity), Some(limits)) => (identity, limits),
            (None, None) => return Err(CowVolumeEd25519Error::UnboundDiff),
            _ => return Err(CowVolumeEd25519Error::IncompleteBinding),
        };

    let mut hasher = Sha256::new();
    hasher.update(COW_VOLUME_EVIDENCE_DOMAIN);
    hash_bytes(&mut hasher, &volume_diff.source);
    hash_bytes(&mut hasher, &volume_diff.target);
    hasher.update(base_identity.sha256);
    hasher.update(base_identity.encoded_bytes.to_le_bytes());
    hasher.update(base_identity.nodes.to_le_bytes());
    hasher.update(limits.max_bytes.to_le_bytes());
    hasher.update(limits.max_nodes.to_le_bytes());
    hasher.update(volume_diff.diff.encoded_bytes.to_le_bytes());
    hasher.update((volume_diff.diff.entries.len() as u64).to_le_bytes());

    for entry in &volume_diff.diff.entries {
        match entry {
            CowDiffEntry::UpsertFile { path, mode, bytes } => {
                hasher.update([1]);
                hash_bytes(&mut hasher, path);
                hasher.update(mode.to_le_bytes());
                hash_bytes(&mut hasher, bytes);
            }
            CowDiffEntry::EnsureDirectory { path, mode } => {
                hasher.update([2]);
                hash_bytes(&mut hasher, path);
                hasher.update(mode.to_le_bytes());
            }
            CowDiffEntry::Symlink { path, target } => {
                hasher.update([3]);
                hash_bytes(&mut hasher, path);
                hash_bytes(&mut hasher, target);
            }
            CowDiffEntry::Remove { path } => {
                hasher.update([4]);
                hash_bytes(&mut hasher, path);
            }
            CowDiffEntry::OpaqueDirectory { path } => {
                hasher.update([5]);
                hash_bytes(&mut hasher, path);
            }
        }
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn signature_message(evidence_sha256: [u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(COW_VOLUME_SIGNATURE_DOMAIN.len() + 32);
    message.extend_from_slice(COW_VOLUME_SIGNATURE_DOMAIN);
    message.extend_from_slice(&evidence_sha256);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CowDiff, SnapshotIdentity, SnapshotIdentityLimits, SnapshotTrustKey, SnapshotTrustKeyState,
    };

    fn bound_diff() -> CowVolumeDiff {
        CowVolumeDiff {
            source: b"/host/source".to_vec(),
            target: b"/sandbox/state".to_vec(),
            base_identity: Some(SnapshotIdentity {
                sha256: [0x11; 32],
                encoded_bytes: 123,
                nodes: 4,
            }),
            base_identity_limits: Some(SnapshotIdentityLimits {
                max_bytes: 4096,
                max_nodes: 32,
            }),
            diff: CowDiff {
                entries: vec![
                    CowDiffEntry::EnsureDirectory {
                        path: b"/nested".to_vec(),
                        mode: 0o750,
                    },
                    CowDiffEntry::UpsertFile {
                        path: b"/nested/value".to_vec(),
                        mode: 0o640,
                        bytes: b"payload\n".to_vec(),
                    },
                    CowDiffEntry::Symlink {
                        path: b"/link".to_vec(),
                        target: b"nested/value".to_vec(),
                    },
                    CowDiffEntry::Remove {
                        path: b"/old".to_vec(),
                    },
                    CowDiffEntry::OpaqueDirectory {
                        path: b"/opaque".to_vec(),
                    },
                ],
                encoded_bytes: 321,
            },
        }
    }

    #[test]
    fn exact_bound_evidence_verifies_and_field_mutation_fails() {
        let seed = [0x51; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
        let original = bound_diff();
        let evidence = sign_cow_volume_diff_ed25519(&original, &seed).unwrap();
        assert_eq!(
            verify_cow_volume_diff_ed25519(&original, &evidence).unwrap(),
            evidence.evidence_sha256
        );

        let mut mutations = Vec::new();

        let mut changed = original.clone();
        changed.source.push(b'x');
        mutations.push(changed);

        let mut changed = original.clone();
        changed.target.push(b'x');
        mutations.push(changed);

        let mut changed = original.clone();
        changed.base_identity.as_mut().unwrap().sha256[0] ^= 1;
        mutations.push(changed);

        let mut changed = original.clone();
        changed.base_identity_limits.as_mut().unwrap().max_nodes += 1;
        mutations.push(changed);

        let mut changed = original.clone();
        changed.diff.encoded_bytes += 1;
        mutations.push(changed);

        let mut changed = original.clone();
        match &mut changed.diff.entries[1] {
            CowDiffEntry::UpsertFile { bytes, .. } => bytes.push(b'x'),
            _ => unreachable!(),
        }
        mutations.push(changed);

        for changed in mutations {
            assert!(matches!(
                verify_cow_volume_diff_ed25519(&changed, &evidence),
                Err(CowVolumeEd25519Error::EvidenceDigestMismatch { .. })
            ));
        }
    }

    #[test]
    fn unbound_or_incomplete_report_cannot_be_signed() {
        let seed = [0x52; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
        let mut diff = bound_diff();
        diff.base_identity = None;
        diff.base_identity_limits = None;
        assert!(matches!(
            sign_cow_volume_diff_ed25519(&diff, &seed),
            Err(CowVolumeEd25519Error::UnboundDiff)
        ));

        diff.base_identity = Some(SnapshotIdentity {
            sha256: [0x22; 32],
            encoded_bytes: 1,
            nodes: 1,
        });
        assert!(matches!(
            sign_cow_volume_diff_ed25519(&diff, &seed),
            Err(CowVolumeEd25519Error::IncompleteBinding)
        ));
    }

    #[test]
    fn trust_policy_rejects_revoked_signer_before_publication() {
        let seed = [0x53; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
        let evidence = sign_cow_volume_diff_ed25519(&bound_diff(), &seed).unwrap();
        let signer = SnapshotTrustKeyId::from_public_key(&evidence.public_key);
        let policy = SnapshotTrustPolicy::new(
            1,
            vec![SnapshotTrustKey {
                public_key: evidence.public_key,
                state: SnapshotTrustKeyState::Revoked,
            }],
        )
        .unwrap();

        let error = publish_cow_volume_diff_trusted_ed25519_atomic(
            Path::new("/definitely/not/inspected"),
            Path::new("/also/not/inspected"),
            &bound_diff(),
            &evidence,
            &policy,
            signer,
            CowDiffApplyLimits {
                max_bytes: 4096,
                max_nodes: 32,
            },
        )
        .unwrap_err();
        assert!(matches!(
            error,
            CowVolumeTrustedPublicationError::Trust(SnapshotTrustError::RevokedSigner { .. })
        ));
    }
}
