use crate::snapshot_archive::{
    materialize_snapshot_archive_ed25519_atomic, snapshot_archive_identity, SnapshotArchiveError,
    SnapshotArchiveLimits,
};
use crate::snapshot_identity::{
    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,
};
use crate::snapshot_signature::{
    verify_snapshot_identity_ed25519, SnapshotEd25519Error, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES,
    SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotStorePublishDisposition {
    Published,
    Reused,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStorePublishReport {
    pub identity: SnapshotIdentity,
    pub disposition: SnapshotStorePublishDisposition,
    pub version_path: PathBuf,
}

#[derive(Debug)]
pub enum SnapshotStoreError {
    InvalidInput(String),
    Archive(SnapshotArchiveError),
    Signature(SnapshotEd25519Error),
    Identity(SnapshotIdentityError),
    ExistingVersionInvalid(String),
    ExistingVersionMismatch {
        expected: SnapshotIdentity,
        actual: SnapshotIdentity,
    },
    Io {
        phase: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for SnapshotStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid snapshot store input: {message}"),
            Self::Archive(source) => write!(f, "snapshot store archive failed: {source}"),
            Self::Signature(source) => write!(f, "snapshot store signature failed: {source}"),
            Self::Identity(source) => write!(f, "snapshot store identity failed: {source}"),
            Self::ExistingVersionInvalid(message) => {
                write!(f, "snapshot store existing version is invalid: {message}")
            }
            Self::ExistingVersionMismatch { expected, actual } => write!(
                f,
                "snapshot store existing version identity mismatch: expected={} bytes={} nodes={} actual={} bytes={} nodes={}",
                expected.sha256_hex(),
                expected.encoded_bytes,
                expected.nodes,
                actual.sha256_hex(),
                actual.encoded_bytes,
                actual.nodes
            ),
            Self::Io { phase, source } => {
                write!(f, "snapshot store failed during {phase}: {source}")
            }
        }
    }
}

impl Error for SnapshotStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Archive(source) => Some(source),
            Self::Signature(source) => Some(source),
            Self::Identity(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::InvalidInput(_)
            | Self::ExistingVersionInvalid(_)
            | Self::ExistingVersionMismatch { .. } => None,
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

impl From<SnapshotIdentityError> for SnapshotStoreError {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}

/// Publish one strictly verified frozen snapshot archive into a content-addressed
/// version directory under an existing trusted store root.
///
/// The archive is fully validated and its canonical Milestone 33A identity is
/// strictly verified under the exact caller-supplied Ed25519 public key/signature
/// before the store path is inspected. The version directory name is the fixed
/// lowercase hexadecimal SHA-256 digest of that identity.
///
/// If the version does not yet exist, publication reuses the Milestone 39A
/// verification-before-staging path and Milestone 38A failure-atomic
/// `renameat2(RENAME_NOREPLACE)` publication. If it already exists, the existing
/// directory is re-hashed and is reusable only when the complete canonical
/// identity (digest, encoded byte count, and node count) matches exactly.
///
/// The store root and version directory are expected to remain stable while this
/// function executes. This slice does not claim alias-proof or hostile-concurrent-
/// writer pinning, host immutability, or fsync-backed crash durability.
pub fn publish_snapshot_archive_ed25519_version(
    archive: &[u8],
    store_root: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotStorePublishReport, SnapshotStoreError> {
    let identity = snapshot_archive_identity(archive, limits)?;
    verify_snapshot_identity_ed25519(identity, public_key, expected_signature)?;

    if !store_root.is_absolute() {
        return Err(SnapshotStoreError::InvalidInput(
            "store root must be an absolute host path".to_owned(),
        ));
    }
    let store_metadata = fs::symlink_metadata(store_root)
        .map_err(|source| io_error("inspect snapshot store root", source))?;
    if !store_metadata.file_type().is_dir() {
        return Err(SnapshotStoreError::InvalidInput(
            "store root must be an existing non-symlink directory".to_owned(),
        ));
    }

    let version_path = store_root.join(identity.sha256_hex());
    match fs::symlink_metadata(&version_path) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() {
                return Err(SnapshotStoreError::ExistingVersionInvalid(
                    "content-addressed version path must be a non-symlink directory".to_owned(),
                ));
            }
            let actual = snapshot_sha256(&version_path, identity_limits(limits))?;
            if actual != identity {
                return Err(SnapshotStoreError::ExistingVersionMismatch {
                    expected: identity,
                    actual,
                });
            }
            Ok(SnapshotStorePublishReport {
                identity,
                disposition: SnapshotStorePublishDisposition::Reused,
                version_path,
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let published = materialize_snapshot_archive_ed25519_atomic(
                archive,
                &version_path,
                public_key,
                expected_signature,
                limits,
            )?;
            if published.identity != identity {
                return Err(SnapshotStoreError::Archive(
                    SnapshotArchiveError::InvalidInput(
                        "verified materializer returned an unexpected canonical identity".to_owned(),
                    ),
                ));
            }
            Ok(SnapshotStorePublishReport {
                identity,
                disposition: SnapshotStorePublishDisposition::Published,
                version_path,
            })
        }
        Err(source) => Err(io_error("inspect content-addressed version", source)),
    }
}

fn identity_limits(limits: SnapshotArchiveLimits) -> SnapshotIdentityLimits {
    SnapshotIdentityLimits {
        max_bytes: limits.max_identity_bytes,
        max_nodes: limits.max_nodes,
    }
}

fn io_error(phase: &'static str, source: io::Error) -> SnapshotStoreError {
    SnapshotStoreError::Io { phase, source }
}
