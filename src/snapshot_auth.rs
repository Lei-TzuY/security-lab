use crate::snapshot_identity::{snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::error::Error;
use std::fmt;
use std::path::Path;

const SNAPSHOT_HMAC_DOMAIN: &[u8] = b"security-lab-snapshot-hmac-sha256-v1\0";
pub const SNAPSHOT_HMAC_KEY_BYTES: usize = 32;

type HmacSha256 = Hmac<Sha256>;

/// Keyed authentication evidence for one canonical supported snapshot tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotHmac {
    /// Canonical snapshot identity authenticated by `tag`.
    pub snapshot: SnapshotIdentity,
    /// HMAC-SHA256 over a versioned domain plus the canonical identity fields.
    pub tag: [u8; 32],
}

impl SnapshotHmac {
    pub fn tag_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(64);
        for byte in self.tag {
            write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
        }
        text
    }
}

#[derive(Debug)]
pub enum SnapshotHmacError {
    Identity(SnapshotIdentityError),
    AuthenticationFailed,
}

impl fmt::Display for SnapshotHmacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(source) => write!(f, "snapshot HMAC identity failed: {source}"),
            Self::AuthenticationFailed => f.write_str("snapshot HMAC authentication failed"),
        }
    }
}

impl Error for SnapshotHmacError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::AuthenticationFailed => None,
        }
    }
}

impl From<SnapshotIdentityError> for SnapshotHmacError {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}

/// Compute keyed HMAC-SHA256 authentication evidence for the canonical snapshot
/// identity of `root`.
///
/// The 32-byte key is supplied by the trusted caller and is never stored by the
/// library. The tag authenticates the existing versioned canonical SHA-256
/// identity plus its byte/node accounting under a separate versioned HMAC
/// domain. This is symmetric key-possession evidence, not a digital signature or
/// public provenance statement.
pub fn snapshot_hmac_sha256(
    root: &Path,
    key: &[u8; SNAPSHOT_HMAC_KEY_BYTES],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotHmac, SnapshotHmacError> {
    let snapshot = snapshot_sha256(root, limits)?;
    let tag = tag_identity(key, snapshot);
    Ok(SnapshotHmac { snapshot, tag })
}

/// Recompute the canonical snapshot identity and authenticate it against
/// `expected_tag` using HMAC's constant-time tag verification path.
pub fn verify_snapshot_hmac_sha256(
    root: &Path,
    key: &[u8; SNAPSHOT_HMAC_KEY_BYTES],
    expected_tag: &[u8; 32],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotIdentity, SnapshotHmacError> {
    let snapshot = snapshot_sha256(root, limits)?;
    let mac = mac_for_identity(key, snapshot);
    mac.verify_slice(expected_tag)
        .map_err(|_| SnapshotHmacError::AuthenticationFailed)?;
    Ok(snapshot)
}

fn tag_identity(key: &[u8; SNAPSHOT_HMAC_KEY_BYTES], snapshot: SnapshotIdentity) -> [u8; 32] {
    let bytes = mac_for_identity(key, snapshot).finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&bytes);
    tag
}

fn mac_for_identity(
    key: &[u8; SNAPSHOT_HMAC_KEY_BYTES],
    snapshot: SnapshotIdentity,
) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 accepts the fixed 32-byte snapshot key length");
    mac.update(SNAPSHOT_HMAC_DOMAIN);
    mac.update(&snapshot.sha256);
    mac.update(&snapshot.encoded_bytes.to_le_bytes());
    mac.update(&snapshot.nodes.to_le_bytes());
    mac
}
