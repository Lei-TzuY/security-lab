use crate::snapshot_identity::{
    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::error::Error;
use std::fmt;
use std::path::Path;

const SNAPSHOT_ED25519_DOMAIN: &[u8] = b"security-lab-snapshot-ed25519-v1\0";
pub const SNAPSHOT_ED25519_SIGNING_KEY_BYTES: usize = 32;
pub const SNAPSHOT_ED25519_PUBLIC_KEY_BYTES: usize = 32;
pub const SNAPSHOT_ED25519_SIGNATURE_BYTES: usize = 64;

/// Public-key signature evidence for one canonical supported snapshot tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotEd25519Signature {
    /// Canonical snapshot identity signed by `signature`.
    pub snapshot: SnapshotIdentity,
    /// Ed25519 verifying key corresponding to the caller-supplied signing seed.
    pub public_key: [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    /// Ed25519 signature over the versioned canonical identity message.
    pub signature: [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
}

impl SnapshotEd25519Signature {
    pub fn signature_hex(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::with_capacity(SNAPSHOT_ED25519_SIGNATURE_BYTES * 2);
        for byte in self.signature {
            write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
        }
        text
    }
}

#[derive(Debug)]
pub enum SnapshotEd25519Error {
    Identity(SnapshotIdentityError),
    InvalidPublicKey,
    VerificationFailed,
}

impl fmt::Display for SnapshotEd25519Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(source) => write!(f, "snapshot Ed25519 identity failed: {source}"),
            Self::InvalidPublicKey => f.write_str("snapshot Ed25519 public key is invalid"),
            Self::VerificationFailed => f.write_str("snapshot Ed25519 verification failed"),
        }
    }
}

impl Error for SnapshotEd25519Error {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::InvalidPublicKey | Self::VerificationFailed => None,
        }
    }
}

impl From<SnapshotIdentityError> for SnapshotEd25519Error {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}

/// Sign the canonical snapshot identity with Ed25519.
///
/// The caller supplies an exact 32-byte Ed25519 signing seed. The library does
/// not generate, store, rotate, persist, or distribute keys. The signature is
/// over a versioned domain plus the canonical SHA-256 identity and its encoded
/// byte/node accounting. This is public-key signature evidence for that bounded
/// identity model; it is not certificate validation, remote attestation, key
/// provenance, or a point-in-time freeze of the live source tree.
pub fn sign_snapshot_ed25519(
    root: &Path,
    signing_key: &[u8; SNAPSHOT_ED25519_SIGNING_KEY_BYTES],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotEd25519Signature, SnapshotEd25519Error> {
    let snapshot = snapshot_sha256(root, limits)?;
    let signing_key = SigningKey::from_bytes(signing_key);
    let signature = signing_key.sign(&signature_message(snapshot)).to_bytes();
    Ok(SnapshotEd25519Signature {
        snapshot,
        public_key: signing_key.verifying_key().to_bytes(),
        signature,
    })
}

/// Recompute the canonical snapshot identity and strictly verify its Ed25519
/// signature under the exact caller-supplied public key.
pub fn verify_snapshot_ed25519(
    root: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotIdentity, SnapshotEd25519Error> {
    let snapshot = snapshot_sha256(root, limits)?;
    verify_snapshot_identity_ed25519(snapshot, public_key, expected_signature)?;
    Ok(snapshot)
}

pub(crate) fn verify_snapshot_identity_ed25519(
    snapshot: SnapshotIdentity,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
) -> Result<(), SnapshotEd25519Error> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SnapshotEd25519Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(expected_signature);
    verifying_key
        .verify_strict(&signature_message(snapshot), &signature)
        .map_err(|_| SnapshotEd25519Error::VerificationFailed)
}

fn signature_message(snapshot: SnapshotIdentity) -> Vec<u8> {
    let mut message = Vec::with_capacity(SNAPSHOT_ED25519_DOMAIN.len() + 32 + 8 + 8);
    message.extend_from_slice(SNAPSHOT_ED25519_DOMAIN);
    message.extend_from_slice(&snapshot.sha256);
    message.extend_from_slice(&snapshot.encoded_bytes.to_le_bytes());
    message.extend_from_slice(&snapshot.nodes.to_le_bytes());
    message
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "security-lab-ed25519-{}-{suffix}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).expect("create signature test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn limits() -> SnapshotIdentityLimits {
        SnapshotIdentityLimits {
            max_bytes: 1024 * 1024,
            max_nodes: 64,
        }
    }

    fn populate(root: &Path) {
        fs::write(root.join("payload"), b"signed-data\n").expect("write payload");
        fs::create_dir(root.join("nested")).expect("create nested directory");
        fs::write(root.join("nested/value"), b"nested\n").expect("write nested payload");
        symlink("../payload", root.join("nested/link")).expect("create snapshot symlink");
    }

    #[test]
    fn signed_snapshot_verifies_and_mutation_fails_closed() {
        let tree = TempTree::new();
        populate(tree.path());
        let seed = [0x11; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];

        let evidence = sign_snapshot_ed25519(tree.path(), &seed, limits()).unwrap();
        let verified = verify_snapshot_ed25519(
            tree.path(),
            &evidence.public_key,
            &evidence.signature,
            limits(),
        )
        .unwrap();
        assert_eq!(verified, evidence.snapshot);

        fs::write(tree.path().join("payload"), b"mutated\n").expect("mutate signed tree");
        assert!(matches!(
            verify_snapshot_ed25519(
                tree.path(),
                &evidence.public_key,
                &evidence.signature,
                limits(),
            ),
            Err(SnapshotEd25519Error::VerificationFailed)
        ));
    }

    #[test]
    fn wrong_public_key_and_signature_mutation_are_rejected() {
        let tree = TempTree::new();
        populate(tree.path());
        let seed = [0x21; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
        let evidence = sign_snapshot_ed25519(tree.path(), &seed, limits()).unwrap();

        let wrong_public = SigningKey::from_bytes(&[0x22; SNAPSHOT_ED25519_SIGNING_KEY_BYTES])
            .verifying_key()
            .to_bytes();
        assert!(matches!(
            verify_snapshot_ed25519(tree.path(), &wrong_public, &evidence.signature, limits()),
            Err(SnapshotEd25519Error::VerificationFailed)
        ));

        let mut corrupted = evidence.signature;
        corrupted[17] ^= 0x80;
        assert!(matches!(
            verify_snapshot_ed25519(tree.path(), &evidence.public_key, &corrupted, limits()),
            Err(SnapshotEd25519Error::VerificationFailed)
        ));
    }

    #[test]
    fn signing_is_deterministic_for_same_snapshot_and_seed() {
        let tree = TempTree::new();
        populate(tree.path());
        let seed = [0x31; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];
        let first = sign_snapshot_ed25519(tree.path(), &seed, limits()).unwrap();
        let second = sign_snapshot_ed25519(tree.path(), &seed, limits()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn ed25519_backend_matches_rfc8032_test_vector_one() {
        let seed =
            decode_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            decode_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let expected_signature = decode_hex::<64>(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        );

        let signing_key = SigningKey::from_bytes(&seed);
        assert_eq!(signing_key.verifying_key().to_bytes(), expected_public);
        assert_eq!(signing_key.sign(b"").to_bytes(), expected_signature);
        let verifying_key = VerifyingKey::from_bytes(&expected_public).unwrap();
        verifying_key
            .verify_strict(b"", &Signature::from_bytes(&expected_signature))
            .unwrap();
    }

    fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        let compact: Vec<u8> = text
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        assert_eq!(compact.len(), N * 2);
        let mut out = [0u8; N];
        for (index, slot) in out.iter_mut().enumerate() {
            *slot = (hex_nibble(compact[index * 2]) << 4) | hex_nibble(compact[index * 2 + 1]);
        }
        out
    }

    fn hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => panic!("invalid hexadecimal test vector"),
        }
    }
}
