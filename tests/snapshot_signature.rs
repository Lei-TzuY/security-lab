#![cfg(target_os = "linux")]

use ed25519_dalek::VerifyingKey;
use security_lab::{
    sign_snapshot_ed25519, verify_snapshot_ed25519, SnapshotEd25519Error, SnapshotIdentityLimits,
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
    SNAPSHOT_ED25519_SIGNING_KEY_BYTES,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-ed25519-integration-{}-{suffix}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot-signature integration root");
        fs::write(path.join("payload"), b"signed-public-api\n").expect("write payload");
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
        max_nodes: 32,
    }
}

#[test]
fn public_api_signs_verifies_and_rejects_content_mutation() {
    let tree = TempTree::new();
    let seed = [0x42; SNAPSHOT_ED25519_SIGNING_KEY_BYTES];

    let signed = sign_snapshot_ed25519(tree.path(), &seed, limits()).unwrap();
    let verified =
        verify_snapshot_ed25519(tree.path(), &signed.public_key, &signed.signature, limits())
            .unwrap();
    assert_eq!(verified, signed.snapshot);

    fs::write(tree.path().join("payload"), b"mutated-public-api\n").expect("mutate payload");
    assert!(matches!(
        verify_snapshot_ed25519(tree.path(), &signed.public_key, &signed.signature, limits(),),
        Err(SnapshotEd25519Error::VerificationFailed)
    ));
}

#[test]
fn weak_identity_public_key_universal_forgery_shape_is_rejected() {
    let tree = TempTree::new();

    // Compressed Edwards identity. ed25519-dalek parses it but classifies it as
    // weak; strict verification must reject it rather than accepting signatures
    // under the cofactored equation used by permissive verifiers.
    let mut weak_public = [0u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES];
    weak_public[0] = 1;
    let parsed = VerifyingKey::from_bytes(&weak_public).expect("identity point decodes");
    assert!(parsed.is_weak(), "fixture must exercise a weak Ed25519 key");

    // Classic universal-forgery shape for A=identity: R=B and S=1. A lax
    // verifier can make the public-key term disappear; verify_strict must not.
    let mut forgery = [0u8; SNAPSHOT_ED25519_SIGNATURE_BYTES];
    forgery[0] = 0x58;
    forgery[1..32].fill(0x66);
    forgery[32] = 1;

    assert!(matches!(
        verify_snapshot_ed25519(tree.path(), &weak_public, &forgery, limits()),
        Err(SnapshotEd25519Error::VerificationFailed)
    ));
}
