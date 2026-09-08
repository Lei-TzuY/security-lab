from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, insertion: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(marker)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one marker, got {count}")
    p.write_text(text.replace(marker, insertion + marker, 1))


# Public integration evidence, including the classic weak-identity-key forgery shape.
test_path = Path("tests/snapshot_signature.rs")
if test_path.exists():
    raise SystemExit("tests/snapshot_signature.rs already exists")
test_path.write_text(r'''#![cfg(target_os = "linux")]

use ed25519_dalek::VerifyingKey;
use security_lab::{
    sign_snapshot_ed25519, verify_snapshot_ed25519, SnapshotEd25519Error,
    SnapshotIdentityLimits, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
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
    let verified = verify_snapshot_ed25519(
        tree.path(),
        &signed.public_key,
        &signed.signature,
        limits(),
    )
    .unwrap();
    assert_eq!(verified, signed.snapshot);

    fs::write(tree.path().join("payload"), b"mutated-public-api\n").expect("mutate payload");
    assert!(matches!(
        verify_snapshot_ed25519(
            tree.path(),
            &signed.public_key,
            &signed.signature,
            limits(),
        ),
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
''')

# README: seal 36A and describe only the public-key semantics actually evidenced by 37A.
replace_one(
    "README.md",
    "The current Milestone 36A verified candidate adds **keyed HMAC-SHA256 authentication evidence for canonical snapshot identity** with a caller-supplied fixed-size secret key and constant-time tag verification.",
    "Milestone 36A added **keyed HMAC-SHA256 authentication evidence for canonical snapshot identity** with a caller-supplied fixed-size secret key and constant-time tag verification. The current Milestone 37A verified candidate adds **Ed25519 public-key signatures over canonical snapshot identity** with strict verification under an exact caller-supplied public key.",
    "README milestone summary",
)
insert_before(
    "README.md",
    "## Policy observability commands\n",
    r'''## Public-key snapshot signatures

The current Milestone 37A verified candidate adds `sign_snapshot_ed25519(root, signing_key, limits)` and `verify_snapshot_ed25519(root, public_key, expected_signature, limits)`. Both reuse the bounded Milestone 33A canonical identity. Signing accepts an exact 32-byte caller-supplied Ed25519 seed and returns the canonical identity, its 32-byte public key, and a 64-byte signature. The signed message is the fixed domain `security-lab-snapshot-ed25519-v1\0`, followed by canonical SHA-256, `encoded_bytes` as little-endian `u64`, and `nodes` as little-endian `u64`.

Verification parses the exact caller-supplied public key and uses pinned `ed25519-dalek` 2.1.1 `verify_strict`, so malformed keys fail separately and weak-key/noncanonical signature shapes are not accepted through a permissive verification equation. Executable evidence includes RFC 8032 test vector 1 for the backend, deterministic signing for the same seed/identity, success for an unchanged tree, rejection after content mutation, rejection under a different public key or corrupted signature, and a public-API regression proving the Edwards-identity weak key plus the classic `R=B, S=1` universal-forgery shape fails closed.

This is a **signature over the existing canonical identity tuple**, not a certificate chain, trust-store policy, remote attestation, hardware-backed identity, or proof of who controls a supplied public key. The library does not generate, persist, rotate, distribute, revoke, or protect signing keys. As in 33A–36A, signing/verifying recomputes a bounded live-tree identity; it does not freeze the source into a point-in-time filesystem snapshot and adds no durability/crash-recovery guarantee.

''',
    "README Ed25519 section",
)

# Threat model: distinguish public verification semantics from trusted-key provenance.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 36A verified candidate adds symmetric HMAC-SHA256 key-possession authentication evidence over the canonical identity, with a fixed-size caller key and constant-time tag verification.",
    "Milestone 36A added symmetric HMAC-SHA256 key-possession authentication evidence over the canonical identity, with a fixed-size caller key and constant-time tag verification. The current Milestone 37A verified candidate adds Ed25519 public-key signature verification over that same bounded canonical identity tuple.",
    "threat milestone summary",
)
insert_before(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP ingress listener:**",
    r'''- **Ed25519 canonical snapshot signature:** `sign_snapshot_ed25519` signs a versioned domain plus the bounded 33A identity digest/byte/node accounting under an exact caller-supplied 32-byte signing seed and returns its corresponding public key. `verify_snapshot_ed25519` independently recomputes the identity, parses the supplied public key, and uses `ed25519-dalek` strict verification. Content mutation, a different public key, corrupted signature bytes, and the decoded Edwards-identity weak key with the `R=B, S=1` universal-forgery shape all fail closed. This establishes signature validity under the supplied public key for the modeled identity; it does not establish certificate/trust-chain provenance, public-key ownership, hardware attestation, key generation/storage/rotation/revocation, point-in-time source consistency, or durability.
''',
    "threat Ed25519 property",
)

# Roadmap: 36A is already on main; promote the next materially stronger authentication slice.
p = Path("ROADMAP.md")
roadmap = p.read_text()
start = roadmap.find("## Milestone 36 — keyed canonical snapshot authentication\n")
end_marker = "## Independent host-local IPC frontier — post-launch object transfer\n"
end = roadmap.find(end_marker)
if start < 0 or end < 0 or end <= start:
    raise SystemExit("ROADMAP milestone 36/frontier markers not found")
section36 = roadmap[start:end]
if section36.count("**Current verified candidate.**") != 1:
    raise SystemExit("ROADMAP 36A status marker is not unique")
section36 = section36.replace(
    "**Current verified candidate.**",
    "**Status: complete on `main`.**",
    1,
)
section37 = r'''## Milestone 37 — public-key canonical snapshot signatures

### Slice 37A — Ed25519 signature over canonical snapshot identity

**Current verified candidate.** Adds independently verifiable public-key signature semantics to the existing bounded canonical snapshot identity rather than another symmetric tag encoding.

Acceptance evidence is executable:

- `sign_snapshot_ed25519(root, signing_key, limits)` accepts exactly one caller-supplied 32-byte Ed25519 signing seed, reuses the bounded 33A canonical scan, and returns the checked `SnapshotIdentity`, corresponding 32-byte public key, and 64-byte signature;
- the signature message is unambiguous and versioned: `security-lab-snapshot-ed25519-v1\0` followed by canonical SHA-256, `encoded_bytes` little-endian `u64`, and `nodes` little-endian `u64`;
- `verify_snapshot_ed25519(root, public_key, signature, limits)` independently recomputes the bounded identity, rejects malformed public keys, and uses pinned `ed25519-dalek` 2.1.1 `verify_strict` rather than permissive verification;
- backend evidence reproduces RFC 8032 test vector 1; deterministic same-seed/same-identity signing reproduces the same evidence; content mutation, a different public key, and signature-bit mutation each fail verification;
- public-API integration evidence proves an Edwards-identity weak key is decoded/classified as weak and that the classic `R=B, S=1` universal-forgery shape is rejected by the snapshot verification path;
- identity byte/node budget failures remain distinct `SnapshotIdentityError` failures rather than being converted into signature mismatch;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite must remain green on the exact candidate head.

Boundary: 37A proves signature validity under the exact supplied public key for the existing canonical identity tuple. It does not provide certificate/trust-store semantics, signer provenance beyond possession of the corresponding secret key, hardware/remote attestation, key generation/storage/rotation/revocation, immutable point-in-time source capture, a broader metadata identity model, or durability/crash recovery.

### Milestone 37 promotion rule

After 37A integrates, do not farm key encodings, signature text formats, algorithm aliases, or extra verify wrappers. A stronger provenance phase requires an independently specified trust/key lifecycle or attestation model. Otherwise promote to a real frozen/serialized source snapshot, durability/versioned publication, or a materially new launcher-owned mediation boundary.

'''
p.write_text(roadmap[:start] + section36 + section37 + roadmap[end:])
