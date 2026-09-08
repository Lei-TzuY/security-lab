#![cfg(target_os = "linux")]

use security_lab::{
    materialize_snapshot_store_object_trusted_ed25519_atomic, serialize_snapshot_archive,
    sign_snapshot_ed25519, store_snapshot_archive_trusted_ed25519_durable, SnapshotArchiveLimits,
    SnapshotIdentityLimits, SnapshotTrustError, SnapshotTrustKey, SnapshotTrustKeyId,
    SnapshotTrustKeyState, SnapshotTrustPolicy,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-snapshot-trust-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot-trust workspace");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn archive_limits() -> SnapshotArchiveLimits {
    SnapshotArchiveLimits {
        max_archive_bytes: 1024 * 1024,
        max_identity_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn identity_limits() -> SnapshotIdentityLimits {
    SnapshotIdentityLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn create_source(workspace: &Path) -> PathBuf {
    let source = workspace.join("source");
    fs::create_dir(&source).expect("create source root");
    fs::write(source.join("payload"), b"trust-policy-payload\n").expect("write source payload");
    source
}

#[test]
fn rotation_revokes_old_signer_before_store_access_and_accepts_new_signer() {
    let workspace = TempDir::new("rotation");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let old =
        sign_snapshot_ed25519(&source, &[0x51; 32], identity_limits()).expect("sign with old key");
    let new =
        sign_snapshot_ed25519(&source, &[0x52; 32], identity_limits()).expect("sign with new key");
    assert_eq!(old.snapshot, archive.identity);
    assert_eq!(new.snapshot, archive.identity);

    let old_id = SnapshotTrustKeyId::from_public_key(&old.public_key);
    let new_id = SnapshotTrustKeyId::from_public_key(&new.public_key);
    let generation_one =
        SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(old.public_key)])
            .expect("build generation-one trust policy");

    let first = store_snapshot_archive_trusted_ed25519_durable(
        &store,
        &archive.bytes,
        &generation_one,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect("old signer is authorized before rotation");
    assert!(first.store.inserted);
    assert_eq!(first.store.identity, archive.identity);
    assert_eq!(first.trust.policy, generation_one.identity());
    assert_eq!(first.trust.signer, old_id);

    let generation_two = generation_one
        .rotate(2, vec![new.public_key], &[old_id])
        .expect("rotate trust policy");
    assert_eq!(
        generation_two.key_state(old_id),
        Some(SnapshotTrustKeyState::Revoked)
    );
    assert_eq!(
        generation_two.key_state(new_id),
        Some(SnapshotTrustKeyState::Active)
    );
    assert_ne!(generation_one.identity(), generation_two.identity());

    let missing_store = workspace.path().join("missing-store");
    match store_snapshot_archive_trusted_ed25519_durable(
        &missing_store,
        &archive.bytes,
        &generation_two,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("revoked signer must fail before store inspection")
    {
        SnapshotTrustError::RevokedSigner { key_id } => assert_eq!(key_id, old_id),
        other => panic!("unexpected revoked-signer result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "revoked signer must not create or inspect a missing store root"
    );

    let unknown =
        sign_snapshot_ed25519(&source, &[0x53; 32], identity_limits()).expect("derive unknown key");
    let unknown_id = SnapshotTrustKeyId::from_public_key(&unknown.public_key);
    match store_snapshot_archive_trusted_ed25519_durable(
        &missing_store,
        &archive.bytes,
        &generation_two,
        unknown_id,
        &unknown.signature,
        archive_limits(),
    )
    .expect_err("unknown signer must fail before store inspection")
    {
        SnapshotTrustError::UnknownSigner { key_id } => assert_eq!(key_id, unknown_id),
        other => panic!("unexpected unknown-signer result: {other}"),
    }
    assert!(!missing_store.exists());

    let rotated = store_snapshot_archive_trusted_ed25519_durable(
        &store,
        &archive.bytes,
        &generation_two,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("new signer is authorized after rotation");
    assert!(
        !rotated.store.inserted,
        "same authenticated object should converge through exact deduplication"
    );
    assert_eq!(rotated.trust.policy, generation_two.identity());
    assert_eq!(rotated.trust.signer, new_id);

    let destination = workspace.path().join("restored");
    let restored = materialize_snapshot_store_object_trusted_ed25519_atomic(
        &store,
        archive.identity,
        &destination,
        &generation_two,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("materialize under rotated active signer");
    assert_eq!(restored.materialization.identity, archive.identity);
    assert_eq!(restored.trust.policy, generation_two.identity());
    assert_eq!(restored.trust.signer, new_id);
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"trust-policy-payload\n"
    );
}

#[test]
fn active_signer_still_requires_valid_signature() {
    let workspace = TempDir::new("signature");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let evidence =
        sign_snapshot_ed25519(&source, &[0x61; 32], identity_limits()).expect("sign snapshot");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let signer = SnapshotTrustKeyId::from_public_key(&evidence.public_key);
    let policy = SnapshotTrustPolicy::new(9, vec![SnapshotTrustKey::active(evidence.public_key)])
        .expect("build trust policy");
    let mut corrupted = evidence.signature;
    corrupted[7] ^= 0x80;

    match store_snapshot_archive_trusted_ed25519_durable(
        &store,
        &archive.bytes,
        &policy,
        signer,
        &corrupted,
        archive_limits(),
    )
    .expect_err("trust membership must not bypass strict signature verification")
    {
        SnapshotTrustError::Store(_) => {}
        other => panic!("unexpected corrupted-signature result: {other}"),
    }
    assert!(
        !store.join("objects").exists(),
        "failed signature must not reach object publication"
    );
}
