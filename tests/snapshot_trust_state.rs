#![cfg(target_os = "linux")]

use security_lab::{
    initialize_snapshot_trust_state, load_snapshot_trust_state_identity,
    materialize_snapshot_store_object_persisted_trust_ed25519_atomic,
    rotate_snapshot_trust_state, serialize_snapshot_archive, sign_snapshot_ed25519,
    snapshot_trust_state_path, store_snapshot_archive_persisted_trust_ed25519_durable,
    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotTrustError, SnapshotTrustKey,
    SnapshotTrustKeyId, SnapshotTrustKeyState, SnapshotTrustPolicy, SnapshotTrustStateError,
    SnapshotTrustStateKey,
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
            "security-lab-snapshot-trust-state-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot-trust-state workspace");
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
    fs::write(source.join("payload"), b"persisted-trust-state-payload\n")
        .expect("write source payload");
    source
}

#[test]
fn persisted_rotation_rejects_stale_policy_before_store_io_and_accepts_successor() {
    let workspace = TempDir::new("rotation");
    let state_root = workspace.path().join("state");
    let store = workspace.path().join("store");
    fs::create_dir(&state_root).expect("create trust state root");
    fs::create_dir(&store).expect("create snapshot store root");
    let source = create_source(workspace.path());
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");

    let old =
        sign_snapshot_ed25519(&source, &[0x71; 32], identity_limits()).expect("sign with old key");
    let new =
        sign_snapshot_ed25519(&source, &[0x72; 32], identity_limits()).expect("sign with new key");
    let third = sign_snapshot_ed25519(&source, &[0x73; 32], identity_limits())
        .expect("derive third key");
    let old_id = SnapshotTrustKeyId::from_public_key(&old.public_key);
    let new_id = SnapshotTrustKeyId::from_public_key(&new.public_key);
    let state_key = SnapshotTrustStateKey::new([0xa5; 32]);
    let generation_one =
        SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(old.public_key)])
            .expect("build generation-one policy");

    let initialized = initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("initialize trust state");
    assert_eq!(initialized.policy, generation_one.identity());
    let initialized_again = initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("exact initialization retry must converge");
    assert_eq!(initialized_again.policy, generation_one.identity());
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key).expect("load trust state"),
        generation_one.identity()
    );

    let first = store_snapshot_archive_persisted_trust_ed25519_durable(
        &state_root,
        &state_key,
        &store,
        &archive.bytes,
        &generation_one,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect("generation-one signer is authorized by persisted state");
    assert!(first.store.inserted);
    assert_eq!(first.store.identity, archive.identity);
    assert_eq!(first.trust.policy, generation_one.identity());

    let generation_two = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("persist generation-two rotation");
    assert_eq!(
        generation_two.key_state(old_id),
        Some(SnapshotTrustKeyState::Revoked)
    );
    assert_eq!(
        generation_two.key_state(new_id),
        Some(SnapshotTrustKeyState::Active)
    );
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key).expect("load rotated state"),
        generation_two.identity()
    );

    let retry = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("exact rotation retry must converge after ambiguous acknowledgement");
    assert_eq!(retry.identity(), generation_two.identity());

    let missing_store = workspace.path().join("missing-store");
    match store_snapshot_archive_persisted_trust_ed25519_durable(
        &state_root,
        &state_key,
        &missing_store,
        &archive.bytes,
        &generation_one,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("stale policy must fail before snapshot store access")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale-policy result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "stale policy must not create or inspect a missing snapshot store"
    );

    match store_snapshot_archive_persisted_trust_ed25519_durable(
        &state_root,
        &state_key,
        &missing_store,
        &archive.bytes,
        &generation_two,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("persisted successor must still reject its revoked signer")
    {
        SnapshotTrustStateError::Trust(SnapshotTrustError::RevokedSigner { key_id }) => {
            assert_eq!(key_id, old_id)
        }
        other => panic!("unexpected revoked-signer result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "revoked signer must fail before snapshot store access"
    );

    let deduplicated = store_snapshot_archive_persisted_trust_ed25519_durable(
        &state_root,
        &state_key,
        &store,
        &archive.bytes,
        &generation_two,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("persisted successor authorizes the new signer");
    assert!(!deduplicated.store.inserted);
    assert_eq!(deduplicated.trust.policy, generation_two.identity());
    assert_eq!(deduplicated.trust.signer, new_id);

    let destination = workspace.path().join("restored");
    let restored = materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
        &state_root,
        &state_key,
        &store,
        archive.identity,
        &destination,
        &generation_two,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("materialize through persisted successor trust state");
    assert_eq!(restored.materialization.identity, archive.identity);
    assert_eq!(restored.trust.policy, generation_two.identity());
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"persisted-trust-state-payload\n"
    );

    match rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        3,
        vec![third.public_key],
        &[],
    )
    .expect_err("a different stale writer must not overwrite generation two")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale-rotation result: {other}"),
    }
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("stale rotation must leave persisted state intact"),
        generation_two.identity()
    );
}

#[test]
fn authenticated_state_rejects_wrong_key_and_tampering_before_store_io() {
    let workspace = TempDir::new("authentication");
    let state_root = workspace.path().join("state");
    fs::create_dir(&state_root).expect("create trust state root");
    let source = create_source(workspace.path());
    let evidence =
        sign_snapshot_ed25519(&source, &[0x81; 32], identity_limits()).expect("sign snapshot");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let signer = SnapshotTrustKeyId::from_public_key(&evidence.public_key);
    let policy = SnapshotTrustPolicy::new(5, vec![SnapshotTrustKey::active(evidence.public_key)])
        .expect("build trust policy");
    let state_key = SnapshotTrustStateKey::new([0xb4; 32]);
    let wrong_key = SnapshotTrustStateKey::new([0xb5; 32]);

    initialize_snapshot_trust_state(&state_root, &state_key, &policy)
        .expect("initialize authenticated trust state");
    match load_snapshot_trust_state_identity(&state_root, &wrong_key)
        .expect_err("wrong state key must fail authentication")
    {
        SnapshotTrustStateError::AuthenticationFailed => {}
        other => panic!("unexpected wrong-key result: {other}"),
    }

    let state_path = snapshot_trust_state_path(&state_root);
    let mut bytes = fs::read(&state_path).expect("read trust state for tamper fixture");
    assert!(bytes.len() > 20);
    bytes[20] ^= 0x40;
    fs::write(&state_path, bytes).expect("tamper trust state fixture");

    let missing_store = workspace.path().join("missing-store");
    match store_snapshot_archive_persisted_trust_ed25519_durable(
        &state_root,
        &state_key,
        &missing_store,
        &archive.bytes,
        &policy,
        signer,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("tampered state must fail before snapshot store access")
    {
        SnapshotTrustStateError::AuthenticationFailed => {}
        other => panic!("unexpected tampered-state result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "tampered trust state must not reach a missing snapshot store"
    );
}
