#![cfg(target_os = "linux")]

use security_lab::{
    initialize_snapshot_trust_state, load_snapshot_trust_state_identity,
    materialize_snapshot_store_object_persisted_trust_ed25519_atomic, rotate_snapshot_trust_state,
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_trust_state_path,
    store_snapshot_archive_persisted_trust_ed25519_durable, SnapshotArchiveLimits,
    SnapshotIdentityLimits, SnapshotTrustKey, SnapshotTrustKeyId, SnapshotTrustKeyState,
    SnapshotTrustPolicy, SnapshotTrustStateContext, SnapshotTrustStateError, SnapshotTrustStateKey,
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
        fs::create_dir(&path).expect("create snapshot trust-state workspace");
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
    fs::write(source.join("payload"), b"persisted-trust-payload\n").expect("write source payload");
    source
}

#[test]
fn persisted_rotation_rejects_stale_policy_before_store_access_and_accepts_successor() {
    let workspace = TempDir::new("rotation");
    let source = create_source(workspace.path());
    let state_root = workspace.path().join("trust-state");
    let store = workspace.path().join("store");
    fs::create_dir(&state_root).expect("create trust-state root");
    fs::create_dir(&store).expect("create store root");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let old = sign_snapshot_ed25519(&source, &[0x71; 32], identity_limits()).expect("sign old key");
    let new = sign_snapshot_ed25519(&source, &[0x72; 32], identity_limits()).expect("sign new key");
    assert_eq!(old.snapshot, archive.identity);
    assert_eq!(new.snapshot, archive.identity);

    let old_id = SnapshotTrustKeyId::from_public_key(&old.public_key);
    let new_id = SnapshotTrustKeyId::from_public_key(&new.public_key);
    let generation_one =
        SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(old.public_key)])
            .expect("build generation-one policy");
    let state_key = SnapshotTrustStateKey::new([0xA5; 32]);

    let initialized = initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("initialize persisted trust state");
    assert_eq!(initialized.policy, generation_one.identity());
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("load initialized trust state"),
        generation_one.identity()
    );
    assert_eq!(
        initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
            .expect("exact initialization retry converges")
            .policy,
        generation_one.identity()
    );

    let first_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_one);
    let first = store_snapshot_archive_persisted_trust_ed25519_durable(
        &first_context,
        &store,
        &archive.bytes,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect("state-backed generation-one publication");
    assert!(first.store.inserted);
    assert_eq!(first.trust.policy, generation_one.identity());

    let generation_two = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("persist rotation");
    assert_eq!(
        generation_two.key_state(old_id),
        Some(SnapshotTrustKeyState::Revoked)
    );
    assert_eq!(
        generation_two.key_state(new_id),
        Some(SnapshotTrustKeyState::Active)
    );
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("load rotated trust state"),
        generation_two.identity()
    );

    let converged = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("ambiguous rotation retry converges to persisted successor");
    assert_eq!(converged.identity(), generation_two.identity());

    let stale_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_one);
    let missing_store = workspace.path().join("missing-store");
    match store_snapshot_archive_persisted_trust_ed25519_durable(
        &stale_context,
        &missing_store,
        &archive.bytes,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("stale policy must fail before store access")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale store result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "stale state-backed publication must not touch missing store root"
    );

    let missing_parent = workspace.path().join("missing-destination-parent");
    let missing_destination = missing_parent.join("restored");
    match materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
        &stale_context,
        &store,
        archive.identity,
        &missing_destination,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("stale policy must fail before destination access")
    {
        SnapshotTrustStateError::StalePolicy { .. } => {}
        other => panic!("unexpected stale materialize result: {other}"),
    }
    assert!(
        !missing_parent.exists(),
        "stale state-backed materialization must not inspect destination parent"
    );

    let current_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_two);
    let current = store_snapshot_archive_persisted_trust_ed25519_durable(
        &current_context,
        &store,
        &archive.bytes,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("rotated active signer deduplicates state-backed object");
    assert!(!current.store.inserted);
    assert_eq!(current.trust.policy, generation_two.identity());
    assert_eq!(current.trust.signer, new_id);

    let destination = workspace.path().join("restored");
    let restored = materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
        &current_context,
        &store,
        archive.identity,
        &destination,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("materialize under persisted rotated trust state");
    assert_eq!(restored.materialization.identity, archive.identity);
    assert_eq!(restored.trust.policy, generation_two.identity());
    assert_eq!(restored.trust.signer, new_id);
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"persisted-trust-payload\n"
    );
}

#[test]
fn persisted_state_authentication_rejects_wrong_key_and_same_size_tamper() {
    let workspace = TempDir::new("authentication");
    let state_root = workspace.path().join("trust-state");
    fs::create_dir(&state_root).expect("create trust-state root");

    let source = create_source(workspace.path());
    let evidence =
        sign_snapshot_ed25519(&source, &[0x81; 32], identity_limits()).expect("derive trust key");
    let policy = SnapshotTrustPolicy::new(7, vec![SnapshotTrustKey::active(evidence.public_key)])
        .expect("build trust policy");
    let correct_key = SnapshotTrustStateKey::new([0xB4; 32]);
    initialize_snapshot_trust_state(&state_root, &correct_key, &policy)
        .expect("initialize authenticated state");

    let wrong_key = SnapshotTrustStateKey::new([0xB5; 32]);
    assert!(matches!(
        load_snapshot_trust_state_identity(&state_root, &wrong_key),
        Err(SnapshotTrustStateError::AuthenticationFailed)
    ));

    let state_path = snapshot_trust_state_path(&state_root);
    let mut bytes = fs::read(&state_path).expect("read persisted state bytes");
    assert!(
        bytes.len() > 20,
        "trust-state fixture must contain authenticated header"
    );
    bytes[20] ^= 0x40;
    fs::write(&state_path, &bytes).expect("tamper persisted state without changing length");
    assert!(matches!(
        load_snapshot_trust_state_identity(&state_root, &correct_key),
        Err(SnapshotTrustStateError::AuthenticationFailed)
    ));
}

#[test]
fn stale_rotation_cannot_overwrite_newer_persisted_generation() {
    let workspace = TempDir::new("stale-rotation");
    let state_root = workspace.path().join("trust-state");
    fs::create_dir(&state_root).expect("create trust-state root");

    let source = create_source(workspace.path());
    let a = sign_snapshot_ed25519(&source, &[0x91; 32], identity_limits()).expect("derive key A");
    let b = sign_snapshot_ed25519(&source, &[0x92; 32], identity_limits()).expect("derive key B");
    let c = sign_snapshot_ed25519(&source, &[0x93; 32], identity_limits()).expect("derive key C");
    let a_id = SnapshotTrustKeyId::from_public_key(&a.public_key);
    let generation_one = SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(a.public_key)])
        .expect("build generation one");
    let state_key = SnapshotTrustStateKey::new([0xC6; 32]);
    initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("initialize trust state");

    let generation_two = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![b.public_key],
        &[a_id],
    )
    .expect("advance persisted generation");

    match rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        3,
        vec![c.public_key],
        &[],
    )
    .expect_err("stale writer must not replace newer persisted generation")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale rotation result: {other}"),
    }
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("newer generation remains persisted"),
        generation_two.identity()
    );
}
