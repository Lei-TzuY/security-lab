#![cfg(target_os = "linux")]

use security_lab::{
    initialize_snapshot_store_head_state, load_snapshot_store_head_state,
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_store_head_state_path,
    snapshot_store_object_path, store_snapshot_archive_ed25519_durable_with_head_state,
    verify_snapshot_store_head_state, SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits,
    SnapshotStoreAuditLimits, SnapshotStoreHeadStateError, SnapshotStoreHeadStateKey,
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
            "security-lab-snapshot-store-head-state-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create head-state workspace");
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

fn audit_limits() -> SnapshotStoreAuditLimits {
    SnapshotStoreAuditLimits {
        max_entries: 32,
        max_total_archive_bytes: 4 * 1024 * 1024,
        archive: archive_limits(),
    }
}

struct Fixture {
    identity: SnapshotIdentity,
    archive: Vec<u8>,
    public_key: [u8; 32],
    signature: [u8; 64],
}

fn fixture(workspace: &Path, label: &str, payload: &[u8], signing_byte: u8) -> Fixture {
    let source = workspace.join(format!("source-{label}"));
    fs::create_dir(&source).expect("create head-state source");
    fs::write(source.join("payload"), payload).expect("write head-state payload");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize fixture");
    let signed = sign_snapshot_ed25519(&source, &[signing_byte; 32], identity_limits())
        .expect("sign head-state fixture");
    assert_eq!(archive.identity, signed.snapshot);
    Fixture {
        identity: archive.identity,
        archive: archive.bytes,
        public_key: signed.public_key,
        signature: signed.signature,
    }
}

fn roots(workspace: &Path) -> (PathBuf, PathBuf) {
    let store = workspace.join("store");
    let state = workspace.join("head-state");
    fs::create_dir(&store).expect("create snapshot store");
    fs::create_dir(&state).expect("create head-state root");
    (store, state)
}

#[test]
fn anchored_publication_advances_once_and_exact_dedup_keeps_same_head() {
    let workspace = TempDir::new("advance");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xA5; 32]);
    let first = fixture(workspace.path(), "first", b"head-state-first\n", 0x51);

    let initial = initialize_snapshot_store_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
    )
    .expect("initialize empty store head");
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.inventory.objects, 0);

    let inserted = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
        &first.archive,
        &first.public_key,
        &first.signature,
        archive_limits(),
    )
    .expect("publish first object under authenticated head");
    assert!(inserted.put.inserted);
    assert_eq!(inserted.put.identity, first.identity);
    assert_eq!(inserted.previous, initial);
    assert_eq!(inserted.successor.generation, 2);
    assert_eq!(inserted.successor.inventory.objects, 1);
    assert_ne!(inserted.successor.inventory, initial.inventory);

    assert_eq!(
        load_snapshot_store_head_state(&state, &key).expect("load advanced head"),
        inserted.successor
    );
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify advanced store against head"),
        inserted.successor
    );

    let dedup = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
        &first.archive,
        &first.public_key,
        &first.signature,
        archive_limits(),
    )
    .expect("deduplicate exact object under authenticated head");
    assert!(!dedup.put.inserted);
    assert_eq!(dedup.previous, inserted.successor);
    assert_eq!(dedup.successor, inserted.successor);
    assert_eq!(
        load_snapshot_store_head_state(&state, &key).expect("load head after dedup"),
        inserted.successor
    );
}

#[test]
fn store_only_rollback_is_detected_before_later_publication() {
    let workspace = TempDir::new("rollback");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xB6; 32]);
    let first = fixture(workspace.path(), "first", b"rollback-first\n", 0x61);
    let second = fixture(workspace.path(), "second", b"rollback-second\n", 0x62);

    initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize rollback head");
    let committed = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
        &first.archive,
        &first.public_key,
        &first.signature,
        archive_limits(),
    )
    .expect("commit first rollback fixture");
    assert_eq!(committed.successor.inventory.objects, 1);

    let first_path = snapshot_store_object_path(&store, first.identity);
    assert!(first_path.exists(), "first object should exist before rollback");
    fs::remove_file(&first_path).expect("simulate hostile store-only rollback");

    match verify_snapshot_store_head_state(&state, &key, &store, audit_limits()) {
        Err(SnapshotStoreHeadStateError::StoreDiverged { anchored, actual }) => {
            assert_eq!(anchored, committed.successor);
            assert_eq!(actual.objects, 0);
        }
        Err(other) => panic!("unexpected rollback verification result: {other}"),
        Ok(_) => panic!("store-only rollback unexpectedly matched authenticated head"),
    }

    let second_path = snapshot_store_object_path(&store, second.identity);
    match store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
        &second.archive,
        &second.public_key,
        &second.signature,
        archive_limits(),
    ) {
        Err(SnapshotStoreHeadStateError::StoreDiverged { anchored, actual }) => {
            assert_eq!(anchored, committed.successor);
            assert_eq!(actual.objects, 0);
        }
        Err(other) => panic!("unexpected guarded publication result after rollback: {other}"),
        Ok(_) => panic!("publication proceeded from a rolled-back store"),
    }
    assert!(
        !second_path.exists(),
        "candidate object was published before rollback mismatch rejection"
    );
}

#[test]
fn head_state_authentication_rejects_wrong_key_and_byte_tamper() {
    let workspace = TempDir::new("authentication");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xC7; 32]);
    let wrong_key = SnapshotStoreHeadStateKey::new([0xD8; 32]);

    let initialized = initialize_snapshot_store_head_state(
        &state,
        &key,
        &store,
        audit_limits(),
    )
    .expect("initialize authentication head");
    assert_eq!(initialized.generation, 1);

    assert!(matches!(
        load_snapshot_store_head_state(&state, &wrong_key),
        Err(SnapshotStoreHeadStateError::AuthenticationFailed)
    ));

    let path = snapshot_store_head_state_path(&state);
    let mut bytes = fs::read(&path).expect("read authenticated head bytes");
    assert!(bytes.len() > 24);
    bytes[24] ^= 0x80;
    fs::write(&path, &bytes).expect("tamper authenticated head bytes");

    assert!(matches!(
        load_snapshot_store_head_state(&state, &key),
        Err(SnapshotStoreHeadStateError::AuthenticationFailed)
    ));
}

#[test]
fn configured_state_and_store_roots_must_be_disjoint() {
    let workspace = TempDir::new("root-overlap");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create overlap store");
    let nested_state = store.join("state");
    fs::create_dir(&nested_state).expect("create nested state root");
    let key = SnapshotStoreHeadStateKey::new([0xE9; 32]);

    assert!(matches!(
        initialize_snapshot_store_head_state(
            &nested_state,
            &key,
            &store,
            audit_limits(),
        ),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));

    let outer_state = workspace.path().join("outer-state");
    fs::create_dir(&outer_state).expect("create outer state root");
    let nested_store = outer_state.join("nested-store");
    fs::create_dir(&nested_store).expect("create nested store root");
    assert!(matches!(
        initialize_snapshot_store_head_state(
            &outer_state,
            &key,
            &nested_store,
            audit_limits(),
        ),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));
}
