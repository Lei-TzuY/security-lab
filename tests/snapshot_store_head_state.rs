#![cfg(target_os = "linux")]

use hmac::{Hmac, Mac};
use security_lab::{
    initialize_snapshot_store_head_state, load_snapshot_store_head_state,
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_store_head_state_path,
    snapshot_store_inventory_identity, snapshot_store_object_path,
    store_snapshot_archive_ed25519_atomic, store_snapshot_archive_ed25519_durable,
    store_snapshot_archive_ed25519_durable_with_head_state,
    store_snapshot_archives_ed25519_durable_with_head_state, verify_snapshot_store_head_state,
    SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits, SnapshotStoreAuditLimits,
    SnapshotStoreError, SnapshotStoreHeadBatchItem, SnapshotStoreHeadBatchPublishRequest,
    SnapshotStoreHeadPublishRequest, SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity,
    SnapshotStoreHeadStateKey, SnapshotStoreTransactionError,
};
use sha2::Sha256;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
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

fn publish_request(fixture: &Fixture) -> SnapshotStoreHeadPublishRequest<'_> {
    SnapshotStoreHeadPublishRequest {
        inventory_limits: audit_limits(),
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}

fn batch_item(fixture: &Fixture) -> SnapshotStoreHeadBatchItem<'_> {
    SnapshotStoreHeadBatchItem {
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}

const PENDING_DOMAIN: &[u8] = b"security-lab-snapshot-store-head-pending-v2\0";
const PENDING_MAGIC: [u8; 8] = *b"SLHPND2\0";
const PENDING_HEADER_BYTES: usize = 176;
const PENDING_BYTES: usize = 208;

fn encode_pending_identity(bytes: &mut [u8], identity: SnapshotStoreHeadStateIdentity) {
    assert_eq!(bytes.len(), 56);
    bytes[0..8].copy_from_slice(&identity.generation.to_le_bytes());
    bytes[8..40].copy_from_slice(&identity.inventory.sha256);
    bytes[40..48].copy_from_slice(&identity.inventory.objects.to_le_bytes());
    bytes[48..56].copy_from_slice(&identity.inventory.archive_bytes.to_le_bytes());
}

fn pending_bytes(
    key: &SnapshotStoreHeadStateKey,
    previous: SnapshotStoreHeadStateIdentity,
    successor: SnapshotStoreHeadStateIdentity,
    candidate: &Fixture,
) -> [u8; PENDING_BYTES] {
    let mut bytes = [0u8; PENDING_BYTES];
    bytes[0..8].copy_from_slice(&PENDING_MAGIC);
    encode_pending_identity(&mut bytes[8..64], previous);
    encode_pending_identity(&mut bytes[64..120], successor);
    bytes[120..152].copy_from_slice(&candidate.identity.sha256);
    bytes[152..160].copy_from_slice(&candidate.identity.encoded_bytes.to_le_bytes());
    bytes[160..168].copy_from_slice(&candidate.identity.nodes.to_le_bytes());
    bytes[168..176].copy_from_slice(&(candidate.archive.len() as u64).to_le_bytes());
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("fixed HMAC key is valid");
    mac.update(PENDING_DOMAIN);
    mac.update(&bytes[..PENDING_HEADER_BYTES]);
    bytes[PENDING_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());
    bytes
}

fn pending_path(state: &Path) -> PathBuf {
    state.join("snapshot-store-head-pending")
}

fn write_pending_fixture(
    state: &Path,
    key: &SnapshotStoreHeadStateKey,
    previous: SnapshotStoreHeadStateIdentity,
    successor: SnapshotStoreHeadStateIdentity,
    candidate: &Fixture,
) {
    fs::write(
        pending_path(state),
        pending_bytes(key, previous, successor, candidate),
    )
    .expect("write authenticated pending fixture");
}

fn projected_successor_fixture(
    workspace: &Path,
    previous: SnapshotStoreHeadStateIdentity,
    fixture: &Fixture,
) -> SnapshotStoreHeadStateIdentity {
    let mirror = workspace.join("projection-store");
    fs::create_dir(&mirror).expect("create projection mirror store");
    store_snapshot_archive_ed25519_durable(
        &mirror,
        &fixture.archive,
        &fixture.public_key,
        &fixture.signature,
        archive_limits(),
    )
    .expect("publish fixture into independent projection mirror");
    let inventory =
        snapshot_store_inventory_identity(&mirror, audit_limits()).expect("audit mirror inventory");
    SnapshotStoreHeadStateIdentity {
        generation: previous.generation + 1,
        inventory,
    }
}

const BATCH_PENDING_DOMAIN: &[u8] = b"security-lab-snapshot-store-head-batch-pending-v1\0";
const BATCH_PENDING_MAGIC: [u8; 8] = *b"SLHBPN1\0";
const BATCH_PENDING_FIXED_BYTES: usize = 128;
const BATCH_PENDING_ENTRY_BYTES: usize = 208;
const BATCH_PENDING_HEADER_BYTES: usize =
    BATCH_PENDING_FIXED_BYTES + 16 * BATCH_PENDING_ENTRY_BYTES;
const BATCH_PENDING_BYTES: usize = BATCH_PENDING_HEADER_BYTES + 32;

fn encode_inventory_fixture(
    bytes: &mut [u8],
    inventory: security_lab::SnapshotStoreInventoryIdentity,
) {
    assert_eq!(bytes.len(), 48);
    bytes[0..32].copy_from_slice(&inventory.sha256);
    bytes[32..40].copy_from_slice(&inventory.objects.to_le_bytes());
    bytes[40..48].copy_from_slice(&inventory.archive_bytes.to_le_bytes());
}

fn batch_pending_path(state: &Path) -> PathBuf {
    state.join("snapshot-store-head-batch-pending")
}

fn batch_stage_path(state: &Path, index: usize) -> PathBuf {
    state.join(format!("snapshot-store-head-batch-stage-{index:02}"))
}

fn projected_batch_successor_fixture(
    workspace: &Path,
    previous: SnapshotStoreHeadStateIdentity,
    fixtures: &[&Fixture],
) -> (
    Vec<security_lab::SnapshotStoreInventoryIdentity>,
    SnapshotStoreHeadStateIdentity,
) {
    let mirror = workspace.join("batch-projection-store");
    fs::create_dir(&mirror).expect("create batch projection mirror store");
    let mut after = Vec::new();
    for fixture in fixtures {
        store_snapshot_archive_ed25519_durable(
            &mirror,
            &fixture.archive,
            &fixture.public_key,
            &fixture.signature,
            archive_limits(),
        )
        .expect("publish fixture into batch projection mirror");
        after.push(
            snapshot_store_inventory_identity(&mirror, audit_limits())
                .expect("audit batch projection mirror"),
        );
    }
    let successor = SnapshotStoreHeadStateIdentity {
        generation: previous.generation + 1,
        inventory: *after.last().expect("batch projection must be non-empty"),
    };
    (after, successor)
}

fn write_batch_recovery_fixture(
    state: &Path,
    key: &SnapshotStoreHeadStateKey,
    previous: SnapshotStoreHeadStateIdentity,
    successor: SnapshotStoreHeadStateIdentity,
    fixtures: &[&Fixture],
    after: &[security_lab::SnapshotStoreInventoryIdentity],
) {
    assert_eq!(fixtures.len(), after.len());
    let mut bytes = [0u8; BATCH_PENDING_BYTES];
    bytes[0..8].copy_from_slice(&BATCH_PENDING_MAGIC);
    encode_pending_identity(&mut bytes[8..64], previous);
    encode_pending_identity(&mut bytes[64..120], successor);
    bytes[120..128].copy_from_slice(&(fixtures.len() as u64).to_le_bytes());
    for (index, (fixture, inventory)) in fixtures.iter().zip(after.iter()).enumerate() {
        let offset = BATCH_PENDING_FIXED_BYTES + index * BATCH_PENDING_ENTRY_BYTES;
        let slot = &mut bytes[offset..offset + BATCH_PENDING_ENTRY_BYTES];
        slot[0..32].copy_from_slice(&fixture.identity.sha256);
        slot[32..40].copy_from_slice(&fixture.identity.encoded_bytes.to_le_bytes());
        slot[40..48].copy_from_slice(&fixture.identity.nodes.to_le_bytes());
        slot[48..56].copy_from_slice(&(fixture.archive.len() as u64).to_le_bytes());
        slot[56..88].copy_from_slice(&fixture.public_key);
        slot[88..152].copy_from_slice(&fixture.signature);
        slot[152] = 0;
        encode_inventory_fixture(&mut slot[160..208], *inventory);
    }
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("fixed HMAC key is valid");
    mac.update(BATCH_PENDING_DOMAIN);
    mac.update(&bytes[..BATCH_PENDING_HEADER_BYTES]);
    bytes[BATCH_PENDING_HEADER_BYTES..].copy_from_slice(&mac.finalize().into_bytes());

    let pending = batch_pending_path(state);
    fs::write(&pending, bytes).expect("write authenticated batch pending fixture");
    fs::File::open(&pending)
        .expect("open batch pending fixture")
        .sync_all()
        .expect("sync batch pending fixture");

    for (index, fixture) in fixtures.iter().enumerate() {
        let path = batch_stage_path(state, index);
        fs::write(&path, &fixture.archive).expect("write batch recovery stage fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .expect("seal batch recovery stage fixture");
        fs::File::open(&path)
            .expect("open batch recovery stage fixture")
            .sync_all()
            .expect("sync batch recovery stage fixture");
    }
    fs::File::open(state)
        .expect("open head-state directory")
        .sync_all()
        .expect("sync head-state directory after batch fixture");
}

#[test]
fn anchored_publication_advances_once_and_exact_dedup_keeps_same_head() {
    let workspace = TempDir::new("advance");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xA5; 32]);
    let first = fixture(workspace.path(), "first", b"head-state-first\n", 0x51);

    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize empty store head");
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.inventory.objects, 0);

    let inserted = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        publish_request(&first),
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
        publish_request(&first),
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
        publish_request(&first),
    )
    .expect("commit first rollback fixture");
    assert_eq!(committed.successor.inventory.objects, 1);

    let first_path = snapshot_store_object_path(&store, first.identity);
    assert!(
        first_path.exists(),
        "first object should exist before rollback"
    );
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
        publish_request(&second),
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

    let initialized = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
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
        initialize_snapshot_store_head_state(&nested_state, &key, &store, audit_limits(),),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));

    let outer_state = workspace.path().join("outer-state");
    fs::create_dir(&outer_state).expect("create outer state root");
    let nested_store = outer_state.join("nested-store");
    fs::create_dir(&nested_store).expect("create nested store root");
    assert!(matches!(
        initialize_snapshot_store_head_state(&outer_state, &key, &nested_store, audit_limits(),),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));
}

#[test]
fn recovery_clears_pre_store_intent_without_advancing_head() {
    let workspace = TempDir::new("recover-before-store");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x11; 32]);
    let candidate = fixture(
        workspace.path(),
        "recover-before-store",
        b"before-store\n",
        0x11,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize recovery predecessor");
    let successor = projected_successor_fixture(workspace.path(), previous, &candidate);
    write_pending_fixture(&state, &key, previous, successor, &candidate);

    match load_snapshot_store_head_state(&state, &key) {
        Err(SnapshotStoreHeadStateError::RecoveryRequired {
            previous: observed_previous,
            successor: observed_successor,
        }) => {
            assert_eq!(observed_previous, previous);
            assert_eq!(observed_successor, successor);
        }
        Err(other) => panic!("unexpected pending load result: {other}"),
        Ok(_) => panic!("pending publication was ignored"),
    }

    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("recover untouched predecessor"),
        previous
    );
    assert!(!pending_path(&state).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify predecessor after recovery"),
        previous
    );
}

#[test]
fn recovery_advances_head_for_exact_durable_successor() {
    let workspace = TempDir::new("recover-after-store");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x22; 32]);
    let candidate = fixture(
        workspace.path(),
        "recover-after-store",
        b"after-store\n",
        0x22,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize recovery predecessor");
    let successor = projected_successor_fixture(workspace.path(), previous, &candidate);
    write_pending_fixture(&state, &key, previous, successor, &candidate);

    let put = store_snapshot_archive_ed25519_durable(
        &store,
        &candidate.archive,
        &candidate.public_key,
        &candidate.signature,
        archive_limits(),
    )
    .expect("simulate durable object publication before head update");
    assert!(put.inserted);

    assert!(matches!(
        load_snapshot_store_head_state(&state, &key),
        Err(SnapshotStoreHeadStateError::RecoveryRequired { .. })
    ));
    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("recover exact durable successor"),
        successor
    );
    assert!(!pending_path(&state).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify recovered successor"),
        successor
    );
}

#[test]
fn recovery_clears_leftover_intent_after_head_commit() {
    let workspace = TempDir::new("recover-after-head");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x33; 32]);
    let candidate = fixture(
        workspace.path(),
        "recover-after-head",
        b"after-head\n",
        0x33,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize recovery predecessor");
    let committed = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        publish_request(&candidate),
    )
    .expect("commit exact successor before simulating leftover intent");
    assert_eq!(committed.previous, previous);
    write_pending_fixture(&state, &key, previous, committed.successor, &candidate);

    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("clear post-head pending intent"),
        committed.successor
    );
    assert!(!pending_path(&state).exists());
    assert_eq!(
        load_snapshot_store_head_state(&state, &key).expect("load committed successor"),
        committed.successor
    );
}

#[test]
fn recovery_keeps_pending_intent_on_unknown_store_state() {
    let workspace = TempDir::new("recover-diverged");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x44; 32]);
    let expected = fixture(workspace.path(), "recover-expected", b"expected\n", 0x44);
    let unexpected = fixture(
        workspace.path(),
        "recover-unexpected",
        b"unexpected\n",
        0x45,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize recovery predecessor");
    let successor = projected_successor_fixture(workspace.path(), previous, &expected);
    write_pending_fixture(&state, &key, previous, successor, &expected);

    store_snapshot_archive_ed25519_durable(
        &store,
        &unexpected.archive,
        &unexpected.public_key,
        &unexpected.signature,
        archive_limits(),
    )
    .expect("publish unexpected durable store state");

    match key.recover_pending_publication(&state, &store, audit_limits()) {
        Err(SnapshotStoreHeadStateError::PendingStateDiverged {
            previous: observed_previous,
            successor: observed_successor,
            anchored,
            actual,
        }) => {
            assert_eq!(*observed_previous, previous);
            assert_eq!(*observed_successor, successor);
            assert_eq!(anchored, previous);
            assert_ne!(actual, previous.inventory);
            assert_ne!(actual, successor.inventory);
        }
        Err(other) => panic!("unexpected divergent recovery result: {other}"),
        Ok(_) => panic!("unknown durable store state was accepted"),
    }
    assert!(
        pending_path(&state).exists(),
        "divergent recovery must preserve authenticated pending evidence"
    );
    assert!(matches!(
        load_snapshot_store_head_state(&state, &key),
        Err(SnapshotStoreHeadStateError::RecoveryRequired { .. })
    ));
}

#[test]
fn pending_intent_authentication_fails_closed() {
    let workspace = TempDir::new("recover-authentication");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x55; 32]);
    let wrong_key = SnapshotStoreHeadStateKey::new([0x56; 32]);
    let candidate = fixture(
        workspace.path(),
        "recover-authentication",
        b"pending-auth\n",
        0x55,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize recovery predecessor");
    let successor = projected_successor_fixture(workspace.path(), previous, &candidate);
    write_pending_fixture(&state, &key, previous, successor, &candidate);

    assert!(matches!(
        wrong_key.recover_pending_publication(&state, &store, audit_limits()),
        Err(SnapshotStoreHeadStateError::AuthenticationFailed)
    ));
    assert!(pending_path(&state).exists());

    let path = pending_path(&state);
    let mut bytes = fs::read(&path).expect("read pending fixture");
    bytes[24] ^= 0x80;
    fs::write(&path, bytes).expect("tamper pending fixture");
    assert!(matches!(
        key.recover_pending_publication(&state, &store, audit_limits()),
        Err(SnapshotStoreHeadStateError::AuthenticationFailed)
    ));
    assert!(
        path.exists(),
        "tampered pending evidence must not be deleted"
    );
}

const RECOVERY_FSYNC_HELPER_ROOT: &str = "SECURITY_LAB_HEAD_RECOVERY_FSYNC_HELPER_ROOT";

#[test]
fn recovery_fsync_failure_helper() {
    let Some(root) = std::env::var_os(RECOVERY_FSYNC_HELPER_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let store = root.join("store");
    let state = root.join("head-state");
    let key = SnapshotStoreHeadStateKey::new([0x66; 32]);

    match key
        .recover_pending_publication(&state, &store, audit_limits())
        .expect_err("denied fsync must prevent recovered head advancement")
    {
        SnapshotStoreHeadStateError::Transaction(source) => match *source {
            SnapshotStoreTransactionError::Store(SnapshotStoreError::Io { phase, source }) => {
                assert_eq!(phase, "sync durable snapshot object");
                assert_eq!(source.raw_os_error(), Some(libc::EPERM));
            }
            other => panic!("unexpected recovery transaction error: {other}"),
        },
        other => panic!("unexpected denied-fsync recovery result: {other}"),
    }
}

#[test]
fn recovery_requires_durability_barrier_before_advancing_head() {
    let workspace = TempDir::new("recover-durability");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x66; 32]);
    let candidate = fixture(
        workspace.path(),
        "recover-durability",
        b"recover-durability\n",
        0x66,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize durability recovery predecessor");
    let successor = projected_successor_fixture(workspace.path(), previous, &candidate);
    write_pending_fixture(&state, &key, previous, successor, &candidate);

    let put = store_snapshot_archive_ed25519_atomic(
        &store,
        &candidate.archive,
        &candidate.public_key,
        &candidate.signature,
        archive_limits(),
    )
    .expect("simulate visible object before durable acknowledgement");
    assert!(put.inserted);
    assert_eq!(
        snapshot_store_inventory_identity(&store, audit_limits())
            .expect("audit visible successor before recovery"),
        successor.inventory
    );

    let mut command =
        Command::new(std::env::current_exe().expect("resolve current test executable"));
    command
        .arg("--exact")
        .arg("recovery_fsync_failure_helper")
        .arg("--nocapture")
        .env(RECOVERY_FSYNC_HELPER_ROOT, workspace.path());
    unsafe {
        command.pre_exec(install_fsync_deny_filter);
    }
    let status = command
        .status()
        .expect("run denied-fsync recovery helper subprocess");
    assert!(
        status.success(),
        "denied-fsync recovery helper failed: {status}"
    );

    assert!(
        pending_path(&state).exists(),
        "failed recovery must preserve authenticated pending evidence"
    );
    let pending = pending_path(&state);
    let held = state.join("snapshot-store-head-pending.inspect");
    fs::rename(&pending, &held).expect("temporarily move pending evidence for head inspection");
    assert_eq!(
        load_snapshot_store_head_state(&state, &key).expect("load head after denied recovery"),
        previous,
        "denied durability barrier must not advance authenticated head"
    );
    fs::rename(&held, &pending).expect("restore pending evidence after head inspection");

    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("retry recovery with durability barrier available"),
        successor
    );
    assert!(!pending.exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify recovered durable successor"),
        successor
    );
}

fn install_fsync_deny_filter() -> std::io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

    let mut filter = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_fsync as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    let no_new_privs = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if no_new_privs != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seccomp = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    };
    if seccomp != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[test]
fn batch_publication_advances_one_generation_for_two_objects_and_dedups_as_a_unit() {
    let workspace = TempDir::new("batch-success");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x7A; 32]);
    let first = fixture(workspace.path(), "batch-first", b"batch-first\n", 0x31);
    let second = fixture(workspace.path(), "batch-second", b"batch-second\n", 0x32);

    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize batch head");
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.inventory.objects, 0);

    let items = [batch_item(&first), batch_item(&second)];
    let committed = store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &items,
        },
    )
    .expect("publish two-object batch");
    assert_eq!(committed.previous, initial);
    assert_eq!(committed.puts.len(), 2);
    assert!(committed.puts.iter().all(|put| put.inserted));
    assert_eq!(committed.successor.generation, 2);
    assert_eq!(committed.successor.inventory.objects, 2);
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify batch successor"),
        committed.successor
    );
    assert!(
        !batch_pending_path(&state).exists(),
        "successful batch must clear its recovery journal"
    );
    assert!(
        !batch_stage_path(&state, 0).exists() && !batch_stage_path(&state, 1).exists(),
        "successful batch must clear durable recovery stages"
    );

    let dedup_items = [batch_item(&first), batch_item(&second)];
    let dedup = store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &dedup_items,
        },
    )
    .expect("deduplicate full batch");
    assert_eq!(dedup.previous, committed.successor);
    assert_eq!(dedup.successor, committed.successor);
    assert_eq!(dedup.puts.len(), 2);
    assert!(dedup.puts.iter().all(|put| !put.inserted));
}

#[test]
fn batch_mixes_preexisting_and_new_members_under_one_recoverable_transition() {
    let workspace = TempDir::new("batch-mixed");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x7B; 32]);
    let first = fixture(workspace.path(), "mixed-first", b"mixed-first\n", 0x35);
    let second = fixture(workspace.path(), "mixed-second", b"mixed-second\n", 0x36);

    initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize mixed batch head");
    let first_commit = store_snapshot_archive_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        publish_request(&first),
    )
    .expect("publish preexisting mixed-batch member");

    let items = [batch_item(&first), batch_item(&second)];
    let committed = store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &items,
        },
    )
    .expect("publish mixed dedup/new batch");
    assert_eq!(committed.previous, first_commit.successor);
    assert_eq!(
        committed.successor.generation,
        first_commit.successor.generation + 1
    );
    assert_eq!(committed.successor.inventory.objects, 2);
    assert!(!committed.puts[0].inserted);
    assert!(committed.puts[1].inserted);
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify mixed batch successor"),
        committed.successor
    );
    assert!(!batch_pending_path(&state).exists());
    assert!(!batch_stage_path(&state, 0).exists());
    assert!(!batch_stage_path(&state, 1).exists());
}

#[test]
fn batch_pending_authentication_tamper_fails_closed_before_store_mutation() {
    let workspace = TempDir::new("batch-pending-auth");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x7C; 32]);
    let first = fixture(
        workspace.path(),
        "batch-auth-first",
        b"batch-auth-first\n",
        0x37,
    );
    let second = fixture(
        workspace.path(),
        "batch-auth-second",
        b"batch-auth-second\n",
        0x38,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize batch auth head");
    let (after, successor) =
        projected_batch_successor_fixture(workspace.path(), previous, &[&first, &second]);
    write_batch_recovery_fixture(
        &state,
        &key,
        previous,
        successor,
        &[&first, &second],
        &after,
    );

    let pending = batch_pending_path(&state);
    let mut bytes = fs::read(&pending).expect("read batch pending fixture");
    bytes[160] ^= 0x01;
    fs::write(&pending, bytes).expect("tamper batch pending fixture");

    assert!(matches!(
        key.recover_pending_publication(&state, &store, audit_limits()),
        Err(SnapshotStoreHeadStateError::AuthenticationFailed)
    ));
    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert!(!snapshot_store_object_path(&store, second.identity).exists());
    assert!(batch_pending_path(&state).exists());
    assert!(batch_stage_path(&state, 0).exists());
    assert!(batch_stage_path(&state, 1).exists());
}

#[test]
fn batch_prevalidates_every_item_before_first_object_publication() {
    let workspace = TempDir::new("batch-preflight");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x8B; 32]);
    let first = fixture(
        workspace.path(),
        "preflight-first",
        b"preflight-first\n",
        0x41,
    );
    let second = fixture(
        workspace.path(),
        "preflight-second",
        b"preflight-second\n",
        0x42,
    );
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize preflight head");

    let mut bad_signature = second.signature;
    bad_signature[0] ^= 0x80;
    let items = [
        batch_item(&first),
        SnapshotStoreHeadBatchItem {
            archive: &second.archive,
            public_key: &second.public_key,
            expected_signature: &bad_signature,
            archive_limits: archive_limits(),
        },
    ];
    match store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &items,
        },
    ) {
        Err(SnapshotStoreHeadStateError::BatchItemInvalid { index: 1, .. }) => {}
        Err(other) => panic!("unexpected batch prevalidation result: {other}"),
        Ok(_) => panic!("invalid second batch member unexpectedly published"),
    }

    assert!(
        !snapshot_store_object_path(&store, first.identity).exists(),
        "first object was published before later batch prevalidation failed"
    );
    assert!(
        !snapshot_store_object_path(&store, second.identity).exists(),
        "invalid second object was published"
    );
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify unchanged head after batch prevalidation failure"),
        initial
    );
}

#[test]
fn batch_rejects_duplicate_identity_before_store_mutation() {
    let workspace = TempDir::new("batch-duplicate");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x9C; 32]);
    let first = fixture(workspace.path(), "duplicate", b"duplicate-batch\n", 0x52);
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize duplicate head");
    let items = [batch_item(&first), batch_item(&first)];

    assert!(matches!(
        store_snapshot_archives_ed25519_durable_with_head_state(
            &state,
            &key,
            &store,
            SnapshotStoreHeadBatchPublishRequest {
                inventory_limits: audit_limits(),
                items: &items,
            },
        ),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));
    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify unchanged head after duplicate batch"),
        initial
    );
}

#[test]
fn batch_successor_budget_failure_occurs_before_journal_or_store_mutation() {
    let workspace = TempDir::new("batch-budget-preflight");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xAD; 32]);
    let first = fixture(workspace.path(), "budget-first", b"budget-first\n", 0x71);
    let second = fixture(workspace.path(), "budget-second", b"budget-second\n", 0x72);
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize batch budget head");

    let mut successor_limits = audit_limits();
    successor_limits.max_total_archive_bytes = first.archive.len() as u64;
    let items = [batch_item(&first), batch_item(&second)];
    assert!(
        store_snapshot_archives_ed25519_durable_with_head_state(
            &state,
            &key,
            &store,
            SnapshotStoreHeadBatchPublishRequest {
                inventory_limits: successor_limits,
                items: &items,
            },
        )
        .is_err(),
        "successor inventory budget should fail before durable batch staging or publication"
    );

    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert!(!snapshot_store_object_path(&store, second.identity).exists());
    assert!(!batch_pending_path(&state).exists());
    assert!(!batch_stage_path(&state, 0).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify unchanged head after batch budget rejection"),
        initial
    );
}

#[test]
fn batch_recovery_aborts_staged_predecessor_without_store_mutation() {
    let workspace = TempDir::new("batch-recover-predecessor");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xB1; 32]);
    let first = fixture(
        workspace.path(),
        "recover-pre-first",
        b"recover-pre-first\n",
        0x11,
    );
    let second = fixture(
        workspace.path(),
        "recover-pre-second",
        b"recover-pre-second\n",
        0x12,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize batch recovery predecessor");
    let (after, successor) =
        projected_batch_successor_fixture(workspace.path(), previous, &[&first, &second]);
    write_batch_recovery_fixture(
        &state,
        &key,
        previous,
        successor,
        &[&first, &second],
        &after,
    );

    assert!(matches!(
        load_snapshot_store_head_state(&state, &key),
        Err(SnapshotStoreHeadStateError::RecoveryRequired { .. })
    ));
    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("abort staged predecessor batch"),
        previous
    );
    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert!(!snapshot_store_object_path(&store, second.identity).exists());
    assert!(!batch_pending_path(&state).exists());
    assert!(!batch_stage_path(&state, 0).exists());
    assert!(!batch_stage_path(&state, 1).exists());
}

#[test]
fn batch_recovery_completes_exact_partial_durable_prefix() {
    let workspace = TempDir::new("batch-recover-prefix");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xB2; 32]);
    let first = fixture(
        workspace.path(),
        "recover-prefix-first",
        b"recover-prefix-first\n",
        0x21,
    );
    let second = fixture(
        workspace.path(),
        "recover-prefix-second",
        b"recover-prefix-second\n",
        0x22,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize partial-prefix head");
    let (after, successor) =
        projected_batch_successor_fixture(workspace.path(), previous, &[&first, &second]);
    write_batch_recovery_fixture(
        &state,
        &key,
        previous,
        successor,
        &[&first, &second],
        &after,
    );
    store_snapshot_archive_ed25519_durable(
        &store,
        &first.archive,
        &first.public_key,
        &first.signature,
        archive_limits(),
    )
    .expect("simulate first durable batch member before crash");
    assert_eq!(
        snapshot_store_inventory_identity(&store, audit_limits())
            .expect("audit partial batch prefix"),
        after[0]
    );

    assert_eq!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .expect("recover exact partial batch prefix"),
        successor
    );
    assert!(snapshot_store_object_path(&store, first.identity).exists());
    assert!(snapshot_store_object_path(&store, second.identity).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify recovered batch successor"),
        successor
    );
    assert!(!batch_pending_path(&state).exists());
    assert!(!batch_stage_path(&state, 0).exists());
    assert!(!batch_stage_path(&state, 1).exists());
}

#[test]
fn batch_recovery_rejects_unknown_inventory_without_mutating() {
    let workspace = TempDir::new("batch-recover-unknown");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xB3; 32]);
    let first = fixture(
        workspace.path(),
        "recover-unknown-first",
        b"recover-unknown-first\n",
        0x31,
    );
    let second = fixture(
        workspace.path(),
        "recover-unknown-second",
        b"recover-unknown-second\n",
        0x32,
    );
    let outsider = fixture(
        workspace.path(),
        "recover-outsider",
        b"recover-outsider\n",
        0x33,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize unknown-inventory head");
    let (after, successor) =
        projected_batch_successor_fixture(workspace.path(), previous, &[&first, &second]);
    write_batch_recovery_fixture(
        &state,
        &key,
        previous,
        successor,
        &[&first, &second],
        &after,
    );
    store_snapshot_archive_ed25519_durable(
        &store,
        &outsider.archive,
        &outsider.public_key,
        &outsider.signature,
        archive_limits(),
    )
    .expect("publish unrelated unknown store state");

    assert!(matches!(
        key.recover_pending_publication(&state, &store, audit_limits()),
        Err(SnapshotStoreHeadStateError::PendingStateDiverged { .. })
    ));
    assert!(snapshot_store_object_path(&store, outsider.identity).exists());
    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert!(!snapshot_store_object_path(&store, second.identity).exists());
    assert!(batch_pending_path(&state).exists());
    assert!(batch_stage_path(&state, 0).exists());
    assert!(batch_stage_path(&state, 1).exists());
}

#[test]
fn batch_recovery_validates_all_stages_before_forward_replay() {
    let workspace = TempDir::new("batch-recover-stage-tamper");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xB4; 32]);
    let first = fixture(
        workspace.path(),
        "recover-tamper-first",
        b"recover-tamper-first\n",
        0x41,
    );
    let second = fixture(
        workspace.path(),
        "recover-tamper-second",
        b"recover-tamper-second\n",
        0x42,
    );
    let previous = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize stage-tamper head");
    let (after, successor) =
        projected_batch_successor_fixture(workspace.path(), previous, &[&first, &second]);
    write_batch_recovery_fixture(
        &state,
        &key,
        previous,
        successor,
        &[&first, &second],
        &after,
    );
    store_snapshot_archive_ed25519_durable(
        &store,
        &first.archive,
        &first.public_key,
        &first.signature,
        archive_limits(),
    )
    .expect("simulate first durable member before staged tamper");

    let second_stage = batch_stage_path(&state, 1);
    fs::set_permissions(&second_stage, fs::Permissions::from_mode(0o600))
        .expect("make staged fixture writable for corruption");
    let mut tampered = second.archive.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x80;
    fs::write(&second_stage, tampered).expect("tamper second recovery stage");
    fs::set_permissions(&second_stage, fs::Permissions::from_mode(0o400))
        .expect("reseal tampered recovery stage");

    assert!(
        key.recover_pending_publication(&state, &store, audit_limits())
            .is_err(),
        "tampered staged archive must fail before forward replay"
    );
    assert!(snapshot_store_object_path(&store, first.identity).exists());
    assert!(
        !snapshot_store_object_path(&store, second.identity).exists(),
        "recovery mutated the store before validating every staged archive"
    );
    assert!(batch_pending_path(&state).exists());
    assert!(batch_stage_path(&state, 0).exists());
    assert!(batch_stage_path(&state, 1).exists());
}
