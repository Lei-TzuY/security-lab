#![cfg(target_os = "linux")]

use security_lab::{
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_store_inventory_identity,
    snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,
    verify_snapshot_store_inventory_identity, SnapshotArchiveLimits, SnapshotIdentity,
    SnapshotIdentityLimits, SnapshotStoreAuditError, SnapshotStoreAuditLimits,
    SnapshotStoreInventoryError,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-snapshot-store-inventory-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create inventory workspace");
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

fn inventory_limits() -> SnapshotStoreAuditLimits {
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
    fs::create_dir(&source).expect("create inventory source");
    fs::write(source.join("payload"), payload).expect("write inventory payload");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize fixture");
    let signed = sign_snapshot_ed25519(&source, &[signing_byte; 32], identity_limits())
        .expect("sign fixture");
    assert_eq!(archive.identity, signed.snapshot);
    Fixture {
        identity: archive.identity,
        archive: archive.bytes,
        public_key: signed.public_key,
        signature: signed.signature,
    }
}

fn put(store: &Path, fixture: &Fixture) {
    let report = store_snapshot_archive_ed25519_atomic(
        store,
        &fixture.archive,
        &fixture.public_key,
        &fixture.signature,
        archive_limits(),
    )
    .expect("store inventory fixture");
    assert_eq!(report.identity, fixture.identity);
}

#[test]
fn inventory_identity_is_repeatable_and_creation_order_independent() {
    let workspace = TempDir::new("order");
    let store_a = workspace.path().join("store-a");
    let store_b = workspace.path().join("store-b");
    fs::create_dir(&store_a).expect("create store a");
    fs::create_dir(&store_b).expect("create store b");
    let first = fixture(workspace.path(), "first", b"inventory-first\n", 0x31);
    let second = fixture(
        workspace.path(),
        "second",
        b"inventory-second-is-different\n",
        0x32,
    );

    put(&store_a, &first);
    put(&store_a, &second);
    put(&store_b, &second);
    put(&store_b, &first);

    let identity_a =
        snapshot_store_inventory_identity(&store_a, inventory_limits()).expect("inventory a");
    let identity_a_again =
        snapshot_store_inventory_identity(&store_a, inventory_limits()).expect("inventory a again");
    let identity_b =
        snapshot_store_inventory_identity(&store_b, inventory_limits()).expect("inventory b");
    assert_eq!(identity_a, identity_a_again);
    assert_eq!(identity_a, identity_b);
    assert_eq!(identity_a.objects, 2);
    assert_eq!(identity_a.archive_bytes, 198);
    assert_eq!(
        identity_a.sha256_hex(),
        "74ac767d1be69f143d68b88a8202214af6cf464aa2307b4397f84eb9baef0af1"
    );
}

#[test]
fn externally_retained_expected_identity_detects_membership_addition_and_deletion() {
    let workspace = TempDir::new("membership");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create membership store");
    let first = fixture(workspace.path(), "member-a", b"member-a\n", 0x41);
    let second = fixture(workspace.path(), "member-b", b"member-b\n", 0x42);

    put(&store, &first);
    let one_object = snapshot_store_inventory_identity(&store, inventory_limits())
        .expect("one-object inventory");
    put(&store, &second);
    let two_objects = snapshot_store_inventory_identity(&store, inventory_limits())
        .expect("two-object inventory");
    assert_ne!(one_object, two_objects);
    assert_eq!(two_objects.objects, 2);
    verify_snapshot_store_inventory_identity(&store, two_objects, inventory_limits())
        .expect("verify current two-object inventory");

    fs::remove_file(snapshot_store_object_path(&store, first.identity))
        .expect("remove one stored object");
    match verify_snapshot_store_inventory_identity(&store, two_objects, inventory_limits())
        .unwrap_err()
    {
        SnapshotStoreInventoryError::IdentityMismatch { expected, actual } => {
            assert_eq!(expected, two_objects);
            assert_eq!(actual.objects, 1);
            assert_ne!(actual, expected);
        }
        other => panic!("unexpected deletion verification result: {other}"),
    }
}

#[test]
fn inventory_identity_propagates_existing_store_integrity_failures() {
    let workspace = TempDir::new("tamper");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create tamper store");
    let fixture = fixture(
        workspace.path(),
        "tamper",
        b"inventory-tamper-payload\n",
        0x51,
    );
    put(&store, &fixture);
    let object = snapshot_store_object_path(&store, fixture.identity);
    let payload = b"inventory-tamper-payload\n";
    let mut bytes = fs::read(&object).expect("read object to tamper");
    let offset = bytes
        .windows(payload.len())
        .position(|window| window == payload)
        .expect("find payload bytes");
    bytes[offset] ^= 0x01;
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600))
        .expect("temporarily make object writable");
    fs::write(&object, bytes).expect("tamper object bytes");
    fs::set_permissions(&object, fs::Permissions::from_mode(0o444)).expect("restore object mode");

    match snapshot_store_inventory_identity(&store, inventory_limits()).unwrap_err() {
        SnapshotStoreInventoryError::Audit(SnapshotStoreAuditError::IdentityMismatch {
            expected,
            actual,
            ..
        }) => {
            assert_eq!(expected, fixture.identity);
            assert_ne!(actual, fixture.identity);
        }
        other => panic!("unexpected tamper inventory result: {other}"),
    }
}
