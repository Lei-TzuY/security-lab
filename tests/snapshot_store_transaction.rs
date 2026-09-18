#![cfg(target_os = "linux")]

use security_lab::{
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_store_object_path,
    SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits, SnapshotStoreAuditLimits,
    SnapshotStoreReadTransaction, SnapshotStoreTransactionError, SnapshotStoreTransactionMode,
    SnapshotStoreWriteTransaction,
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
            "security-lab-snapshot-store-transaction-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create transaction workspace");
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
    fs::create_dir(&source).expect("create transaction source");
    fs::write(source.join("payload"), payload).expect("write transaction payload");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize fixture");
    let signed = sign_snapshot_ed25519(&source, &[signing_byte; 32], identity_limits())
        .expect("sign transaction fixture");
    assert_eq!(archive.identity, signed.snapshot);
    Fixture {
        identity: archive.identity,
        archive: archive.bytes,
        public_key: signed.public_key,
        signature: signed.signature,
    }
}

fn assert_contended<T>(
    result: Result<T, SnapshotStoreTransactionError>,
    mode: SnapshotStoreTransactionMode,
) {
    match result {
        Err(SnapshotStoreTransactionError::LockContended { requested }) => {
            assert_eq!(requested, mode);
        }
        Err(other) => panic!("unexpected transaction lock result: {other}"),
        Ok(_) => panic!("transaction lock unexpectedly succeeded"),
    }
}

#[test]
fn shared_read_transactions_exclude_write_and_write_excludes_read() {
    let workspace = TempDir::new("locking");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create transaction store");

    let first_reader = SnapshotStoreReadTransaction::begin(&store).expect("begin first read");
    let second_reader =
        SnapshotStoreReadTransaction::try_begin(&store).expect("shared read lock should coexist");
    assert_contended(
        SnapshotStoreWriteTransaction::try_begin(&store),
        SnapshotStoreTransactionMode::Write,
    );
    drop(second_reader);
    drop(first_reader);

    let writer = SnapshotStoreWriteTransaction::try_begin(&store).expect("begin exclusive write");
    assert_contended(
        SnapshotStoreReadTransaction::try_begin(&store),
        SnapshotStoreTransactionMode::Read,
    );
    assert_contended(
        SnapshotStoreWriteTransaction::try_begin(&store),
        SnapshotStoreTransactionMode::Write,
    );
    drop(writer);

    SnapshotStoreReadTransaction::try_begin(&store)
        .expect("read lock should succeed after writer release");
}

#[test]
fn serialized_publication_linearizes_complete_inventory_states() {
    let workspace = TempDir::new("inventory");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create inventory store");
    let first = fixture(workspace.path(), "first", b"transaction-first\n", 0x61);
    let second = fixture(
        workspace.path(),
        "second",
        b"transaction-second-is-distinct\n",
        0x62,
    );

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin first writer");
        let report = writer
            .store_ed25519_durable(
                &first.archive,
                &first.public_key,
                &first.signature,
                archive_limits(),
            )
            .expect("publish first object durably");
        assert!(report.inserted);
        assert_eq!(report.identity, first.identity);
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
    }

    let one_object = {
        let reader = SnapshotStoreReadTransaction::begin(&store).expect("begin inventory reader");
        let inventory = reader
            .inventory_identity(audit_limits())
            .expect("read one-object inventory");
        assert_eq!(inventory.objects, 1);
        reader
            .verify_inventory_identity(inventory, audit_limits())
            .expect("verify one-object inventory inside same read transaction");
        assert_contended(
            SnapshotStoreWriteTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Write,
        );
        inventory
    };

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin second writer");
        let report = writer
            .store_ed25519_durable(
                &second.archive,
                &second.public_key,
                &second.signature,
                archive_limits(),
            )
            .expect("publish second object durably");
        assert!(report.inserted);
        assert_eq!(report.identity, second.identity);
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
    }

    let reader = SnapshotStoreReadTransaction::begin(&store).expect("begin final inventory reader");
    let two_objects = reader
        .inventory_identity(audit_limits())
        .expect("read two-object inventory");
    assert_eq!(two_objects.objects, 2);
    assert_ne!(two_objects, one_object);
    let audit = reader.audit(audit_limits()).expect("audit final inventory");
    assert_eq!(audit.objects, 2);
    assert_eq!(audit.archive_bytes, two_objects.archive_bytes);
}

#[test]
fn inventory_guarded_write_rejects_stale_base_then_publishes_matching_successor() {
    let workspace = TempDir::new("guarded-inventory");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create guarded inventory store");
    let first = fixture(workspace.path(), "guard-first", b"guard-first\n", 0x71);
    let second = fixture(workspace.path(), "guard-second", b"guard-second\n", 0x72);
    let third = fixture(workspace.path(), "guard-third", b"guard-third\n", 0x73);

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin first writer");
        writer
            .store_ed25519_durable(
                &first.archive,
                &first.public_key,
                &first.signature,
                archive_limits(),
            )
            .expect("publish first guarded fixture");
    }

    let one_object = {
        let reader = SnapshotStoreReadTransaction::begin(&store).expect("capture base inventory");
        reader
            .inventory_identity(audit_limits())
            .expect("read one-object base inventory")
    };
    assert_eq!(one_object.objects, 1);

    {
        let writer =
            SnapshotStoreWriteTransaction::begin(&store).expect("begin intervening writer");
        writer
            .store_ed25519_durable(
                &second.archive,
                &second.public_key,
                &second.signature,
                archive_limits(),
            )
            .expect("publish intervening object");
    }

    let two_objects = {
        let reader = SnapshotStoreReadTransaction::begin(&store).expect("read advanced inventory");
        reader
            .inventory_identity(audit_limits())
            .expect("read two-object inventory")
    };
    assert_eq!(two_objects.objects, 2);
    assert_ne!(two_objects, one_object);

    {
        let writer =
            SnapshotStoreWriteTransaction::begin(&store).expect("begin stale guarded writer");
        match writer.store_ed25519_durable_if_inventory(
            one_object,
            audit_limits(),
            &third.archive,
            &third.public_key,
            &third.signature,
            archive_limits(),
        ) {
            Err(SnapshotStoreTransactionError::InventoryConflict { expected, actual }) => {
                assert_eq!(expected, one_object);
                assert_eq!(actual, two_objects);
            }
            Err(other) => panic!("unexpected stale guarded write result: {other}"),
            Ok(_) => panic!("stale guarded write unexpectedly published"),
        }
        assert!(
            !snapshot_store_object_path(&store, third.identity).exists(),
            "stale guarded write published the candidate object"
        );
        assert_eq!(
            writer
                .inventory_identity(audit_limits())
                .expect("re-read inventory under stale writer lock"),
            two_objects
        );
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
    }

    let three_objects = {
        let writer =
            SnapshotStoreWriteTransaction::begin(&store).expect("begin matching guarded writer");
        let report = writer
            .store_ed25519_durable_if_inventory(
                two_objects,
                audit_limits(),
                &third.archive,
                &third.public_key,
                &third.signature,
                archive_limits(),
            )
            .expect("publish with matching inventory precondition");
        assert!(report.inserted);
        assert_eq!(report.identity, third.identity);
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
        writer
            .inventory_identity(audit_limits())
            .expect("read successor inventory under same write lock")
    };

    assert_eq!(three_objects.objects, 3);
    assert_ne!(three_objects, two_objects);
    let reader = SnapshotStoreReadTransaction::begin(&store).expect("begin final inventory reader");
    assert_eq!(
        reader
            .inventory_identity(audit_limits())
            .expect("read final guarded inventory"),
        three_objects
    );
}
