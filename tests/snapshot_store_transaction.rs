#![cfg(target_os = "linux")]

use security_lab::{
    serialize_snapshot_archive, sign_snapshot_ed25519, SnapshotArchiveLimits, SnapshotIdentity,
    SnapshotIdentityLimits, SnapshotStoreAuditLimits, SnapshotStoreReadTransaction,
    SnapshotStoreTransactionError, SnapshotStoreTransactionMode, SnapshotStoreWriteTransaction,
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
