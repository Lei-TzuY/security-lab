#![cfg(target_os = "linux")]

use security_lab::{
    audit_snapshot_store, serialize_snapshot_archive, sign_snapshot_ed25519,
    snapshot_store_object_path, store_snapshot_archive_ed25519_atomic, SnapshotArchiveLimits,
    SnapshotIdentity, SnapshotIdentityLimits, SnapshotStoreAuditError, SnapshotStoreAuditLimits,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-snapshot-store-audit-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create store-audit workspace");
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

fn store_fixture(
    workspace: &Path,
    store: &Path,
    label: &str,
    payload: &[u8],
    signing_byte: u8,
) -> (SnapshotIdentity, u64) {
    let source = workspace.join(format!("source-{label}"));
    fs::create_dir(&source).expect("create audit source");
    fs::write(source.join("payload"), payload).expect("write audit payload");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize fixture");
    let signed = sign_snapshot_ed25519(&source, &[signing_byte; 32], identity_limits())
        .expect("sign fixture");
    assert_eq!(archive.identity, signed.snapshot);
    let report = store_snapshot_archive_ed25519_atomic(
        store,
        &archive.bytes,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect("store fixture");
    assert_eq!(report.identity, archive.identity);
    (archive.identity, report.archive_bytes)
}

fn different_identity(identity: SnapshotIdentity) -> SnapshotIdentity {
    let mut sha256 = identity.sha256;
    sha256[0] ^= 0x80;
    SnapshotIdentity {
        sha256,
        encoded_bytes: identity.encoded_bytes,
        nodes: identity.nodes,
    }
}

#[test]
fn healthy_multi_object_store_audits_exact_inventory() {
    let workspace = TempDir::new("healthy");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (_, bytes_a) = store_fixture(workspace.path(), &store, "a", b"audit-object-a\n", 0x31);
    let (_, bytes_b) = store_fixture(
        workspace.path(),
        &store,
        "b",
        b"audit-object-b-is-different\n",
        0x32,
    );

    let report = audit_snapshot_store(&store, audit_limits()).expect("audit healthy store");
    assert_eq!(report.objects, 2);
    assert_eq!(report.archive_bytes, bytes_a + bytes_b);
}

#[test]
fn content_tamper_is_detected_as_identity_mismatch() {
    let workspace = TempDir::new("tamper");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let payload = b"audit-tamper-payload\n";
    let (identity, _) = store_fixture(workspace.path(), &store, "tamper", payload, 0x41);
    let object = snapshot_store_object_path(&store, identity);
    let mut bytes = fs::read(&object).expect("read stored object");
    let offset = bytes
        .windows(payload.len())
        .position(|window| window == payload)
        .expect("locate payload bytes in canonical archive");
    bytes[offset] ^= 0x01;
    fs::set_permissions(&object, fs::Permissions::from_mode(0o600))
        .expect("temporarily make fixture writable");
    fs::write(&object, bytes).expect("tamper stored object");
    fs::set_permissions(&object, fs::Permissions::from_mode(0o444))
        .expect("restore read-only mode");

    match audit_snapshot_store(&store, audit_limits()).unwrap_err() {
        SnapshotStoreAuditError::IdentityMismatch {
            expected, actual, ..
        } => {
            assert_eq!(expected, identity);
            assert_ne!(actual, identity);
        }
        other => panic!("unexpected tamper audit result: {other}"),
    }
}

#[test]
fn canonical_filename_must_match_archive_identity() {
    let workspace = TempDir::new("filename-mismatch");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (actual_identity, _) = store_fixture(
        workspace.path(),
        &store,
        "rename",
        b"filename-mismatch-payload\n",
        0x51,
    );
    let expected_identity = different_identity(actual_identity);
    let original = snapshot_store_object_path(&store, actual_identity);
    let renamed = snapshot_store_object_path(&store, expected_identity);
    fs::rename(&original, &renamed).expect("rename object under different canonical address");

    match audit_snapshot_store(&store, audit_limits()).unwrap_err() {
        SnapshotStoreAuditError::IdentityMismatch {
            expected, actual, ..
        } => {
            assert_eq!(expected, expected_identity);
            assert_eq!(actual, actual_identity);
        }
        other => panic!("unexpected filename mismatch result: {other}"),
    }
}

#[test]
fn symlink_entry_is_rejected_without_following_it() {
    let workspace = TempDir::new("symlink");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (identity, _) = store_fixture(
        workspace.path(),
        &store,
        "base",
        b"safe-base-object\n",
        0x61,
    );
    let unsafe_identity = different_identity(identity);
    let unsafe_path = snapshot_store_object_path(&store, unsafe_identity);
    symlink("/etc/passwd", &unsafe_path).expect("create unsafe store symlink");

    match audit_snapshot_store(&store, audit_limits()).unwrap_err() {
        SnapshotStoreAuditError::UnsafeObject { reason, .. } => {
            assert!(reason.contains("regular file"));
        }
        other => panic!("unexpected symlink audit result: {other}"),
    }
}

#[test]
fn writable_object_is_rejected_even_when_archive_identity_is_valid() {
    let workspace = TempDir::new("writable-object");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (identity, _) = store_fixture(
        workspace.path(),
        &store,
        "writable",
        b"writable-object-payload\n",
        0x62,
    );
    let object = snapshot_store_object_path(&store, identity);
    fs::set_permissions(&object, fs::Permissions::from_mode(0o644))
        .expect("make stored object writable");

    match audit_snapshot_store(&store, audit_limits()).unwrap_err() {
        SnapshotStoreAuditError::UnsafeObject { reason, .. } => {
            assert!(reason.contains("write permission"));
        }
        other => panic!("unexpected writable-object audit result: {other}"),
    }
}

#[test]
fn hard_linked_object_is_rejected_even_when_archive_identity_is_valid() {
    let workspace = TempDir::new("hard-link");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (identity, _) = store_fixture(
        workspace.path(),
        &store,
        "hard-link",
        b"hard-linked-object-payload\n",
        0x63,
    );
    let object = snapshot_store_object_path(&store, identity);
    let alias = workspace.path().join("outside-store-object-alias");
    fs::hard_link(&object, &alias).expect("create second hard link to stored object");

    match audit_snapshot_store(&store, audit_limits()).unwrap_err() {
        SnapshotStoreAuditError::UnsafeObject { reason, .. } => {
            assert!(reason.contains("hard link"));
        }
        other => panic!("unexpected hard-link audit result: {other}"),
    }
}

#[test]
fn audit_budgets_fail_closed_before_unbounded_inventory_work() {
    let workspace = TempDir::new("budget");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let (_, first_bytes) = store_fixture(workspace.path(), &store, "one", b"budget-one\n", 0x71);
    store_fixture(workspace.path(), &store, "two", b"budget-two\n", 0x72);

    let mut limits = audit_limits();
    limits.max_entries = 1;
    match audit_snapshot_store(&store, limits).unwrap_err() {
        SnapshotStoreAuditError::BudgetExceeded {
            resource,
            limit,
            attempted,
        } => {
            assert_eq!(resource, "entry");
            assert_eq!(limit, 1);
            assert_eq!(attempted, 2);
        }
        other => panic!("unexpected entry-budget result: {other}"),
    }

    let mut limits = audit_limits();
    limits.max_total_archive_bytes = first_bytes.saturating_sub(1);
    match audit_snapshot_store(&store, limits).unwrap_err() {
        SnapshotStoreAuditError::BudgetExceeded {
            resource,
            limit,
            attempted,
        } => {
            assert_eq!(resource, "aggregate byte");
            assert_eq!(limit, first_bytes - 1);
            assert!(attempted >= first_bytes);
        }
        other => panic!("unexpected aggregate-budget result: {other}"),
    }
}
