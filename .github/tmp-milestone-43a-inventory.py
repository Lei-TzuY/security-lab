from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Reuse the exact 42A audited-object traversal instead of creating a second filesystem walker.
replace_once(
    "src/snapshot_store_audit.rs",
    '''pub fn audit_snapshot_store(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError> {
    validate_store_root(store_root)?;
    validate_limits(limits)?;

    #[cfg(target_os = "linux")]
    {
        linux::audit(store_root, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, limits);
        Err(SnapshotStoreAuditError::UnsupportedPlatform(
            "snapshot-store integrity audit currently requires Linux fd-relative directory enumeration and O_NOFOLLOW object access"
                .to_owned(),
        ))
    }
}
''',
    '''pub fn audit_snapshot_store(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError> {
    audit_snapshot_store_objects(store_root, limits, |_, _| {})
}

pub(crate) fn audit_snapshot_store_objects<F>(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
    mut on_object: F,
) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError>
where
    F: FnMut(SnapshotIdentity, u64),
{
    validate_store_root(store_root)?;
    validate_limits(limits)?;

    #[cfg(target_os = "linux")]
    {
        linux::audit(store_root, limits, &mut on_object)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, limits, &mut on_object);
        Err(SnapshotStoreAuditError::UnsupportedPlatform(
            "snapshot-store integrity audit currently requires Linux fd-relative directory enumeration and O_NOFOLLOW object access"
                .to_owned(),
        ))
    }
}
''',
    "audit observer wrapper",
)

replace_once(
    "src/snapshot_store_audit.rs",
    '''    use super::{
        audit_archive, invalid_name, parse_object_filename, SnapshotStoreAuditError,
        SnapshotStoreAuditLimits, SnapshotStoreAuditReport,
    };
''',
    '''    use super::{
        audit_archive, invalid_name, parse_object_filename, SnapshotIdentity, SnapshotStoreAuditError,
        SnapshotStoreAuditLimits, SnapshotStoreAuditReport,
    };
''',
    "linux audit imports",
)

replace_once(
    "src/snapshot_store_audit.rs",
    '''    pub(super) fn audit(
        store_root: &Path,
        limits: SnapshotStoreAuditLimits,
    ) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError> {
''',
    '''    pub(super) fn audit<F>(
        store_root: &Path,
        limits: SnapshotStoreAuditLimits,
        on_object: &mut F,
    ) -> Result<SnapshotStoreAuditReport, SnapshotStoreAuditError>
    where
        F: FnMut(SnapshotIdentity, u64),
    {
''',
    "linux audit observer signature",
)

replace_once(
    "src/snapshot_store_audit.rs",
    '''            if actual != expected {
                return Err(SnapshotStoreAuditError::IdentityMismatch {
                    name: name_text,
                    expected,
                    actual,
                });
            }
            total_bytes = attempted_total;
            object_count += 1;
''',
    '''            if actual != expected {
                return Err(SnapshotStoreAuditError::IdentityMismatch {
                    name: name_text,
                    expected,
                    actual,
                });
            }
            on_object(actual, size);
            total_bytes = attempted_total;
            object_count += 1;
''',
    "audited object callback",
)

# Export the new inventory identity layer.
replace_once(
    "src/lib.rs",
    "mod snapshot_store_durable;\n",
    "mod snapshot_store_durable;\nmod snapshot_store_inventory;\n",
    "inventory module declaration",
)
replace_once(
    "src/lib.rs",
    "pub use snapshot_store_durable::store_snapshot_archive_ed25519_durable;\n",
    '''pub use snapshot_store_durable::store_snapshot_archive_ed25519_durable;
pub use snapshot_store_inventory::{
    snapshot_store_inventory_identity, verify_snapshot_store_inventory_identity,
    SnapshotStoreInventoryError, SnapshotStoreInventoryIdentity,
};
''',
    "inventory public exports",
)

Path("src/snapshot_store_inventory.rs").write_text(r'''use crate::snapshot_store_audit::{
    audit_snapshot_store_objects, SnapshotStoreAuditError, SnapshotStoreAuditLimits,
    SnapshotStoreAuditReport,
};
use crate::snapshot_identity::SnapshotIdentity;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::error::Error;
use std::fmt;
use std::path::Path;

const INVENTORY_DOMAIN: &[u8] = b"security-lab-snapshot-store-inventory-v1\0";

/// Deterministic identity of one successfully audited snapshot-store inventory.
///
/// The digest covers a versioned domain, exact object count, aggregate archive
/// bytes, and every audited object record in canonical identity order. This is
/// an unkeyed integrity fingerprint, not signer authentication or rollback
/// protection by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreInventoryIdentity {
    pub sha256: [u8; 32],
    pub objects: u64,
    pub archive_bytes: u64,
}

impl SnapshotStoreInventoryIdentity {
    pub fn sha256_hex(&self) -> String {
        let mut text = String::with_capacity(64);
        for byte in self.sha256 {
            use std::fmt::Write as _;
            write!(&mut text, "{byte:02x}").expect("writing to String cannot fail");
        }
        text
    }
}

#[derive(Debug)]
pub enum SnapshotStoreInventoryError {
    Audit(SnapshotStoreAuditError),
    AllocationFailed {
        attempted_entries: u64,
    },
    IdentityMismatch {
        expected: SnapshotStoreInventoryIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
}

impl fmt::Display for SnapshotStoreInventoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Audit(source) => write!(f, "snapshot store inventory audit failed: {source}"),
            Self::AllocationFailed { attempted_entries } => write!(
                f,
                "snapshot store inventory metadata allocation failed at entry {attempted_entries}"
            ),
            Self::IdentityMismatch { expected, actual } => write!(
                f,
                "snapshot store inventory identity mismatch: expected {} objects={} bytes={} actual {} objects={} bytes={}",
                expected.sha256_hex(),
                expected.objects,
                expected.archive_bytes,
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
        }
    }
}

impl Error for SnapshotStoreInventoryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Audit(source) => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotStoreAuditError> for SnapshotStoreInventoryError {
    fn from(value: SnapshotStoreAuditError) -> Self {
        Self::Audit(value)
    }
}

#[derive(Debug, Clone, Copy)]
struct InventoryRecord {
    identity: SnapshotIdentity,
    archive_bytes: u64,
}

/// Audit the complete observed store and derive a deterministic inventory
/// fingerprint independent of filesystem directory-enumeration order.
///
/// Every included record has already crossed the exact 42A object-safety and
/// canonical-archive identity gates. The fixed-width records are sorted by the
/// complete canonical identity tuple before hashing, then include the exact
/// archive byte length as additional store-layout evidence.
pub fn snapshot_store_inventory_identity(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreInventoryIdentity, SnapshotStoreInventoryError> {
    let mut records = Vec::new();
    let mut allocation_failure = None;
    let report = audit_snapshot_store_objects(store_root, limits, |identity, archive_bytes| {
        if allocation_failure.is_some() {
            return;
        }
        let attempted_entries = u64::try_from(records.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if records.try_reserve(1).is_err() {
            allocation_failure = Some(attempted_entries);
            return;
        }
        records.push(InventoryRecord {
            identity,
            archive_bytes,
        });
    })?;

    if let Some(attempted_entries) = allocation_failure {
        return Err(SnapshotStoreInventoryError::AllocationFailed { attempted_entries });
    }

    records.sort_unstable_by(compare_records);
    Ok(hash_inventory(report, &records))
}

/// Recompute the bounded audited inventory and require exact equality with a
/// caller-retained expected identity.
///
/// The expected identity is trusted input to this comparison. Persisting it in
/// the same rollbackable store does not create rollback resistance; callers that
/// need cross-run change detection must retain it in an independently trusted
/// location or state channel.
pub fn verify_snapshot_store_inventory_identity(
    store_root: &Path,
    expected: SnapshotStoreInventoryIdentity,
    limits: SnapshotStoreAuditLimits,
) -> Result<SnapshotStoreAuditReport, SnapshotStoreInventoryError> {
    let actual = snapshot_store_inventory_identity(store_root, limits)?;
    if actual != expected {
        return Err(SnapshotStoreInventoryError::IdentityMismatch { expected, actual });
    }
    Ok(SnapshotStoreAuditReport {
        objects: actual.objects,
        archive_bytes: actual.archive_bytes,
    })
}

fn compare_records(left: &InventoryRecord, right: &InventoryRecord) -> Ordering {
    left.identity
        .sha256
        .cmp(&right.identity.sha256)
        .then_with(|| left.identity.encoded_bytes.cmp(&right.identity.encoded_bytes))
        .then_with(|| left.identity.nodes.cmp(&right.identity.nodes))
        .then_with(|| left.archive_bytes.cmp(&right.archive_bytes))
}

fn hash_inventory(
    report: SnapshotStoreAuditReport,
    records: &[InventoryRecord],
) -> SnapshotStoreInventoryIdentity {
    let mut hasher = Sha256::new();
    hasher.update(INVENTORY_DOMAIN);
    hasher.update(report.objects.to_le_bytes());
    hasher.update(report.archive_bytes.to_le_bytes());
    for record in records {
        hasher.update(record.identity.sha256);
        hasher.update(record.identity.encoded_bytes.to_le_bytes());
        hasher.update(record.identity.nodes.to_le_bytes());
        hasher.update(record.archive_bytes.to_le_bytes());
    }
    let digest = hasher.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest);
    SnapshotStoreInventoryIdentity {
        sha256,
        objects: report.objects,
        archive_bytes: report.archive_bytes,
    }
}
''')

Path("tests/snapshot_store_inventory.rs").write_text(r'''#![cfg(target_os = "linux")]

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
    let second = fixture(workspace.path(), "second", b"inventory-second-is-different\n", 0x32);

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
    assert_eq!(identity_a.sha256_hex().len(), 64);
}

#[test]
fn externally_retained_expected_identity_detects_membership_addition_and_deletion() {
    let workspace = TempDir::new("membership");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create membership store");
    let first = fixture(workspace.path(), "member-a", b"member-a\n", 0x41);
    let second = fixture(workspace.path(), "member-b", b"member-b\n", 0x42);

    put(&store, &first);
    let one_object =
        snapshot_store_inventory_identity(&store, inventory_limits()).expect("one-object inventory");
    put(&store, &second);
    let two_objects =
        snapshot_store_inventory_identity(&store, inventory_limits()).expect("two-object inventory");
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
    let fixture = fixture(workspace.path(), "tamper", b"inventory-tamper-payload\n", 0x51);
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
    fs::set_permissions(&object, fs::Permissions::from_mode(0o444))
        .expect("restore object mode");

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
''')
