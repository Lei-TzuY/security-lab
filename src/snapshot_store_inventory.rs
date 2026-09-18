use crate::snapshot_identity::SnapshotIdentity;
use crate::snapshot_store_audit::{
    audit_snapshot_store_objects, SnapshotStoreAuditError, SnapshotStoreAuditLimits,
    SnapshotStoreAuditReport,
};
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

pub(crate) fn projected_snapshot_store_inventory_identity(
    store_root: &Path,
    limits: SnapshotStoreAuditLimits,
    candidate_identity: SnapshotIdentity,
    candidate_archive_bytes: u64,
) -> Result<
    (
        SnapshotStoreInventoryIdentity,
        SnapshotStoreInventoryIdentity,
    ),
    SnapshotStoreInventoryError,
> {
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
    let current = hash_inventory(report, &records);
    if records
        .iter()
        .any(|record| record.identity == candidate_identity)
    {
        return Ok((current, current));
    }

    let attempted_objects =
        report
            .objects
            .checked_add(1)
            .ok_or(SnapshotStoreAuditError::BudgetExceeded {
                resource: "entry",
                limit: limits.max_entries,
                attempted: u64::MAX,
            })?;
    if attempted_objects > limits.max_entries {
        return Err(SnapshotStoreAuditError::BudgetExceeded {
            resource: "entry",
            limit: limits.max_entries,
            attempted: attempted_objects,
        }
        .into());
    }
    if candidate_archive_bytes > limits.archive.max_archive_bytes {
        return Err(SnapshotStoreAuditError::BudgetExceeded {
            resource: "per-object byte",
            limit: limits.archive.max_archive_bytes,
            attempted: candidate_archive_bytes,
        }
        .into());
    }
    let attempted_archive_bytes = report
        .archive_bytes
        .checked_add(candidate_archive_bytes)
        .ok_or(SnapshotStoreAuditError::BudgetExceeded {
            resource: "aggregate byte",
            limit: limits.max_total_archive_bytes,
            attempted: u64::MAX,
        })?;
    if attempted_archive_bytes > limits.max_total_archive_bytes {
        return Err(SnapshotStoreAuditError::BudgetExceeded {
            resource: "aggregate byte",
            limit: limits.max_total_archive_bytes,
            attempted: attempted_archive_bytes,
        }
        .into());
    }

    if records.try_reserve(1).is_err() {
        return Err(SnapshotStoreInventoryError::AllocationFailed {
            attempted_entries: attempted_objects,
        });
    }
    records.push(InventoryRecord {
        identity: candidate_identity,
        archive_bytes: candidate_archive_bytes,
    });
    records.sort_unstable_by(compare_records);
    let successor = hash_inventory(
        SnapshotStoreAuditReport {
            objects: attempted_objects,
            archive_bytes: attempted_archive_bytes,
        },
        &records,
    );
    Ok((current, successor))
}

/// Project the exact audited inventory that would result from adding one
/// canonical object without mutating the store.
///
/// If the candidate identity is already present, the projected successor is
/// identical to the current inventory; the eventual store path must still
/// perform its byte-for-byte deduplication check. Otherwise the same canonical
/// record ordering, hash domain, and inventory budgets used by the full audit
/// are applied to the synthetic one-object successor.

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
        .then_with(|| {
            left.identity
                .encoded_bytes
                .cmp(&right.identity.encoded_bytes)
        })
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
