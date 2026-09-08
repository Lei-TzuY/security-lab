//! Small, correctness-first process sandbox used by the security lab.
//!
//! The policy model is platform-neutral. Enforcement is delegated to a
//! platform layer which either applies every requested boundary or fails.

mod cancellation;
mod cow_diff_apply;
mod platform;
pub mod policy;
pub mod report;
mod snapshot_archive;
mod snapshot_auth;
mod snapshot_identity;
mod snapshot_signature;
mod snapshot_store;
mod snapshot_store_durable;
mod snapshot_trust;

use std::error::Error;
use std::fmt;

pub use cancellation::CancellationToken;
pub use cow_diff_apply::{
    apply_cow_diff_atomic, apply_cow_diff_atomic_with_expected_base, CowDiffApplyBoundReport,
    CowDiffApplyError, CowDiffApplyLimits, CowDiffApplyReport,
};
pub use policy::{
    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRangeRule, SeccompArgRule, SeccompPolicy,
    StdioMode, StdioPolicy,
};
pub use report::{
    CapturedOutput, ChildOutcome, CowDiff, CowDiffEntry, EnforcementReceipt, ProcessTreeUsage,
    RunReport,
};
pub use snapshot_archive::{
    materialize_snapshot_archive_atomic, materialize_snapshot_archive_ed25519_atomic,
    serialize_snapshot_archive, snapshot_archive_identity, SnapshotArchive, SnapshotArchiveError,
    SnapshotArchiveLimits, SnapshotArchiveMaterializeReport,
};
pub use snapshot_auth::{
    snapshot_hmac_sha256, verify_snapshot_hmac_sha256, SnapshotHmac, SnapshotHmacError,
    SNAPSHOT_HMAC_KEY_BYTES,
};
pub use snapshot_identity::{
    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,
};
pub use snapshot_signature::{
    sign_snapshot_ed25519, verify_snapshot_ed25519, SnapshotEd25519Error, SnapshotEd25519Signature,
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
    SNAPSHOT_ED25519_SIGNING_KEY_BYTES,
};
pub use snapshot_store::{
    materialize_snapshot_store_object_ed25519_atomic, snapshot_store_object_path,
    store_snapshot_archive_ed25519_atomic, SnapshotStoreError, SnapshotStorePutReport,
};
pub use snapshot_store_durable::store_snapshot_archive_ed25519_durable;
pub use snapshot_trust::{
    materialize_snapshot_store_object_trusted_ed25519_atomic,
    store_snapshot_archive_trusted_ed25519_durable, SnapshotTrustDecision, SnapshotTrustError,
    SnapshotTrustKey, SnapshotTrustKeyId, SnapshotTrustKeyState, SnapshotTrustPolicy,
    SnapshotTrustPolicyIdentity, SnapshotTrustedMaterializeReport, SnapshotTrustedStorePutReport,
    SNAPSHOT_TRUST_MAX_KEYS,
};

#[derive(Debug)]
pub enum SandboxError {
    InvalidPolicy(PolicyError),
    UnsupportedPlatform(String),
    SetupFailed(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(err) => write!(f, "invalid policy: {err}"),
            Self::UnsupportedPlatform(message) => write!(f, "unsupported platform: {message}"),
            Self::SetupFailed(message) => write!(f, "sandbox setup failed: {message}"),
        }
    }
}

impl Error for SandboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPolicy(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PolicyError> for SandboxError {
    fn from(value: PolicyError) -> Self {
        Self::InvalidPolicy(value)
    }
}

/// Validate and execute exactly the invocation described by `policy`,
/// returning terminal status plus any launcher-owned captured output.
pub fn run_report(policy: &SandboxPolicy) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, None)
}

/// Validate and execute the invocation while allowing another thread holding a
/// clone of `cancellation` to request launcher-owned process-tree termination.
pub fn run_report_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, Some(cancellation))
}

/// Validate and execute exactly the invocation described by `policy`.
///
/// This status-only compatibility API still drains any configured capture pipe
/// through `run_report`, then discards the retained bytes. A setup error is
/// terminal; execution never retries without the requested restrictions.
pub fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report(policy)?.outcome)
}

/// Status-only counterpart to [`run_report_with_cancel`].
pub fn run_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report_with_cancel(policy, cancellation)?.outcome)
}
