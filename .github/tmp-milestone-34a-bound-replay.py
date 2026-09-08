from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Production: bind the existing atomic replay to the existing canonical snapshot identity.
replace_one(
    "src/cow_diff_apply.rs",
    "use crate::{CowDiff, CowDiffEntry};\n",
    "use crate::snapshot_identity::{\n    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,\n};\nuse crate::{CowDiff, CowDiffEntry};\n",
    "cow apply identity imports",
)

replace_one(
    "src/cow_diff_apply.rs",
    """pub struct CowDiffApplyReport {\n    pub copied_base_bytes: u64,\n    pub diff_encoded_bytes: u64,\n    pub accounted_nodes: u64,\n}\n\n#[derive(Debug)]\npub enum CowDiffApplyError {\n""",
    """pub struct CowDiffApplyReport {\n    pub copied_base_bytes: u64,\n    pub diff_encoded_bytes: u64,\n    pub accounted_nodes: u64,\n}\n\n/// Evidence returned when replay was gated by an expected canonical base identity.\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct CowDiffApplyBoundReport {\n    /// Canonical identity observed immediately before replay setup began.\n    pub base_identity: SnapshotIdentity,\n    /// Existing bounded/failure-atomic replay accounting.\n    pub replay: CowDiffApplyReport,\n}\n\n#[derive(Debug)]\npub enum CowDiffApplyError {\n""",
    "cow apply bound report",
)

replace_one(
    "src/cow_diff_apply.rs",
    """    BudgetExceeded {\n        resource: &'static str,\n        limit: u64,\n        attempted: u64,\n    },\n    UnsupportedPlatform(String),\n""",
    """    BudgetExceeded {\n        resource: &'static str,\n        limit: u64,\n        attempted: u64,\n    },\n    BaseIdentity {\n        source: SnapshotIdentityError,\n    },\n    BaseIdentityMismatch {\n        expected: SnapshotIdentity,\n        actual: SnapshotIdentity,\n    },\n    UnsupportedPlatform(String),\n""",
    "cow apply identity errors",
)

replace_one(
    "src/cow_diff_apply.rs",
    """            Self::UnsupportedPlatform(message) => {\n                write!(f, \"unsupported COW diff apply platform: {message}\")\n            }\n""",
    """            Self::BaseIdentity { source } => {\n                write!(f, \"COW diff apply base identity check failed: {source}\")\n            }\n            Self::BaseIdentityMismatch { expected, actual } => write!(\n                f,\n                \"COW diff apply base identity mismatch: expected_sha256={} actual_sha256={}\",\n                expected.sha256_hex(),\n                actual.sha256_hex()\n            ),\n            Self::UnsupportedPlatform(message) => {\n                write!(f, \"unsupported COW diff apply platform: {message}\")\n            }\n""",
    "cow apply identity display",
)

replace_one(
    "src/cow_diff_apply.rs",
    """        match self {\n            Self::Io { source, .. } => Some(source),\n            _ => None,\n        }\n""",
    """        match self {\n            Self::BaseIdentity { source } => Some(source),\n            Self::Io { source, .. } => Some(source),\n            _ => None,\n        }\n""",
    "cow apply identity source",
)

replace_one(
    "src/cow_diff_apply.rs",
    """fn validate_limits(limits: CowDiffApplyLimits) -> Result<(), CowDiffApplyError> {\n""",
    """/// Replay `diff` only when the current canonical identity of `base` matches\n/// `expected_base`. The identity check is completed before destination inspection\n/// or replay staging begins. A mismatch therefore cannot publish or stage a tree.\n///\n/// This is an optimistic trusted-base precondition, not hostile-writer locking:\n/// callers must not infer protection against a concurrent mutation after the\n/// identity scan and before/during replay. The SHA-256 identity is also not an\n/// authenticity or provenance statement.\npub fn apply_cow_diff_atomic_with_expected_base(\n    base: &Path,\n    destination: &Path,\n    diff: &CowDiff,\n    expected_base: SnapshotIdentity,\n    identity_limits: SnapshotIdentityLimits,\n    replay_limits: CowDiffApplyLimits,\n) -> Result<CowDiffApplyBoundReport, CowDiffApplyError> {\n    validate_limits(replay_limits)?;\n    let actual = snapshot_sha256(base, identity_limits)\n        .map_err(|source| CowDiffApplyError::BaseIdentity { source })?;\n    if actual.sha256 != expected_base.sha256 {\n        return Err(CowDiffApplyError::BaseIdentityMismatch {\n            expected: expected_base,\n            actual,\n        });\n    }\n\n    let replay = apply_cow_diff_atomic(base, destination, diff, replay_limits)?;\n    Ok(CowDiffApplyBoundReport {\n        base_identity: actual,\n        replay,\n    })\n}\n\nfn validate_limits(limits: CowDiffApplyLimits) -> Result<(), CowDiffApplyError> {\n""",
    "cow apply expected-base API",
)

# Public surface: expose the checked replay without changing the existing API.
replace_one(
    "src/lib.rs",
    """pub use cow_diff_apply::{\n    apply_cow_diff_atomic, CowDiffApplyError, CowDiffApplyLimits, CowDiffApplyReport,\n};\n""",
    """pub use cow_diff_apply::{\n    apply_cow_diff_atomic, apply_cow_diff_atomic_with_expected_base, CowDiffApplyBoundReport,\n    CowDiffApplyError, CowDiffApplyLimits, CowDiffApplyReport,\n};\n""",
    "lib bound replay exports",
)

# Integration regressions: matching identity succeeds; mismatch wins before replay setup.
replace_one(
    "tests/cow_diff_apply.rs",
    """use security_lab::{\n    apply_cow_diff_atomic, CowDiff, CowDiffApplyError, CowDiffApplyLimits, CowDiffEntry,\n};\n""",
    """use security_lab::{\n    apply_cow_diff_atomic, apply_cow_diff_atomic_with_expected_base, snapshot_sha256, CowDiff,\n    CowDiffApplyError, CowDiffApplyLimits, CowDiffEntry, SnapshotIdentityLimits,\n};\n""",
    "cow apply test imports",
)

replace_one(
    "tests/cow_diff_apply.rs",
    """fn limits() -> CowDiffApplyLimits {\n    CowDiffApplyLimits {\n        max_bytes: 1024 * 1024,\n        max_nodes: 1024,\n    }\n}\n\nfn staging_entries(parent: &Path) -> Vec<PathBuf> {\n""",
    """fn limits() -> CowDiffApplyLimits {\n    CowDiffApplyLimits {\n        max_bytes: 1024 * 1024,\n        max_nodes: 1024,\n    }\n}\n\nfn identity_limits() -> SnapshotIdentityLimits {\n    SnapshotIdentityLimits {\n        max_bytes: 1024 * 1024,\n        max_nodes: 1024,\n    }\n}\n\nfn staging_entries(parent: &Path) -> Vec<PathBuf> {\n""",
    "cow apply identity limits",
)

tests = Path("tests/cow_diff_apply.rs")
text = tests.read_text()
addition = r'''

#[test]
fn expected_base_identity_allows_matching_atomic_replay() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    let destination = tree.path().join("snapshot");
    fs::create_dir(&base).expect("create base");
    fs::write(base.join("value"), b"before\n").expect("write base value");

    let expected = snapshot_sha256(&base, identity_limits()).expect("hash expected base");
    let changes = diff(vec![CowDiffEntry::UpsertFile {
        path: b"/value".to_vec(),
        mode: 0o600,
        bytes: b"after\n".to_vec(),
    }]);

    let report = apply_cow_diff_atomic_with_expected_base(
        &base,
        &destination,
        &changes,
        expected,
        identity_limits(),
        limits(),
    )
    .expect("matching expected base identity permits replay");

    assert_eq!(report.base_identity, expected);
    assert_eq!(report.replay.diff_encoded_bytes, changes.encoded_bytes);
    assert_eq!(fs::read(destination.join("value")).unwrap(), b"after\n");
    assert_eq!(fs::read(base.join("value")).unwrap(), b"before\n");
    assert!(staging_entries(tree.path()).is_empty());
}

#[test]
fn base_identity_mismatch_fails_before_destination_or_staging_setup() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    fs::create_dir(&base).expect("create base");
    fs::write(base.join("value"), b"expected\n").expect("write expected base value");
    let expected = snapshot_sha256(&base, identity_limits()).expect("hash expected base");

    fs::write(base.join("value"), b"mutated\n").expect("mutate base after identity capture");
    let actual = snapshot_sha256(&base, identity_limits()).expect("hash mutated base");
    assert_ne!(actual.sha256, expected.sha256);

    // The parent deliberately does not exist. If replay setup runs before the
    // identity gate, destination-parent canonicalization would win instead.
    let missing_parent = tree.path().join("missing-parent");
    let destination = missing_parent.join("snapshot");
    let changes = diff(vec![CowDiffEntry::UpsertFile {
        path: b"/new".to_vec(),
        mode: 0o600,
        bytes: b"must-not-publish\n".to_vec(),
    }]);

    let error = apply_cow_diff_atomic_with_expected_base(
        &base,
        &destination,
        &changes,
        expected,
        identity_limits(),
        limits(),
    )
    .expect_err("mismatched base identity must fail closed before replay setup");

    match error {
        CowDiffApplyError::BaseIdentityMismatch {
            expected: observed_expected,
            actual: observed_actual,
        } => {
            assert_eq!(observed_expected, expected);
            assert_eq!(observed_actual, actual);
        }
        other => panic!("unexpected expected-base failure: {other}"),
    }
    assert!(!missing_parent.exists());
    assert!(!destination.exists());
    assert!(staging_entries(tree.path()).is_empty());
}
'''
if "fn expected_base_identity_allows_matching_atomic_replay()" in text:
    raise SystemExit("bound replay tests already present")
tests.write_text(text + addition)
