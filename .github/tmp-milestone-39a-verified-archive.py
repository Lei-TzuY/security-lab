from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Reuse the exact Milestone 37A strict-verification equation for identities that
# have already been derived from a canonical archive, without adding a second
# public signing API or duplicating the Ed25519 domain encoding.
replace_one(
    "src/snapshot_signature.rs",
    '''pub fn verify_snapshot_ed25519(
    root: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotIdentity, SnapshotEd25519Error> {
    let snapshot = snapshot_sha256(root, limits)?;
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SnapshotEd25519Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(expected_signature);
    verifying_key
        .verify_strict(&signature_message(snapshot), &signature)
        .map_err(|_| SnapshotEd25519Error::VerificationFailed)?;
    Ok(snapshot)
}
''',
    '''pub fn verify_snapshot_ed25519(
    root: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotIdentityLimits,
) -> Result<SnapshotIdentity, SnapshotEd25519Error> {
    let snapshot = snapshot_sha256(root, limits)?;
    verify_snapshot_identity_ed25519(snapshot, public_key, expected_signature)?;
    Ok(snapshot)
}

pub(crate) fn verify_snapshot_identity_ed25519(
    snapshot: SnapshotIdentity,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
) -> Result<(), SnapshotEd25519Error> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SnapshotEd25519Error::InvalidPublicKey)?;
    let signature = Signature::from_bytes(expected_signature);
    verifying_key
        .verify_strict(&signature_message(snapshot), &signature)
        .map_err(|_| SnapshotEd25519Error::VerificationFailed)
}
''',
    "signature identity verifier",
)

replace_one(
    "src/snapshot_archive.rs",
    'use crate::snapshot_identity::{SnapshotIdentity, SnapshotIdentityError};\n',
    '''use crate::snapshot_identity::{SnapshotIdentity, SnapshotIdentityError};
use crate::snapshot_signature::{
    verify_snapshot_identity_ed25519, SnapshotEd25519Error, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES,
    SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
''',
    "archive signature imports",
)
replace_one(
    "src/snapshot_archive.rs",
    '''    Identity(SnapshotIdentityError),
    UnsupportedPlatform(String),
''',
    '''    Identity(SnapshotIdentityError),
    Signature(SnapshotEd25519Error),
    UnsupportedPlatform(String),
''',
    "archive signature error variant",
)
replace_one(
    "src/snapshot_archive.rs",
    '''            Self::Identity(source) => write!(f, "snapshot archive identity failed: {source}"),
            Self::UnsupportedPlatform(message) => {
''',
    '''            Self::Identity(source) => write!(f, "snapshot archive identity failed: {source}"),
            Self::Signature(source) => {
                write!(f, "snapshot archive signature verification failed: {source}")
            }
            Self::UnsupportedPlatform(message) => {
''',
    "archive signature display",
)
replace_one(
    "src/snapshot_archive.rs",
    '''            Self::Identity(source) => Some(source),
            Self::Io { source, .. } => Some(source),
''',
    '''            Self::Identity(source) => Some(source),
            Self::Signature(source) => Some(source),
            Self::Io { source, .. } => Some(source),
''',
    "archive signature error source",
)
replace_one(
    "src/snapshot_archive.rs",
    '''impl From<SnapshotIdentityError> for SnapshotArchiveError {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}
''',
    '''impl From<SnapshotIdentityError> for SnapshotArchiveError {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<SnapshotEd25519Error> for SnapshotArchiveError {
    fn from(value: SnapshotEd25519Error) -> Self {
        Self::Signature(value)
    }
}
''',
    "archive signature conversion",
)

materialize_anchor = '''pub fn materialize_snapshot_archive_atomic(
    archive: &[u8],
    destination: &Path,
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchiveMaterializeReport, SnapshotArchiveError> {
    validate_limits(limits)?;
    let parsed = parse_archive(archive, limits)?;
    #[cfg(target_os = "linux")]
    {
        linux::materialize(archive, destination, parsed, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (archive, destination, parsed, limits);
        Err(SnapshotArchiveError::UnsupportedPlatform(
            "atomic snapshot materialization requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}
'''
verified_api = materialize_anchor + '''
/// Validate a canonical archive, strictly verify its Milestone 37A Ed25519
/// signature under the exact caller-supplied public key, and only then permit
/// destination inspection or staging-tree creation.
///
/// The signature covers the canonical Milestone 33A identity derived directly
/// from the frozen archive records. A verification failure therefore cannot
/// publish or stage an unauthenticated tree. Publication retains the same
/// failure-atomic, non-fsync durability boundary as
/// `materialize_snapshot_archive_atomic`.
pub fn materialize_snapshot_archive_ed25519_atomic(
    archive: &[u8],
    destination: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchiveMaterializeReport, SnapshotArchiveError> {
    validate_limits(limits)?;
    let parsed = parse_archive(archive, limits)?;
    verify_snapshot_identity_ed25519(parsed.identity, public_key, expected_signature)?;
    #[cfg(target_os = "linux")]
    {
        linux::materialize(archive, destination, parsed, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (archive, destination, parsed, limits);
        Err(SnapshotArchiveError::UnsupportedPlatform(
            "atomic snapshot materialization requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}
'''
replace_one(
    "src/snapshot_archive.rs",
    materialize_anchor,
    verified_api,
    "verified archive materialization API",
)

replace_one(
    "src/lib.rs",
    '''pub use snapshot_archive::{
    materialize_snapshot_archive_atomic, serialize_snapshot_archive, snapshot_archive_identity,
    SnapshotArchive, SnapshotArchiveError, SnapshotArchiveLimits, SnapshotArchiveMaterializeReport,
};
''',
    '''pub use snapshot_archive::{
    materialize_snapshot_archive_atomic, materialize_snapshot_archive_ed25519_atomic,
    serialize_snapshot_archive, snapshot_archive_identity, SnapshotArchive, SnapshotArchiveError,
    SnapshotArchiveLimits, SnapshotArchiveMaterializeReport,
};
''',
    "archive public export",
)

replace_one(
    "tests/snapshot_archive.rs",
    '''use security_lab::{
    materialize_snapshot_archive_atomic, serialize_snapshot_archive, snapshot_archive_identity,
    snapshot_sha256, SnapshotArchiveError, SnapshotArchiveLimits, SnapshotIdentityLimits,
};
''',
    '''use security_lab::{
    materialize_snapshot_archive_atomic, materialize_snapshot_archive_ed25519_atomic,
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_archive_identity, snapshot_sha256,
    SnapshotArchiveError, SnapshotArchiveLimits, SnapshotEd25519Error, SnapshotIdentityLimits,
};
''',
    "archive test imports",
)

tests_path = Path("tests/snapshot_archive.rs")
tests = tests_path.read_text()
marker = "fn ed25519_verified_archive_publication_survives_live_source_mutation"
if marker in tests:
    raise SystemExit("39A tests already present")
tests += r'''

#[test]
fn ed25519_verified_archive_publication_survives_live_source_mutation() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let destination = temp.path().join("verified-materialized");
    fs::create_dir(&source).expect("create source");
    populate(&source);

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let seed = [0x5a; 32];
    let evidence = sign_snapshot_ed25519(&source, &seed, identity_limits())
        .expect("sign source identity");
    assert_eq!(evidence.snapshot, archive.identity);

    fs::write(source.join("alpha"), b"live-source-changed-after-signing\n")
        .expect("mutate live source after archive signing");
    assert_ne!(
        snapshot_sha256(&source, identity_limits()).expect("hash mutated source"),
        archive.identity
    );

    let report = materialize_snapshot_archive_ed25519_atomic(
        &archive.bytes,
        &destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("verify frozen archive and publish");
    assert_eq!(report.identity, archive.identity);
    assert_eq!(
        snapshot_sha256(&destination, identity_limits()).expect("hash verified publication"),
        archive.identity
    );
    assert_eq!(
        fs::read(destination.join("alpha")).expect("read captured alpha"),
        b"captured-alpha\n"
    );
    assert!(!has_staging_residue(temp.path()));
}

#[test]
fn ed25519_archive_verification_fails_before_publication_side_effects() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("create source");
    populate(&source);

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let evidence = sign_snapshot_ed25519(&source, &[0x61; 32], identity_limits())
        .expect("sign source identity");
    let wrong = sign_snapshot_ed25519(&source, &[0x62; 32], identity_limits())
        .expect("derive wrong verifying key");

    let missing_parent_destination = temp.path().join("missing-parent/out");
    let wrong_key_error = materialize_snapshot_archive_ed25519_atomic(
        &archive.bytes,
        &missing_parent_destination,
        &wrong.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("wrong key must fail before destination inspection");
    assert!(matches!(
        wrong_key_error,
        SnapshotArchiveError::Signature(SnapshotEd25519Error::VerificationFailed)
    ));
    assert!(!temp.path().join("missing-parent").exists());

    let mut tampered = archive.bytes.clone();
    let needle = b"captured-alpha\n";
    let offset = tampered
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("archive contains captured alpha payload");
    tampered[offset] ^= 0x01;
    let tampered_destination = temp.path().join("tampered-must-not-publish");
    let tampered_error = materialize_snapshot_archive_ed25519_atomic(
        &tampered,
        &tampered_destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("parse-valid content tamper must fail signature verification");
    assert!(matches!(
        tampered_error,
        SnapshotArchiveError::Signature(SnapshotEd25519Error::VerificationFailed)
    ));
    assert!(!tampered_destination.exists());
    assert!(!has_staging_residue(temp.path()));
}
'''
tests_path.write_text(tests)
