#![cfg(target_os = "linux")]

use security_lab::{
    materialize_snapshot_archive_atomic, materialize_snapshot_archive_ed25519_atomic,
    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_archive_identity, snapshot_sha256,
    SnapshotArchiveError, SnapshotArchiveLimits, SnapshotEd25519Error, SnapshotIdentityLimits,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "security-lab-snapshot-archive-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create snapshot archive temp root");
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempTree {
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

fn populate(root: &Path) {
    fs::write(root.join("alpha"), b"captured-alpha\n").expect("write alpha");
    fs::set_permissions(root.join("alpha"), fs::Permissions::from_mode(0o640))
        .expect("set alpha mode");
    fs::create_dir(root.join("nested")).expect("create nested");
    fs::set_permissions(root.join("nested"), fs::Permissions::from_mode(0o750))
        .expect("set nested mode");
    fs::write(root.join("nested/value"), b"captured-value\n").expect("write nested value");
    fs::set_permissions(root.join("nested/value"), fs::Permissions::from_mode(0o600))
        .expect("set nested value mode");
    symlink("../alpha", root.join("nested/link")).expect("create symlink");
    fs::set_permissions(root, fs::Permissions::from_mode(0o751)).expect("set root mode");
}

fn has_staging_residue(parent: &Path) -> bool {
    fs::read_dir(parent)
        .expect("read archive test parent")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".security-lab-snapshot-archive-")
        })
}

#[test]
fn deterministic_archive_round_trip_preserves_captured_identity() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let destination = temp.path().join("materialized");
    fs::create_dir(&source).expect("create source");
    populate(&source);

    let live_identity = snapshot_sha256(&source, identity_limits()).expect("hash source");
    let first = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let second = serialize_snapshot_archive(&source, archive_limits()).expect("serialize again");
    assert_eq!(
        first.bytes, second.bytes,
        "archive bytes must be deterministic"
    );
    assert_eq!(first.identity, second.identity);
    assert_eq!(first.identity, live_identity);
    assert_eq!(
        snapshot_archive_identity(&first.bytes, archive_limits()).expect("hash archive"),
        live_identity
    );

    fs::write(source.join("alpha"), b"mutated-after-capture\n").expect("mutate source");
    let mutated_identity = snapshot_sha256(&source, identity_limits()).expect("hash mutation");
    assert_ne!(mutated_identity, first.identity);

    let report = materialize_snapshot_archive_atomic(&first.bytes, &destination, archive_limits())
        .expect("materialize captured archive");
    assert_eq!(report.identity, first.identity);
    assert_eq!(report.archive_bytes, first.bytes.len() as u64);
    assert_eq!(report.nodes, first.identity.nodes);

    assert_eq!(
        fs::read(destination.join("alpha")).expect("read restored alpha"),
        b"captured-alpha\n"
    );
    assert_eq!(
        fs::read(destination.join("nested/value")).expect("read restored value"),
        b"captured-value\n"
    );
    assert_eq!(
        fs::read_link(destination.join("nested/link")).expect("read restored link"),
        PathBuf::from("../alpha")
    );
    assert_eq!(
        fs::metadata(&destination)
            .expect("stat root")
            .permissions()
            .mode()
            & 0o7777,
        0o751
    );
    assert_eq!(
        fs::metadata(destination.join("nested"))
            .expect("stat nested")
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );
    assert_eq!(
        fs::metadata(destination.join("alpha"))
            .expect("stat alpha")
            .permissions()
            .mode()
            & 0o7777,
        0o640
    );
    assert_eq!(
        fs::metadata(destination.join("nested/value"))
            .expect("stat value")
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        snapshot_sha256(&destination, identity_limits()).expect("hash materialized tree"),
        first.identity
    );
    assert!(!has_staging_residue(temp.path()));
}

#[test]
fn malformed_and_budget_failures_never_publish_or_leave_staging() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("create source");
    populate(&source);
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");

    let truncated = &archive.bytes[..archive.bytes.len() - 1];
    assert!(snapshot_archive_identity(truncated, archive_limits()).is_err());
    let truncated_destination = temp.path().join("truncated");
    assert!(materialize_snapshot_archive_atomic(
        truncated,
        &truncated_destination,
        archive_limits()
    )
    .is_err());
    assert!(!truncated_destination.exists());
    assert!(!has_staging_residue(temp.path()));

    let tight_bytes = SnapshotArchiveLimits {
        max_archive_bytes: archive.bytes.len() as u64 - 1,
        ..archive_limits()
    };
    let byte_destination = temp.path().join("byte-budget");
    assert!(matches!(
        materialize_snapshot_archive_atomic(&archive.bytes, &byte_destination, tight_bytes),
        Err(SnapshotArchiveError::BudgetExceeded {
            resource: "archive byte",
            ..
        })
    ));
    assert!(!byte_destination.exists());

    let tight_nodes = SnapshotArchiveLimits {
        max_nodes: 1,
        ..archive_limits()
    };
    let node_destination = temp.path().join("node-budget");
    assert!(matches!(
        materialize_snapshot_archive_atomic(&archive.bytes, &node_destination, tight_nodes),
        Err(SnapshotArchiveError::BudgetExceeded {
            resource: "node",
            ..
        })
    ));
    assert!(!node_destination.exists());
    assert!(!has_staging_residue(temp.path()));
}

#[test]
fn existing_destination_is_preserved_without_partial_publication() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let destination = temp.path().join("existing");
    fs::create_dir(&source).expect("create source");
    populate(&source);
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");

    fs::create_dir(&destination).expect("create existing destination");
    fs::write(destination.join("marker"), b"do-not-replace\n").expect("write destination marker");
    assert!(matches!(
        materialize_snapshot_archive_atomic(&archive.bytes, &destination, archive_limits()),
        Err(SnapshotArchiveError::InvalidInput(_))
    ));
    assert_eq!(
        fs::read(destination.join("marker")).expect("read destination marker"),
        b"do-not-replace\n"
    );
    assert!(!has_staging_residue(temp.path()));
}

fn push_path_record_prefix(bytes: &mut Vec<u8>, tag: u8, path: &[u8]) {
    bytes.push(tag);
    bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
    bytes.extend_from_slice(path);
}

#[test]
fn symlink_parent_archive_is_rejected_before_materialization() {
    let temp = TempTree::new();
    let destination = temp.path().join("must-not-publish");

    let mut archive = b"security-lab-snapshot-archive-v1\0".to_vec();
    archive.extend_from_slice(&3u64.to_le_bytes());

    push_path_record_prefix(&mut archive, b'D', b"/");
    archive.extend_from_slice(&0o755u32.to_le_bytes());

    push_path_record_prefix(&mut archive, b'L', b"/pivot");
    archive.extend_from_slice(&2u32.to_le_bytes());
    archive.extend_from_slice(b"..");

    push_path_record_prefix(&mut archive, b'F', b"/pivot/escape");
    archive.extend_from_slice(&0o600u32.to_le_bytes());
    archive.extend_from_slice(&1u64.to_le_bytes());
    archive.push(b'x');

    let identity_error = snapshot_archive_identity(&archive, archive_limits())
        .expect_err("a symlink may not become an archive parent");
    assert!(matches!(
        identity_error,
        SnapshotArchiveError::InvalidInput(_)
    ));

    let materialize_error =
        materialize_snapshot_archive_atomic(&archive, &destination, archive_limits())
            .expect_err("symlink-parent archive must fail before materialization");
    assert!(matches!(
        materialize_error,
        SnapshotArchiveError::InvalidInput(_)
    ));
    assert!(!destination.exists());
    assert!(!has_staging_residue(temp.path()));
}

#[test]
fn ed25519_verified_archive_publication_survives_live_source_mutation() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let destination = temp.path().join("verified-materialized");
    fs::create_dir(&source).expect("create source");
    populate(&source);

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let seed = [0x5a; 32];
    let evidence =
        sign_snapshot_ed25519(&source, &seed, identity_limits()).expect("sign source identity");
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
