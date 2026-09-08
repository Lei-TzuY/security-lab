#![cfg(target_os = "linux")]

use security_lab::{
    publish_snapshot_archive_ed25519_version, serialize_snapshot_archive, sign_snapshot_ed25519,
    snapshot_sha256, SnapshotArchiveLimits, SnapshotEd25519Error, SnapshotIdentityLimits,
    SnapshotStoreError, SnapshotStorePublishDisposition,
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
            "security-lab-snapshot-store-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create snapshot store temp root");
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

fn populate(root: &Path, marker: &[u8]) {
    fs::write(root.join("alpha"), marker).expect("write alpha");
    fs::set_permissions(root.join("alpha"), fs::Permissions::from_mode(0o640))
        .expect("set alpha mode");
    fs::create_dir(root.join("nested")).expect("create nested");
    fs::set_permissions(root.join("nested"), fs::Permissions::from_mode(0o750))
        .expect("set nested mode");
    fs::write(root.join("nested/value"), b"versioned-value\n").expect("write nested value");
    fs::set_permissions(root.join("nested/value"), fs::Permissions::from_mode(0o600))
        .expect("set nested value mode");
    symlink("../alpha", root.join("nested/link")).expect("create symlink");
    fs::set_permissions(root, fs::Permissions::from_mode(0o751)).expect("set root mode");
}

fn has_staging_residue(store: &Path) -> bool {
    fs::read_dir(store)
        .expect("read snapshot store")
        .filter_map(Result::ok)
        .any(|entry| {
            entry
                .file_name()
                .as_encoded_bytes()
                .starts_with(b".security-lab-snapshot-archive-")
        })
}

#[test]
fn first_publish_and_verified_reuse_share_one_content_addressed_version() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let store = temp.path().join("store");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&store).expect("create store");
    populate(&source, b"version-one\n");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let signed = sign_snapshot_ed25519(&source, &[7u8; 32], identity_limits()).expect("sign source");
    assert_eq!(archive.identity, signed.snapshot);

    let first = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &store,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect("publish first version");
    assert_eq!(first.identity, archive.identity);
    assert_eq!(first.disposition, SnapshotStorePublishDisposition::Published);
    assert_eq!(
        first.version_path,
        store.join(archive.identity.sha256_hex()),
        "version path must be derived only from the canonical digest"
    );
    assert_eq!(
        snapshot_sha256(&first.version_path, identity_limits()).expect("hash published version"),
        archive.identity
    );

    let second = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &store,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect("reuse verified version");
    assert_eq!(second.identity, archive.identity);
    assert_eq!(second.disposition, SnapshotStorePublishDisposition::Reused);
    assert_eq!(second.version_path, first.version_path);
    assert_eq!(
        fs::read_dir(&store).expect("read store").count(),
        1,
        "idempotent reuse must not create another version object"
    );
    assert!(!has_staging_residue(&store));
}

#[test]
fn distinct_verified_archives_coexist_as_distinct_versions() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let store = temp.path().join("store");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&store).expect("create store");
    populate(&source, b"version-one\n");

    let first_archive =
        serialize_snapshot_archive(&source, archive_limits()).expect("serialize first source");
    let first_signed =
        sign_snapshot_ed25519(&source, &[11u8; 32], identity_limits()).expect("sign first source");
    let first = publish_snapshot_archive_ed25519_version(
        &first_archive.bytes,
        &store,
        &first_signed.public_key,
        &first_signed.signature,
        archive_limits(),
    )
    .expect("publish first version");

    fs::write(source.join("alpha"), b"version-two\n").expect("mutate source for second version");
    let second_archive =
        serialize_snapshot_archive(&source, archive_limits()).expect("serialize second source");
    let second_signed =
        sign_snapshot_ed25519(&source, &[13u8; 32], identity_limits()).expect("sign second source");
    assert_ne!(first_archive.identity, second_archive.identity);

    let second = publish_snapshot_archive_ed25519_version(
        &second_archive.bytes,
        &store,
        &second_signed.public_key,
        &second_signed.signature,
        archive_limits(),
    )
    .expect("publish second version");
    assert_eq!(second.disposition, SnapshotStorePublishDisposition::Published);
    assert_ne!(first.version_path, second.version_path);
    assert_eq!(
        snapshot_sha256(&first.version_path, identity_limits()).expect("hash first version"),
        first_archive.identity
    );
    assert_eq!(
        snapshot_sha256(&second.version_path, identity_limits()).expect("hash second version"),
        second_archive.identity
    );
    assert_eq!(fs::read_dir(&store).expect("read store").count(), 2);
}

#[test]
fn tampered_existing_version_fails_closed_instead_of_being_reused_or_overwritten() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let store = temp.path().join("store");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&store).expect("create store");
    populate(&source, b"original-version\n");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let signed = sign_snapshot_ed25519(&source, &[17u8; 32], identity_limits()).expect("sign source");
    let published = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &store,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect("publish version");

    fs::write(published.version_path.join("alpha"), b"host-tampered\n")
        .expect("tamper stored version");
    let error = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &store,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect_err("tampered content-addressed version must never be reused");
    match error {
        SnapshotStoreError::ExistingVersionMismatch { expected, actual } => {
            assert_eq!(expected, archive.identity);
            assert_ne!(actual, archive.identity);
        }
        other => panic!("unexpected tamper result: {other}"),
    }
    assert_eq!(
        fs::read(published.version_path.join("alpha")).expect("read tampered version"),
        b"host-tampered\n",
        "failed reuse must not overwrite the conflicting existing version"
    );
    assert!(!has_staging_residue(&store));
}

#[test]
fn signature_failure_precedes_store_root_inspection() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    fs::create_dir(&source).expect("create source");
    populate(&source, b"signed-version\n");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let signed = sign_snapshot_ed25519(&source, &[19u8; 32], identity_limits()).expect("sign source");
    let wrong_key = sign_snapshot_ed25519(&source, &[23u8; 32], identity_limits())
        .expect("derive wrong public key");
    let missing_store = temp.path().join("missing-store");
    assert!(!missing_store.exists());

    let error = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &missing_store,
        &wrong_key.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect_err("wrong key must fail before the missing store root is inspected");
    assert!(matches!(
        error,
        SnapshotStoreError::Signature(SnapshotEd25519Error::VerificationFailed)
    ));
    assert!(!missing_store.exists());
}

#[test]
fn symlink_at_content_address_is_never_treated_as_verified_reuse() {
    let temp = TempTree::new();
    let source = temp.path().join("source");
    let store = temp.path().join("store");
    fs::create_dir(&source).expect("create source");
    fs::create_dir(&store).expect("create store");
    populate(&source, b"symlink-version\n");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize source");
    let signed = sign_snapshot_ed25519(&source, &[29u8; 32], identity_limits()).expect("sign source");
    let version_path = store.join(archive.identity.sha256_hex());
    symlink(&source, &version_path).expect("create forged version symlink");

    let error = publish_snapshot_archive_ed25519_version(
        &archive.bytes,
        &store,
        &signed.public_key,
        &signed.signature,
        archive_limits(),
    )
    .expect_err("symlink version path must not be reused");
    assert!(matches!(error, SnapshotStoreError::ExistingVersionInvalid(_)));
    assert!(fs::symlink_metadata(&version_path)
        .expect("stat forged version")
        .file_type()
        .is_symlink());
    assert!(!has_staging_residue(&store));
}
