#![cfg(target_os = "linux")]

use security_lab::{
    materialize_snapshot_store_object_ed25519_atomic, serialize_snapshot_archive,
    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,
    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotStoreError,
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
            "security-lab-snapshot-store-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot-store workspace");
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

fn create_source(workspace: &Path) -> PathBuf {
    let source = workspace.join("source");
    fs::create_dir(&source).expect("create source root");
    fs::create_dir(source.join("nested")).expect("create nested source directory");
    fs::write(source.join("payload"), b"frozen-original\n").expect("write source payload");
    fs::write(source.join("nested/child"), b"nested\n").expect("write nested payload");
    source
}

#[test]
fn authenticated_store_deduplicates_and_materializes_frozen_archive() {
    let workspace = TempDir::new("dedup");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let destination = workspace.path().join("restored");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x42; 32], identity_limits())
        .expect("sign canonical source identity");
    assert_eq!(archive.identity, evidence.snapshot);

    let first = store_snapshot_archive_ed25519_atomic(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("insert authenticated archive");
    assert!(first.inserted);
    assert_eq!(first.identity, archive.identity);
    assert_eq!(first.archive_bytes, archive.bytes.len() as u64);

    let object = snapshot_store_object_path(&store, first.identity);
    let mode = fs::metadata(&object)
        .expect("stat stored object")
        .permissions()
        .mode();
    assert_eq!(mode & 0o222, 0, "stored object must be sealed read-only");

    let second = store_snapshot_archive_ed25519_atomic(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("deduplicate authenticated archive");
    assert!(!second.inserted);
    assert_eq!(second.identity, first.identity);

    fs::write(source.join("payload"), b"live-mutated\n").expect("mutate live source");

    let report = materialize_snapshot_store_object_ed25519_atomic(
        &store,
        first.identity,
        &destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("materialize stored object");
    assert_eq!(report.identity, first.identity);
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"frozen-original\n"
    );
    assert_eq!(
        fs::read(destination.join("nested/child")).expect("read restored nested payload"),
        b"nested\n"
    );
}

#[test]
fn wrong_key_fails_before_missing_store_root_is_inspected() {
    let workspace = TempDir::new("wrong-key");
    let source = create_source(workspace.path());
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x11; 32], identity_limits())
        .expect("sign canonical source identity");
    let wrong = sign_snapshot_ed25519(&source, &[0x22; 32], identity_limits())
        .expect("derive different public key");
    let missing_store = workspace.path().join("missing-store");

    match store_snapshot_archive_ed25519_atomic(
        &missing_store,
        &archive.bytes,
        &wrong.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("wrong key must fail closed")
    {
        SnapshotStoreError::Signature(_) => {}
        other => panic!("unexpected wrong-key result: {other}"),
    }
    assert!(!missing_store.exists());
}

#[test]
fn tampered_stored_object_cannot_materialize_under_original_identity() {
    let workspace = TempDir::new("tamper");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let destination = workspace.path().join("restored");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x77; 32], identity_limits())
        .expect("sign canonical source identity");
    let stored = store_snapshot_archive_ed25519_atomic(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("insert authenticated archive");
    let object = snapshot_store_object_path(&store, stored.identity);

    let mut bytes = fs::read(&object).expect("read stored object for controlled tamper");
    let needle = b"frozen-original\n";
    let offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("archive contains payload bytes");
    bytes[offset] ^= 0x01;
    fs::set_permissions(&object, fs::Permissions::from_mode(0o644))
        .expect("temporarily make object writable for tamper fixture");
    fs::write(&object, &bytes).expect("tamper stored archive bytes");
    fs::set_permissions(&object, fs::Permissions::from_mode(0o444))
        .expect("restore read-only object mode");

    match materialize_snapshot_store_object_ed25519_atomic(
        &store,
        stored.identity,
        &destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("tampered object must fail closed")
    {
        SnapshotStoreError::ObjectConflict { identity } => assert_eq!(identity, stored.identity),
        other => panic!("unexpected tamper result: {other}"),
    }
    assert!(!destination.exists());
}
