#![cfg(target_os = "linux")]

use security_lab::{
    snapshot_hmac_sha256, verify_snapshot_hmac_sha256, SnapshotHmacError, SnapshotIdentityError,
    SnapshotIdentityLimits, SNAPSHOT_HMAC_KEY_BYTES,
};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "security-lab-snapshot-auth-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create snapshot-auth test root");
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

fn identity_limits() -> SnapshotIdentityLimits {
    SnapshotIdentityLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 1024,
    }
}

fn key() -> [u8; SNAPSHOT_HMAC_KEY_BYTES] {
    let mut key = [0u8; SNAPSHOT_HMAC_KEY_BYTES];
    for (index, byte) in key.iter_mut().enumerate() {
        *byte = index as u8;
    }
    key
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set fixture mode");
}

fn build_reference_tree(root: &Path) {
    fs::create_dir(root).expect("create reference root");
    fs::write(root.join("alpha"), b"hello\n").expect("write alpha");
    fs::create_dir(root.join("dir")).expect("create dir");
    fs::write(root.join("dir/value"), b"value\n").expect("write nested value");
    symlink("dir/value", root.join("link")).expect("create reference symlink");
    set_mode(root, 0o751);
    set_mode(&root.join("alpha"), 0o640);
    set_mode(&root.join("dir"), 0o750);
    set_mode(&root.join("dir/value"), 0o600);
}

#[test]
fn snapshot_hmac_matches_fixed_vector_and_verifies() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    build_reference_tree(&root);
    let key = key();

    let authenticated =
        snapshot_hmac_sha256(&root, &key, identity_limits()).expect("authenticate snapshot");

    assert_eq!(authenticated.snapshot.nodes, 5);
    assert_eq!(authenticated.snapshot.encoded_bytes, 140);
    assert_eq!(
        authenticated.snapshot.sha256_hex(),
        "b3ff412811f2f9298015ab9320339ab3d35bd53a531b6b4e645ae8656d3c1c85"
    );
    assert_eq!(
        authenticated.tag_hex(),
        "70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743"
    );

    let verified = verify_snapshot_hmac_sha256(&root, &key, &authenticated.tag, identity_limits())
        .expect("verify matching snapshot HMAC");
    assert_eq!(verified, authenticated.snapshot);
}

#[test]
fn mutation_and_wrong_key_fail_authentication() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    build_reference_tree(&root);
    let key = key();
    let baseline =
        snapshot_hmac_sha256(&root, &key, identity_limits()).expect("authenticate baseline");

    fs::write(root.join("alpha"), b"changed\n").expect("mutate authenticated content");
    let error = verify_snapshot_hmac_sha256(&root, &key, &baseline.tag, identity_limits())
        .expect_err("mutated snapshot must not authenticate with old tag");
    assert!(matches!(error, SnapshotHmacError::AuthenticationFailed));

    fs::write(root.join("alpha"), b"hello\n").expect("restore authenticated content");
    let wrong_key = [0xa5u8; SNAPSHOT_HMAC_KEY_BYTES];
    let error = verify_snapshot_hmac_sha256(&root, &wrong_key, &baseline.tag, identity_limits())
        .expect_err("wrong key must not authenticate snapshot");
    assert!(matches!(error, SnapshotHmacError::AuthenticationFailed));
}

#[test]
fn identity_budget_failure_precedes_authentication_result() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    build_reference_tree(&root);
    let key = key();
    let arbitrary_tag = [0u8; 32];

    let error = verify_snapshot_hmac_sha256(
        &root,
        &key,
        &arbitrary_tag,
        SnapshotIdentityLimits {
            max_bytes: 32,
            max_nodes: 1024,
        },
    )
    .expect_err("identity budget must fail before authentication comparison");

    assert!(matches!(
        error,
        SnapshotHmacError::Identity(SnapshotIdentityError::BudgetExceeded {
            resource: "byte",
            ..
        })
    ));
}
