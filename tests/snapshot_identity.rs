#![cfg(target_os = "linux")]

use security_lab::{
    apply_cow_diff_atomic, snapshot_sha256, CowDiff, CowDiffApplyLimits, CowDiffEntry,
    SnapshotIdentityError, SnapshotIdentityLimits,
};
use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TempTree(PathBuf);

impl TempTree {
    fn new() -> Self {
        let id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "security-lab-snapshot-identity-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create identity test root");
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

fn replay_limits() -> CowDiffApplyLimits {
    CowDiffApplyLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 1024,
    }
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
fn canonical_snapshot_sha256_matches_fixed_vector() {
    let tree = TempTree::new();
    let first = tree.path().join("first");
    let second = tree.path().join("second");
    build_reference_tree(&first);
    build_reference_tree(&second);

    let first_identity = snapshot_sha256(&first, identity_limits()).expect("hash first tree");
    let second_identity = snapshot_sha256(&second, identity_limits()).expect("hash second tree");

    assert_eq!(first_identity, second_identity);
    assert_eq!(first_identity.nodes, 5);
    assert_eq!(first_identity.encoded_bytes, 140);
    assert_eq!(
        first_identity.sha256_hex(),
        "b3ff412811f2f9298015ab9320339ab3d35bd53a531b6b4e645ae8656d3c1c85"
    );
}

#[test]
fn content_mode_symlink_and_topology_change_identity() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    build_reference_tree(&root);
    let baseline = snapshot_sha256(&root, identity_limits()).expect("hash baseline");

    fs::write(root.join("alpha"), b"changed\n").expect("change content");
    let content = snapshot_sha256(&root, identity_limits()).expect("hash content change");
    assert_ne!(baseline.sha256, content.sha256);

    fs::write(root.join("alpha"), b"hello\n").expect("restore content");
    set_mode(&root.join("alpha"), 0o600);
    let mode = snapshot_sha256(&root, identity_limits()).expect("hash mode change");
    assert_ne!(baseline.sha256, mode.sha256);

    set_mode(&root.join("alpha"), 0o640);
    fs::remove_file(root.join("link")).expect("remove old symlink");
    symlink("alpha", root.join("link")).expect("replace symlink target");
    let link = snapshot_sha256(&root, identity_limits()).expect("hash symlink change");
    assert_ne!(baseline.sha256, link.sha256);

    fs::remove_file(root.join("link")).expect("remove changed symlink");
    symlink("dir/value", root.join("link")).expect("restore symlink target");
    fs::write(root.join("extra"), b"extra\n").expect("add topology node");
    let topology = snapshot_sha256(&root, identity_limits()).expect("hash topology change");
    assert_ne!(baseline.sha256, topology.sha256);
}

#[test]
fn unsupported_node_and_budget_overflow_fail_closed() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    fs::create_dir(&root).expect("create snapshot");
    fs::write(root.join("payload"), vec![b'x'; 4096]).expect("write payload");

    let tight = SnapshotIdentityLimits {
        max_bytes: 128,
        max_nodes: 100,
    };
    let error = snapshot_sha256(&root, tight).expect_err("byte budget must fail");
    assert!(matches!(
        error,
        SnapshotIdentityError::BudgetExceeded {
            resource: "byte",
            ..
        }
    ));

    fs::remove_file(root.join("payload")).expect("remove payload");
    let fifo = root.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL");
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let error = snapshot_sha256(&root, identity_limits()).expect_err("FIFO must be rejected");
    match error {
        SnapshotIdentityError::InvalidInput(message) => {
            assert!(message.contains("unsupported node kind"));
        }
        other => panic!("unexpected unsupported-node result: {other}"),
    }
}

#[test]
fn node_budget_is_enforced_during_directory_enumeration() {
    let tree = TempTree::new();
    let root = tree.path().join("snapshot");
    fs::create_dir(&root).expect("create snapshot");
    fs::write(root.join("regular"), b"x").expect("write regular child");

    let fifo = root.join("fifo");
    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path has no NUL");
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

    let error = snapshot_sha256(
        &root,
        SnapshotIdentityLimits {
            max_bytes: 1024 * 1024,
            max_nodes: 2,
        },
    )
    .expect_err("directory enumeration must stop at the global node budget");

    assert!(matches!(
        error,
        SnapshotIdentityError::BudgetExceeded {
            resource: "node",
            limit: 2,
            attempted: 3,
        }
    ));
}

fn encoded_bytes(entries: &[CowDiffEntry]) -> u64 {
    let mut total = 6u64;
    for entry in entries {
        let (path, payload) = match entry {
            CowDiffEntry::UpsertFile { path, bytes, .. } => (path, 4 + bytes.len() as u64),
            CowDiffEntry::EnsureDirectory { path, .. } => (path, 4),
            CowDiffEntry::Symlink { path, target } => (path, target.len() as u64),
            CowDiffEntry::Remove { path } | CowDiffEntry::OpaqueDirectory { path } => (path, 0),
        };
        total += 11 + (path.len() - 1) as u64 + payload;
    }
    total
}

fn cow_diff(entries: Vec<CowDiffEntry>) -> CowDiff {
    let encoded_bytes = encoded_bytes(&entries);
    CowDiff {
        entries,
        encoded_bytes,
    }
}

fn build_replay_base(root: &Path, item: &[u8]) {
    fs::create_dir(root).expect("create replay tree");
    fs::write(root.join("item"), item).expect("write replay item");
    fs::create_dir(root.join("kept")).expect("create kept dir");
    fs::write(root.join("kept/value"), b"keep\n").expect("write kept value");
    set_mode(root, 0o751);
    set_mode(&root.join("item"), 0o644);
    set_mode(&root.join("kept"), 0o755);
    set_mode(&root.join("kept/value"), 0o600);
}

fn build_expected_replay(root: &Path) {
    fs::create_dir(root).expect("create expected root");
    fs::write(root.join("item"), b"new\n").expect("write expected item");
    fs::create_dir(root.join("kept")).expect("create expected kept dir");
    fs::write(root.join("kept/value"), b"keep\n").expect("write expected kept value");
    fs::create_dir(root.join("newdir")).expect("create expected newdir");
    fs::write(root.join("newdir/new"), b"payload\n").expect("write expected new file");
    symlink("newdir/new", root.join("link")).expect("create expected link");
    set_mode(root, 0o751);
    set_mode(&root.join("item"), 0o640);
    set_mode(&root.join("kept"), 0o755);
    set_mode(&root.join("kept/value"), 0o600);
    set_mode(&root.join("newdir"), 0o750);
    set_mode(&root.join("newdir/new"), 0o600);
}

#[test]
fn replayed_snapshot_identity_matches_independent_expected_tree() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    let destination = tree.path().join("replayed");
    let expected = tree.path().join("expected");
    build_replay_base(&base, b"old\n");
    build_expected_replay(&expected);

    let base_before = snapshot_sha256(&base, identity_limits()).expect("hash base before replay");
    let changes = cow_diff(vec![
        CowDiffEntry::UpsertFile {
            path: b"/item".to_vec(),
            mode: 0o640,
            bytes: b"new\n".to_vec(),
        },
        CowDiffEntry::Symlink {
            path: b"/link".to_vec(),
            target: b"newdir/new".to_vec(),
        },
        CowDiffEntry::EnsureDirectory {
            path: b"/newdir".to_vec(),
            mode: 0o750,
        },
        CowDiffEntry::UpsertFile {
            path: b"/newdir/new".to_vec(),
            mode: 0o600,
            bytes: b"payload\n".to_vec(),
        },
    ]);

    apply_cow_diff_atomic(&base, &destination, &changes, replay_limits())
        .expect("atomic replay succeeds");

    let base_after = snapshot_sha256(&base, identity_limits()).expect("hash base after replay");
    let replayed = snapshot_sha256(&destination, identity_limits()).expect("hash replayed tree");
    let expected_identity =
        snapshot_sha256(&expected, identity_limits()).expect("hash expected tree");

    assert_eq!(
        base_before, base_after,
        "replay mutated trusted base identity"
    );
    assert_ne!(base_before.sha256, replayed.sha256);
    assert_eq!(replayed, expected_identity);
}
