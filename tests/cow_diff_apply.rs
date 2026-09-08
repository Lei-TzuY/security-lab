#![cfg(target_os = "linux")]

use security_lab::{
    apply_cow_diff_atomic, CowDiff, CowDiffApplyError, CowDiffApplyLimits, CowDiffEntry,
};
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
            "security-lab-cow-diff-apply-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).expect("create test root");
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

fn diff(entries: Vec<CowDiffEntry>) -> CowDiff {
    let encoded_bytes = encoded_bytes(&entries);
    CowDiff {
        entries,
        encoded_bytes,
    }
}

fn limits() -> CowDiffApplyLimits {
    CowDiffApplyLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 1024,
    }
}

fn staging_entries(parent: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(parent).expect("read parent") {
        let path = entry.expect("parent entry").path();
        if path
            .file_name()
            .expect("entry name")
            .as_bytes()
            .starts_with(b".security-lab-cow-apply-")
        {
            entries.push(path);
        }
    }
    entries
}

#[test]
fn atomically_replays_supported_diff_without_mutating_base() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    let destination = tree.path().join("snapshot");
    fs::create_dir(&base).expect("create base");
    fs::write(base.join("existing"), b"old\n").expect("write existing");
    fs::write(base.join("remove-me"), b"remove\n").expect("write removable");
    fs::create_dir(base.join("opaque")).expect("create opaque base dir");
    fs::write(base.join("opaque/old-child"), b"old-child\n").expect("write opaque child");
    fs::create_dir(base.join("keep-dir")).expect("create keep dir");
    fs::write(base.join("keep-dir/value"), b"keep\n").expect("write keep value");
    symlink("existing", base.join("base-link")).expect("create base symlink");
    fs::set_permissions(&base, fs::Permissions::from_mode(0o751)).expect("set base mode");
    fs::set_permissions(base.join("keep-dir"), fs::Permissions::from_mode(0o750))
        .expect("set keep-dir mode");

    let changes = diff(vec![
        CowDiffEntry::UpsertFile {
            path: b"/existing".to_vec(),
            mode: 0o640,
            bytes: b"replaced\n".to_vec(),
        },
        CowDiffEntry::EnsureDirectory {
            path: b"/newdir".to_vec(),
            mode: 0o750,
        },
        CowDiffEntry::UpsertFile {
            path: b"/newdir/file".to_vec(),
            mode: 0o600,
            bytes: b"new-file\n".to_vec(),
        },
        CowDiffEntry::EnsureDirectory {
            path: b"/opaque".to_vec(),
            mode: 0o700,
        },
        CowDiffEntry::OpaqueDirectory {
            path: b"/opaque".to_vec(),
        },
        CowDiffEntry::Remove {
            path: b"/remove-me".to_vec(),
        },
        CowDiffEntry::Symlink {
            path: b"/symlink-new".to_vec(),
            target: b"newdir/file".to_vec(),
        },
    ]);

    let report = apply_cow_diff_atomic(&base, &destination, &changes, limits())
        .expect("atomic replay succeeds");

    assert_eq!(report.diff_encoded_bytes, changes.encoded_bytes);
    assert!(report.copied_base_bytes >= b"old\nremove\nold-child\nkeep\nexisting".len() as u64);
    assert!(report.accounted_nodes > changes.entries.len() as u64);
    assert_eq!(
        fs::read(destination.join("existing")).unwrap(),
        b"replaced\n"
    );
    assert_eq!(
        fs::metadata(destination.join("existing"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o640
    );
    assert_eq!(
        fs::read(destination.join("newdir/file")).unwrap(),
        b"new-file\n"
    );
    assert_eq!(
        fs::metadata(destination.join("newdir/file"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(destination.join("newdir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );
    assert!(!destination.join("opaque/old-child").exists());
    assert!(!destination.join("remove-me").exists());
    assert_eq!(
        fs::read_link(destination.join("symlink-new"))
            .unwrap()
            .as_os_str()
            .as_bytes(),
        b"newdir/file"
    );
    assert_eq!(
        fs::read(destination.join("keep-dir/value")).unwrap(),
        b"keep\n"
    );
    assert_eq!(
        fs::metadata(destination.join("keep-dir"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o750
    );
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o7777,
        0o751
    );

    assert_eq!(fs::read(base.join("existing")).unwrap(), b"old\n");
    assert_eq!(fs::read(base.join("remove-me")).unwrap(), b"remove\n");
    assert_eq!(
        fs::read(base.join("opaque/old-child")).unwrap(),
        b"old-child\n"
    );
    assert!(staging_entries(tree.path()).is_empty());
}

#[test]
fn symlink_parent_escape_fails_closed_without_publication() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    let outside = tree.path().join("outside");
    let destination = tree.path().join("snapshot");
    fs::create_dir(&base).expect("create base");
    fs::create_dir(&outside).expect("create outside");
    symlink(&outside, base.join("escape")).expect("create escaping symlink");

    let changes = diff(vec![CowDiffEntry::UpsertFile {
        path: b"/escape/owned".to_vec(),
        mode: 0o600,
        bytes: b"must-not-escape\n".to_vec(),
    }]);

    let error = apply_cow_diff_atomic(&base, &destination, &changes, limits())
        .expect_err("symlink parent must fail closed");
    assert!(matches!(error, CowDiffApplyError::Io { .. }));
    assert!(!outside.join("owned").exists());
    assert!(!destination.exists());
    assert!(staging_entries(tree.path()).is_empty());
}

#[test]
fn byte_budget_failure_is_atomic_and_cleans_staging() {
    let tree = TempTree::new();
    let base = tree.path().join("base");
    let destination = tree.path().join("snapshot");
    fs::create_dir(&base).expect("create base");
    let payload = vec![b'x'; 8192];
    fs::write(base.join("large"), &payload).expect("write large base file");

    let changes = diff(vec![CowDiffEntry::Remove {
        path: b"/missing".to_vec(),
    }]);
    let tight = CowDiffApplyLimits {
        max_bytes: changes.encoded_bytes + 4096,
        max_nodes: 100,
    };
    let error = apply_cow_diff_atomic(&base, &destination, &changes, tight)
        .expect_err("copy budget must fail before publication");
    assert!(matches!(
        error,
        CowDiffApplyError::BudgetExceeded {
            resource: "byte",
            ..
        }
    ));
    assert_eq!(fs::read(base.join("large")).unwrap(), payload);
    assert!(!destination.exists());
    assert!(staging_entries(tree.path()).is_empty());
}
