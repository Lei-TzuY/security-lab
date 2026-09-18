#![cfg(target_os = "linux")]

use security_lab::{
    materialize_snapshot_store_object_ed25519_atomic,
    recover_snapshot_store_stale_temporary_objects, serialize_snapshot_archive,
    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,
    store_snapshot_archive_ed25519_durable, try_recover_snapshot_store_stale_temporary_objects,
    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotStoreError,
};
use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
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
fn stale_temporary_object_recovery_is_bounded_and_preserves_non_temp_entries() {
    let workspace = TempDir::new("stale-temp-recovery");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x7a; 32], identity_limits())
        .expect("sign canonical source identity");
    let stored = store_snapshot_archive_ed25519_atomic(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("seed canonical snapshot object");

    let objects = store.join("objects");
    let stale = objects.join(".tmp-4242-0");
    let unrelated = objects.join("operator-note");
    fs::write(&stale, b"crash residue").expect("write stale temp fixture");
    fs::write(&unrelated, b"preserve me").expect("write unrelated entry");

    let report = recover_snapshot_store_stale_temporary_objects(&store, 16)
        .expect("recover stale temporary object");
    assert_eq!(report.entries_examined, 3);
    assert_eq!(report.removed_temporary_objects, 1);
    assert!(!stale.exists());
    assert!(
        unrelated.exists(),
        "recovery must not become broad garbage collection"
    );
    assert!(
        snapshot_store_object_path(&store, stored.identity).exists(),
        "canonical content-addressed object must remain untouched"
    );
}

#[test]
fn temporary_object_recovery_budget_fails_before_deletion() {
    let workspace = TempDir::new("stale-temp-budget");
    let store = workspace.path().join("store");
    let objects = store.join("objects");
    fs::create_dir(&store).expect("create store root");
    fs::create_dir(&objects).expect("create objects directory");
    let first = objects.join(".tmp-7-0");
    let second = objects.join(".tmp-7-1");
    fs::write(&first, b"first").expect("write first stale temp");
    fs::write(&second, b"second").expect("write second stale temp");

    match recover_snapshot_store_stale_temporary_objects(&store, 1)
        .expect_err("entry budget must fail closed")
    {
        SnapshotStoreError::RecoveryBudgetExceeded {
            limit: 1,
            attempted: 2,
        } => {}
        other => panic!("unexpected recovery budget result: {other}"),
    }
    assert!(
        first.exists() && second.exists(),
        "budget failure must not partially clean"
    );
}

#[test]
fn temporary_object_recovery_rejects_unsafe_reserved_entry_before_deletion() {
    let workspace = TempDir::new("stale-temp-unsafe");
    let store = workspace.path().join("store");
    let objects = store.join("objects");
    fs::create_dir(&store).expect("create store root");
    fs::create_dir(&objects).expect("create objects directory");
    let safe = objects.join(".tmp-8-0");
    let unsafe_entry = objects.join(".tmp-8-1");
    fs::write(&safe, b"safe stale temp").expect("write safe stale temp");
    symlink("missing-target", &unsafe_entry).expect("create reserved-name symlink");

    match recover_snapshot_store_stale_temporary_objects(&store, 16)
        .expect_err("reserved-name symlink must fail closed")
    {
        SnapshotStoreError::UnsafeTemporaryObject { name, .. } => {
            assert_eq!(name, ".tmp-8-1");
        }
        other => panic!("unexpected unsafe temporary-object result: {other}"),
    }
    assert!(
        safe.exists() && fs::symlink_metadata(&unsafe_entry).is_ok(),
        "unsafe preflight must preserve every candidate as evidence"
    );
}

#[test]
fn nonblocking_temporary_object_recovery_reports_live_coordination_lock() {
    let workspace = TempDir::new("stale-temp-lock");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let lock_path = store.join(".snapshot-store-temp-recovery.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .expect("open temporary-object recovery lock fixture");
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) },
        0,
        "hold publisher-form shared recovery lock"
    );

    assert!(matches!(
        try_recover_snapshot_store_stale_temporary_objects(&store, 16),
        Err(SnapshotStoreError::RecoveryLockContended)
    ));

    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) },
        0,
        "release recovery lock fixture"
    );
    let report = try_recover_snapshot_store_stale_temporary_objects(&store, 16)
        .expect("recovery succeeds once live publisher lock is released");
    assert_eq!(report.removed_temporary_objects, 0);
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

#[test]
fn durable_store_inserts_and_materializes_authenticated_object() {
    let workspace = TempDir::new("durable-insert");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");
    let destination = workspace.path().join("restored");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x5a; 32], identity_limits())
        .expect("sign canonical source identity");
    let stored = store_snapshot_archive_ed25519_durable(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("durably publish authenticated archive");
    assert!(stored.inserted);
    assert_eq!(stored.identity, archive.identity);

    let report = materialize_snapshot_store_object_ed25519_atomic(
        &store,
        stored.identity,
        &destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("materialize durably published object");
    assert_eq!(report.identity, stored.identity);
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"frozen-original\n"
    );
}

const DURABLE_HELPER_ROOT: &str = "SECURITY_LAB_DURABLE_FSYNC_HELPER_ROOT";

#[test]
fn durable_sync_failure_helper() {
    let Some(root) = std::env::var_os(DURABLE_HELPER_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let source = root.join("source");
    let store = root.join("store");
    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x6b; 32], identity_limits())
        .expect("sign canonical source identity");

    match store_snapshot_archive_ed25519_durable(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect_err("denied fsync must prevent durable success acknowledgement")
    {
        SnapshotStoreError::Io { phase, source } => {
            assert_eq!(phase, "sync durable snapshot object");
            assert_eq!(source.raw_os_error(), Some(libc::EPERM));
        }
        other => panic!("unexpected denied-fsync result: {other}"),
    }
}

#[test]
fn denied_durability_barrier_fails_closed_and_retry_converges() {
    let workspace = TempDir::new("durable-retry");
    let source = create_source(workspace.path());
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create store root");

    let mut command =
        Command::new(std::env::current_exe().expect("resolve current test executable"));
    command
        .arg("--exact")
        .arg("durable_sync_failure_helper")
        .arg("--nocapture")
        .env(DURABLE_HELPER_ROOT, workspace.path());
    unsafe {
        command.pre_exec(install_fsync_deny_filter);
    }
    let status = command
        .status()
        .expect("run denied-fsync durable helper subprocess");
    assert!(status.success(), "denied-fsync helper failed: {status}");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let evidence = sign_snapshot_ed25519(&source, &[0x6b; 32], identity_limits())
        .expect("sign canonical source identity");
    let recovered = store_snapshot_archive_ed25519_durable(
        &store,
        &archive.bytes,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("retry must complete durability barriers for exact pre-existing object");
    assert!(
        !recovered.inserted,
        "retry after failed durability acknowledgement must converge through exact dedup"
    );
    assert_eq!(recovered.identity, archive.identity);

    let destination = workspace.path().join("restored");
    materialize_snapshot_store_object_ed25519_atomic(
        &store,
        recovered.identity,
        &destination,
        &evidence.public_key,
        &evidence.signature,
        archive_limits(),
    )
    .expect("materialize recovered durable object");
    assert_eq!(
        fs::read(destination.join("payload")).expect("read recovered payload"),
        b"frozen-original\n"
    );
}

fn install_fsync_deny_filter() -> std::io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

    let mut filter = [
        libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt: 0,
            jf: 1,
            k: libc::SYS_fsync as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO | libc::EPERM as u32,
        },
        libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
