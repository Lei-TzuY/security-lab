from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


module = r'''use crate::snapshot_archive::SnapshotArchiveLimits;
use crate::snapshot_signature::{
    SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use crate::snapshot_store::{
    snapshot_store_object_path, store_snapshot_archive_ed25519_atomic, SnapshotStoreError,
    SnapshotStorePutReport,
};
use std::path::Path;

/// Authenticated content-addressed publication with success-return durability.
///
/// This first executes the existing verify-before-store, no-replace atomic put.
/// On Linux, a successful result is acknowledged only after the final object,
/// the `objects/` directory containing its name, and the pre-existing store root
/// have each crossed an `fsync` barrier in that order. If execution is
/// interrupted after the atomic rename but before this function returns, the
/// caller can retry the same authenticated archive: the existing exact-object
/// deduplication path converges on the same identity and the barriers are run
/// again before success is returned.
///
/// The durability guarantee is exactly the underlying local filesystem/kernel
/// `fsync` contract. This does not add a journal, garbage collection, stale-temp
/// scavenging, remote replication, or protection against a hostile privileged
/// writer controlling the store root.
pub fn store_snapshot_archive_ed25519_durable(
    store_root: &Path,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotStorePutReport, SnapshotStoreError> {
    let report = store_snapshot_archive_ed25519_atomic(
        store_root,
        archive,
        public_key,
        expected_signature,
        limits,
    )?;

    #[cfg(target_os = "linux")]
    {
        linux::sync_committed_object(store_root, report)?;
        Ok(report)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, report);
        Err(SnapshotStoreError::UnsupportedPlatform(
            "durable content-addressed snapshot publication currently requires Linux fsync and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{snapshot_store_object_path, SnapshotStoreError, SnapshotStorePutReport};
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::os::fd::RawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    struct OwnedFd(RawFd);

    impl OwnedFd {
        fn raw(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for OwnedFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    pub(super) fn sync_committed_object(
        store_root: &Path,
        report: SnapshotStorePutReport,
    ) -> Result<(), SnapshotStoreError> {
        let root = open_root(store_root)?;
        let objects_name = CString::new("objects").expect("static objects directory has no NUL");
        let objects = open_directory_at(
            root.raw(),
            &objects_name,
            "open objects directory for durability sync",
        )?;

        let object_path = snapshot_store_object_path(store_root, report.identity);
        let object_name = object_path.file_name().ok_or_else(|| {
            SnapshotStoreError::InvalidInput(
                "content-addressed object path has no filename".to_owned(),
            )
        })?;
        let object_name = CString::new(object_name.as_bytes()).map_err(|_| {
            SnapshotStoreError::InvalidInput(
                "content-addressed object filename contains NUL".to_owned(),
            )
        })?;
        let object = open_object_at(objects.raw(), &object_name, report)?;

        sync_fd(object.raw(), "sync durable snapshot object")?;
        sync_fd(objects.raw(), "sync durable snapshot objects directory")?;
        sync_fd(root.raw(), "sync durable snapshot store root")?;
        Ok(())
    }

    fn open_root(store_root: &Path) -> Result<OwnedFd, SnapshotStoreError> {
        let path = CString::new(store_root.as_os_str().as_bytes()).map_err(|_| {
            SnapshotStoreError::InvalidInput("store_root contains NUL".to_owned())
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase: "open store root for durability sync",
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(OwnedFd(fd))
    }

    fn open_directory_at(
        parent_fd: RawFd,
        name: &CString,
        phase: &'static str,
    ) -> Result<OwnedFd, SnapshotStoreError> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(OwnedFd(fd))
    }

    fn open_object_at(
        objects_fd: RawFd,
        name: &CString,
        report: SnapshotStorePutReport,
    ) -> Result<OwnedFd, SnapshotStoreError> {
        let fd = unsafe {
            libc::openat(
                objects_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase: "open committed snapshot object for durability sync",
                source: std::io::Error::last_os_error(),
            });
        }
        let fd = OwnedFd(fd);
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd.raw(), stat.as_mut_ptr()) } != 0 {
            return Err(SnapshotStoreError::Io {
                phase: "stat committed snapshot object for durability sync",
                source: std::io::Error::last_os_error(),
            });
        }
        let stat = unsafe { stat.assume_init() };
        if (stat.st_mode & libc::S_IFMT) != libc::S_IFREG
            || stat.st_size < 0
            || stat.st_size as u64 != report.archive_bytes
            || (stat.st_mode & 0o222) != 0
        {
            return Err(SnapshotStoreError::ObjectConflict {
                identity: report.identity,
            });
        }
        Ok(fd)
    }

    fn sync_fd(fd: RawFd, phase: &'static str) -> Result<(), SnapshotStoreError> {
        if unsafe { libc::fsync(fd) } != 0 {
            return Err(SnapshotStoreError::Io {
                phase,
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}
'''
Path("src/snapshot_store_durable.rs").write_text(module)

replace_once(
    "src/lib.rs",
    "mod snapshot_store;\n",
    "mod snapshot_store;\nmod snapshot_store_durable;\n",
    "lib durable module declaration",
)
replace_once(
    "src/lib.rs",
    "pub use snapshot_store::{\n    materialize_snapshot_store_object_ed25519_atomic, snapshot_store_object_path,\n    store_snapshot_archive_ed25519_atomic, SnapshotStoreError, SnapshotStorePutReport,\n};\n",
    "pub use snapshot_store::{\n    materialize_snapshot_store_object_ed25519_atomic, snapshot_store_object_path,\n    store_snapshot_archive_ed25519_atomic, SnapshotStoreError, SnapshotStorePutReport,\n};\npub use snapshot_store_durable::store_snapshot_archive_ed25519_durable;\n",
    "lib durable export",
)

replace_once(
    "tests/snapshot_store.rs",
    "    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,\n    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotStoreError,\n",
    "    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,\n    store_snapshot_archive_ed25519_durable, SnapshotArchiveLimits, SnapshotIdentityLimits,\n    SnapshotStoreError,\n",
    "snapshot store durable import",
)
replace_once(
    "tests/snapshot_store.rs",
    "use std::os::unix::fs::PermissionsExt;\nuse std::path::{Path, PathBuf};\nuse std::process;\n",
    "use std::os::unix::fs::PermissionsExt;\nuse std::os::unix::process::CommandExt;\nuse std::path::{Path, PathBuf};\nuse std::process::{self, Command};\n",
    "snapshot store subprocess imports",
)

with Path("tests/snapshot_store.rs").open("a") as f:
    f.write(r'''

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

    let mut command = Command::new(std::env::current_exe().expect("resolve current test executable"));
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
''')
