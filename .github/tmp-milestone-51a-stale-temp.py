from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Public recovery report.
replace_one(
    "src/snapshot_store.rs",
    r'''pub struct SnapshotStorePutReport {
    pub identity: SnapshotIdentity,
    pub archive_bytes: u64,
    /// \`true\` when this call published a new object, \`false\` when an exact
    /// immutable object already occupied the same content address.
    pub inserted: bool,
}

#[derive(Debug)]
pub enum SnapshotStoreError {''',
    r'''pub struct SnapshotStorePutReport {
    pub identity: SnapshotIdentity,
    pub archive_bytes: u64,
    /// \`true\` when this call published a new object, \`false\` when an exact
    /// immutable object already occupied the same content address.
    pub inserted: bool,
}

/// Result of one bounded stale temporary-object recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreTempRecoveryReport {
    /// Non-dot entries observed in the objects directory while proving the scan
    /// stayed within the caller's explicit work bound.
    pub entries_examined: u64,
    /// Reserved temporary object files durably removed by this pass.
    pub removed_temporary_objects: u64,
}

#[derive(Debug)]
pub enum SnapshotStoreError {''',
    "snapshot store recovery report",
)

# Recovery-specific fail-closed errors.
replace_one(
    "src/snapshot_store.rs",
    r'''    ObjectConflict {
        identity: SnapshotIdentity,
    },
    UnsupportedPlatform(String),''',
    r'''    ObjectConflict {
        identity: SnapshotIdentity,
    },
    RecoveryLockContended,
    RecoveryBudgetExceeded {
        limit: u64,
        attempted: u64,
    },
    UnsafeTemporaryObject {
        name: String,
        reason: &'static str,
    },
    UnsupportedPlatform(String),''',
    "snapshot store recovery error variants",
)

replace_one(
    "src/snapshot_store.rs",
    r'''            Self::ObjectConflict { identity } => write!(
                f,
                "snapshot store object conflicts with content address: {}-{}-{}",
                identity.sha256_hex(),
                identity.encoded_bytes,
                identity.nodes
            ),
            Self::UnsupportedPlatform(message) => {''',
    r'''            Self::ObjectConflict { identity } => write!(
                f,
                "snapshot store object conflicts with content address: {}-{}-{}",
                identity.sha256_hex(),
                identity.encoded_bytes,
                identity.nodes
            ),
            Self::RecoveryLockContended => {
                f.write_str("snapshot store temporary-object recovery lock is contended")
            }
            Self::RecoveryBudgetExceeded { limit, attempted } => write!(
                f,
                "snapshot store temporary-object recovery entry budget exceeded: limit={limit} attempted={attempted}"
            ),
            Self::UnsafeTemporaryObject { name, reason } => write!(
                f,
                "snapshot store temporary-object recovery rejected {name:?}: {reason}"
            ),
            Self::UnsupportedPlatform(message) => {''',
    "snapshot store recovery display",
)

# Public blocking and nonblocking recovery APIs.
replace_one(
    "src/snapshot_store.rs",
    r'''}

/// Load one exact content-addressed archive object, require that its canonical''',
    r'''}
    
/// Durably remove only crash-left temporary snapshot objects from the object store.
///
/// Every publisher in this runtime holds a shared store-root recovery lock from
/// before temporary-object creation through final rename or cleanup. Recovery
/// takes the exclusive form of that lock, performs a complete bounded preflight
/// of the directory, rejects unsafe reserved-name entries before mutation,
/// unlinks only exact .tmp-<pid>-<counter> single-link regular files, then
/// fsyncs the objects directory and store root before reporting success.
///
/// This is cooperative crash-residue recovery, not general garbage collection:
/// callers that bypass this runtime's coordination lock remain outside the
/// guarantee.
pub fn recover_snapshot_store_stale_temporary_objects(
    store_root: &Path,
    max_entries: u64,
) -> Result<SnapshotStoreTempRecoveryReport, SnapshotStoreError> {
    recover_snapshot_store_stale_temporary_objects_impl(store_root, max_entries, false)
}

/// Nonblocking variant of recover_snapshot_store_stale_temporary_objects.
///
/// Returns RecoveryLockContended instead of waiting when a cooperating
/// publisher or recovery pass currently holds the coordination lock.
pub fn try_recover_snapshot_store_stale_temporary_objects(
    store_root: &Path,
    max_entries: u64,
) -> Result<SnapshotStoreTempRecoveryReport, SnapshotStoreError> {
    recover_snapshot_store_stale_temporary_objects_impl(store_root, max_entries, true)
}

fn recover_snapshot_store_stale_temporary_objects_impl(
    store_root: &Path,
    max_entries: u64,
    nonblocking: bool,
) -> Result<SnapshotStoreTempRecoveryReport, SnapshotStoreError> {
    validate_store_root(store_root)?;
    if max_entries == 0 {
        return Err(SnapshotStoreError::InvalidInput(
            "temporary-object recovery max_entries must be non-zero".to_owned(),
        ));
    }

    #[cfg(target_os = "linux")]
    {
        linux::recover_stale_temporary_objects(store_root, max_entries, nonblocking)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (store_root, max_entries, nonblocking);
        Err(SnapshotStoreError::UnsupportedPlatform(
            "snapshot-store temporary-object recovery currently requires Linux flock, fd-relative directory enumeration, unlinkat, and fsync"
                .to_owned(),
        ))
    }
}

/// Load one exact content-addressed archive object, require that its canonical''',
    "public stale temporary-object recovery API",
)

# Linux imports/coordination filename.
replace_one(
    "src/snapshot_store.rs",
    r'''mod linux {
    use super::{object_filename, SnapshotIdentity, SnapshotStoreError, SnapshotStorePutReport};
    use std::ffi::CString;''',
    r'''mod linux {
    use super::{
        object_filename, SnapshotIdentity, SnapshotStoreError, SnapshotStorePutReport,
        SnapshotStoreTempRecoveryReport,
    };
    use std::ffi::{CStr, CString};''',
    "snapshot store Linux imports",
)

replace_one(
    "src/snapshot_store.rs",
    r'''    const RENAME_NOREPLACE: libc::c_uint = 1;
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);''',
    r'''    const RENAME_NOREPLACE: libc::c_uint = 1;
    const TEMP_RECOVERY_LOCK_FILE: &str = ".snapshot-store-temp-recovery.lock";
    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);''',
    "snapshot store temp recovery lock constant",
)

# Hold a shared recovery lock for the complete temp publication lifetime and
# recheck the final object after waiting for the lock.
replace_one(
    "src/snapshot_store.rs",
    r'''        let (temp, temp_name) = create_temp(objects.raw())?;
        if let Err(primary) = write_and_seal(temp.raw(), archive) {
            drop(temp);
            return cleanup_after_error(objects.raw(), &temp_name, primary);
        }
        drop(temp);

        let renamed = unsafe {''',
    r'''        let _publication_guard = acquire_temp_recovery_lock(root.raw(), false, false)?;
        if let Some(existing) = open_existing(objects.raw(), &final_name)? {
            require_existing_matches(existing.raw(), archive, identity)?;
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: false,
            });
        }

        let (temp, temp_name) = create_temp(objects.raw())?;
        if let Err(primary) = write_and_seal(temp.raw(), archive) {
            drop(temp);
            return cleanup_after_error(objects.raw(), &temp_name, primary);
        }

        let renamed = unsafe {''',
    "publisher shared recovery lock",
)

replace_one(
    "src/snapshot_store.rs",
    r'''        if renamed == 0 {
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: true,
            });
        }

        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            unlink_temp(objects.raw(), &temp_name).map_err(|cleanup| {''',
    r'''        if renamed == 0 {
            drop(temp);
            return Ok(SnapshotStorePutReport {
                identity,
                archive_bytes: archive.len() as u64,
                inserted: true,
            });
        }

        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EEXIST) {
            drop(temp);
            unlink_temp(objects.raw(), &temp_name).map_err(|cleanup| {''',
    "keep temp descriptor alive through rename",
)

replace_one(
    "src/snapshot_store.rs",
    r'''        };
        cleanup_after_error(objects.raw(), &temp_name, primary)
    }

    pub(super) fn read_object(''',
    r'''        };
        drop(temp);
        cleanup_after_error(objects.raw(), &temp_name, primary)
    }

    pub(super) fn recover_stale_temporary_objects(
        store_root: &Path,
        max_entries: u64,
        nonblocking: bool,
    ) -> Result<SnapshotStoreTempRecoveryReport, SnapshotStoreError> {
        let root = open_store_root(store_root)?;
        let _recovery_guard = acquire_temp_recovery_lock(root.raw(), true, nonblocking)?;
        let Some(objects) = open_objects_stream(root.raw())? else {
            return Ok(SnapshotStoreTempRecoveryReport {
                entries_examined: 0,
                removed_temporary_objects: 0,
            });
        };
        let objects_fd = objects.fd()?;
        let mut entries_examined = 0u64;
        let mut candidates = Vec::<CString>::new();

        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(objects.0) };
            if entry.is_null() {
                let errno = unsafe { *libc::__errno_location() };
                if errno != 0 {
                    return Err(SnapshotStoreError::Io {
                        phase: "enumerate temporary snapshot objects",
                        source: std::io::Error::from_raw_os_error(errno),
                    });
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }

            entries_examined = entries_examined.checked_add(1).ok_or(
                SnapshotStoreError::RecoveryBudgetExceeded {
                    limit: max_entries,
                    attempted: u64::MAX,
                },
            )?;
            if entries_examined > max_entries {
                return Err(SnapshotStoreError::RecoveryBudgetExceeded {
                    limit: max_entries,
                    attempted: entries_examined,
                });
            }

            if is_reserved_temp_name(name) {
                candidates.try_reserve(1).map_err(|_| SnapshotStoreError::Io {
                    phase: "reserve temporary-object recovery inventory",
                    source: std::io::Error::from_raw_os_error(libc::ENOMEM),
                })?;
                candidates.push(CString::new(name).map_err(|_| {
                    SnapshotStoreError::InvalidInput(
                        "temporary object filename unexpectedly contains NUL".to_owned(),
                    )
                })?);
            }
        }

        for name in &candidates {
            require_safe_stale_temp(objects_fd, name)?;
        }

        for name in &candidates {
            if unsafe { libc::unlinkat(objects_fd, name.as_ptr(), 0) } != 0 {
                return Err(SnapshotStoreError::Io {
                    phase: "remove stale temporary snapshot object",
                    source: std::io::Error::last_os_error(),
                });
            }
        }

        if !candidates.is_empty() {
            sync_fd(
                objects_fd,
                "sync objects directory after temporary-object recovery",
            )?;
            sync_fd(root.raw(), "sync store root after temporary-object recovery")?;
        }

        Ok(SnapshotStoreTempRecoveryReport {
            entries_examined,
            removed_temporary_objects: candidates.len() as u64,
        })
    }

    pub(super) fn read_object(''',
    "Linux stale temporary-object recovery",
)

# Directory stream and dedicated coordination lock.
replace_one(
    "src/snapshot_store.rs",
    r'''    fn open_existing(
        objects_fd: RawFd,
        name: &CString,
    ) -> Result<Option<OwnedFd>, SnapshotStoreError> {''',
    r'''    struct DirStream(*mut libc::DIR);

    impl DirStream {
        fn fd(&self) -> Result<RawFd, SnapshotStoreError> {
            let fd = unsafe { libc::dirfd(self.0) };
            if fd < 0 {
                return Err(SnapshotStoreError::Io {
                    phase: "query objects directory descriptor for temporary-object recovery",
                    source: std::io::Error::last_os_error(),
                });
            }
            Ok(fd)
        }
    }

    impl Drop for DirStream {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }

    fn open_objects_stream(root_fd: RawFd) -> Result<Option<DirStream>, SnapshotStoreError> {
        let name = cstring_text("objects", "objects directory")?;
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(SnapshotStoreError::Io {
                phase: "open objects directory for temporary-object recovery",
                source: error,
            });
        }

        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(fd);
            }
            return Err(SnapshotStoreError::Io {
                phase: "open objects directory stream for temporary-object recovery",
                source: error,
            });
        }
        Ok(Some(DirStream(stream)))
    }

    fn acquire_temp_recovery_lock(
        root_fd: RawFd,
        exclusive: bool,
        nonblocking: bool,
    ) -> Result<OwnedFd, SnapshotStoreError> {
        let name = cstring_text(
            TEMP_RECOVERY_LOCK_FILE,
            "temporary-object recovery lock filename",
        )?;
        let fd = unsafe {
            libc::openat(
                root_fd,
                name.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(SnapshotStoreError::Io {
                phase: "open temporary-object recovery lock",
                source: std::io::Error::last_os_error(),
            });
        }
        let lock = OwnedFd(fd);

        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(lock.raw(), stat.as_mut_ptr()) } != 0 {
            return Err(SnapshotStoreError::Io {
                phase: "inspect temporary-object recovery lock",
                source: std::io::Error::last_os_error(),
            });
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 {
            return Err(SnapshotStoreError::InvalidInput(
                "temporary-object recovery lock must be a single-link regular file".to_owned(),
            ));
        }

        let mut operation = if exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
        if nonblocking {
            operation |= libc::LOCK_NB;
        }
        if unsafe { libc::flock(lock.raw(), operation) } != 0 {
            let error = std::io::Error::last_os_error();
            if nonblocking
                && matches!(
                    error.raw_os_error(),
                    Some(libc::EAGAIN) | Some(libc::EWOULDBLOCK)
                )
            {
                return Err(SnapshotStoreError::RecoveryLockContended);
            }
            return Err(SnapshotStoreError::Io {
                phase: "acquire temporary-object recovery lock",
                source: error,
            });
        }
        Ok(lock)
    }

    fn open_existing(
        objects_fd: RawFd,
        name: &CString,
    ) -> Result<Option<OwnedFd>, SnapshotStoreError> {''',
    "temporary-object recovery stream and lock helpers",
)

# Strict reserved namespace, safe-object preflight, and fsync helper.
replace_one(
    "src/snapshot_store.rs",
    r'''    fn write_and_seal(fd: RawFd, archive: &[u8]) -> Result<(), SnapshotStoreError> {''',
    r'''    fn is_reserved_temp_name(name: &[u8]) -> bool {
        let Some(rest) = name.strip_prefix(b".tmp-") else {
            return false;
        };
        let mut parts = rest.split(|byte| *byte == b'-');
        let Some(pid) = parts.next() else {
            return false;
        };
        let Some(counter) = parts.next() else {
            return false;
        };
        parts.next().is_none() && is_canonical_decimal(pid) && is_canonical_decimal(counter)
    }

    fn is_canonical_decimal(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && !(bytes.len() > 1 && bytes[0] == b'0')
            && bytes.iter().all(u8::is_ascii_digit)
    }

    fn require_safe_stale_temp(
        objects_fd: RawFd,
        name: &CString,
    ) -> Result<(), SnapshotStoreError> {
        let mut stat = MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                objects_fd,
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err(SnapshotStoreError::Io {
                phase: "inspect stale temporary snapshot object",
                source: std::io::Error::last_os_error(),
            });
        }
        let stat = unsafe { stat.assume_init() };
        let name_text = name.to_string_lossy().into_owned();
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SnapshotStoreError::UnsafeTemporaryObject {
                name: name_text,
                reason: "reserved temporary-object name is not a regular file",
            });
        }
        if stat.st_nlink != 1 {
            return Err(SnapshotStoreError::UnsafeTemporaryObject {
                name: name_text,
                reason: "reserved temporary-object file has multiple hard links",
            });
        }
        Ok(())
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

    fn write_and_seal(fd: RawFd, archive: &[u8]) -> Result<(), SnapshotStoreError> {''',
    "temporary-object recovery validation helpers",
)

# Public exports.
replace_one(
    "src/lib.rs",
    r'''    materialize_snapshot_store_object_ed25519_atomic, snapshot_store_object_path,
    store_snapshot_archive_ed25519_atomic, SnapshotStoreError, SnapshotStorePutReport,
};''',
    r'''    materialize_snapshot_store_object_ed25519_atomic,
    recover_snapshot_store_stale_temporary_objects, snapshot_store_object_path,
    store_snapshot_archive_ed25519_atomic, try_recover_snapshot_store_stale_temporary_objects,
    SnapshotStoreError, SnapshotStorePutReport, SnapshotStoreTempRecoveryReport,
};''',
    "snapshot-store recovery exports",
)

# Integration test imports.
replace_one(
    "tests/snapshot_store.rs",
    r'''    materialize_snapshot_store_object_ed25519_atomic, serialize_snapshot_archive,
    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,
    store_snapshot_archive_ed25519_durable, SnapshotArchiveLimits, SnapshotIdentityLimits,
    SnapshotStoreError,
};''',
    r'''    materialize_snapshot_store_object_ed25519_atomic,
    recover_snapshot_store_stale_temporary_objects, serialize_snapshot_archive,
    sign_snapshot_ed25519, snapshot_store_object_path, store_snapshot_archive_ed25519_atomic,
    store_snapshot_archive_ed25519_durable, try_recover_snapshot_store_stale_temporary_objects,
    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotStoreError,
};''',
    "snapshot-store recovery test imports",
)

replace_one(
    "tests/snapshot_store.rs",
    r'''use std::fs;
use std::os::unix::fs::PermissionsExt;''',
    r'''use std::fs;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};''',
    "snapshot-store recovery test std imports",
)

replace_one(
    "tests/snapshot_store.rs",
    r'''#[test]
fn authenticated_store_deduplicates_and_materializes_frozen_archive() {''',
    r'''#[test]
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
fn authenticated_store_deduplicates_and_materializes_frozen_archive() {''',
    "snapshot-store recovery integration tests",
)
