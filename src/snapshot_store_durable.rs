use crate::snapshot_archive::SnapshotArchiveLimits;
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
        let path = CString::new(store_root.as_os_str().as_bytes())
            .map_err(|_| SnapshotStoreError::InvalidInput("store_root contains NUL".to_owned()))?;
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
