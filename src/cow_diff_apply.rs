use crate::snapshot_identity::{
    snapshot_sha256, SnapshotIdentity, SnapshotIdentityError, SnapshotIdentityLimits,
};
use crate::{CowDiff, CowDiffEntry};
use std::error::Error;
use std::fmt;
use std::path::Path;

const MAX_APPLY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_APPLY_NODES: u64 = 100_000;

/// Explicit host-side work limits for atomic COW-diff replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowDiffApplyLimits {
    /// Maximum canonical diff bytes plus regular-file/symlink bytes copied from the base tree.
    pub max_bytes: u64,
    /// Maximum accounted nodes: base-tree nodes plus diff records.
    pub max_nodes: u64,
}

/// Observable work consumed by a successful atomic replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowDiffApplyReport {
    pub copied_base_bytes: u64,
    pub diff_encoded_bytes: u64,
    pub accounted_nodes: u64,
}

/// Evidence returned when replay was gated by an expected canonical base identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CowDiffApplyBoundReport {
    /// Canonical identity observed immediately before replay setup began.
    pub base_identity: SnapshotIdentity,
    /// Existing bounded/failure-atomic replay accounting.
    pub replay: CowDiffApplyReport,
}

#[derive(Debug)]
pub enum CowDiffApplyError {
    InvalidInput(String),
    BudgetExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    BaseIdentity {
        source: SnapshotIdentityError,
    },
    BaseIdentityMismatch {
        expected: SnapshotIdentity,
        actual: SnapshotIdentity,
    },
    UnsupportedPlatform(String),
    Io {
        phase: &'static str,
        source: std::io::Error,
    },
    CleanupFailed {
        primary: String,
        cleanup: String,
    },
}

impl fmt::Display for CowDiffApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid COW diff apply input: {message}"),
            Self::BudgetExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                f,
                "COW diff apply {resource} budget exceeded: limit={limit} attempted={attempted}"
            ),
            Self::BaseIdentity { source } => {
                write!(f, "COW diff apply base identity check failed: {source}")
            }
            Self::BaseIdentityMismatch { expected, actual } => write!(
                f,
                "COW diff apply base identity mismatch: expected_sha256={} actual_sha256={}",
                expected.sha256_hex(),
                actual.sha256_hex()
            ),
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported COW diff apply platform: {message}")
            }
            Self::Io { phase, source } => {
                write!(f, "COW diff apply failed during {phase}: {source}")
            }
            Self::CleanupFailed { primary, cleanup } => write!(
                f,
                "COW diff apply failed ({primary}) and staging cleanup also failed ({cleanup})"
            ),
        }
    }
}

impl Error for CowDiffApplyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BaseIdentity { source } => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Materialize `base` plus `diff` as a new snapshot directory at `destination`.
///
/// The base tree is copied into a private sibling staging directory, the canonical
/// COW diff is replayed there without following symlink parents, and the completed
/// tree is published with one Linux `renameat2(RENAME_NOREPLACE)`. `destination`
/// must not already exist. Any pre-publish failure leaves `base` untouched and
/// keeps `destination` absent; a staging-cleanup failure is reported explicitly.
pub fn apply_cow_diff_atomic(
    base: &Path,
    destination: &Path,
    diff: &CowDiff,
    limits: CowDiffApplyLimits,
) -> Result<CowDiffApplyReport, CowDiffApplyError> {
    validate_limits(limits)?;
    #[cfg(target_os = "linux")]
    {
        linux::apply(base, destination, diff, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (base, destination, diff);
        Err(CowDiffApplyError::UnsupportedPlatform(
            "atomic replay requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

/// Replay `diff` only when the current canonical identity of `base` matches
/// `expected_base`. The identity check is completed before destination inspection
/// or replay staging begins. A mismatch therefore cannot publish or stage a tree.
///
/// This is an optimistic trusted-base precondition, not hostile-writer locking:
/// callers must not infer protection against a concurrent mutation after the
/// identity scan and before/during replay. The SHA-256 identity is also not an
/// authenticity or provenance statement.
pub fn apply_cow_diff_atomic_with_expected_base(
    base: &Path,
    destination: &Path,
    diff: &CowDiff,
    expected_base: SnapshotIdentity,
    identity_limits: SnapshotIdentityLimits,
    replay_limits: CowDiffApplyLimits,
) -> Result<CowDiffApplyBoundReport, CowDiffApplyError> {
    validate_limits(replay_limits)?;
    let actual = snapshot_sha256(base, identity_limits)
        .map_err(|source| CowDiffApplyError::BaseIdentity { source })?;
    if actual.sha256 != expected_base.sha256 {
        return Err(CowDiffApplyError::BaseIdentityMismatch {
            expected: expected_base,
            actual,
        });
    }

    let replay = apply_cow_diff_atomic(base, destination, diff, replay_limits)?;
    Ok(CowDiffApplyBoundReport {
        base_identity: actual,
        replay,
    })
}

fn validate_limits(limits: CowDiffApplyLimits) -> Result<(), CowDiffApplyError> {
    if limits.max_bytes == 0 || limits.max_bytes > MAX_APPLY_BYTES {
        return Err(CowDiffApplyError::InvalidInput(format!(
            "max_bytes must be between 1 and {MAX_APPLY_BYTES}"
        )));
    }
    if limits.max_nodes == 0 || limits.max_nodes > MAX_APPLY_NODES {
        return Err(CowDiffApplyError::InvalidInput(format!(
            "max_nodes must be between 1 and {MAX_APPLY_NODES}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::cmp::Ordering as CmpOrdering;
    use std::collections::BTreeMap;
    use std::ffi::{CString, OsString};
    use std::fs;
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    const CANONICAL_MAGIC_BYTES: u64 = 6;
    const RECORD_HEADER_BYTES: u64 = 11;
    const MAX_RELATIVE_PATH_BYTES: usize = 4096;
    const MAX_SYMLINK_TARGET_BYTES: usize = 4095;
    const MAX_TREE_DEPTH: usize = 64;
    const DIRENT_BUFFER_BYTES: usize = 8192;
    const RENAME_NOREPLACE: u32 = 1;
    static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Fd(RawFd);

    impl Fd {
        fn raw(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    struct Budget {
        limits: CowDiffApplyLimits,
        diff_bytes: u64,
        copied_base_bytes: u64,
        accounted_nodes: u64,
    }

    impl Budget {
        fn new(
            limits: CowDiffApplyLimits,
            diff_bytes: u64,
            diff_nodes: u64,
        ) -> Result<Self, CowDiffApplyError> {
            if diff_bytes > limits.max_bytes {
                return Err(CowDiffApplyError::BudgetExceeded {
                    resource: "byte",
                    limit: limits.max_bytes,
                    attempted: diff_bytes,
                });
            }
            let accounted_nodes = diff_nodes.checked_add(1).ok_or_else(|| {
                CowDiffApplyError::InvalidInput("node accounting overflow".to_owned())
            })?;
            if accounted_nodes > limits.max_nodes {
                return Err(CowDiffApplyError::BudgetExceeded {
                    resource: "node",
                    limit: limits.max_nodes,
                    attempted: accounted_nodes,
                });
            }
            Ok(Self {
                limits,
                diff_bytes,
                copied_base_bytes: 0,
                accounted_nodes,
            })
        }

        fn consume_base_bytes(&mut self, amount: u64) -> Result<(), CowDiffApplyError> {
            let copied = self.copied_base_bytes.checked_add(amount).ok_or_else(|| {
                CowDiffApplyError::InvalidInput("byte accounting overflow".to_owned())
            })?;
            let attempted = self.diff_bytes.checked_add(copied).ok_or_else(|| {
                CowDiffApplyError::InvalidInput("byte accounting overflow".to_owned())
            })?;
            if attempted > self.limits.max_bytes {
                return Err(CowDiffApplyError::BudgetExceeded {
                    resource: "byte",
                    limit: self.limits.max_bytes,
                    attempted,
                });
            }
            self.copied_base_bytes = copied;
            Ok(())
        }

        fn consume_base_node(&mut self) -> Result<(), CowDiffApplyError> {
            let attempted = self.accounted_nodes.checked_add(1).ok_or_else(|| {
                CowDiffApplyError::InvalidInput("node accounting overflow".to_owned())
            })?;
            if attempted > self.limits.max_nodes {
                return Err(CowDiffApplyError::BudgetExceeded {
                    resource: "node",
                    limit: self.limits.max_nodes,
                    attempted,
                });
            }
            self.accounted_nodes = attempted;
            Ok(())
        }

        fn report(&self) -> CowDiffApplyReport {
            CowDiffApplyReport {
                copied_base_bytes: self.copied_base_bytes,
                diff_encoded_bytes: self.diff_bytes,
                accounted_nodes: self.accounted_nodes,
            }
        }
    }

    pub(super) fn apply(
        base: &Path,
        destination: &Path,
        diff: &CowDiff,
        limits: CowDiffApplyLimits,
    ) -> Result<CowDiffApplyReport, CowDiffApplyError> {
        if !base.is_absolute() || !destination.is_absolute() {
            return Err(CowDiffApplyError::InvalidInput(
                "base and destination must be absolute host paths".to_owned(),
            ));
        }
        let validated_paths = validate_diff(diff)?;
        let mut budget = Budget::new(limits, diff.encoded_bytes, diff.entries.len() as u64)?;

        let canonical_base =
            fs::canonicalize(base).map_err(|source| io_error("canonicalize base", source))?;
        let destination_parent = destination.parent().ok_or_else(|| {
            CowDiffApplyError::InvalidInput("destination must have a parent directory".to_owned())
        })?;
        let canonical_parent = fs::canonicalize(destination_parent)
            .map_err(|source| io_error("canonicalize destination parent", source))?;
        if canonical_parent.starts_with(&canonical_base) {
            return Err(CowDiffApplyError::InvalidInput(
                "destination parent must not be the base directory or a descendant of it"
                    .to_owned(),
            ));
        }
        let destination_name = destination.file_name().ok_or_else(|| {
            CowDiffApplyError::InvalidInput(
                "destination must name one snapshot directory".to_owned(),
            )
        })?;
        let destination_name = checked_component(destination_name.as_bytes(), "destination name")?;
        let published_path =
            canonical_parent.join(OsString::from_vec(destination_name.as_bytes().to_vec()));
        match fs::symlink_metadata(&published_path) {
            Ok(_) => {
                return Err(CowDiffApplyError::InvalidInput(
                    "destination already exists".to_owned(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect destination", source)),
        }

        let base_fd = open_directory_path(&canonical_base, "open base directory")?;
        let parent_fd = open_directory_path(&canonical_parent, "open destination parent")?;
        let (staging_name, staging_fd) = create_staging(parent_fd.raw())?;

        let replay_result = (|| {
            let mut root_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(base_fd.raw(), &mut root_stat) } == -1 {
                return Err(io_error("stat base directory", io::Error::last_os_error()));
            }
            let mut directory_modes = BTreeMap::new();
            directory_modes.insert(Vec::new(), (root_stat.st_mode & 0o7777) as u32);
            copy_directory(
                base_fd.raw(),
                staging_fd.raw(),
                &mut budget,
                &mut directory_modes,
                &[],
                0,
            )?;
            apply_entries(
                staging_fd.raw(),
                diff,
                &validated_paths,
                &mut directory_modes,
            )?;
            restore_directory_modes(staging_fd.raw(), &directory_modes)?;
            atomic_publish(
                parent_fd.raw(),
                staging_name.as_c_str(),
                destination_name.as_c_str(),
            )?;
            Ok(budget.report())
        })();

        if let Err(primary) = replay_result {
            if let Err(cleanup) = remove_any(parent_fd.raw(), staging_name.as_c_str()) {
                return Err(CowDiffApplyError::CleanupFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                });
            }
            return Err(primary);
        }
        replay_result
    }

    fn validate_diff(diff: &CowDiff) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {
        let mut encoded = CANONICAL_MAGIC_BYTES;
        let mut paths = Vec::with_capacity(diff.entries.len());
        let mut previous: Option<(Vec<u8>, u8)> = None;
        for entry in &diff.entries {
            let path = entry_path(entry);
            let relative =
                validate_diff_path(path, matches!(entry, CowDiffEntry::OpaqueDirectory { .. }))?;
            let rank = entry_rank(entry);
            if let Some((previous_path, previous_rank)) = &previous {
                match relative.cmp(previous_path) {
                    CmpOrdering::Less => {
                        return Err(CowDiffApplyError::InvalidInput(
                            "diff entries are not in canonical path order".to_owned(),
                        ));
                    }
                    CmpOrdering::Equal if !(*previous_rank == 0 && rank == 1) => {
                        return Err(CowDiffApplyError::InvalidInput(
                            "duplicate diff path is only valid for directory plus opaque-directory records"
                                .to_owned(),
                        ));
                    }
                    _ => {}
                }
            }
            let payload_len = match entry {
                CowDiffEntry::UpsertFile { mode, bytes, .. } => {
                    validate_mode(*mode)?;
                    4u64.checked_add(bytes.len() as u64).ok_or_else(|| {
                        CowDiffApplyError::InvalidInput("file payload length overflow".to_owned())
                    })?
                }
                CowDiffEntry::EnsureDirectory { mode, .. } => {
                    validate_mode(*mode)?;
                    4
                }
                CowDiffEntry::Symlink { target, .. } => {
                    if target.is_empty()
                        || target.len() > MAX_SYMLINK_TARGET_BYTES
                        || target.contains(&0)
                    {
                        return Err(CowDiffApplyError::InvalidInput(
                            "symlink target must be non-empty, NUL-free, and at most 4095 bytes"
                                .to_owned(),
                        ));
                    }
                    target.len() as u64
                }
                CowDiffEntry::Remove { .. } | CowDiffEntry::OpaqueDirectory { .. } => 0,
            };
            let record_bytes = RECORD_HEADER_BYTES
                .checked_add(relative.len() as u64)
                .and_then(|value| value.checked_add(payload_len))
                .ok_or_else(|| {
                    CowDiffApplyError::InvalidInput("canonical diff length overflow".to_owned())
                })?;
            encoded = encoded.checked_add(record_bytes).ok_or_else(|| {
                CowDiffApplyError::InvalidInput("canonical diff length overflow".to_owned())
            })?;
            previous = Some((relative.clone(), rank));
            paths.push(relative);
        }
        if encoded != diff.encoded_bytes {
            return Err(CowDiffApplyError::InvalidInput(format!(
                "encoded_bytes mismatch: declared={} canonical={encoded}",
                diff.encoded_bytes
            )));
        }
        Ok(paths)
    }

    fn validate_mode(mode: u32) -> Result<(), CowDiffApplyError> {
        if mode & !0o7777 != 0 {
            return Err(CowDiffApplyError::InvalidInput(
                "exported Unix mode contains bits outside 0o7777".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_diff_path(path: &[u8], allow_root: bool) -> Result<Vec<u8>, CowDiffApplyError> {
        if path.first() != Some(&b'/') || path.contains(&0) {
            return Err(CowDiffApplyError::InvalidInput(
                "diff paths must be absolute and NUL-free".to_owned(),
            ));
        }
        let relative = &path[1..];
        if relative.is_empty() {
            if allow_root {
                return Ok(Vec::new());
            }
            return Err(CowDiffApplyError::InvalidInput(
                "only an opaque-directory record may address the snapshot root".to_owned(),
            ));
        }
        if relative.len() > MAX_RELATIVE_PATH_BYTES || relative.ends_with(b"/") {
            return Err(CowDiffApplyError::InvalidInput(
                "diff path exceeds 4096 relative bytes or has a trailing slash".to_owned(),
            ));
        }
        for component in relative.split(|byte| *byte == b'/') {
            if component.is_empty() || component == b"." || component == b".." {
                return Err(CowDiffApplyError::InvalidInput(
                    "diff path contains an empty, dot, or dot-dot component".to_owned(),
                ));
            }
        }
        Ok(relative.to_vec())
    }

    fn entry_path(entry: &CowDiffEntry) -> &[u8] {
        match entry {
            CowDiffEntry::UpsertFile { path, .. }
            | CowDiffEntry::EnsureDirectory { path, .. }
            | CowDiffEntry::Symlink { path, .. }
            | CowDiffEntry::Remove { path }
            | CowDiffEntry::OpaqueDirectory { path } => path,
        }
    }

    fn entry_rank(entry: &CowDiffEntry) -> u8 {
        match entry {
            CowDiffEntry::EnsureDirectory { .. } => 0,
            CowDiffEntry::OpaqueDirectory { .. } => 1,
            CowDiffEntry::UpsertFile { .. } => 2,
            CowDiffEntry::Symlink { .. } => 3,
            CowDiffEntry::Remove { .. } => 4,
        }
    }

    fn checked_component(bytes: &[u8], label: &str) -> Result<CString, CowDiffApplyError> {
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
            || bytes.contains(&0)
        {
            return Err(CowDiffApplyError::InvalidInput(format!(
                "{label} is not a safe single path component"
            )));
        }
        CString::new(bytes).map_err(|_| {
            CowDiffApplyError::InvalidInput(format!("{label} contains an embedded NUL"))
        })
    }

    fn open_directory_path(path: &Path, phase: &'static str) -> Result<Fd, CowDiffApplyError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            CowDiffApplyError::InvalidInput(format!("{phase} path contains an embedded NUL"))
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(phase, io::Error::last_os_error()));
        }
        Ok(Fd(fd))
    }

    fn duplicate_fd(fd: RawFd) -> Result<Fd, CowDiffApplyError> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated == -1 {
            return Err(io_error(
                "duplicate directory descriptor",
                io::Error::last_os_error(),
            ));
        }
        Ok(Fd(duplicated))
    }

    fn create_staging(parent_fd: RawFd) -> Result<(CString, Fd), CowDiffApplyError> {
        for _ in 0..64 {
            let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(".security-lab-cow-apply-{}-{counter}", unsafe {
                libc::getpid()
            }))
            .expect("generated staging name contains no NUL");
            let created = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o700) };
            if created == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(io_error("create replay staging directory", error));
            }
            let fd = unsafe {
                libc::openat(
                    parent_fd,
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd == -1 {
                let source = io::Error::last_os_error();
                let _ = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
                return Err(io_error("open replay staging directory", source));
            }
            if unsafe { libc::fchmod(fd, 0o700) } == -1 {
                let source = io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                    libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR);
                }
                return Err(io_error("harden replay staging directory", source));
            }
            return Ok((name, Fd(fd)));
        }
        Err(CowDiffApplyError::InvalidInput(
            "could not allocate a collision-free replay staging name".to_owned(),
        ))
    }

    fn copy_directory(
        source_fd: RawFd,
        destination_fd: RawFd,
        budget: &mut Budget,
        directory_modes: &mut BTreeMap<Vec<u8>, u32>,
        relative: &[u8],
        depth: usize,
    ) -> Result<(), CowDiffApplyError> {
        if depth > MAX_TREE_DEPTH {
            return Err(CowDiffApplyError::InvalidInput(
                "base snapshot exceeds the 64-level replay depth ceiling".to_owned(),
            ));
        }
        for name in read_directory_names_bounded(source_fd, Some(budget))? {
            let name_c = CString::new(name.clone()).expect("directory entry has no embedded NUL");
            let child_relative = join_relative(relative, &name);
            let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe {
                libc::fstatat(
                    source_fd,
                    name_c.as_ptr(),
                    &mut stat,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } == -1
            {
                return Err(io_error(
                    "stat base snapshot entry",
                    io::Error::last_os_error(),
                ));
            }
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    if unsafe { libc::mkdirat(destination_fd, name_c.as_ptr(), 0o700) } == -1 {
                        return Err(io_error(
                            "create copied base directory",
                            io::Error::last_os_error(),
                        ));
                    }
                    let source_child = open_child_directory(
                        source_fd,
                        name_c.as_c_str(),
                        "open base child directory",
                    )?;
                    let destination_child = open_child_directory(
                        destination_fd,
                        name_c.as_c_str(),
                        "open copied child directory",
                    )?;
                    directory_modes.insert(child_relative.clone(), (stat.st_mode & 0o7777) as u32);
                    copy_directory(
                        source_child.raw(),
                        destination_child.raw(),
                        budget,
                        directory_modes,
                        &child_relative,
                        depth + 1,
                    )?;
                }
                libc::S_IFREG => {
                    copy_regular_file(
                        source_fd,
                        destination_fd,
                        name_c.as_c_str(),
                        (stat.st_mode & 0o7777) as u32,
                        budget,
                    )?;
                }
                libc::S_IFLNK => {
                    copy_symlink(source_fd, destination_fd, name_c.as_c_str(), budget)?;
                }
                _ => {
                    return Err(CowDiffApplyError::InvalidInput(format!(
                        "base snapshot contains unsupported node kind at /{}",
                        String::from_utf8_lossy(&child_relative)
                    )));
                }
            }
        }
        Ok(())
    }

    fn open_child_directory(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        phase: &'static str,
    ) -> Result<Fd, CowDiffApplyError> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(phase, io::Error::last_os_error()));
        }
        Ok(Fd(fd))
    }

    fn copy_regular_file(
        source_parent: RawFd,
        destination_parent: RawFd,
        name: &std::ffi::CStr,
        mode: u32,
        budget: &mut Budget,
    ) -> Result<(), CowDiffApplyError> {
        let source_fd = unsafe {
            libc::openat(
                source_parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if source_fd == -1 {
            return Err(io_error(
                "open base regular file",
                io::Error::last_os_error(),
            ));
        }
        let source_fd = Fd(source_fd);
        let destination_fd = unsafe {
            libc::openat(
                destination_parent,
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if destination_fd == -1 {
            return Err(io_error(
                "create copied regular file",
                io::Error::last_os_error(),
            ));
        }
        let destination_fd = Fd(destination_fd);
        let mut buffer = [0u8; 8192];
        loop {
            let count = unsafe {
                libc::read(
                    source_fd.raw(),
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("read base regular file", error));
            }
            if count == 0 {
                break;
            }
            budget.consume_base_bytes(count as u64)?;
            write_all(destination_fd.raw(), &buffer[..count as usize])?;
        }
        if unsafe { libc::fchmod(destination_fd.raw(), mode as libc::mode_t) } == -1 {
            return Err(io_error(
                "restore copied file mode",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn copy_symlink(
        source_parent: RawFd,
        destination_parent: RawFd,
        name: &std::ffi::CStr,
        budget: &mut Budget,
    ) -> Result<(), CowDiffApplyError> {
        let mut target = [0u8; MAX_SYMLINK_TARGET_BYTES + 1];
        let count = unsafe {
            libc::readlinkat(
                source_parent,
                name.as_ptr(),
                target.as_mut_ptr().cast::<libc::c_char>(),
                target.len(),
            )
        };
        if count == -1 {
            return Err(io_error("read base symlink", io::Error::last_os_error()));
        }
        let count = count as usize;
        if count == target.len() {
            return Err(CowDiffApplyError::InvalidInput(
                "base symlink target exceeds 4095 bytes".to_owned(),
            ));
        }
        budget.consume_base_bytes(count as u64)?;
        let target = CString::new(&target[..count]).map_err(|_| {
            CowDiffApplyError::InvalidInput("base symlink target contains NUL".to_owned())
        })?;
        if unsafe { libc::symlinkat(target.as_ptr(), destination_parent, name.as_ptr()) } == -1 {
            return Err(io_error("copy base symlink", io::Error::last_os_error()));
        }
        Ok(())
    }

    fn apply_entries(
        root_fd: RawFd,
        diff: &CowDiff,
        validated_paths: &[Vec<u8>],
        directory_modes: &mut BTreeMap<Vec<u8>, u32>,
    ) -> Result<(), CowDiffApplyError> {
        for (entry, relative) in diff.entries.iter().zip(validated_paths) {
            match entry {
                CowDiffEntry::EnsureDirectory { mode, .. } => {
                    ensure_directory(root_fd, relative, *mode, directory_modes)?;
                }
                CowDiffEntry::OpaqueDirectory { .. } => {
                    let directory = open_relative_directory(root_fd, relative)?;
                    clear_directory(directory.raw())?;
                    remove_mode_descendants(directory_modes, relative);
                }
                CowDiffEntry::UpsertFile { mode, bytes, .. } => {
                    let (parent, leaf) = split_parent_leaf(relative)?;
                    let parent_fd = open_relative_directory(root_fd, parent)?;
                    let leaf = checked_component(leaf, "diff file name")?;
                    remove_any(parent_fd.raw(), leaf.as_c_str())?;
                    remove_mode_subtree(directory_modes, relative);
                    let fd = unsafe {
                        libc::openat(
                            parent_fd.raw(),
                            leaf.as_ptr(),
                            libc::O_WRONLY
                                | libc::O_CREAT
                                | libc::O_EXCL
                                | libc::O_CLOEXEC
                                | libc::O_NOFOLLOW,
                            0o600,
                        )
                    };
                    if fd == -1 {
                        return Err(io_error(
                            "create replayed regular file",
                            io::Error::last_os_error(),
                        ));
                    }
                    let fd = Fd(fd);
                    write_all(fd.raw(), bytes)?;
                    if unsafe { libc::fchmod(fd.raw(), *mode as libc::mode_t) } == -1 {
                        return Err(io_error(
                            "apply replayed file mode",
                            io::Error::last_os_error(),
                        ));
                    }
                }
                CowDiffEntry::Symlink { target, .. } => {
                    let (parent, leaf) = split_parent_leaf(relative)?;
                    let parent_fd = open_relative_directory(root_fd, parent)?;
                    let leaf = checked_component(leaf, "diff symlink name")?;
                    remove_any(parent_fd.raw(), leaf.as_c_str())?;
                    remove_mode_subtree(directory_modes, relative);
                    let target = CString::new(target.as_slice()).map_err(|_| {
                        CowDiffApplyError::InvalidInput(
                            "diff symlink target contains NUL".to_owned(),
                        )
                    })?;
                    if unsafe { libc::symlinkat(target.as_ptr(), parent_fd.raw(), leaf.as_ptr()) }
                        == -1
                    {
                        return Err(io_error(
                            "create replayed symlink",
                            io::Error::last_os_error(),
                        ));
                    }
                }
                CowDiffEntry::Remove { .. } => {
                    let (parent, leaf) = split_parent_leaf(relative)?;
                    let parent_fd = open_relative_directory(root_fd, parent)?;
                    let leaf = checked_component(leaf, "diff removal name")?;
                    remove_any(parent_fd.raw(), leaf.as_c_str())?;
                    remove_mode_subtree(directory_modes, relative);
                }
            }
        }
        Ok(())
    }

    fn ensure_directory(
        root_fd: RawFd,
        relative: &[u8],
        mode: u32,
        directory_modes: &mut BTreeMap<Vec<u8>, u32>,
    ) -> Result<(), CowDiffApplyError> {
        let (parent, leaf) = split_parent_leaf(relative)?;
        let parent_fd = open_relative_directory(root_fd, parent)?;
        let leaf = checked_component(leaf, "diff directory name")?;
        match stat_entry(parent_fd.raw(), leaf.as_c_str())? {
            Some(existing) if existing & libc::S_IFMT == libc::S_IFDIR => {}
            Some(_) => {
                remove_any(parent_fd.raw(), leaf.as_c_str())?;
                remove_mode_subtree(directory_modes, relative);
                if unsafe { libc::mkdirat(parent_fd.raw(), leaf.as_ptr(), 0o700) } == -1 {
                    return Err(io_error(
                        "create replayed directory",
                        io::Error::last_os_error(),
                    ));
                }
            }
            None => {
                if unsafe { libc::mkdirat(parent_fd.raw(), leaf.as_ptr(), 0o700) } == -1 {
                    return Err(io_error(
                        "create replayed directory",
                        io::Error::last_os_error(),
                    ));
                }
            }
        }
        directory_modes.insert(relative.to_vec(), mode);
        Ok(())
    }

    fn restore_directory_modes(
        root_fd: RawFd,
        directory_modes: &BTreeMap<Vec<u8>, u32>,
    ) -> Result<(), CowDiffApplyError> {
        let mut modes: Vec<(&Vec<u8>, &u32)> = directory_modes.iter().collect();
        modes.sort_by(|(left, _), (right, _)| {
            path_depth(right)
                .cmp(&path_depth(left))
                .then_with(|| left.cmp(right))
        });
        for (relative, mode) in modes {
            let directory = open_relative_directory(root_fd, relative)?;
            if unsafe { libc::fchmod(directory.raw(), *mode as libc::mode_t) } == -1 {
                return Err(io_error(
                    "restore replayed directory mode",
                    io::Error::last_os_error(),
                ));
            }
        }
        Ok(())
    }

    fn path_depth(path: &[u8]) -> usize {
        if path.is_empty() {
            0
        } else {
            1 + path.iter().filter(|byte| **byte == b'/').count()
        }
    }

    fn remove_mode_subtree(directory_modes: &mut BTreeMap<Vec<u8>, u32>, prefix: &[u8]) {
        directory_modes.retain(|path, _| !same_or_descendant(path, prefix));
    }

    fn remove_mode_descendants(directory_modes: &mut BTreeMap<Vec<u8>, u32>, prefix: &[u8]) {
        directory_modes.retain(|path, _| path == prefix || !same_or_descendant(path, prefix));
    }

    fn same_or_descendant(path: &[u8], prefix: &[u8]) -> bool {
        if prefix.is_empty() {
            return true;
        }
        path == prefix || (path.starts_with(prefix) && path.get(prefix.len()) == Some(&b'/'))
    }

    fn split_parent_leaf(relative: &[u8]) -> Result<(&[u8], &[u8]), CowDiffApplyError> {
        if relative.is_empty() {
            return Err(CowDiffApplyError::InvalidInput(
                "snapshot root cannot be replaced or removed".to_owned(),
            ));
        }
        match relative.iter().rposition(|byte| *byte == b'/') {
            Some(index) => Ok((&relative[..index], &relative[index + 1..])),
            None => Ok((&[], relative)),
        }
    }

    fn open_relative_directory(root_fd: RawFd, relative: &[u8]) -> Result<Fd, CowDiffApplyError> {
        let mut current = duplicate_fd(root_fd)?;
        if relative.is_empty() {
            return Ok(current);
        }
        for component in relative.split(|byte| *byte == b'/') {
            let component = checked_component(component, "diff parent component")?;
            let next = unsafe {
                libc::openat(
                    current.raw(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next == -1 {
                return Err(io_error(
                    "resolve replay parent without symlinks",
                    io::Error::last_os_error(),
                ));
            }
            current = Fd(next);
        }
        Ok(current)
    }

    fn stat_entry(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
    ) -> Result<Option<libc::mode_t>, CowDiffApplyError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe {
            libc::fstatat(
                parent_fd,
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == -1
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(io_error("stat replay path", error));
        }
        Ok(Some(stat.st_mode))
    }

    fn remove_any(parent_fd: RawFd, name: &std::ffi::CStr) -> Result<(), CowDiffApplyError> {
        let Some(mode) = stat_entry(parent_fd, name)? else {
            return Ok(());
        };
        if mode & libc::S_IFMT == libc::S_IFDIR {
            let directory =
                open_child_directory(parent_fd, name, "open directory for replay removal")?;
            clear_directory(directory.raw())?;
            if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) } == -1 {
                return Err(io_error(
                    "remove replayed directory",
                    io::Error::last_os_error(),
                ));
            }
        } else if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } == -1 {
            return Err(io_error(
                "remove replayed non-directory",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn clear_directory(directory_fd: RawFd) -> Result<(), CowDiffApplyError> {
        for name in read_directory_names_bounded(directory_fd, None)? {
            let name = CString::new(name).expect("directory entry has no embedded NUL");
            remove_any(directory_fd, name.as_c_str())?;
        }
        Ok(())
    }

    fn read_directory_names_bounded(
        directory_fd: RawFd,
        mut base_budget: Option<&mut Budget>,
    ) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {
        if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
            return Err(io_error(
                "rewind directory enumeration",
                io::Error::last_os_error(),
            ));
        }
        let mut names = Vec::new();
        let mut buffer = [0u8; DIRENT_BUFFER_BYTES];
        loop {
            let count = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    directory_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("enumerate directory", error));
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            let mut offset = 0usize;
            while offset < count {
                if count - offset < 19 {
                    return Err(CowDiffApplyError::InvalidInput(
                        "directory enumeration returned a truncated dirent".to_owned(),
                    ));
                }
                let record = unsafe { buffer.as_ptr().add(offset) };
                let reclen =
                    unsafe { u16::from_ne_bytes([*record.add(16), *record.add(17)]) as usize };
                if reclen < 20 || offset + reclen > count {
                    return Err(CowDiffApplyError::InvalidInput(
                        "directory enumeration returned an invalid record length".to_owned(),
                    ));
                }
                let name_region = &buffer[offset + 19..offset + reclen];
                let name_len = name_region
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| {
                        CowDiffApplyError::InvalidInput(
                            "directory enumeration returned an unterminated name".to_owned(),
                        )
                    })?;
                let name = &name_region[..name_len];
                if name != b"." && name != b".." {
                    if let Some(budget) = &mut base_budget {
                        // Reserve the base-tree node before retaining its name.
                        // This makes max_nodes bound directory-enumeration
                        // buffering instead of applying only after collection.
                        budget.consume_base_node()?;
                    }
                    names.push(name.to_vec());
                }
                offset += reclen;
            }
        }
        names.sort();
        Ok(names)
    }

    fn join_relative(parent: &[u8], name: &[u8]) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(parent.len() + usize::from(!parent.is_empty()) + name.len());
        result.extend_from_slice(parent);
        if !parent.is_empty() {
            result.push(b'/');
        }
        result.extend_from_slice(name);
        result
    }

    fn write_all(fd: RawFd, mut bytes: &[u8]) -> Result<(), CowDiffApplyError> {
        while !bytes.is_empty() {
            let written =
                unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
            if written == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("write replayed file", error));
            }
            if written == 0 {
                return Err(io_error(
                    "write replayed file",
                    io::Error::new(io::ErrorKind::WriteZero, "zero-byte write"),
                ));
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }

    fn atomic_publish(
        parent_fd: RawFd,
        staging_name: &std::ffi::CStr,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), CowDiffApplyError> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent_fd,
                staging_name.as_ptr(),
                parent_fd,
                destination_name.as_ptr(),
                RENAME_NOREPLACE,
            )
        };
        if result == -1 {
            let error = io::Error::last_os_error();
            return match error.raw_os_error() {
                Some(libc::ENOSYS) => Err(CowDiffApplyError::UnsupportedPlatform(
                    "renameat2(RENAME_NOREPLACE) is required for atomic publication".to_owned(),
                )),
                Some(libc::EEXIST) => Err(CowDiffApplyError::InvalidInput(
                    "destination appeared before atomic publication".to_owned(),
                )),
                _ => Err(io_error("atomically publish replay snapshot", error)),
            };
        }
        Ok(())
    }

    fn io_error(phase: &'static str, source: io::Error) -> CowDiffApplyError {
        CowDiffApplyError::Io { phase, source }
    }
}
