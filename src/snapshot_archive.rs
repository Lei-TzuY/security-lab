use crate::snapshot_identity::{SnapshotIdentity, SnapshotIdentityError};
use crate::snapshot_signature::{
    verify_snapshot_identity_ed25519, SnapshotEd25519Error, SNAPSHOT_ED25519_PUBLIC_KEY_BYTES,
    SNAPSHOT_ED25519_SIGNATURE_BYTES,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::path::Path;

const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_NODES: u64 = 100_000;
const MAX_RELATIVE_PATH_BYTES: usize = 4096;
const MAX_SYMLINK_TARGET_BYTES: usize = 4095;
const ARCHIVE_MAGIC: &[u8] = b"security-lab-snapshot-archive-v1\0";
const CANONICAL_MAGIC: &[u8] = b"security-lab-snapshot-sha256-v1\0";
const DIRECTORY_TAG: u8 = b'D';
const FILE_TAG: u8 = b'F';
const SYMLINK_TAG: u8 = b'L';

/// Explicit work and retained-artifact limits for snapshot archive operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotArchiveLimits {
    /// Maximum serialized archive bytes retained in memory.
    pub max_archive_bytes: u64,
    /// Maximum canonical identity bytes hashed while validating the archive.
    pub max_identity_bytes: u64,
    /// Maximum nodes in the archive, including the root directory.
    pub max_nodes: u64,
}

/// Deterministic serialized snapshot plus the canonical Milestone 33A identity
/// derived from the serialized records themselves.
#[derive(Debug, PartialEq, Eq)]
pub struct SnapshotArchive {
    pub bytes: Vec<u8>,
    pub identity: SnapshotIdentity,
}

/// Result of failure-atomic archive materialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotArchiveMaterializeReport {
    pub identity: SnapshotIdentity,
    pub archive_bytes: u64,
    pub nodes: u64,
}

#[derive(Debug)]
pub enum SnapshotArchiveError {
    InvalidInput(String),
    BudgetExceeded {
        resource: &'static str,
        limit: u64,
        attempted: u64,
    },
    Identity(SnapshotIdentityError),
    Signature(SnapshotEd25519Error),
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

impl fmt::Display for SnapshotArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => write!(f, "invalid snapshot archive: {message}"),
            Self::BudgetExceeded {
                resource,
                limit,
                attempted,
            } => write!(
                f,
                "snapshot archive {resource} budget exceeded: limit={limit} attempted={attempted}"
            ),
            Self::Identity(source) => write!(f, "snapshot archive identity failed: {source}"),
            Self::Signature(source) => {
                write!(
                    f,
                    "snapshot archive signature verification failed: {source}"
                )
            }
            Self::UnsupportedPlatform(message) => {
                write!(f, "unsupported snapshot archive platform: {message}")
            }
            Self::Io { phase, source } => {
                write!(f, "snapshot archive failed during {phase}: {source}")
            }
            Self::CleanupFailed { primary, cleanup } => write!(
                f,
                "snapshot archive failed ({primary}) and staging cleanup also failed ({cleanup})"
            ),
        }
    }
}

impl Error for SnapshotArchiveError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(source) => Some(source),
            Self::Signature(source) => Some(source),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<SnapshotIdentityError> for SnapshotArchiveError {
    fn from(value: SnapshotIdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<SnapshotEd25519Error> for SnapshotArchiveError {
    fn from(value: SnapshotEd25519Error) -> Self {
        Self::Signature(value)
    }
}

/// Serialize one supported snapshot tree into a deterministic, bounded binary
/// artifact. The returned identity is recomputed from the completed archive,
/// not trusted from a separate live-tree scan.
///
/// A successful return freezes the exact serialized bytes against later source
/// mutation. This operation does not claim a hostile-writer atomic point-in-time
/// view while the live source tree is being read.
pub fn serialize_snapshot_archive(
    root: &Path,
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchive, SnapshotArchiveError> {
    validate_limits(limits)?;
    #[cfg(target_os = "linux")]
    {
        linux::serialize(root, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = root;
        Err(SnapshotArchiveError::UnsupportedPlatform(
            "snapshot serialization currently requires Linux fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

/// Validate a serialized archive and derive the existing canonical snapshot
/// identity directly from its deterministic records without touching a live tree.
pub fn snapshot_archive_identity(
    archive: &[u8],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotIdentity, SnapshotArchiveError> {
    validate_limits(limits)?;
    Ok(parse_archive(archive, limits)?.identity)
}

/// Validate an entire archive before destination mutation, materialize it in a
/// private sibling staging tree, and publish the completed tree with
/// `renameat2(RENAME_NOREPLACE)`.
///
/// The destination must not already exist. This is failure-atomic publication,
/// not fsync-backed crash durability.
pub fn materialize_snapshot_archive_atomic(
    archive: &[u8],
    destination: &Path,
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchiveMaterializeReport, SnapshotArchiveError> {
    validate_limits(limits)?;
    let parsed = parse_archive(archive, limits)?;
    #[cfg(target_os = "linux")]
    {
        linux::materialize(archive, destination, parsed, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (archive, destination, parsed, limits);
        Err(SnapshotArchiveError::UnsupportedPlatform(
            "atomic snapshot materialization requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

/// Validate a canonical archive, strictly verify its Milestone 37A Ed25519
/// signature under the exact caller-supplied public key, and only then permit
/// destination inspection or staging-tree creation.
///
/// The signature covers the canonical Milestone 33A identity derived directly
/// from the frozen archive records. A verification failure therefore cannot
/// publish or stage an unauthenticated tree. Publication retains the same
/// failure-atomic, non-fsync durability boundary as
/// `materialize_snapshot_archive_atomic`.
pub fn materialize_snapshot_archive_ed25519_atomic(
    archive: &[u8],
    destination: &Path,
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotArchiveMaterializeReport, SnapshotArchiveError> {
    validate_limits(limits)?;
    let parsed = parse_archive(archive, limits)?;
    verify_snapshot_identity_ed25519(parsed.identity, public_key, expected_signature)?;
    #[cfg(target_os = "linux")]
    {
        linux::materialize(archive, destination, parsed, limits)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (archive, destination, parsed, limits);
        Err(SnapshotArchiveError::UnsupportedPlatform(
            "atomic snapshot materialization requires Linux renameat2 and fd-relative filesystem operations"
                .to_owned(),
        ))
    }
}

fn validate_limits(limits: SnapshotArchiveLimits) -> Result<(), SnapshotArchiveError> {
    if limits.max_archive_bytes == 0 || limits.max_archive_bytes > MAX_ARCHIVE_BYTES {
        return Err(SnapshotArchiveError::InvalidInput(format!(
            "max_archive_bytes must be between 1 and {MAX_ARCHIVE_BYTES}"
        )));
    }
    if limits.max_identity_bytes == 0 || limits.max_identity_bytes > MAX_IDENTITY_BYTES {
        return Err(SnapshotArchiveError::InvalidInput(format!(
            "max_identity_bytes must be between 1 and {MAX_IDENTITY_BYTES}"
        )));
    }
    if limits.max_nodes == 0 || limits.max_nodes > MAX_ARCHIVE_NODES {
        return Err(SnapshotArchiveError::InvalidInput(format!(
            "max_nodes must be between 1 and {MAX_ARCHIVE_NODES}"
        )));
    }
    Ok(())
}

struct ArchiveWriter {
    bytes: Vec<u8>,
    limits: SnapshotArchiveLimits,
    nodes: u64,
}

impl ArchiveWriter {
    fn new(limits: SnapshotArchiveLimits) -> Result<Self, SnapshotArchiveError> {
        let mut value = Self {
            bytes: Vec::new(),
            limits,
            nodes: 0,
        };
        value.append(ARCHIVE_MAGIC)?;
        value.append(&0u64.to_le_bytes())?;
        Ok(value)
    }

    fn reserve_node(&mut self) -> Result<(), SnapshotArchiveError> {
        let attempted = self.nodes.checked_add(1).ok_or_else(|| {
            SnapshotArchiveError::InvalidInput("archive node accounting overflow".to_owned())
        })?;
        if attempted > self.limits.max_nodes {
            return Err(SnapshotArchiveError::BudgetExceeded {
                resource: "node",
                limit: self.limits.max_nodes,
                attempted,
            });
        }
        self.nodes = attempted;
        Ok(())
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), SnapshotArchiveError> {
        let attempted = (self.bytes.len() as u64)
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                SnapshotArchiveError::InvalidInput("archive byte accounting overflow".to_owned())
            })?;
        if attempted > self.limits.max_archive_bytes {
            return Err(SnapshotArchiveError::BudgetExceeded {
                resource: "archive byte",
                limit: self.limits.max_archive_bytes,
                attempted,
            });
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn record_prefix(&mut self, tag: u8, path: &[u8]) -> Result<(), SnapshotArchiveError> {
        let path_len = u32::try_from(path.len()).map_err(|_| {
            SnapshotArchiveError::InvalidInput("archive path length overflow".to_owned())
        })?;
        self.append(&[tag])?;
        self.append(&path_len.to_le_bytes())?;
        self.append(path)
    }

    fn record_directory(&mut self, path: &[u8], mode: u32) -> Result<(), SnapshotArchiveError> {
        self.record_prefix(DIRECTORY_TAG, path)?;
        self.append(&mode.to_le_bytes())
    }

    fn begin_file(
        &mut self,
        path: &[u8],
        mode: u32,
        length: u64,
    ) -> Result<(), SnapshotArchiveError> {
        self.record_prefix(FILE_TAG, path)?;
        self.append(&mode.to_le_bytes())?;
        self.append(&length.to_le_bytes())
    }

    fn record_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), SnapshotArchiveError> {
        let target_len = u32::try_from(target.len()).map_err(|_| {
            SnapshotArchiveError::InvalidInput("symlink target length overflow".to_owned())
        })?;
        self.record_prefix(SYMLINK_TAG, path)?;
        self.append(&target_len.to_le_bytes())?;
        self.append(target)
    }

    fn finish(mut self) -> Result<SnapshotArchive, SnapshotArchiveError> {
        let count_offset = ARCHIVE_MAGIC.len();
        self.bytes[count_offset..count_offset + 8].copy_from_slice(&self.nodes.to_le_bytes());
        let identity = parse_archive(&self.bytes, self.limits)?.identity;
        Ok(SnapshotArchive {
            bytes: self.bytes,
            identity,
        })
    }
}

struct IdentityBuilder {
    hasher: Sha256,
    max_bytes: u64,
    max_nodes: u64,
    encoded_bytes: u64,
    nodes: u64,
}

impl IdentityBuilder {
    fn new(limits: SnapshotArchiveLimits) -> Result<Self, SnapshotIdentityError> {
        let mut value = Self {
            hasher: Sha256::new(),
            max_bytes: limits.max_identity_bytes,
            max_nodes: limits.max_nodes,
            encoded_bytes: 0,
            nodes: 0,
        };
        value.update(CANONICAL_MAGIC)?;
        Ok(value)
    }

    fn consume_node(&mut self) -> Result<(), SnapshotIdentityError> {
        let attempted = self.nodes.checked_add(1).ok_or_else(|| {
            SnapshotIdentityError::InvalidInput("node accounting overflow".to_owned())
        })?;
        if attempted > self.max_nodes {
            return Err(SnapshotIdentityError::BudgetExceeded {
                resource: "node",
                limit: self.max_nodes,
                attempted,
            });
        }
        self.nodes = attempted;
        Ok(())
    }

    fn update(&mut self, bytes: &[u8]) -> Result<(), SnapshotIdentityError> {
        let attempted = self
            .encoded_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| {
                SnapshotIdentityError::InvalidInput("byte accounting overflow".to_owned())
            })?;
        if attempted > self.max_bytes {
            return Err(SnapshotIdentityError::BudgetExceeded {
                resource: "byte",
                limit: self.max_bytes,
                attempted,
            });
        }
        self.hasher.update(bytes);
        self.encoded_bytes = attempted;
        Ok(())
    }

    fn record_prefix(&mut self, tag: u8, path: &[u8]) -> Result<(), SnapshotIdentityError> {
        let path_len = u32::try_from(path.len()).map_err(|_| {
            SnapshotIdentityError::InvalidInput("snapshot path length overflow".to_owned())
        })?;
        self.update(&[tag])?;
        self.update(&path_len.to_le_bytes())?;
        self.update(path)
    }

    fn record_directory(&mut self, path: &[u8], mode: u32) -> Result<(), SnapshotIdentityError> {
        self.record_prefix(DIRECTORY_TAG, path)?;
        self.update(&mode.to_le_bytes())
    }

    fn begin_file(
        &mut self,
        path: &[u8],
        mode: u32,
        length: u64,
    ) -> Result<(), SnapshotIdentityError> {
        self.record_prefix(FILE_TAG, path)?;
        self.update(&mode.to_le_bytes())?;
        self.update(&length.to_le_bytes())
    }

    fn record_symlink(&mut self, path: &[u8], target: &[u8]) -> Result<(), SnapshotIdentityError> {
        let target_len = u32::try_from(target.len()).map_err(|_| {
            SnapshotIdentityError::InvalidInput("symlink target length overflow".to_owned())
        })?;
        self.record_prefix(SYMLINK_TAG, path)?;
        self.update(&target_len.to_le_bytes())?;
        self.update(target)
    }

    fn finish(self) -> SnapshotIdentity {
        let digest = self.hasher.finalize();
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);
        SnapshotIdentity {
            sha256,
            encoded_bytes: self.encoded_bytes,
            nodes: self.nodes,
        }
    }
}

#[derive(Clone, Copy)]
enum ParsedEntry<'a> {
    Directory {
        path: &'a [u8],
        mode: u32,
    },
    File {
        path: &'a [u8],
        mode: u32,
        bytes: &'a [u8],
    },
    Symlink {
        path: &'a [u8],
        target: &'a [u8],
    },
}

impl<'a> ParsedEntry<'a> {
    fn path(&self) -> &'a [u8] {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } | Self::Symlink { path, .. } => {
                path
            }
        }
    }
}

struct ParsedArchive<'a> {
    entries: Vec<ParsedEntry<'a>>,
    identity: SnapshotIdentity,
}

fn parse_archive<'a>(
    archive: &'a [u8],
    limits: SnapshotArchiveLimits,
) -> Result<ParsedArchive<'a>, SnapshotArchiveError> {
    if archive.len() as u64 > limits.max_archive_bytes {
        return Err(SnapshotArchiveError::BudgetExceeded {
            resource: "archive byte",
            limit: limits.max_archive_bytes,
            attempted: archive.len() as u64,
        });
    }
    if archive.len() < ARCHIVE_MAGIC.len() + 8 || !archive.starts_with(ARCHIVE_MAGIC) {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive header magic is missing or truncated".to_owned(),
        ));
    }

    let mut offset = ARCHIVE_MAGIC.len();
    let declared_nodes = read_u64(archive, &mut offset, "archive node count")?;
    if declared_nodes == 0 {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive must contain a root directory record".to_owned(),
        ));
    }
    if declared_nodes > limits.max_nodes {
        return Err(SnapshotArchiveError::BudgetExceeded {
            resource: "node",
            limit: limits.max_nodes,
            attempted: declared_nodes,
        });
    }

    let capacity = usize::try_from(declared_nodes).map_err(|_| {
        SnapshotArchiveError::InvalidInput("archive node count does not fit memory".to_owned())
    })?;
    let mut entries = Vec::with_capacity(capacity);
    let mut directories = BTreeSet::<Vec<u8>>::new();
    let mut previous = Vec::<u8>::new();
    let mut identity = IdentityBuilder::new(limits)?;

    for index in 0..declared_nodes {
        let tag = *take(archive, &mut offset, 1, "record tag")?
            .first()
            .expect("one-byte record tag");
        let path_len = read_u32(archive, &mut offset, "record path length")? as usize;
        let path = take(archive, &mut offset, path_len, "record path")?;
        let relative = validate_archive_path(path)?;

        if index == 0 {
            if tag != DIRECTORY_TAG || path != b"/" {
                return Err(SnapshotArchiveError::InvalidInput(
                    "first archive record must be the root directory '/'".to_owned(),
                ));
            }
        } else {
            if relative.is_empty() {
                return Err(SnapshotArchiveError::InvalidInput(
                    "only the first archive record may address '/'".to_owned(),
                ));
            }
            if path <= previous.as_slice() {
                return Err(SnapshotArchiveError::InvalidInput(
                    "archive records must use strictly increasing raw path order".to_owned(),
                ));
            }
            let parent = parent_relative(relative);
            if !directories.contains(parent) {
                return Err(SnapshotArchiveError::InvalidInput(
                    "archive record parent must be an earlier directory record".to_owned(),
                ));
            }
        }

        identity.consume_node()?;
        let entry = match tag {
            DIRECTORY_TAG => {
                let mode = read_u32(archive, &mut offset, "directory mode")?;
                validate_mode(mode)?;
                identity.record_directory(path, mode)?;
                directories.insert(relative.to_vec());
                ParsedEntry::Directory { path, mode }
            }
            FILE_TAG => {
                let mode = read_u32(archive, &mut offset, "file mode")?;
                validate_mode(mode)?;
                let length = read_u64(archive, &mut offset, "file length")?;
                let length = usize::try_from(length).map_err(|_| {
                    SnapshotArchiveError::InvalidInput(
                        "archive file length does not fit memory".to_owned(),
                    )
                })?;
                let bytes = take(archive, &mut offset, length, "file bytes")?;
                identity.begin_file(path, mode, bytes.len() as u64)?;
                identity.update(bytes)?;
                ParsedEntry::File { path, mode, bytes }
            }
            SYMLINK_TAG => {
                let target_len = read_u32(archive, &mut offset, "symlink target length")? as usize;
                if target_len == 0 || target_len > MAX_SYMLINK_TARGET_BYTES {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "symlink target must be 1..=4095 bytes".to_owned(),
                    ));
                }
                let target = take(archive, &mut offset, target_len, "symlink target")?;
                if target.contains(&0) {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "symlink target contains an embedded NUL".to_owned(),
                    ));
                }
                identity.record_symlink(path, target)?;
                ParsedEntry::Symlink { path, target }
            }
            _ => {
                return Err(SnapshotArchiveError::InvalidInput(format!(
                    "unknown archive record tag {tag}"
                )));
            }
        };
        previous.clear();
        previous.extend_from_slice(path);
        entries.push(entry);
    }

    if offset != archive.len() {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive contains trailing bytes after declared records".to_owned(),
        ));
    }

    let identity = identity.finish();
    if identity.nodes != declared_nodes {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive node accounting mismatch".to_owned(),
        ));
    }
    Ok(ParsedArchive { entries, identity })
}

fn validate_archive_path(path: &[u8]) -> Result<&[u8], SnapshotArchiveError> {
    if path.first() != Some(&b'/') || path.contains(&0) {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive paths must be absolute and NUL-free".to_owned(),
        ));
    }
    let relative = &path[1..];
    if relative.is_empty() {
        return Ok(relative);
    }
    if relative.len() > MAX_RELATIVE_PATH_BYTES || relative.ends_with(b"/") {
        return Err(SnapshotArchiveError::InvalidInput(
            "archive path exceeds 4096 relative bytes or has a trailing slash".to_owned(),
        ));
    }
    for component in relative.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(SnapshotArchiveError::InvalidInput(
                "archive path contains an empty, dot, or dot-dot component".to_owned(),
            ));
        }
    }
    Ok(relative)
}

fn parent_relative(relative: &[u8]) -> &[u8] {
    match relative.iter().rposition(|byte| *byte == b'/') {
        Some(index) => &relative[..index],
        None => &[],
    }
}

fn validate_mode(mode: u32) -> Result<(), SnapshotArchiveError> {
    if mode & !0o7777 != 0 {
        return Err(SnapshotArchiveError::InvalidInput(
            "Unix mode contains bits outside 0o7777".to_owned(),
        ));
    }
    Ok(())
}

fn take<'a>(
    archive: &'a [u8],
    offset: &mut usize,
    length: usize,
    label: &str,
) -> Result<&'a [u8], SnapshotArchiveError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| SnapshotArchiveError::InvalidInput(format!("{label} offset overflow")))?;
    if end > archive.len() {
        return Err(SnapshotArchiveError::InvalidInput(format!(
            "archive is truncated while reading {label}"
        )));
    }
    let value = &archive[*offset..end];
    *offset = end;
    Ok(value)
}

fn read_u32(archive: &[u8], offset: &mut usize, label: &str) -> Result<u32, SnapshotArchiveError> {
    let bytes = take(archive, offset, 4, label)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(archive: &[u8], offset: &mut usize, label: &str) -> Result<u64, SnapshotArchiveError> {
    let bytes = take(archive, offset, 8, label)?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::{CString, OsString};
    use std::fs;
    use std::io;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::io::RawFd;
    use std::sync::atomic::{AtomicU64, Ordering};

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

    pub(super) fn serialize(
        root: &Path,
        limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotArchive, SnapshotArchiveError> {
        if !root.is_absolute() {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot root must be an absolute host path".to_owned(),
            ));
        }
        let canonical = fs::canonicalize(root)
            .map_err(|source| io_error("canonicalize snapshot root", source))?;
        let root_fd = open_directory_path(&canonical, "open snapshot root")?;
        let root_stat = stat_fd(root_fd.raw(), "stat snapshot root")?;
        if root_stat.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot root is not a directory".to_owned(),
            ));
        }

        let mut writer = ArchiveWriter::new(limits)?;
        writer.reserve_node()?;
        writer.record_directory(b"/", root_stat.st_mode & 0o7777)?;
        serialize_directory(root_fd.raw(), &[], 0, &mut writer)?;
        writer.finish()
    }

    fn serialize_directory(
        directory_fd: RawFd,
        relative: &[u8],
        depth: usize,
        writer: &mut ArchiveWriter,
    ) -> Result<(), SnapshotArchiveError> {
        if depth > MAX_TREE_DEPTH {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot exceeds the 64-level archive depth ceiling".to_owned(),
            ));
        }
        for name in read_directory_names_bounded(directory_fd, writer)? {
            let child_relative = join_relative(relative, &name)?;
            let path = absolute_snapshot_path(&child_relative);
            let name_c = CString::new(name).expect("directory entry has no embedded NUL");
            let stat = stat_entry(directory_fd, name_c.as_c_str())?;
            match stat.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let child = open_child_directory(
                        directory_fd,
                        name_c.as_c_str(),
                        "open snapshot child directory",
                    )?;
                    let current = stat_fd(child.raw(), "stat opened snapshot directory")?;
                    if current.st_mode & libc::S_IFMT != libc::S_IFDIR {
                        return Err(SnapshotArchiveError::InvalidInput(
                            "snapshot directory changed type during archive capture".to_owned(),
                        ));
                    }
                    writer.record_directory(&path, current.st_mode & 0o7777)?;
                    serialize_directory(child.raw(), &child_relative, depth + 1, writer)?;
                }
                libc::S_IFREG => {
                    serialize_regular_file(directory_fd, name_c.as_c_str(), &path, writer)?;
                }
                libc::S_IFLNK => {
                    serialize_symlink(directory_fd, name_c.as_c_str(), &path, writer)?;
                }
                _ => {
                    return Err(SnapshotArchiveError::InvalidInput(format!(
                        "snapshot contains unsupported node kind at {}",
                        String::from_utf8_lossy(&path)
                    )));
                }
            }
        }
        Ok(())
    }

    fn serialize_regular_file(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        writer: &mut ArchiveWriter,
    ) -> Result<(), SnapshotArchiveError> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd == -1 {
            return Err(io_error(
                "open snapshot regular file",
                io::Error::last_os_error(),
            ));
        }
        let fd = Fd(fd);
        let stat = stat_fd(fd.raw(), "stat opened snapshot regular file")?;
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_size < 0 {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot regular file changed type or has invalid size during archive capture"
                    .to_owned(),
            ));
        }
        let length = stat.st_size as u64;
        writer.begin_file(path, stat.st_mode & 0o7777, length)?;

        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let request = std::cmp::min(remaining, buffer.len() as u64) as usize;
            let count = loop {
                let count = unsafe {
                    libc::read(
                        fd.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        request,
                    )
                };
                if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break count;
            };
            if count == -1 {
                return Err(io_error(
                    "read snapshot regular file",
                    io::Error::last_os_error(),
                ));
            }
            if count == 0 {
                return Err(SnapshotArchiveError::InvalidInput(
                    "snapshot regular file shrank during archive capture".to_owned(),
                ));
            }
            writer.append(&buffer[..count as usize])?;
            remaining -= count as u64;
        }

        let mut extra = [0u8; 1];
        let extra_count = loop {
            let count = unsafe {
                libc::read(
                    fd.raw(),
                    extra.as_mut_ptr().cast::<libc::c_void>(),
                    extra.len(),
                )
            };
            if count == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            break count;
        };
        if extra_count == -1 {
            return Err(io_error(
                "verify snapshot regular file length",
                io::Error::last_os_error(),
            ));
        }
        if extra_count != 0 {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot regular file grew during archive capture".to_owned(),
            ));
        }
        Ok(())
    }

    fn serialize_symlink(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        path: &[u8],
        writer: &mut ArchiveWriter,
    ) -> Result<(), SnapshotArchiveError> {
        let mut target = [0u8; MAX_SYMLINK_TARGET_BYTES + 1];
        let count = unsafe {
            libc::readlinkat(
                parent_fd,
                name.as_ptr(),
                target.as_mut_ptr().cast::<libc::c_char>(),
                target.len(),
            )
        };
        if count == -1 {
            return Err(io_error(
                "read snapshot symlink",
                io::Error::last_os_error(),
            ));
        }
        let count = count as usize;
        if count == 0 || count == target.len() {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot symlink target is empty or exceeds 4095 bytes".to_owned(),
            ));
        }
        writer.record_symlink(path, &target[..count])
    }

    fn read_directory_names_bounded(
        directory_fd: RawFd,
        writer: &mut ArchiveWriter,
    ) -> Result<Vec<Vec<u8>>, SnapshotArchiveError> {
        if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
            return Err(io_error(
                "rewind snapshot directory enumeration",
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
                return Err(io_error("enumerate snapshot directory", error));
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            let mut offset = 0usize;
            while offset < count {
                if count - offset < 19 {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "snapshot directory enumeration returned a truncated dirent".to_owned(),
                    ));
                }
                let record = unsafe { buffer.as_ptr().add(offset) };
                let reclen =
                    unsafe { u16::from_ne_bytes([*record.add(16), *record.add(17)]) as usize };
                if reclen < 20 || offset + reclen > count {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "snapshot directory enumeration returned an invalid record length"
                            .to_owned(),
                    ));
                }
                let name_region = &buffer[offset + 19..offset + reclen];
                let name_len = name_region
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| {
                        SnapshotArchiveError::InvalidInput(
                            "snapshot directory enumeration returned an unterminated name"
                                .to_owned(),
                        )
                    })?;
                let name = &name_region[..name_len];
                if name != b"." && name != b".." {
                    writer.reserve_node()?;
                    names.push(name.to_vec());
                }
                offset += reclen;
            }
        }
        names.sort();
        Ok(names)
    }

    fn join_relative(parent: &[u8], name: &[u8]) -> Result<Vec<u8>, SnapshotArchiveError> {
        let extra = usize::from(!parent.is_empty());
        let length = parent
            .len()
            .checked_add(extra)
            .and_then(|value| value.checked_add(name.len()))
            .ok_or_else(|| {
                SnapshotArchiveError::InvalidInput("snapshot path length overflow".to_owned())
            })?;
        if length > MAX_RELATIVE_PATH_BYTES {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot path exceeds the 4096-byte relative path ceiling".to_owned(),
            ));
        }
        let mut result = Vec::with_capacity(length);
        result.extend_from_slice(parent);
        if !parent.is_empty() {
            result.push(b'/');
        }
        result.extend_from_slice(name);
        Ok(result)
    }

    fn absolute_snapshot_path(relative: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(relative.len() + 1);
        result.push(b'/');
        result.extend_from_slice(relative);
        result
    }

    pub(super) fn materialize(
        archive: &[u8],
        destination: &Path,
        parsed: ParsedArchive<'_>,
        _limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotArchiveMaterializeReport, SnapshotArchiveError> {
        if !destination.is_absolute() {
            return Err(SnapshotArchiveError::InvalidInput(
                "destination must be an absolute host path".to_owned(),
            ));
        }
        let destination_parent = destination.parent().ok_or_else(|| {
            SnapshotArchiveError::InvalidInput(
                "destination must have a parent directory".to_owned(),
            )
        })?;
        let canonical_parent = fs::canonicalize(destination_parent)
            .map_err(|source| io_error("canonicalize destination parent", source))?;
        let destination_name = destination.file_name().ok_or_else(|| {
            SnapshotArchiveError::InvalidInput(
                "destination must name one snapshot directory".to_owned(),
            )
        })?;
        let destination_name = checked_component(destination_name.as_bytes(), "destination name")?;
        let published_path =
            canonical_parent.join(OsString::from_vec(destination_name.as_bytes().to_vec()));
        match fs::symlink_metadata(&published_path) {
            Ok(_) => {
                return Err(SnapshotArchiveError::InvalidInput(
                    "destination already exists".to_owned(),
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect destination", source)),
        }

        let root_mode = match parsed.entries.first().expect("parser requires root record") {
            ParsedEntry::Directory { mode, .. } => *mode,
            _ => unreachable!("parser requires root directory"),
        };
        let parent_fd = open_directory_path(&canonical_parent, "open destination parent")?;
        let (staging_name, staging_fd) = create_staging(parent_fd.raw())?;
        let mut directory_modes = vec![(Vec::new(), root_mode)];

        let materialize_result: Result<(), SnapshotArchiveError> = (|| {
            for entry in parsed.entries.iter().skip(1) {
                let relative = &entry.path()[1..];
                match entry {
                    ParsedEntry::Directory { mode, .. } => {
                        create_directory(staging_fd.raw(), relative)?;
                        directory_modes.push((relative.to_vec(), *mode));
                    }
                    ParsedEntry::File { mode, bytes, .. } => {
                        create_file(staging_fd.raw(), relative, *mode, bytes)?;
                    }
                    ParsedEntry::Symlink { target, .. } => {
                        create_symlink(staging_fd.raw(), relative, target)?;
                    }
                }
            }
            restore_directory_modes(staging_fd.raw(), &directory_modes)?;
            atomic_publish(
                parent_fd.raw(),
                staging_name.as_c_str(),
                destination_name.as_c_str(),
            )?;
            Ok(())
        })();

        if let Err(primary) = materialize_result {
            let cleanup = reharden_directories(staging_fd.raw(), &directory_modes)
                .and_then(|_| remove_any(parent_fd.raw(), staging_name.as_c_str()));
            if let Err(cleanup) = cleanup {
                return Err(SnapshotArchiveError::CleanupFailed {
                    primary: primary.to_string(),
                    cleanup: cleanup.to_string(),
                });
            }
            return Err(primary);
        }

        Ok(SnapshotArchiveMaterializeReport {
            identity: parsed.identity,
            archive_bytes: archive.len() as u64,
            nodes: parsed.identity.nodes,
        })
    }

    fn create_directory(root_fd: RawFd, relative: &[u8]) -> Result<(), SnapshotArchiveError> {
        let (parent, leaf) = split_parent_leaf(relative)?;
        let parent_fd = open_relative_directory(root_fd, parent)?;
        let leaf = checked_component(leaf, "archive directory name")?;
        if unsafe { libc::mkdirat(parent_fd.raw(), leaf.as_ptr(), 0o700) } == -1 {
            return Err(io_error(
                "create archived directory",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn create_file(
        root_fd: RawFd,
        relative: &[u8],
        mode: u32,
        bytes: &[u8],
    ) -> Result<(), SnapshotArchiveError> {
        let (parent, leaf) = split_parent_leaf(relative)?;
        let parent_fd = open_relative_directory(root_fd, parent)?;
        let leaf = checked_component(leaf, "archive file name")?;
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                leaf.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd == -1 {
            return Err(io_error(
                "create archived regular file",
                io::Error::last_os_error(),
            ));
        }
        let fd = Fd(fd);
        write_all(fd.raw(), bytes)?;
        if unsafe { libc::fchmod(fd.raw(), mode as libc::mode_t) } == -1 {
            return Err(io_error(
                "apply archived regular-file mode",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn create_symlink(
        root_fd: RawFd,
        relative: &[u8],
        target: &[u8],
    ) -> Result<(), SnapshotArchiveError> {
        let (parent, leaf) = split_parent_leaf(relative)?;
        let parent_fd = open_relative_directory(root_fd, parent)?;
        let leaf = checked_component(leaf, "archive symlink name")?;
        let target = CString::new(target).map_err(|_| {
            SnapshotArchiveError::InvalidInput(
                "archive symlink target contains an embedded NUL".to_owned(),
            )
        })?;
        if unsafe { libc::symlinkat(target.as_ptr(), parent_fd.raw(), leaf.as_ptr()) } == -1 {
            return Err(io_error(
                "create archived symlink",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn restore_directory_modes(
        root_fd: RawFd,
        directory_modes: &[(Vec<u8>, u32)],
    ) -> Result<(), SnapshotArchiveError> {
        let mut modes: Vec<&(Vec<u8>, u32)> = directory_modes.iter().collect();
        modes.sort_by(|(left, _), (right, _)| {
            path_depth(right)
                .cmp(&path_depth(left))
                .then_with(|| left.cmp(right))
        });
        for (relative, mode) in modes {
            let directory = open_relative_directory(root_fd, relative)?;
            if unsafe { libc::fchmod(directory.raw(), *mode as libc::mode_t) } == -1 {
                return Err(io_error(
                    "restore archived directory mode",
                    io::Error::last_os_error(),
                ));
            }
        }
        Ok(())
    }

    fn reharden_directories(
        root_fd: RawFd,
        directory_modes: &[(Vec<u8>, u32)],
    ) -> Result<(), SnapshotArchiveError> {
        if unsafe { libc::fchmod(root_fd, 0o700) } == -1 {
            return Err(io_error(
                "reharden archive staging root",
                io::Error::last_os_error(),
            ));
        }
        let mut directories: Vec<&Vec<u8>> = directory_modes
            .iter()
            .map(|(path, _)| path)
            .filter(|path| !path.is_empty())
            .collect();
        directories.sort_by(|left, right| {
            path_depth(left)
                .cmp(&path_depth(right))
                .then_with(|| left.cmp(right))
        });
        for relative in directories {
            let directory = open_relative_directory(root_fd, relative)?;
            if unsafe { libc::fchmod(directory.raw(), 0o700) } == -1 {
                return Err(io_error(
                    "reharden archive staging directory",
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

    fn split_parent_leaf(relative: &[u8]) -> Result<(&[u8], &[u8]), SnapshotArchiveError> {
        if relative.is_empty() {
            return Err(SnapshotArchiveError::InvalidInput(
                "snapshot root cannot be replaced by an archive entry".to_owned(),
            ));
        }
        match relative.iter().rposition(|byte| *byte == b'/') {
            Some(index) => Ok((&relative[..index], &relative[index + 1..])),
            None => Ok((&[], relative)),
        }
    }

    fn checked_component(bytes: &[u8], label: &str) -> Result<CString, SnapshotArchiveError> {
        if bytes.is_empty()
            || bytes == b"."
            || bytes == b".."
            || bytes.contains(&b'/')
            || bytes.contains(&0)
        {
            return Err(SnapshotArchiveError::InvalidInput(format!(
                "{label} is not a safe single path component"
            )));
        }
        CString::new(bytes).map_err(|_| {
            SnapshotArchiveError::InvalidInput(format!("{label} contains an embedded NUL"))
        })
    }

    fn open_directory_path(path: &Path, phase: &'static str) -> Result<Fd, SnapshotArchiveError> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            SnapshotArchiveError::InvalidInput(format!("{phase} path contains an embedded NUL"))
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

    fn open_child_directory(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
        phase: &'static str,
    ) -> Result<Fd, SnapshotArchiveError> {
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

    fn stat_fd(fd: RawFd, phase: &'static str) -> Result<libc::stat, SnapshotArchiveError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut stat) } == -1 {
            return Err(io_error(phase, io::Error::last_os_error()));
        }
        Ok(stat)
    }

    fn stat_entry(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
    ) -> Result<libc::stat, SnapshotArchiveError> {
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
            return Err(io_error("stat snapshot entry", io::Error::last_os_error()));
        }
        Ok(stat)
    }

    fn duplicate_fd(fd: RawFd) -> Result<Fd, SnapshotArchiveError> {
        let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicated == -1 {
            return Err(io_error(
                "duplicate archive directory descriptor",
                io::Error::last_os_error(),
            ));
        }
        Ok(Fd(duplicated))
    }

    fn open_relative_directory(
        root_fd: RawFd,
        relative: &[u8],
    ) -> Result<Fd, SnapshotArchiveError> {
        let mut current = duplicate_fd(root_fd)?;
        if relative.is_empty() {
            return Ok(current);
        }
        for component in relative.split(|byte| *byte == b'/') {
            let component = checked_component(component, "archive parent component")?;
            let next = unsafe {
                libc::openat(
                    current.raw(),
                    component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next == -1 {
                return Err(io_error(
                    "resolve archive parent without symlinks",
                    io::Error::last_os_error(),
                ));
            }
            current = Fd(next);
        }
        Ok(current)
    }

    fn create_staging(parent_fd: RawFd) -> Result<(CString, Fd), SnapshotArchiveError> {
        for _ in 0..64 {
            let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(
                ".security-lab-snapshot-archive-{}-{counter}",
                unsafe { libc::getpid() }
            ))
            .expect("generated staging name contains no NUL");
            if unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o700) } == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(io_error("create archive staging directory", error));
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
                return Err(io_error("open archive staging directory", source));
            }
            return Ok((name, Fd(fd)));
        }
        Err(SnapshotArchiveError::InvalidInput(
            "could not allocate a collision-free archive staging name".to_owned(),
        ))
    }

    fn write_all(fd: RawFd, mut bytes: &[u8]) -> Result<(), SnapshotArchiveError> {
        while !bytes.is_empty() {
            let written =
                unsafe { libc::write(fd, bytes.as_ptr().cast::<libc::c_void>(), bytes.len()) };
            if written == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(io_error("write archived regular file", error));
            }
            if written == 0 {
                return Err(io_error(
                    "write archived regular file",
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
    ) -> Result<(), SnapshotArchiveError> {
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
                Some(libc::ENOSYS) => Err(SnapshotArchiveError::UnsupportedPlatform(
                    "renameat2(RENAME_NOREPLACE) is required for atomic snapshot publication"
                        .to_owned(),
                )),
                Some(libc::EEXIST) => Err(SnapshotArchiveError::InvalidInput(
                    "destination appeared before atomic snapshot publication".to_owned(),
                )),
                _ => Err(io_error("atomically publish snapshot archive", error)),
            };
        }
        Ok(())
    }

    fn stat_entry_optional(
        parent_fd: RawFd,
        name: &std::ffi::CStr,
    ) -> Result<Option<libc::mode_t>, SnapshotArchiveError> {
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
            return Err(io_error("stat archive staging path", error));
        }
        Ok(Some(stat.st_mode))
    }

    fn remove_any(parent_fd: RawFd, name: &std::ffi::CStr) -> Result<(), SnapshotArchiveError> {
        let Some(mode) = stat_entry_optional(parent_fd, name)? else {
            return Ok(());
        };
        if mode & libc::S_IFMT == libc::S_IFDIR {
            let directory =
                open_child_directory(parent_fd, name, "open directory for archive cleanup")?;
            clear_directory(directory.raw())?;
            if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) } == -1 {
                return Err(io_error(
                    "remove archive staging directory",
                    io::Error::last_os_error(),
                ));
            }
        } else if unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) } == -1 {
            return Err(io_error(
                "remove archive staging non-directory",
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    fn clear_directory(directory_fd: RawFd) -> Result<(), SnapshotArchiveError> {
        for name in read_directory_names(directory_fd)? {
            let name = CString::new(name).expect("directory entry has no embedded NUL");
            remove_any(directory_fd, name.as_c_str())?;
        }
        Ok(())
    }

    fn read_directory_names(directory_fd: RawFd) -> Result<Vec<Vec<u8>>, SnapshotArchiveError> {
        if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
            return Err(io_error(
                "rewind archive cleanup directory",
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
                return Err(io_error("enumerate archive cleanup directory", error));
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            let mut offset = 0usize;
            while offset < count {
                if count - offset < 19 {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "archive cleanup directory returned a truncated dirent".to_owned(),
                    ));
                }
                let record = unsafe { buffer.as_ptr().add(offset) };
                let reclen =
                    unsafe { u16::from_ne_bytes([*record.add(16), *record.add(17)]) as usize };
                if reclen < 20 || offset + reclen > count {
                    return Err(SnapshotArchiveError::InvalidInput(
                        "archive cleanup directory returned an invalid record length".to_owned(),
                    ));
                }
                let name_region = &buffer[offset + 19..offset + reclen];
                let name_len = name_region
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(|| {
                        SnapshotArchiveError::InvalidInput(
                            "archive cleanup directory returned an unterminated name".to_owned(),
                        )
                    })?;
                let name = &name_region[..name_len];
                if name != b"." && name != b".." {
                    names.push(name.to_vec());
                }
                offset += reclen;
            }
        }
        names.sort();
        Ok(names)
    }

    fn io_error(phase: &'static str, source: io::Error) -> SnapshotArchiveError {
        SnapshotArchiveError::Io { phase, source }
    }
}
