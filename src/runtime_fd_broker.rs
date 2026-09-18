use crate::{PolicyError, SandboxPolicy};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

pub const MAX_RUNTIME_SEALED_SNAPSHOT_BYTES: u64 = 64 * 1024 * 1024;
pub const MIN_RUNTIME_SEALED_BUNDLE_ITEMS: usize = 2;
pub const MAX_RUNTIME_SEALED_BUNDLE_ITEMS: usize = 8;
pub const MAX_RUNTIME_SEALED_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum RuntimeFdBrokerError {
    UnsupportedPlatform(String),
    InvalidConfiguration(String),
    Policy(PolicyError),
    SourceNotRegular,
    SourceNotReadable,
    SourcePathOnly,
    SourceSnapshotTooLarge {
        max_bytes: u64,
    },
    SnapshotBundleTooLarge {
        max_bytes: u64,
    },
    UnexpectedPeer {
        expected_pid: i32,
        expected_uid: u32,
        expected_gid: u32,
        actual_pid: i32,
        actual_uid: u32,
        actual_gid: u32,
    },
    Protocol(String),
    Io {
        operation: &'static str,
        source: io::Error,
    },
}

impl RuntimeFdBrokerError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl fmt::Display for RuntimeFdBrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform(message) => f.write_str(message),
            Self::InvalidConfiguration(message) => write!(f, "invalid broker configuration: {message}"),
            Self::Policy(error) => write!(f, "broker policy integration failed: {error}"),
            Self::SourceNotRegular => f.write_str("runtime FD broker source must be a regular file"),
            Self::SourceNotReadable => {
                f.write_str("runtime FD broker source must already carry read authority")
            }
            Self::SourcePathOnly => {
                f.write_str("runtime FD broker does not accept O_PATH-only sources")
            }
            Self::SourceSnapshotTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker source exceeds sealed snapshot byte ceiling of {max_bytes}"
            ),
            Self::SnapshotBundleTooLarge { max_bytes } => write!(
                f,
                "runtime FD broker sealed snapshot bundle exceeds aggregate byte ceiling of {max_bytes}"
            ),
            Self::UnexpectedPeer {
                expected_pid,
                expected_uid,
                expected_gid,
                actual_pid,
                actual_uid,
                actual_gid,
            } => write!(
                f,
                "runtime FD broker peer mismatch: expected pid/uid/gid {expected_pid}/{expected_uid}/{expected_gid}, got {actual_pid}/{actual_uid}/{actual_gid}"
            ),
            Self::Protocol(message) => write!(f, "runtime FD broker protocol error: {message}"),
            Self::Io { operation, source } => write!(f, "{operation}: {source}"),
        }
    }
}

impl Error for RuntimeFdBrokerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Policy(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod imp {
    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};
    use std::ffi::CString;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Component, PathBuf};

    const MAX_UNIX_PATH_BYTES: usize = 107;
    const MFD_CLOEXEC: libc::c_uint = 0x0001;
    const MFD_ALLOW_SEALING: libc::c_uint = 0x0002;

    #[derive(Debug)]
    pub struct PreparedReadOnlyRegularFile {
        fd: RawFd,
    }

    impl Drop for PreparedReadOnlyRegularFile {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct PreparedSealedRegularFileSnapshot {
        fd: RawFd,
        len: u64,
    }

    impl PreparedSealedRegularFileSnapshot {
        pub fn len(&self) -> u64 {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
    }

    impl Drop for PreparedSealedRegularFileSnapshot {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.fd);
            }
        }
    }

    #[derive(Debug)]
    pub struct PreparedSealedSnapshotBundle {
        grants: Vec<PreparedSealedRegularFileSnapshot>,
        total_len: u64,
    }

    impl PreparedSealedSnapshotBundle {
        pub fn item_count(&self) -> usize {
            self.grants.len()
        }

        pub fn total_len(&self) -> u64 {
            self.total_len
        }
    }

    #[derive(Debug)]
    pub struct RuntimeFdBroker {
        path: PathBuf,
        listener: UnixListener,
        owner_pid: i32,
        owner_uid: u32,
        owner_gid: u32,
        socket_dev: u64,
        socket_ino: u64,
    }

    impl Drop for RuntimeFdBroker {
        fn drop(&mut self) {
            let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
                return;
            };
            if metadata.file_type().is_socket()
                && metadata.dev() == self.socket_dev
                && metadata.ino() == self.socket_ino
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RuntimeFdSessionState {
        AwaitingReady,
        Ready,
        GrantSent,
        Failed,
    }

    #[derive(Debug)]
    pub struct RuntimeFdSession {
        stream: UnixStream,
        state: RuntimeFdSessionState,
    }

    impl RuntimeFdBroker {
        /// Bind one host pathname AF_UNIX listener owned by the trusted caller.
        ///
        /// The path must be absolute, must not contain parent traversal, and must
        /// not already exist. Drop removes only the exact socket inode created by
        /// this broker, so a replaced pathname is never unlinked opportunistically.
        pub fn bind(path: impl AsRef<Path>) -> Result<Self, RuntimeFdBrokerError> {
            let path = path.as_ref();
            validate_socket_path(path)?;
            let listener = UnixListener::bind(path).map_err(|error| {
                RuntimeFdBrokerError::io("cannot bind runtime FD broker", error)
            })?;
            let metadata = std::fs::symlink_metadata(path).map_err(|error| {
                RuntimeFdBrokerError::io("cannot inspect runtime FD broker socket", error)
            })?;
            if !metadata.file_type().is_socket() {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "bound broker pathname is not a UNIX socket".to_owned(),
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
                listener,
                owner_pid: unsafe { libc::getpid() },
                owner_uid: unsafe { libc::geteuid() },
                owner_gid: unsafe { libc::getegid() },
                socket_dev: metadata.dev(),
                socket_ino: metadata.ino(),
            })
        }

        pub fn path(&self) -> &Path {
            &self.path
        }

        /// Configure the existing exact-path launcher AF_UNIX broker to connect
        /// the direct target to this runtime broker at `target_fd`.
        ///
        /// Existing host-UNIX broker fields are never overwritten. The candidate
        /// policy is validated before the caller's policy is changed.
        pub fn configure_policy(
            &self,
            policy: &mut SandboxPolicy,
            target_fd: u32,
        ) -> Result<(), RuntimeFdBrokerError> {
            if !policy.seccomp.allowed_syscalls.contains("recvmsg") {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "target policy must explicitly allow recvmsg for runtime FD grants".to_owned(),
                ));
            }
            if policy.host_unix_stream_path.is_some()
                || policy.host_unix_stream_target_fd.is_some()
                || policy.host_unix_stream_peer_uid.is_some()
                || policy.host_unix_stream_peer_gid.is_some()
            {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "policy already declares a host UNIX stream broker".to_owned(),
                ));
            }

            let mut candidate = policy.clone();
            candidate.host_unix_stream_path = Some(self.path.clone());
            candidate.host_unix_stream_target_fd = Some(target_fd);
            candidate.host_unix_stream_peer_uid = Some(self.owner_uid);
            candidate.host_unix_stream_peer_gid = Some(self.owner_gid);
            candidate.validate().map_err(RuntimeFdBrokerError::Policy)?;
            *policy = candidate;
            Ok(())
        }

        /// Accept the launcher-created broker connection and require it to come
        /// from the exact process and effective credentials that created this
        /// broker object. This closes accidental or cross-process queue capture;
        /// code inside the trusted caller process remains in the trust boundary.
        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {
            let (stream, _) = self.listener.accept().map_err(|error| {
                RuntimeFdBrokerError::io("cannot accept runtime FD broker connection", error)
            })?;
            let (pid, uid, gid) = peer_credentials(stream.as_raw_fd())?;
            if pid != self.owner_pid || uid != self.owner_uid || gid != self.owner_gid {
                return Err(RuntimeFdBrokerError::UnexpectedPeer {
                    expected_pid: self.owner_pid,
                    expected_uid: self.owner_uid,
                    expected_gid: self.owner_gid,
                    actual_pid: pid,
                    actual_uid: uid,
                    actual_gid: gid,
                });
            }
            Ok(RuntimeFdSession {
                stream,
                state: RuntimeFdSessionState::AwaitingReady,
            })
        }

        /// Pin one regular-file source as a separate read-only open file
        /// description suitable for later SCM_RIGHTS transfer.
        ///
        /// The caller must already hold read authority (`O_RDONLY` or `O_RDWR`).
        /// `O_WRONLY`, `O_PATH`, directories, devices, pipes, and sockets are
        /// rejected. Reopening through the stable `/proc/self/fd/<n>` reference
        /// gives the target an independent offset and attenuates an `O_RDWR`
        /// source to `O_RDONLY`; device/inode identity is rechecked afterward.
        /// This is data-access-mode attenuation, not immutable-inode semantics:
        /// metadata-changing syscalls remain separately governed by target
        /// seccomp/Landlock policy and normal kernel ownership checks.
        pub fn prepare_readonly_regular_file(
            source: &File,
        ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
            prepare_readonly_regular_file(source)
        }

        /// Copy one readable regular file into a bounded sealed memfd snapshot.
        ///
        /// The completed snapshot freezes the copied bytes and length with
        /// F_SEAL_WRITE/GROW/SHRINK/SEAL, then reopens the sealed object as a
        /// separate O_RDONLY|O_CLOEXEC description for the one-shot runtime
        /// grant protocol. This does not claim an atomic point-in-time read
        /// against a hostile writer mutating the source while the copy runs.
        pub fn prepare_sealed_regular_file_snapshot(
            source: &File,
            max_bytes: u64,
        ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
            prepare_sealed_regular_file_snapshot(source, max_bytes)
        }

        /// Group 2-8 already-sealed snapshots into one bounded ordered grant.
        ///
        /// The aggregate ceiling is caller-selected but may not exceed the
        /// global 64 MiB runtime bundle limit. Preparation consumes the snapshots
        /// so their order and membership cannot be changed before transfer.
        pub fn prepare_sealed_snapshot_bundle(
            grants: Vec<PreparedSealedRegularFileSnapshot>,
            max_total_bytes: u64,
        ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
            prepare_sealed_snapshot_bundle(grants, max_total_bytes)
        }
    }

    impl RuntimeFdSession {
        /// Wait for one exact target-defined readiness byte. Tests use this to
        /// prove a grant is sent only after the untrusted image has executed.
        pub fn wait_for_ready(&mut self, expected: u8) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeFdSessionState::AwaitingReady {
                return Err(RuntimeFdBrokerError::Protocol(
                    "runtime FD broker readiness may be consumed exactly once before the grant"
                        .to_owned(),
                ));
            }

            let mut byte = [0u8; 1];
            if let Err(error) = self.stream.read_exact(&mut byte) {
                self.state = RuntimeFdSessionState::Failed;
                return Err(RuntimeFdBrokerError::io(
                    "cannot read runtime FD broker readiness",
                    error,
                ));
            }
            if byte[0] != expected {
                self.state = RuntimeFdSessionState::Failed;
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "expected readiness byte 0x{expected:02x}, got 0x{:02x}",
                    byte[0]
                )));
            }
            self.state = RuntimeFdSessionState::Ready;
            Ok(())
        }

        /// Transfer exactly one previously prepared read-only regular-file grant.
        pub fn send_readonly_regular_file(
            &mut self,
            grant: PreparedReadOnlyRegularFile,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer exactly one previously prepared sealed regular-file snapshot.
        /// This shares the same one-shot session state as the ordinary read-only
        /// regular-file grant; the two grant kinds cannot be combined on one session.
        pub fn send_sealed_regular_file_snapshot(
            &mut self,
            grant: PreparedSealedRegularFileSnapshot,
        ) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fd(grant.fd)
        }

        /// Transfer one ordered sealed snapshot bundle in a single SCM_RIGHTS
        /// control message. The whole bundle consumes the same one-shot session
        /// transition as every other runtime grant.
        pub fn send_sealed_snapshot_bundle(
            &mut self,
            bundle: PreparedSealedSnapshotBundle,
        ) -> Result<(), RuntimeFdBrokerError> {
            let mut fds = [-1; super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS];
            for (index, grant) in bundle.grants.iter().enumerate() {
                fds[index] = grant.fd;
            }
            self.send_prepared_fds(&fds[..bundle.grants.len()])
        }

        fn send_prepared_fd(&mut self, fd: RawFd) -> Result<(), RuntimeFdBrokerError> {
            self.send_prepared_fds(&[fd])
        }

        fn send_prepared_fds(&mut self, fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
            if self.state != RuntimeFdSessionState::Ready {
                let message = match self.state {
                    RuntimeFdSessionState::AwaitingReady => {
                        "runtime FD broker grant requires the target readiness handshake first"
                    }
                    RuntimeFdSessionState::GrantSent => {
                        "runtime FD broker session permits exactly one successful grant"
                    }
                    RuntimeFdSessionState::Failed => {
                        "runtime FD broker session is closed after a protocol or I/O failure"
                    }
                    RuntimeFdSessionState::Ready => unreachable!(),
                };
                return Err(RuntimeFdBrokerError::Protocol(message.to_owned()));
            }

            match send_fds(self.stream.as_raw_fd(), fds) {
                Ok(()) => {
                    self.state = RuntimeFdSessionState::GrantSent;
                    Ok(())
                }
                Err(error) => {
                    self.state = RuntimeFdSessionState::Failed;
                    Err(error)
                }
            }
        }
    }

    fn validate_socket_path(path: &Path) -> Result<(), RuntimeFdBrokerError> {
        if !path.is_absolute() {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(
                "broker socket path must be absolute".to_owned(),
            ));
        }
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(
                "broker socket path must not contain NUL".to_owned(),
            ));
        }
        if bytes.len() > MAX_UNIX_PATH_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "broker socket path exceeds {MAX_UNIX_PATH_BYTES} bytes"
            )));
        }
        for component in path.components() {
            if matches!(component, Component::ParentDir | Component::CurDir) {
                return Err(RuntimeFdBrokerError::InvalidConfiguration(
                    "broker socket path must not contain . or .. components".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn peer_credentials(fd: RawFd) -> Result<(i32, u32, u32), RuntimeFdBrokerError> {
        let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
        let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast::<libc::c_void>(),
                &mut length,
            )
        };
        if result == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker peer credentials",
                std::io::Error::last_os_error(),
            ));
        }
        if length as usize != std::mem::size_of::<libc::ucred>() {
            return Err(RuntimeFdBrokerError::Protocol(
                "SO_PEERCRED returned an unexpected structure length".to_owned(),
            ));
        }
        Ok((credentials.pid, credentials.uid, credentials.gid))
    }

    fn prepare_readonly_regular_file(
        source: &File,
    ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
        let source_fd = source.as_raw_fd();
        let mut original_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(source_fd, &mut original_stat) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker source",
                std::io::Error::last_os_error(),
            ));
        }
        if original_stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(RuntimeFdBrokerError::SourceNotRegular);
        }

        let original_flags = unsafe { libc::fcntl(source_fd, libc::F_GETFL) };
        if original_flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD broker source flags",
                std::io::Error::last_os_error(),
            ));
        }
        if original_flags & libc::O_PATH != 0 {
            return Err(RuntimeFdBrokerError::SourcePathOnly);
        }
        if original_flags & libc::O_ACCMODE == libc::O_WRONLY {
            return Err(RuntimeFdBrokerError::SourceNotReadable);
        }

        let proc_path = CString::new(format!("/proc/self/fd/{source_fd}"))
            .expect("numeric procfd path cannot contain NUL");
        let reopened = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if reopened == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot reopen runtime FD broker source read-only through procfd",
                std::io::Error::last_os_error(),
            ));
        }
        let reopened = PreparedReadOnlyRegularFile { fd: reopened };

        let mut reopened_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(reopened.fd, &mut reopened_stat) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot revalidate runtime FD broker source identity",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_stat.st_mode & libc::S_IFMT != libc::S_IFREG
            || reopened_stat.st_dev != original_stat.st_dev
            || reopened_stat.st_ino != original_stat.st_ino
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "procfd reopen changed runtime FD broker source identity".to_owned(),
            ));
        }

        let reopened_flags = unsafe { libc::fcntl(reopened.fd, libc::F_GETFL) };
        if reopened_flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect attenuated runtime FD broker source flags",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_flags & libc::O_PATH != 0 || reopened_flags & libc::O_ACCMODE != libc::O_RDONLY
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "runtime FD broker failed to attenuate source to O_RDONLY".to_owned(),
            ));
        }

        Ok(reopened)
    }

    fn prepare_sealed_regular_file_snapshot(
        source: &File,
        max_bytes: u64,
    ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
        if max_bytes == 0 || max_bytes > super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime snapshot max_bytes must be between 1 and {}",
                super::MAX_RUNTIME_SEALED_SNAPSHOT_BYTES
            )));
        }

        let readable = prepare_readonly_regular_file(source)?;
        let name = CString::new("security-lab-runtime-snapshot")
            .expect("static runtime snapshot memfd name contains no NUL");
        let raw_memfd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            )
        };
        if raw_memfd == -1 {
            let error = std::io::Error::last_os_error();
            return if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EPERM) | Some(libc::EACCES)
            ) {
                Err(RuntimeFdBrokerError::UnsupportedPlatform(format!(
                    "sealed runtime FD snapshots require memfd sealing support: {error}"
                )))
            } else {
                Err(RuntimeFdBrokerError::io(
                    "cannot create sealed runtime FD snapshot memfd",
                    error,
                ))
            };
        }
        let mut memfd = PreparedSealedRegularFileSnapshot {
            fd: raw_memfd as RawFd,
            len: 0,
        };
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = unsafe {
                libc::read(
                    readable.fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot read runtime FD source for sealed snapshot",
                    error,
                ));
            }
            if read == 0 {
                break;
            }
            let count = read as usize;
            let new_len = memfd.len.checked_add(count as u64).ok_or_else(|| {
                RuntimeFdBrokerError::Protocol(
                    "sealed runtime snapshot byte count overflow".to_owned(),
                )
            })?;
            if new_len > max_bytes {
                return Err(RuntimeFdBrokerError::SourceSnapshotTooLarge { max_bytes });
            }
            let mut offset = 0usize;
            while offset < count {
                let written = unsafe {
                    libc::write(
                        memfd.fd,
                        buffer[offset..count].as_ptr().cast::<libc::c_void>(),
                        count - offset,
                    )
                };
                if written == -1 {
                    let error = std::io::Error::last_os_error();
                    if error.raw_os_error() == Some(libc::EINTR) {
                        continue;
                    }
                    return Err(RuntimeFdBrokerError::io(
                        "cannot populate sealed runtime FD snapshot",
                        error,
                    ));
                }
                if written == 0 {
                    return Err(RuntimeFdBrokerError::Protocol(
                        "sealed runtime snapshot write made no progress".to_owned(),
                    ));
                }
                offset += written as usize;
            }
            memfd.len = new_len;
        }

        if unsafe { libc::fchmod(memfd.fd, 0o400) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot set sealed runtime FD snapshot mode",
                std::io::Error::last_os_error(),
            ));
        }
        let required_seals =
            libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
        if unsafe { libc::fcntl(memfd.fd, libc::F_ADD_SEALS, required_seals) } == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot seal runtime FD snapshot",
                std::io::Error::last_os_error(),
            ));
        }
        let observed = unsafe { libc::fcntl(memfd.fd, libc::F_GET_SEALS) };
        if observed == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect runtime FD snapshot seals",
                std::io::Error::last_os_error(),
            ));
        }
        if observed & required_seals != required_seals {
            return Err(RuntimeFdBrokerError::Protocol(
                "sealed runtime FD snapshot is missing required immutable seals".to_owned(),
            ));
        }

        let proc_path = CString::new(format!("/proc/self/fd/{}", memfd.fd))
            .expect("numeric runtime snapshot procfd path contains no NUL");
        let readonly = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if readonly == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot reopen sealed runtime FD snapshot read-only",
                std::io::Error::last_os_error(),
            ));
        }
        let readonly = PreparedSealedRegularFileSnapshot {
            fd: readonly,
            len: memfd.len,
        };

        let mut original_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        let mut readonly_stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(memfd.fd, &mut original_stat) } == -1
            || unsafe { libc::fstat(readonly.fd, &mut readonly_stat) } == -1
        {
            return Err(RuntimeFdBrokerError::io(
                "cannot revalidate sealed runtime FD snapshot identity",
                std::io::Error::last_os_error(),
            ));
        }
        if original_stat.st_dev != readonly_stat.st_dev
            || original_stat.st_ino != readonly_stat.st_ino
        {
            return Err(RuntimeFdBrokerError::Protocol(
                "read-only reopen changed sealed runtime FD snapshot identity".to_owned(),
            ));
        }
        let flags = unsafe { libc::fcntl(readonly.fd, libc::F_GETFL) };
        if flags == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot inspect sealed runtime FD snapshot access mode",
                std::io::Error::last_os_error(),
            ));
        }
        if flags & libc::O_PATH != 0 || flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(RuntimeFdBrokerError::Protocol(
                "sealed runtime FD snapshot did not reopen as O_RDONLY".to_owned(),
            ));
        }
        let reopened_seals = unsafe { libc::fcntl(readonly.fd, libc::F_GET_SEALS) };
        if reopened_seals == -1 {
            return Err(RuntimeFdBrokerError::io(
                "cannot verify seals after runtime FD snapshot reopen",
                std::io::Error::last_os_error(),
            ));
        }
        if reopened_seals & required_seals != required_seals {
            return Err(RuntimeFdBrokerError::Protocol(
                "read-only runtime FD snapshot lost required seals".to_owned(),
            ));
        }

        drop(memfd);
        Ok(readonly)
    }

    fn prepare_sealed_snapshot_bundle(
        grants: Vec<PreparedSealedRegularFileSnapshot>,
        max_total_bytes: u64,
    ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
        if max_total_bytes == 0 || max_total_bytes > super::MAX_RUNTIME_SEALED_BUNDLE_BYTES {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime bundle max_total_bytes must be between 1 and {}",
                super::MAX_RUNTIME_SEALED_BUNDLE_BYTES
            )));
        }
        if !(super::MIN_RUNTIME_SEALED_BUNDLE_ITEMS..=super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS)
            .contains(&grants.len())
        {
            return Err(RuntimeFdBrokerError::InvalidConfiguration(format!(
                "sealed runtime bundle must contain between {} and {} snapshots",
                super::MIN_RUNTIME_SEALED_BUNDLE_ITEMS,
                super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS
            )));
        }

        let mut total_len = 0u64;
        for grant in &grants {
            total_len = total_len.checked_add(grant.len).ok_or_else(|| {
                RuntimeFdBrokerError::Protocol(
                    "sealed runtime bundle aggregate byte count overflow".to_owned(),
                )
            })?;
            if total_len > max_total_bytes {
                return Err(RuntimeFdBrokerError::SnapshotBundleTooLarge {
                    max_bytes: max_total_bytes,
                });
            }
        }
        Ok(PreparedSealedSnapshotBundle { grants, total_len })
    }

    #[repr(C, align(8))]
    struct FdControl([u8; 48]);

    fn cmsg_space_for_fd_count(count: usize) -> usize {
        let unaligned = std::mem::size_of::<libc::cmsghdr>()
            + count * std::mem::size_of::<RawFd>();
        let alignment = std::mem::size_of::<usize>();
        (unaligned + alignment - 1) & !(alignment - 1)
    }

    fn send_fds(socket_fd: RawFd, source_fds: &[RawFd]) -> Result<(), RuntimeFdBrokerError> {
        if source_fds.is_empty() || source_fds.len() > super::MAX_RUNTIME_SEALED_BUNDLE_ITEMS {
            return Err(RuntimeFdBrokerError::Protocol(
                "SCM_RIGHTS grant descriptor count is outside the supported bound".to_owned(),
            ));
        }

        let mut payload = if source_fds.len() == 1 { *b"F" } else { *b"B" };
        let mut iovec = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: payload.len(),
        };
        let mut control = FdControl([0; 48]);
        let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_len = std::mem::size_of::<libc::cmsghdr>()
                + source_fds.len() * std::mem::size_of::<RawFd>();
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            let data = control
                .0
                .as_mut_ptr()
                .add(std::mem::size_of::<libc::cmsghdr>())
                .cast::<RawFd>();
            for (index, source_fd) in source_fds.iter().enumerate() {
                data.add(index).write(*source_fd);
            }
        }

        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
        message.msg_controllen = cmsg_space_for_fd_count(source_fds.len());

        loop {
            let sent = unsafe { libc::sendmsg(socket_fd, &message, libc::MSG_NOSIGNAL) };
            if sent == 1 {
                return Ok(());
            }
            if sent == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(RuntimeFdBrokerError::io(
                    "cannot send runtime FD broker SCM_RIGHTS grant",
                    error,
                ));
            }
            return Err(RuntimeFdBrokerError::Protocol(format!(
                "SCM_RIGHTS send wrote unexpected payload length {sent}"
            )));
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod imp {
    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};

    #[derive(Debug)]
    pub struct PreparedReadOnlyRegularFile;

    #[derive(Debug)]
    pub struct PreparedSealedRegularFileSnapshot;

    #[derive(Debug)]
    pub struct PreparedSealedSnapshotBundle;

    impl PreparedSealedSnapshotBundle {
        pub fn item_count(&self) -> usize {
            0
        }

        pub fn total_len(&self) -> u64 {
            0
        }
    }

    impl PreparedSealedRegularFileSnapshot {
        pub fn len(&self) -> u64 {
            0
        }

        pub fn is_empty(&self) -> bool {
            true
        }
    }

    #[derive(Debug)]
    pub struct RuntimeFdBroker;

    #[derive(Debug)]
    pub struct RuntimeFdSession;

    impl RuntimeFdBroker {
        pub fn bind(_path: impl AsRef<Path>) -> Result<Self, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn path(&self) -> &Path {
            Path::new("")
        }

        pub fn configure_policy(
            &self,
            _policy: &mut SandboxPolicy,
            _target_fd: u32,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_readonly_regular_file(
            _source: &File,
        ) -> Result<PreparedReadOnlyRegularFile, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_sealed_regular_file_snapshot(
            _source: &File,
            _max_bytes: u64,
        ) -> Result<PreparedSealedRegularFileSnapshot, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshots currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn prepare_sealed_snapshot_bundle(
            _grants: Vec<PreparedSealedRegularFileSnapshot>,
            _max_total_bytes: u64,
        ) -> Result<PreparedSealedSnapshotBundle, RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshot bundles currently require Linux x86_64".to_owned(),
            ))
        }
    }

    impl RuntimeFdSession {
        pub fn wait_for_ready(&mut self, _expected: u8) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn send_readonly_regular_file(
            &mut self,
            _grant: PreparedReadOnlyRegularFile,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "runtime FD mediation currently requires Linux x86_64".to_owned(),
            ))
        }

        pub fn send_sealed_regular_file_snapshot(
            &mut self,
            _grant: PreparedSealedRegularFileSnapshot,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshots currently require Linux x86_64".to_owned(),
            ))
        }

        pub fn send_sealed_snapshot_bundle(
            &mut self,
            _bundle: PreparedSealedSnapshotBundle,
        ) -> Result<(), RuntimeFdBrokerError> {
            Err(RuntimeFdBrokerError::UnsupportedPlatform(
                "sealed runtime FD snapshot bundles currently require Linux x86_64".to_owned(),
            ))
        }
    }
}

pub use imp::{
    PreparedReadOnlyRegularFile, PreparedSealedRegularFileSnapshot, PreparedSealedSnapshotBundle,
    RuntimeFdBroker, RuntimeFdSession,
};
