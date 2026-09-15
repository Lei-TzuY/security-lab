use crate::{PolicyError, SandboxPolicy};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub enum RuntimeFdBrokerError {
    UnsupportedPlatform(String),
    InvalidConfiguration(String),
    Policy(PolicyError),
    SourceNotRegular,
    SourceNotReadable,
    SourcePathOnly,
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

    #[derive(Debug)]
    pub struct RuntimeFdSession {
        stream: UnixStream,
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
            Ok(RuntimeFdSession { stream })
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
    }

    impl RuntimeFdSession {
        /// Wait for one exact target-defined readiness byte. Tests use this to
        /// prove a grant is sent only after the untrusted image has executed.
        pub fn wait_for_ready(&mut self, expected: u8) -> Result<(), RuntimeFdBrokerError> {
            let mut byte = [0u8; 1];
            self.stream.read_exact(&mut byte).map_err(|error| {
                RuntimeFdBrokerError::io("cannot read runtime FD broker readiness", error)
            })?;
            if byte[0] != expected {
                return Err(RuntimeFdBrokerError::Protocol(format!(
                    "expected readiness byte 0x{expected:02x}, got 0x{:02x}",
                    byte[0]
                )));
            }
            Ok(())
        }

        /// Transfer exactly one previously prepared read-only regular-file grant.
        /// The one-byte `F` payload makes a zero-length ancillary-only send
        /// impossible and matches the bounded receive protocol used by the lab.
        pub fn send_readonly_regular_file(
            &mut self,
            grant: PreparedReadOnlyRegularFile,
        ) -> Result<(), RuntimeFdBrokerError> {
            send_one_fd(self.stream.as_raw_fd(), grant.fd)
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

    #[repr(C, align(8))]
    struct OneFdControl([u8; 24]);

    fn send_one_fd(socket_fd: RawFd, source_fd: RawFd) -> Result<(), RuntimeFdBrokerError> {
        let mut payload = *b"F";
        let mut iovec = libc::iovec {
            iov_base: payload.as_mut_ptr().cast::<libc::c_void>(),
            iov_len: payload.len(),
        };
        let mut control = OneFdControl([0; 24]);
        let header = control.0.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_len =
                std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<RawFd>();
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            control
                .0
                .as_mut_ptr()
                .add(std::mem::size_of::<libc::cmsghdr>())
                .cast::<RawFd>()
                .write(source_fd);
        }

        let mut message = unsafe { std::mem::zeroed::<libc::msghdr>() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast::<libc::c_void>();
        message.msg_controllen = control.0.len();

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
    }
}

pub use imp::{PreparedReadOnlyRegularFile, RuntimeFdBroker, RuntimeFdSession};
