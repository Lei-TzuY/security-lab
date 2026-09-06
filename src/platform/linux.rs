#[cfg(not(target_arch = "x86_64"))]
pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
    _cancellation: Option<&crate::CancellationToken>,
) -> Result<crate::RunReport, crate::SandboxError> {
    Err(crate::SandboxError::UnsupportedPlatform(
        "sandbox enforcement currently supports Linux x86_64 only".to_owned(),
    ))
}

#[cfg(target_arch = "x86_64")]
#[path = "linux_pid_lifecycle.rs"]
mod pid_lifecycle;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use super::pid_lifecycle::{
        self, LaunchErrorRecord, SharedTargetLifecycle, TargetLifecycleRecord,
        TargetSupervisionPhases,
    };
    use crate::policy::{StdioMode, StdioPolicy};
    use crate::{
        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ProcessTreeUsage,
        ResourceLimits, RunReport, SandboxError, SandboxPolicy,
    };
    use std::ffi::CString;
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::RawFd;
    use std::path::{Path, PathBuf};
    use std::ptr;

    const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGT_K: u16 = 0x25;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;

    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const FIRST_NON_STDIO_FD: libc::c_uint = 3;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const AT_EMPTY_PATH: libc::c_uint = 0x1000;
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    const EXECVEAT_AT_EMPTY_PATH: libc::c_int = 0x1000;

    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAPBSET_DROP: libc::c_int = 24;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;

    const PHASE_NAMESPACE: u32 = 1;
    const PHASE_SETGROUPS: u32 = 2;
    const PHASE_UID_MAP: u32 = 3;
    const PHASE_GID_MAP: u32 = 4;
    const PHASE_MOUNT_PRIVATE: u32 = 5;
    const PHASE_STDIO: u32 = 6;
    const PHASE_ROOT_CLONE: u32 = 7;
    const PHASE_ROOT_READONLY: u32 = 8;
    const PHASE_ROOT_ATTACH: u32 = 9;
    const PHASE_ROOT_FCHDIR: u32 = 10;
    const PHASE_SCRATCH_MOUNT: u32 = 11;
    const PHASE_CWD_PIN: u32 = 12;
    const PHASE_CHROOT: u32 = 13;
    const PHASE_CWD_FCHDIR: u32 = 14;
    const PHASE_FD_SANITIZE: u32 = 15;
    const PHASE_RLIMIT_CPU: u32 = 16;
    const PHASE_RLIMIT_AS: u32 = 17;
    const PHASE_RLIMIT_FSIZE: u32 = 18;
    const PHASE_RLIMIT_NOFILE: u32 = 19;
    const PHASE_CAP_BOUNDING: u32 = 20;
    const PHASE_CAP_AMBIENT: u32 = 21;
    const PHASE_CAP_CURRENT: u32 = 22;
    const PHASE_NO_NEW_PRIVS: u32 = 23;
    const PHASE_SECCOMP: u32 = 24;
    const PHASE_EXECVEAT: u32 = 25;
    const PHASE_ROOT_REVALIDATE: u32 = 26;
    const PHASE_STDIO_REDIRECT: u32 = 27;
    const PHASE_STDOUT_CAPTURE: u32 = 28;
    const PHASE_PID_INIT_FORK: u32 = 29;
    const PHASE_TARGET_FORK: u32 = 30;
    const PHASE_PROCESS_TREE_KILL: u32 = 31;
    const PHASE_PROCESS_TREE_REAP: u32 = 32;
    const PHASE_PID_INIT_WAIT: u32 = 33;
    const PHASE_DEADLINE_PIDFD: u32 = 34;
    const PHASE_DEADLINE_TIMERFD: u32 = 35;
    const PHASE_DEADLINE_TIMER_ARM: u32 = 36;
    const PHASE_DEADLINE_POLL: u32 = 37;
    const PHASE_HOSTNAME: u32 = 38;
    const PHASE_SELECTED_HANDLES: u32 = 39;
    const PHASE_CANCELLATION_PIDFD: u32 = 40;
    const PHASE_CANCELLATION_POLL: u32 = 41;
    const PHASE_VOLUME_SOURCE_REVALIDATE: u32 = 42;
    const PHASE_VOLUME_CLONE: u32 = 43;
    const PHASE_VOLUME_READONLY: u32 = 44;
    const PHASE_VOLUME_TARGET_PIN: u32 = 45;
    const PHASE_VOLUME_ATTACH: u32 = 46;
    const PHASE_NETWORK_LOOPBACK: u32 = 47;
    const PHASE_LANDLOCK_RULESET: u32 = 48;
    const PHASE_LANDLOCK_PATH: u32 = 49;
    const PHASE_LANDLOCK_RULE: u32 = 50;
    const PHASE_LANDLOCK_RESTRICT: u32 = 51;
    const PHASE_LANDLOCK_NET_RULE: u32 = 52;
    const PHASE_PROCESS_TREE_USAGE: u32 = 53;
    const PHASE_OUTPUT_LIMIT_PIDFD: u32 = 54;
    const PHASE_OUTPUT_LIMIT_POLL: u32 = 55;

    const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
    const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
    const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;
    const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
    const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;
    const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
    const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
    const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;
    const LANDLOCK_READ_EXECUTE_RIGHTS: u64 =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    const LANDLOCK_FILE_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_TRUNCATE;
    const LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS: u64 = LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_REFER;

    const SIOCGIFFLAGS: libc::c_ulong = 0x8913;
    const SIOCSIFFLAGS: libc::c_ulong = 0x8914;
    const IFF_UP: libc::c_short = 0x1;
    const IFNAMSIZ: usize = 16;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
        scoped: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
        reserved: u32,
    }

    #[repr(C)]
    struct LandlockNetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    #[repr(C, align(8))]
    struct IfreqFlags {
        name: [libc::c_char; IFNAMSIZ],
        flags: libc::c_short,
        _padding: [u8; 22],
    }

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

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

    struct CapturePipe {
        read_fd: OwnedFd,
        write_fd: OwnedFd,
        limit: usize,
    }

    struct PreparedSelectedHandle {
        storage_fd: OwnedFd,
        target_fd: RawFd,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VolumeAccess {
        ReadOnly,
        Writable,
    }

    struct PreparedVolume {
        source_fd: OwnedFd,
        source_path: CString,
        target_relative: CString,
        access: VolumeAccess,
    }

    impl CapturePipe {
        fn new(limit: u64) -> Result<Self, SandboxError> {
            let mut fds = [-1; 2];
            if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == -1 {
                return Err(SandboxError::SetupFailed(format!(
                    "cannot create stdout capture pipe: {}",
                    io::Error::last_os_error()
                )));
            }

            let read_fd = move_parent_fd_above_stdio(OwnedFd(fds[0]), "capture read end")?;
            let write_fd = move_parent_fd_above_stdio(OwnedFd(fds[1]), "capture write end")?;
            Ok(Self {
                read_fd,
                write_fd,
                limit: limit as usize,
            })
        }
    }

    fn move_parent_fd_above_stdio(fd: OwnedFd, label: &str) -> Result<OwnedFd, SandboxError> {
        if fd.raw() >= FIRST_NON_STDIO_FD as RawFd {
            return Ok(fd);
        }
        let moved = unsafe {
            libc::fcntl(
                fd.raw(),
                libc::F_DUPFD_CLOEXEC,
                FIRST_NON_STDIO_FD as libc::c_int,
            )
        };
        if moved == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot normalize {label} above standard descriptors: {}",
                io::Error::last_os_error()
            )));
        }
        drop(fd);
        Ok(OwnedFd(moved))
    }

    fn move_owned_fd_to_selected_storage(
        fd: OwnedFd,
        storage_floor: RawFd,
        label: &str,
    ) -> Result<OwnedFd, SandboxError> {
        if fd.raw() >= storage_floor {
            return Ok(fd);
        }
        let moved = unsafe { libc::fcntl(fd.raw(), libc::F_DUPFD_CLOEXEC, storage_floor) };
        if moved == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot move {label} into the selected-handle storage plane at fd {storage_floor} or above: {}",
                io::Error::last_os_error()
            )));
        }
        drop(fd);
        Ok(OwnedFd(moved))
    }

    fn pin_selected_handle(
        source_fd: u32,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        if source_fd > i32::MAX as u32 {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                "selected handle source fd exceeds the Linux descriptor range: {source_fd}"
            ))));
        }
        let source_fd = source_fd as RawFd;
        let pinned = unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, storage_floor) };
        if pinned == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot pin selected handle source fd {source_fd} for target fd {target_fd}: {}",
                io::Error::last_os_error()
            )));
        }
        let storage_fd = OwnedFd(pinned);
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(storage_fd.raw(), &mut stat) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot inspect selected handle source fd {source_fd}: {}",
                io::Error::last_os_error()
            )));
        }
        if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                "selected handle source fd {source_fd} is a directory descriptor"
            ))));
        }
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn connect_host_tcp_ipv4(
        address: Ipv4Addr,
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
        broker_label: &str,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered {broker_label} TCP socket: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let address_struct = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        };
        loop {
            let connected = unsafe {
                libc::connect(
                    socket_fd.raw(),
                    (&address_struct as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if connected == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot connect brokered {broker_label} TCP endpoint {address}:{port}: {error}"
            )));
        }
        let storage_label = format!("brokered {broker_label} TCP socket");
        let storage_fd =
            move_owned_fd_to_selected_storage(socket_fd, storage_floor, &storage_label)?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn connect_host_loopback_tcp(
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        connect_host_tcp_ipv4(
            Ipv4Addr::new(127, 0, 0, 1),
            port,
            target_fd,
            storage_floor,
            "host-loopback",
        )
    }

    fn connect_host_udp_ipv4(
        address: Ipv4Addr,
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered host-IPv4 UDP socket: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let address_struct = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            },
            sin_zero: [0; 8],
        };
        loop {
            let connected = unsafe {
                libc::connect(
                    socket_fd.raw(),
                    (&address_struct as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if connected == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot connect brokered host-IPv4 UDP socket to {address}:{port}: {error}"
            )));
        }
        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            "brokered host-IPv4 UDP socket",
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn connect_host_unix_stream(
        path: &Path,
        target_fd: u32,
        storage_floor: RawFd,
        expected_peer: Option<(u32, u32)>,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let path_bytes = path.as_os_str().as_bytes();
        if path_bytes.is_empty() || path_bytes.len() >= 108 || path_bytes.contains(&0) {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "ipc.host_unix_stream_path must be a nonempty Linux pathname of at most 107 bytes without NUL",
            )));
        }
        let socket_fd =
            unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered host-UNIX stream socket: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (index, byte) in path_bytes.iter().copied().enumerate() {
            address.sun_path[index] = byte as libc::c_char;
        }
        let address_length =
            (std::mem::size_of::<libc::sa_family_t>() + path_bytes.len() + 1) as libc::socklen_t;
        loop {
            let connected = unsafe {
                libc::connect(
                    socket_fd.raw(),
                    (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                    address_length,
                )
            };
            if connected == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot connect brokered host-UNIX stream endpoint {}: {error}",
                path.display()
            )));
        }
        if let Some((expected_uid, expected_gid)) = expected_peer {
            let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };
            let mut credentials_len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
            if unsafe {
                libc::getsockopt(
                    socket_fd.raw(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut credentials as *mut libc::ucred).cast::<libc::c_void>(),
                    &mut credentials_len,
                )
            } == -1
            {
                return Err(SandboxError::SetupFailed(format!(
                    "cannot inspect brokered host-UNIX peer credentials for {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                )));
            }
            if credentials_len as usize != std::mem::size_of::<libc::ucred>() {
                return Err(SandboxError::SetupFailed(format!(
                    "brokered host-UNIX peer credential query for {} returned {} bytes, expected {}",
                    path.display(),
                    credentials_len,
                    std::mem::size_of::<libc::ucred>()
                )));
            }
            if credentials.uid != expected_uid || credentials.gid != expected_gid {
                return Err(SandboxError::SetupFailed(format!(
                    "brokered host-UNIX peer credentials mismatch for {}: expected uid {expected_uid} gid {expected_gid}, got uid {} gid {}",
                    path.display(),
                    credentials.uid,
                    credentials.gid
                )));
            }
        }

        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            "brokered host-UNIX stream socket",
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn listen_host_loopback_tcp(
        port: u16,
        target_fd: u32,
        storage_floor: RawFd,
    ) -> Result<PreparedSelectedHandle, SandboxError> {
        let socket_fd =
            unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if socket_fd == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot create brokered host-loopback TCP listener: {}",
                io::Error::last_os_error()
            )));
        }
        let socket_fd = OwnedFd(socket_fd);
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
            },
            sin_zero: [0; 8],
        };
        loop {
            let bound = unsafe {
                libc::bind(
                    socket_fd.raw(),
                    (&address as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            };
            if bound == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot bind brokered host-loopback TCP listener 127.0.0.1:{port}: {error}"
            )));
        }
        loop {
            if unsafe { libc::listen(socket_fd.raw(), 1) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::SetupFailed(format!(
                "cannot listen on brokered host-loopback TCP endpoint 127.0.0.1:{port}: {error}"
            )));
        }
        let storage_fd = move_owned_fd_to_selected_storage(
            socket_fd,
            storage_floor,
            "brokered host-loopback TCP listener",
        )?;
        Ok(PreparedSelectedHandle {
            storage_fd,
            target_fd: target_fd as RawFd,
        })
    }

    fn prepare_volume(
        root_fd: RawFd,
        source: &Path,
        target: &Path,
        source_field: &str,
        source_label: &str,
        target_label: &str,
        access: VolumeAccess,
    ) -> Result<PreparedVolume, SandboxError> {
        let source_fd = open_host_directory(source, source_label)?;
        let target_check = open_beneath_root(
            root_fd,
            target,
            (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            target_label,
        )?;
        drop(target_check);
        Ok(PreparedVolume {
            source_fd,
            source_path: cstring_bytes(source_field, source.as_os_str().as_bytes())?,
            target_relative: sandbox_relative(target)?,
            access,
        })
    }

    struct SharedLaunchState {
        record: *mut LaunchErrorRecord,
    }

    impl SharedLaunchState {
        fn new() -> Result<Self, SandboxError> {
            let length = std::mem::size_of::<LaunchErrorRecord>();
            let mapping = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    length,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            if mapping == libc::MAP_FAILED {
                return Err(SandboxError::SetupFailed(format!(
                    "cannot allocate shared launch state: {}",
                    io::Error::last_os_error()
                )));
            }

            let record = mapping.cast::<LaunchErrorRecord>();
            unsafe {
                ptr::write_volatile(record, LaunchErrorRecord { errno: 0, phase: 0 });
            }
            Ok(Self { record })
        }

        fn snapshot(&self) -> LaunchErrorRecord {
            unsafe { ptr::read_volatile(self.record) }
        }
    }

    impl Drop for SharedLaunchState {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(
                    self.record.cast::<libc::c_void>(),
                    std::mem::size_of::<LaunchErrorRecord>(),
                );
            }
        }
    }

    struct PreparedLandlock {
        read_execute: Vec<CString>,
        file_mutate: Vec<CString>,
        path_topology_mutate: Vec<CString>,
        device_ioctl: Vec<CString>,
        tcp_bind_ports: Vec<u16>,
        tcp_connect_ports: Vec<u16>,
        scope_abstract_unix_socket: bool,
        scope_signal: bool,
    }

    struct PreparedLaunch {
        root_fd: OwnedFd,
        root_path: CString,
        executable_fd: OwnedFd,
        selected_handles: Vec<PreparedSelectedHandle>,
        selected_storage_floor: RawFd,
        landlock: PreparedLandlock,
        cancellation_fd: Option<OwnedFd>,
        volumes: Vec<PreparedVolume>,
        cwd_relative: CString,
        scratch_relative: Option<CString>,
        scratch_options: Option<CString>,
        stdout_redirect_relative: Option<CString>,
        _argv0: CString,
        _args: Vec<CString>,
        _environment: Vec<CString>,
        argv: Vec<*const libc::c_char>,
        envp: Vec<*const libc::c_char>,
        uid_map: Vec<u8>,
        gid_map: Vec<u8>,
        hostname: Vec<u8>,
        loopback_enabled: bool,
    }

    impl PreparedLaunch {
        fn new(
            policy: &SandboxPolicy,
            cancellation: Option<&CancellationToken>,
        ) -> Result<Self, SandboxError> {
            let root_fd = open_root(&policy.root_dir)?;
            let root_path =
                cstring_bytes("filesystem.root", policy.root_dir.as_os_str().as_bytes())?;
            let cwd_check = open_beneath_root(
                root_fd.raw(),
                &policy.working_dir,
                (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                "working directory",
            )?;
            drop(cwd_check);

            let executable_fd = open_beneath_root(
                root_fd.raw(),
                &policy.executable,
                (libc::O_PATH | libc::O_CLOEXEC) as u64,
                "executable",
            )?;
            validate_executable_fd(executable_fd.raw(), &policy.executable)?;

            let mut landlock_read_execute = Vec::with_capacity(policy.landlock_read_execute.len());
            for path in &policy.landlock_read_execute {
                let checked = open_beneath_root(
                    root_fd.raw(),
                    path,
                    (libc::O_PATH | libc::O_CLOEXEC) as u64,
                    "Landlock read/execute path",
                )?;
                let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe { libc::fstat(checked.raw(), &mut stat) } == -1 {
                    return Err(SandboxError::SetupFailed(format!(
                        "cannot inspect Landlock read/execute path {}: {}",
                        path.display(),
                        io::Error::last_os_error()
                    )));
                }
                let kind = stat.st_mode & libc::S_IFMT;
                if kind != libc::S_IFDIR && kind != libc::S_IFREG {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                        "landlock.read_execute path must name a regular file or directory: {}",
                        path.display()
                    ))));
                }
                drop(checked);
                landlock_read_execute.push(sandbox_relative(path)?);
            }

            // Mutation paths may live inside the final scratch tmpfs or a mounted
            // writable persistent volume, so only prepare lexical relative paths
            // here. The direct target pins the final directory after mount setup.
            let mut landlock_file_mutate = Vec::with_capacity(policy.landlock_file_mutate.len());
            for path in &policy.landlock_file_mutate {
                landlock_file_mutate.push(sandbox_relative(path)?);
            }
            let mut landlock_path_topology_mutate =
                Vec::with_capacity(policy.landlock_path_topology_mutate.len());
            for path in &policy.landlock_path_topology_mutate {
                landlock_path_topology_mutate.push(sandbox_relative(path)?);
            }
            // Device paths may be supplied by a persistent volume, so the final
            // mounted object is pinned and type-checked by the direct target.
            let mut landlock_device_ioctl = Vec::with_capacity(policy.landlock_device_ioctl.len());
            for path in &policy.landlock_device_ioctl {
                landlock_device_ioctl.push(sandbox_relative(path)?);
            }

            // Keep every launcher-owned source above all target-visible handle
            // destinations. With no selected handles this floor is only 3, so
            // existing sandboxes do not gain an unnecessary fd>=64 requirement.
            let selected_storage_floor = policy
                .selected_handles
                .keys()
                .copied()
                .chain(policy.host_loopback_tcp_target_fd.iter().copied())
                .chain(policy.host_ipv4_tcp_target_fd.iter().copied())
                .chain(policy.host_ipv4_udp_target_fd.iter().copied())
                .chain(policy.host_unix_stream_target_fd.iter().copied())
                .chain(policy.host_loopback_tcp_listen_target_fd.iter().copied())
                .max()
                .map_or(FIRST_NON_STDIO_FD as RawFd, |target_fd| {
                    target_fd as RawFd + 1
                });
            let executable_fd = move_owned_fd_to_selected_storage(
                executable_fd,
                selected_storage_floor,
                "pinned executable",
            )?;

            let mut selected_handles = Vec::with_capacity(
                policy.selected_handles.len()
                    + if policy.host_loopback_tcp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_ipv4_tcp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_ipv4_udp_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_unix_stream_target_fd.is_some() {
                        1
                    } else {
                        0
                    }
                    + if policy.host_loopback_tcp_listen_target_fd.is_some() {
                        1
                    } else {
                        0
                    },
            );
            for (target_fd, source_fd) in &policy.selected_handles {
                selected_handles.push(pin_selected_handle(
                    *source_fd,
                    *target_fd,
                    selected_storage_floor,
                )?);
            }
            match (
                policy.host_loopback_tcp_port,
                policy.host_loopback_tcp_target_fd,
            ) {
                (Some(port), Some(target_fd)) => selected_handles.push(connect_host_loopback_tcp(
                    port,
                    target_fd,
                    selected_storage_floor,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "network.host_loopback_tcp_port and network.host_loopback_tcp_target_fd must be specified together",
                    )));
                }
            }
            match (
                policy.host_ipv4_tcp_address,
                policy.host_ipv4_tcp_port,
                policy.host_ipv4_tcp_target_fd,
            ) {
                (Some(address), Some(port), Some(target_fd)) => {
                    selected_handles.push(connect_host_tcp_ipv4(
                        address,
                        port,
                        target_fd,
                        selected_storage_floor,
                        "host-IPv4",
                    )?)
                }
                (None, None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "network.host_ipv4_tcp_address, network.host_ipv4_tcp_port, and network.host_ipv4_tcp_target_fd must be specified together",
                    )));
                }
            }
            match (
                policy.host_ipv4_udp_address,
                policy.host_ipv4_udp_port,
                policy.host_ipv4_udp_target_fd,
            ) {
                (Some(address), Some(port), Some(target_fd)) => selected_handles.push(
                    connect_host_udp_ipv4(address, port, target_fd, selected_storage_floor)?,
                ),
                (None, None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "network.host_ipv4_udp_address, network.host_ipv4_udp_port, and network.host_ipv4_udp_target_fd must be specified together",
                    )));
                }
            }
            let host_unix_expected_peer = match (
                policy.host_unix_stream_peer_uid,
                policy.host_unix_stream_peer_gid,
            ) {
                (Some(uid), Some(gid)) => Some((uid, gid)),
                (None, None) => None,
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together",
                    )));
                }
            };
            match (
                &policy.host_unix_stream_path,
                policy.host_unix_stream_target_fd,
            ) {
                (Some(path), Some(target_fd)) => selected_handles.push(connect_host_unix_stream(
                    path,
                    target_fd,
                    selected_storage_floor,
                    host_unix_expected_peer,
                )?),
                (None, None) if host_unix_expected_peer.is_none() => {}
                (None, None) => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "host-UNIX peer credentials require a brokered endpoint",
                    )));
                }
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "ipc.host_unix_stream_path and ipc.host_unix_stream_target_fd must be specified together",
                    )));
                }
            }
            match (
                policy.host_loopback_tcp_listen_port,
                policy.host_loopback_tcp_listen_target_fd,
            ) {
                (Some(port), Some(target_fd)) => selected_handles.push(listen_host_loopback_tcp(
                    port,
                    target_fd,
                    selected_storage_floor,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "network.host_loopback_tcp_listen_port and network.host_loopback_tcp_listen_target_fd must be specified together",
                    )));
                }
            }
            let cancellation_fd = cancellation
                .map(|token| {
                    let pinned = unsafe {
                        libc::fcntl(
                            token.raw_fd(),
                            libc::F_DUPFD_CLOEXEC,
                            selected_storage_floor,
                        )
                    };
                    if pinned == -1 {
                        Err(SandboxError::SetupFailed(format!(
                            "cannot pin external cancellation eventfd before fork: {}",
                            io::Error::last_os_error()
                        )))
                    } else {
                        Ok(OwnedFd(pinned))
                    }
                })
                .transpose()?;

            let mut volumes = Vec::with_capacity(2);
            match (
                &policy.readonly_volume_source,
                &policy.readonly_volume_target,
            ) {
                (Some(source), Some(target)) => volumes.push(prepare_volume(
                    root_fd.raw(),
                    source,
                    target,
                    "volume.readonly_source",
                    "read-only volume source",
                    "read-only volume target",
                    VolumeAccess::ReadOnly,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "volume.readonly_source and volume.readonly_target must be specified together",
                    )));
                }
            }
            match (
                &policy.writable_volume_source,
                &policy.writable_volume_target,
            ) {
                (Some(source), Some(target)) => volumes.push(prepare_volume(
                    root_fd.raw(),
                    source,
                    target,
                    "volume.writable_source",
                    "writable volume source",
                    "writable volume target",
                    VolumeAccess::Writable,
                )?),
                (None, None) => {}
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "volume.writable_source and volume.writable_target must be specified together",
                    )));
                }
            }

            let cwd_relative = sandbox_relative(&policy.working_dir)?;
            let (scratch_relative, scratch_options) = match (
                &policy.scratch_dir,
                policy.scratch_bytes,
            ) {
                (Some(path), Some(bytes)) => {
                    let scratch_check = open_beneath_root(
                        root_fd.raw(),
                        path,
                        (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
                        "scratch directory",
                    )?;
                    drop(scratch_check);
                    let relative = sandbox_relative(path)?;
                    let options = cstring_bytes(
                        "scratch mount options",
                        format!("size={bytes},mode=0700").as_bytes(),
                    )?;
                    (Some(relative), Some(options))
                }
                (None, None) => (None, None),
                _ => {
                    return Err(SandboxError::InvalidPolicy(PolicyError::new(
                        "filesystem.scratch and filesystem.scratch_bytes must be specified together",
                    )));
                }
            };
            let stdout_redirect_relative = policy
                .stdout_redirect
                .as_ref()
                .map(|path| sandbox_relative(path))
                .transpose()?;

            let argv0 = cstring_bytes("executable", policy.executable.as_os_str().as_bytes())?;
            let mut args = Vec::with_capacity(policy.args.len());
            for arg in &policy.args {
                args.push(cstring_bytes("argument", arg.as_bytes())?);
            }

            let mut environment = Vec::with_capacity(policy.environment.len());
            for (key, value) in &policy.environment {
                let entry = format!("{key}={value}");
                environment.push(cstring_bytes("environment entry", entry.as_bytes())?);
            }

            let mut argv = Vec::with_capacity(args.len() + 2);
            argv.push(argv0.as_ptr());
            argv.extend(args.iter().map(|arg| arg.as_ptr()));
            argv.push(ptr::null());

            let mut envp = Vec::with_capacity(environment.len() + 1);
            envp.extend(environment.iter().map(|entry| entry.as_ptr()));
            envp.push(ptr::null());

            let uid_map = format!("0 {} 1\n", unsafe { libc::geteuid() }).into_bytes();
            let gid_map = format!("0 {} 1\n", unsafe { libc::getegid() }).into_bytes();
            let hostname = policy.hostname.as_bytes().to_vec();

            Ok(Self {
                root_fd,
                root_path,
                executable_fd,
                selected_handles,
                selected_storage_floor,
                landlock: PreparedLandlock {
                    read_execute: landlock_read_execute,
                    file_mutate: landlock_file_mutate,
                    path_topology_mutate: landlock_path_topology_mutate,
                    device_ioctl: landlock_device_ioctl,
                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),
                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),
                    scope_abstract_unix_socket: policy.landlock_scope_abstract_unix_socket,
                    scope_signal: policy.landlock_scope_signal,
                },
                cancellation_fd,
                volumes,
                cwd_relative,
                scratch_relative,
                scratch_options,
                stdout_redirect_relative,
                _argv0: argv0,
                _args: args,
                _environment: environment,
                argv,
                envp,
                uid_map,
                gid_map,
                hostname,
                loopback_enabled: policy.loopback_enabled,
            })
        }
    }

    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    #[derive(Clone, Copy)]
    struct ChildControl {
        launch_error: *mut LaunchErrorRecord,
        target_lifecycle: *mut TargetLifecycleRecord,
        capture_read_fd: RawFd,
        capture_write_fd: RawFd,
        output_limit_fd: RawFd,
        wall_clock_milliseconds: u64,
    }

    fn create_output_limit_eventfd() -> Result<OwnedFd, SandboxError> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC) };
        if fd == -1 {
            let error = io::Error::last_os_error();
            return if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
            ) {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "stdout output-limit supervision requires eventfd support: {error}"
                )))
            } else {
                Err(SandboxError::SetupFailed(format!(
                    "cannot create stdout output-limit eventfd: {error}"
                )))
            };
        }
        move_parent_fd_above_stdio(OwnedFd(fd), "stdout output-limit eventfd")
    }

    fn signal_output_limit(fd: RawFd) -> Result<(), SandboxError> {
        if fd < FIRST_NON_STDIO_FD as RawFd {
            return Err(SandboxError::SetupFailed(
                "stdout output-limit eventfd is unavailable".to_owned(),
            ));
        }
        let value = 1u64;
        loop {
            let written = unsafe {
                libc::write(
                    fd,
                    (&value as *const u64).cast::<libc::c_void>(),
                    std::mem::size_of::<u64>(),
                )
            };
            if written == std::mem::size_of::<u64>() as isize {
                return Ok(());
            }
            if written == -1 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!(
                    "cannot signal stdout output-limit eventfd: {error}"
                )));
            }
            return Err(SandboxError::SetupFailed(
                "stdout output-limit eventfd accepted a short write".to_owned(),
            ));
        }
    }

    pub(crate) fn run_report(
        policy: &SandboxPolicy,
        cancellation: Option<&CancellationToken>,
    ) -> Result<RunReport, SandboxError> {
        ensure_fd_sanitization_supported()?;
        ensure_supervision_support(
            policy.wall_clock_milliseconds,
            cancellation.is_some(),
            policy.stdout_total_bytes.is_some(),
        )?;
        ensure_landlock_supported(policy)?;
        let prepared = PreparedLaunch::new(policy, cancellation)?;
        let seccomp = compile_seccomp(policy)?;
        let launch_state = SharedLaunchState::new()?;
        let lifecycle = SharedTargetLifecycle::new().map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot allocate shared target lifecycle state: {err}"
            ))
        })?;
        let output_limit_event = policy
            .stdout_total_bytes
            .map(|_| create_output_limit_eventfd())
            .transpose()?;
        let output_limit_fd = output_limit_event.as_ref().map_or(-1, |fd| fd.raw());
        let capture = if policy.stdio.stdout == StdioMode::Capture {
            Some(CapturePipe::new(policy.stdout_capture_bytes.ok_or_else(
                || {
                    SandboxError::InvalidPolicy(PolicyError::new(
                        "stdio.stdout = capture requires stdio.stdout_capture_bytes",
                    ))
                },
            )?)?)
        } else {
            None
        };
        let capture_read_fd = capture.as_ref().map_or(-1, |pipe| pipe.read_fd.raw());
        let capture_write_fd = capture.as_ref().map_or(-1, |pipe| pipe.write_fd.raw());
        let child_control = ChildControl {
            launch_error: launch_state.record,
            target_lifecycle: lifecycle.raw(),
            capture_read_fd,
            capture_write_fd,
            output_limit_fd,
            wall_clock_milliseconds: policy.wall_clock_milliseconds.unwrap_or(0),
        };

        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "fork failed closed: {}",
                io::Error::last_os_error()
            )));
        }

        if pid == 0 {
            unsafe {
                child_exec(
                    &prepared,
                    policy.stdio,
                    policy.limits,
                    &seccomp,
                    child_control,
                )
            }
        }
        // The host parent does not retain launcher-owned duplicates of selected
        // object capabilities while the target runs. Caller-owned source FDs
        // remain under caller control.
        drop(prepared);

        let capture_result = capture.map(|pipe| {
            let CapturePipe {
                read_fd,
                write_fd,
                limit,
            } = pipe;
            drop(write_fd);
            let result = read_capture(
                read_fd.raw(),
                limit,
                policy.stdout_total_bytes,
                output_limit_fd,
            );
            drop(read_fd);
            result
        });

        let bootstrap_status = wait_for_child(pid)?;
        let launch_error = launch_state.snapshot();
        if launch_error.phase != 0 {
            return decode_launch_error(launch_error).map(|outcome| RunReport {
                outcome,
                stdout: None,
                reaped_descendants: 0,
                process_tree_usage: ProcessTreeUsage::default(),
            });
        }

        let lifecycle_record = lifecycle.snapshot();
        if lifecycle_record.ready != 1 {
            return Err(SandboxError::SetupFailed(format!(
                "PID namespace lifecycle did not publish target status; bootstrap wait status 0x{bootstrap_status:x}"
            )));
        }

        let (stdout, output_limit_observed) = match capture_result {
            Some(result) => {
                let (captured, exceeded) = result?;
                (Some(captured), exceeded)
            }
            None => (None, false),
        };
        let control_flags = lifecycle_record.timed_out
            + lifecycle_record.cancelled
            + lifecycle_record.output_limit_exceeded;
        if control_flags > 1 {
            return Err(SandboxError::SetupFailed(format!(
                "PID namespace lifecycle published conflicting termination flags timed_out={} cancelled={} output_limit_exceeded={}",
                lifecycle_record.timed_out,
                lifecycle_record.cancelled,
                lifecycle_record.output_limit_exceeded
            )));
        }
        let outcome = if output_limit_observed || lifecycle_record.output_limit_exceeded == 1 {
            ChildOutcome::OutputLimitExceeded
        } else {
            match (lifecycle_record.timed_out, lifecycle_record.cancelled) {
                (0, 0) => decode_wait_status(lifecycle_record.status)?,
                (1, 0) => ChildOutcome::TimedOut,
                (0, 1) => ChildOutcome::Cancelled,
                (timed_out, cancelled) => {
                    return Err(SandboxError::SetupFailed(format!(
                        "PID namespace lifecycle published invalid termination flags timed_out={timed_out} cancelled={cancelled}"
                    )));
                }
            }
        };
        Ok(RunReport {
            outcome,
            stdout,
            reaped_descendants: lifecycle_record.reaped_descendants,
            process_tree_usage: ProcessTreeUsage {
                user_cpu_micros: lifecycle_record.user_cpu_micros,
                system_cpu_micros: lifecycle_record.system_cpu_micros,
                max_child_rss_kib: lifecycle_record.max_child_rss_kib,
            },
        })
    }

    fn read_capture(
        fd: RawFd,
        retain_limit: usize,
        total_limit: Option<u64>,
        output_limit_fd: RawFd,
    ) -> Result<(CapturedOutput, bool), SandboxError> {
        let mut bytes = Vec::with_capacity(retain_limit.min(8192));
        let mut truncated = false;
        let mut observed = 0u64;
        let mut buffer = [0u8; 8192];

        loop {
            let read =
                unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<libc::c_void>(), buffer.len()) };
            if read == 0 {
                break;
            }
            if read == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!(
                    "stdout capture read failed: {err}"
                )));
            }

            let read = read as usize;
            observed = observed.saturating_add(read as u64);
            let remaining = retain_limit.saturating_sub(bytes.len());
            let retained = remaining.min(read);
            bytes.extend_from_slice(&buffer[..retained]);
            if retained < read {
                truncated = true;
            }

            if total_limit.is_some_and(|limit| observed > limit) {
                signal_output_limit(output_limit_fd)?;
                return Ok((CapturedOutput { bytes, truncated }, true));
            }
        }

        Ok((CapturedOutput { bytes, truncated }, false))
    }

    fn cstring_bytes(label: &str, bytes: &[u8]) -> Result<CString, SandboxError> {
        CString::new(bytes).map_err(|_| {
            SandboxError::InvalidPolicy(PolicyError::new(format!(
                "{label} must not contain NUL bytes"
            )))
        })
    }

    fn sandbox_relative(path: &Path) -> Result<CString, SandboxError> {
        let relative = path.strip_prefix(Path::new("/")).map_err(|_| {
            SandboxError::InvalidPolicy(PolicyError::new("sandbox paths must be absolute"))
        })?;
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative.to_path_buf()
        };
        cstring_bytes("sandbox path", relative.as_os_str().as_bytes())
    }

    fn open_root(path: &Path) -> Result<OwnedFd, SandboxError> {
        let path = cstring_bytes("filesystem.root", path.as_os_str().as_bytes())?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        match openat2(libc::AT_FDCWD, &path, &how) {
            Ok(fd) => Ok(OwnedFd(fd)),
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) => {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "filesystem confinement requires Linux openat2 support: {err}"
                )))
            }
            Err(err) => Err(SandboxError::SetupFailed(format!(
                "cannot pin filesystem.root without symlink traversal: {err}"
            ))),
        }
    }

    fn open_host_directory(path: &Path, label: &str) -> Result<OwnedFd, SandboxError> {
        let path = cstring_bytes(label, path.as_os_str().as_bytes())?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        match openat2(libc::AT_FDCWD, &path, &how) {
            Ok(fd) => Ok(OwnedFd(fd)),
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOSYS | libc::EINVAL)) => {
                Err(SandboxError::UnsupportedPlatform(format!(
                    "{label} requires Linux openat2 support: {err}"
                )))
            }
            Err(err) => Err(SandboxError::SetupFailed(format!(
                "cannot pin {label} without symlink traversal: {err}"
            ))),
        }
    }

    fn open_beneath_root(
        root_fd: RawFd,
        path: &Path,
        flags: u64,
        label: &str,
    ) -> Result<OwnedFd, SandboxError> {
        let path = sandbox_relative(path)?;
        let how = OpenHow {
            flags,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        openat2(root_fd, &path, &how).map(OwnedFd).map_err(|err| {
            SandboxError::SetupFailed(format!(
                "cannot pin sandbox {label} beneath filesystem.root: {err}"
            ))
        })
    }

    fn openat2(dirfd: RawFd, path: &CString, how: &OpenHow) -> io::Result<RawFd> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as RawFd)
        }
    }

    fn validate_executable_fd(fd: RawFd, path: &Path) -> Result<(), SandboxError> {
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(fd, &mut stat) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot inspect pinned executable {}: {}",
                path.display(),
                io::Error::last_os_error()
            )));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SandboxError::SetupFailed(format!(
                "sandbox executable is not a regular file: {}",
                path.display()
            )));
        }
        if stat.st_mode & 0o111 == 0 {
            return Err(SandboxError::SetupFailed(format!(
                "sandbox executable has no execute bit: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn ensure_fd_sanitization_supported() -> Result<(), SandboxError> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                u32::MAX,
                u32::MAX,
                CLOSE_RANGE_CLOEXEC,
            )
        };
        if result == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => Err(SandboxError::UnsupportedPlatform(
                format!(
                    "inherited-FD sanitization requires close_range(CLOSE_RANGE_CLOEXEC) support: {err}"
                ),
            )),
            _ => Err(SandboxError::SetupFailed(format!(
                "cannot verify inherited-FD sanitization support: {err}"
            ))),
        }
    }

    fn ensure_supervision_support(
        deadline: Option<u64>,
        cancellable: bool,
        output_limited: bool,
    ) -> Result<(), SandboxError> {
        if deadline.is_none() && !cancellable && !output_limited {
            return Ok(());
        }

        let purpose = if output_limited {
            "stdout output-limit supervision"
        } else {
            match (deadline.is_some(), cancellable) {
                (true, true) => "deadline/cancellation supervision",
                (true, false) => "wall-clock deadline",
                (false, true) => "external cancellation",
                (false, false) => unreachable!(),
            }
        };
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
        if pidfd == -1 {
            return Err(supervision_support_error(
                purpose,
                "pidfd_open",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(pidfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close {purpose} pidfd probe: {}",
                io::Error::last_os_error()
            )));
        }

        if deadline.is_none() {
            return Ok(());
        }
        let timerfd = unsafe {
            libc::syscall(
                libc::SYS_timerfd_create,
                libc::CLOCK_MONOTONIC,
                libc::TFD_CLOEXEC,
            )
        };
        if timerfd == -1 {
            return Err(supervision_support_error(
                purpose,
                "timerfd_create(CLOCK_MONOTONIC)",
                io::Error::last_os_error(),
            ));
        }
        if unsafe { libc::close(timerfd as RawFd) } == -1 {
            return Err(SandboxError::SetupFailed(format!(
                "cannot close {purpose} timerfd probe: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn supervision_support_error(purpose: &str, mechanism: &str, error: io::Error) -> SandboxError {
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EINVAL | libc::EPERM | libc::EACCES)
        ) {
            SandboxError::UnsupportedPlatform(format!("{purpose} requires {mechanism}: {error}"))
        } else {
            SandboxError::SetupFailed(format!(
                "cannot verify {purpose} mechanism {mechanism}: {error}"
            ))
        }
    }

    fn compile_seccomp(policy: &SandboxPolicy) -> Result<CompiledSeccomp, SandboxError> {
        let error_exit_syscall = if policy.seccomp.allowed_syscalls.contains("exit") {
            libc::SYS_exit
        } else if policy.seccomp.allowed_syscalls.contains("exit_group") {
            libc::SYS_exit_group
        } else {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include exit or exit_group so launch failures can terminate after filter installation",
            )));
        };

        if !policy.seccomp.allowed_syscalls.contains("execveat") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execveat so the pinned child can start",
            )));
        }

        let mut syscalls = Vec::with_capacity(policy.seccomp.allowed_syscalls.len());
        for name in &policy.seccomp.allowed_syscalls {
            let number = syscall_number(name).ok_or_else(|| {
                SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "unsupported Linux x86_64 syscall name: {name}"
                )))
            })?;
            syscalls.push((number as u32, name.as_str()));
        }
        syscalls.sort_unstable_by_key(|(number, _)| *number);
        for pair in syscalls.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "multiple syscall names resolve to Linux x86_64 number {}",
                    pair[0].0
                ))));
            }
        }

        let mut filter = vec![
            stmt(BPF_LD_W_ABS, 4),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, 0),
        ];

        for (number, name) in syscalls {
            let mut checks = Vec::new();
            if let Some(rules) = policy.seccomp.argument_rules.get(name) {
                for (argument_index, rule) in rules {
                    append_seccomp_argument_checks(
                        &mut checks,
                        *argument_index,
                        rule.mask,
                        rule.value,
                    );
                }
            }
            if let Some(rules) = policy.seccomp.argument_range_rules.get(name) {
                for (argument_index, rule) in rules {
                    append_seccomp_argument_range_checks(
                        &mut checks,
                        *argument_index,
                        rule.minimum,
                        rule.maximum,
                    );
                }
            }
            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            if checks.len() > u8::MAX as usize {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "seccomp argument-check block for {name} is too large"
                ))));
            }
            filter.push(jump(BPF_JMP_JEQ_K, number, 0, checks.len() as u8));
            filter.extend(checks);
        }
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));

        if filter.len() > u16::MAX as usize {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp program is too large",
            )));
        }

        Ok(CompiledSeccomp {
            filter,
            error_exit_syscall,
        })
    }

    fn append_seccomp_argument_checks(
        filter: &mut Vec<libc::sock_filter>,
        argument_index: u8,
        mask: u64,
        value: u64,
    ) {
        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;
        append_seccomp_argument_word_check(filter, argument_offset, mask as u32, value as u32);
        append_seccomp_argument_word_check(
            filter,
            argument_offset + 4,
            (mask >> 32) as u32,
            (value >> 32) as u32,
        );
    }

    fn append_seccomp_argument_word_check(
        filter: &mut Vec<libc::sock_filter>,
        offset: u32,
        mask: u32,
        value: u32,
    ) {
        if mask == 0 {
            return;
        }
        filter.push(stmt(BPF_LD_W_ABS, offset));
        if mask != u32::MAX {
            filter.push(stmt(BPF_ALU_AND_K, mask));
        }
        filter.push(jump(BPF_JMP_JEQ_K, value, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }

    fn append_seccomp_argument_range_checks(
        filter: &mut Vec<libc::sock_filter>,
        argument_index: u8,
        minimum: u64,
        maximum: u64,
    ) {
        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;
        let minimum_low = minimum as u32;
        let minimum_high = (minimum >> 32) as u32;
        let maximum_low = maximum as u32;
        let maximum_high = (maximum >> 32) as u32;

        // Unsigned lower bound. A high word above minimum skips the low-word
        // comparison; equality requires low >= minimum_low.
        filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));
        filter.push(jump(BPF_JMP_JGE_K, minimum_high, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
        filter.push(jump(BPF_JMP_JEQ_K, minimum_high, 0, 3));
        filter.push(stmt(BPF_LD_W_ABS, argument_offset));
        filter.push(jump(BPF_JMP_JGE_K, minimum_low, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));

        // Unsigned upper bound. A high word below maximum skips the low-word
        // comparison; equality requires low <= maximum_low.
        filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));
        filter.push(jump(BPF_JMP_JGT_K, maximum_high, 0, 1));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
        filter.push(jump(BPF_JMP_JEQ_K, maximum_high, 0, 3));
        filter.push(stmt(BPF_LD_W_ABS, argument_offset));
        filter.push(jump(BPF_JMP_JGT_K, maximum_low, 0, 1));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }

    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {
        if policy.landlock_read_execute.is_empty()
            && policy.landlock_file_mutate.is_empty()
            && policy.landlock_path_topology_mutate.is_empty()
            && policy.landlock_device_ioctl.is_empty()
            && policy.landlock_tcp_bind_ports.is_empty()
            && policy.landlock_tcp_connect_ports.is_empty()
            && !policy.landlock_scope_abstract_unix_socket
            && !policy.landlock_scope_signal
        {
            return Ok(());
        }
        let abi = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if abi >= 1 {
            if !policy.landlock_file_mutate.is_empty() && abi < 3 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock file-mutation enforcement requires ABI 3 for TRUNCATE control; kernel reports ABI {abi}"
                )));
            }
            if !policy.landlock_device_ioctl.is_empty() && abi < 5 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock device ioctl enforcement requires ABI 5; kernel reports ABI {abi}"
                )));
            }
            if (!policy.landlock_tcp_bind_ports.is_empty()
                || !policy.landlock_tcp_connect_ports.is_empty())
                && abi < 4
            {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock TCP port enforcement requires ABI 4; kernel reports ABI {abi}"
                )));
            }
            if policy.landlock_scope_abstract_unix_socket && abi < 6 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock abstract UNIX socket scoping requires ABI 6; kernel reports ABI {abi}"
                )));
            }
            if policy.landlock_scope_signal && abi < 6 {
                return Err(SandboxError::UnsupportedPlatform(format!(
                    "Landlock signal scoping requires ABI 6; kernel reports ABI {abi}"
                )));
            }
            return Ok(());
        }
        if abi != -1 {
            return Err(SandboxError::SetupFailed(format!(
                "Landlock ABI query returned invalid version {abi}"
            )));
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::ENOSYS | libc::EOPNOTSUPP) => Err(SandboxError::UnsupportedPlatform(
                format!("Landlock enforcement is unavailable: {error}"),
            )),
            _ => Err(SandboxError::SetupFailed(format!(
                "cannot query Landlock ABI: {error}"
            ))),
        }
    }

    unsafe fn prepare_landlock_ruleset_or_fail(
        landlock: &PreparedLandlock,
        root_tree_fd: RawFd,
        storage_floor: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        if landlock.read_execute.is_empty()
            && landlock.file_mutate.is_empty()
            && landlock.path_topology_mutate.is_empty()
            && landlock.device_ioctl.is_empty()
            && landlock.tcp_bind_ports.is_empty()
            && landlock.tcp_connect_ports.is_empty()
            && !landlock.scope_abstract_unix_socket
            && !landlock.scope_signal
        {
            return -1;
        }

        let mut handled_access_fs = 0;
        if !landlock.read_execute.is_empty() {
            handled_access_fs |= LANDLOCK_READ_EXECUTE_RIGHTS;
        }
        if !landlock.file_mutate.is_empty() {
            handled_access_fs |= LANDLOCK_FILE_MUTATE_RIGHTS;
        }
        if !landlock.path_topology_mutate.is_empty() {
            handled_access_fs |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;
        }
        if !landlock.device_ioctl.is_empty() {
            handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
        }
        let mut handled_access_net = 0;
        if !landlock.tcp_bind_ports.is_empty() {
            handled_access_net |= LANDLOCK_ACCESS_NET_BIND_TCP;
        }
        if !landlock.tcp_connect_ports.is_empty() {
            handled_access_net |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
        }
        let mut scoped = 0;
        if landlock.scope_abstract_unix_socket {
            scoped |= LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET;
        }
        if landlock.scope_signal {
            scoped |= LANDLOCK_SCOPE_SIGNAL;
        }
        let ruleset = LandlockRulesetAttr {
            handled_access_fs,
            handled_access_net,
            scoped,
        };
        // Preserve old-ABI struct sizing: handled_access_net was appended in
        // ABI 4 and scoped in ABI 6. Only expose fields the active policy uses.
        let ruleset_size = if scoped != 0 {
            std::mem::size_of::<LandlockRulesetAttr>()
        } else if handled_access_net != 0 {
            2 * std::mem::size_of::<u64>()
        } else {
            std::mem::size_of::<u64>()
        };
        let raw_ruleset_fd = libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &ruleset as *const LandlockRulesetAttr,
            ruleset_size,
            0u32,
        );
        if raw_ruleset_fd == -1 {
            child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);
        }
        let mut ruleset_fd = raw_ruleset_fd as RawFd;
        if ruleset_fd < storage_floor {
            let moved = libc::fcntl(ruleset_fd, libc::F_DUPFD_CLOEXEC, storage_floor);
            if moved == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);
            }
            if libc::close(ruleset_fd) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_RULESET, error_exit_syscall);
            }
            ruleset_fd = moved;
        }

        let path_how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        for path in &landlock.read_execute {
            let path_fd = libc::syscall(
                libc::SYS_openat2,
                root_tree_fd,
                path.as_ptr(),
                &path_how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            );
            if path_fd == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
            let path_fd = path_fd as RawFd;
            let mut stat = std::mem::zeroed::<libc::stat>();
            if libc::fstat(path_fd, &mut stat) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
            let kind = stat.st_mode & libc::S_IFMT;
            let mut allowed_access = if kind == libc::S_IFDIR {
                LANDLOCK_READ_EXECUTE_RIGHTS
            } else if kind == libc::S_IFREG {
                LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE
            } else {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall)
            };
            let also_mutable = landlock
                .file_mutate
                .iter()
                .any(|candidate| candidate.as_bytes() == path.as_bytes());
            if also_mutable {
                if kind != libc::S_IFDIR {
                    child_fail_errno(
                        launch_error,
                        PHASE_LANDLOCK_PATH,
                        libc::ENOTDIR,
                        error_exit_syscall,
                    );
                }
                allowed_access |= LANDLOCK_FILE_MUTATE_RIGHTS;
                if landlock
                    .path_topology_mutate
                    .iter()
                    .any(|candidate| candidate.as_bytes() == path.as_bytes())
                {
                    allowed_access |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;
                }
            }
            let rule = LandlockPathBeneathAttr {
                allowed_access,
                parent_fd: path_fd,
                reserved: 0,
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);
            }
            if libc::close(path_fd) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
        }

        let mutation_path_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        for path in &landlock.file_mutate {
            if landlock
                .read_execute
                .iter()
                .any(|candidate| candidate.as_bytes() == path.as_bytes())
            {
                continue;
            }
            let path_fd = libc::syscall(
                libc::SYS_openat2,
                root_tree_fd,
                path.as_ptr(),
                &mutation_path_how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            );
            if path_fd == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
            let path_fd = path_fd as RawFd;
            let mut allowed_access = LANDLOCK_FILE_MUTATE_RIGHTS;
            if landlock
                .path_topology_mutate
                .iter()
                .any(|candidate| candidate.as_bytes() == path.as_bytes())
            {
                allowed_access |= LANDLOCK_PATH_TOPOLOGY_MUTATE_RIGHTS;
            }
            let rule = LandlockPathBeneathAttr {
                allowed_access,
                parent_fd: path_fd,
                reserved: 0,
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);
            }
            if libc::close(path_fd) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
        }
        let device_path_how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        for path in &landlock.device_ioctl {
            let path_fd = libc::syscall(
                libc::SYS_openat2,
                root_tree_fd,
                path.as_ptr(),
                &device_path_how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            );
            if path_fd == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
            let path_fd = path_fd as RawFd;
            let mut stat = std::mem::zeroed::<libc::stat>();
            if libc::fstat(path_fd, &mut stat) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
            let kind = stat.st_mode & libc::S_IFMT;
            if kind != libc::S_IFCHR && kind != libc::S_IFBLK {
                child_fail_errno(
                    launch_error,
                    PHASE_LANDLOCK_PATH,
                    libc::ENODEV,
                    error_exit_syscall,
                );
            }
            let rule = LandlockPathBeneathAttr {
                allowed_access: LANDLOCK_ACCESS_FS_IOCTL_DEV,
                parent_fd: path_fd,
                reserved: 0,
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_RULE, error_exit_syscall);
            }
            if libc::close(path_fd) == -1 {
                child_fail(launch_error, PHASE_LANDLOCK_PATH, error_exit_syscall);
            }
        }
        for &port in &landlock.tcp_bind_ports {
            let mut allowed_access = LANDLOCK_ACCESS_NET_BIND_TCP;
            if landlock.tcp_connect_ports.contains(&port) {
                allowed_access |= LANDLOCK_ACCESS_NET_CONNECT_TCP;
            }
            let rule = LandlockNetPortAttr {
                allowed_access,
                port: u64::from(port),
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_NET_RULE, error_exit_syscall);
            }
        }
        for &port in &landlock.tcp_connect_ports {
            if landlock.tcp_bind_ports.contains(&port) {
                continue;
            }
            let rule = LandlockNetPortAttr {
                allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port: u64::from(port),
            };
            if libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_LANDLOCK_NET_RULE, error_exit_syscall);
            }
        }
        ruleset_fd
    }

    unsafe fn restrict_landlock_or_fail(
        ruleset_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        if ruleset_fd < 0 {
            return;
        }
        if libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) == -1 {
            child_fail(launch_error, PHASE_LANDLOCK_RESTRICT, error_exit_syscall);
        }
        if libc::close(ruleset_fd) == -1 {
            child_fail(launch_error, PHASE_LANDLOCK_RESTRICT, error_exit_syscall);
        }
    }

    unsafe fn child_exec(
        prepared: &PreparedLaunch,
        stdio: StdioPolicy,
        limits: ResourceLimits,
        seccomp: &CompiledSeccomp,
        control: ChildControl,
    ) -> ! {
        let ChildControl {
            launch_error,
            target_lifecycle,
            capture_read_fd,
            capture_write_fd,
            output_limit_fd,
            wall_clock_milliseconds,
        } = control;
        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {
            child_fail(
                launch_error,
                PHASE_STDOUT_CAPTURE,
                seccomp.error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_unshare,
            libc::CLONE_NEWUSER
                | libc::CLONE_NEWNS
                | libc::CLONE_NEWPID
                | libc::CLONE_NEWNET
                | libc::CLONE_NEWIPC
                | libc::CLONE_NEWUTS,
        ) == -1
        {
            child_fail(launch_error, PHASE_NAMESPACE, seccomp.error_exit_syscall);
        }

        write_proc_file_or_fail(
            b"/proc/self/setgroups\0",
            b"deny\n",
            launch_error,
            PHASE_SETGROUPS,
            seccomp.error_exit_syscall,
        );
        write_proc_file_or_fail(
            b"/proc/self/uid_map\0",
            &prepared.uid_map,
            launch_error,
            PHASE_UID_MAP,
            seccomp.error_exit_syscall,
        );
        write_proc_file_or_fail(
            b"/proc/self/gid_map\0",
            &prepared.gid_map,
            launch_error,
            PHASE_GID_MAP,
            seccomp.error_exit_syscall,
        );

        if libc::syscall(
            libc::SYS_sethostname,
            prepared.hostname.as_ptr(),
            prepared.hostname.len(),
        ) == -1
        {
            child_fail(launch_error, PHASE_HOSTNAME, seccomp.error_exit_syscall);
        }

        if prepared.loopback_enabled {
            enable_loopback_or_fail(launch_error, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_mount,
            ptr::null::<libc::c_char>(),
            b"/\0".as_ptr().cast::<libc::c_char>(),
            ptr::null::<libc::c_char>(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            ptr::null::<libc::c_void>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_MOUNT_PRIVATE,
                seccomp.error_exit_syscall,
            );
        }

        let current_root_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let current_root_fd = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            prepared.root_path.as_ptr(),
            &current_root_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if current_root_fd == -1 {
            child_fail(
                launch_error,
                PHASE_ROOT_REVALIDATE,
                seccomp.error_exit_syscall,
            );
        }
        let current_root_fd = current_root_fd as RawFd;
        revalidate_root_identity_or_fail(
            prepared.root_fd.raw(),
            current_root_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );

        let root_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_root_fd,
            b".\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if root_tree_fd == -1 {
            child_fail(launch_error, PHASE_ROOT_CLONE, seccomp.error_exit_syscall);
        }
        let root_tree_fd = root_tree_fd as RawFd;

        let mount_attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if libc::syscall(
            libc::SYS_mount_setattr,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            AT_EMPTY_PATH | AT_RECURSIVE,
            &mount_attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_ROOT_READONLY,
                seccomp.error_exit_syscall,
            );
        }

        if libc::syscall(
            libc::SYS_move_mount,
            root_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            current_root_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_ROOT_ATTACH, seccomp.error_exit_syscall);
        }

        if libc::syscall(libc::SYS_fchdir, root_tree_fd) == -1 {
            child_fail(launch_error, PHASE_ROOT_FCHDIR, seccomp.error_exit_syscall);
        }

        for volume in &prepared.volumes {
            install_volume_or_fail(
                volume,
                root_tree_fd,
                launch_error,
                seccomp.error_exit_syscall,
            );
        }

        if let (Some(scratch), Some(options)) =
            (&prepared.scratch_relative, &prepared.scratch_options)
        {
            if libc::syscall(
                libc::SYS_mount,
                b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
                scratch.as_ptr(),
                b"tmpfs\0".as_ptr().cast::<libc::c_char>(),
                (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
                options.as_ptr(),
            ) == -1
            {
                child_fail(
                    launch_error,
                    PHASE_SCRATCH_MOUNT,
                    seccomp.error_exit_syscall,
                );
            }
        }

        let stdout_redirect_fd = if let Some(path) = &prepared.stdout_redirect_relative {
            open_stdout_redirect_or_fail(
                root_tree_fd,
                path,
                launch_error,
                seccomp.error_exit_syscall,
            )
        } else {
            -1
        };

        let cwd_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let cwd_fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            prepared.cwd_relative.as_ptr(),
            &cwd_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if cwd_fd == -1 {
            child_fail(launch_error, PHASE_CWD_PIN, seccomp.error_exit_syscall);
        }
        let cwd_fd = cwd_fd as RawFd;

        if libc::syscall(libc::SYS_chroot, b".\0".as_ptr().cast::<libc::c_char>()) == -1 {
            child_fail(launch_error, PHASE_CHROOT, seccomp.error_exit_syscall);
        }
        if libc::syscall(libc::SYS_fchdir, cwd_fd) == -1 {
            child_fail(launch_error, PHASE_CWD_FCHDIR, seccomp.error_exit_syscall);
        }

        if libc::syscall(
            libc::SYS_close_range,
            FIRST_NON_STDIO_FD,
            u32::MAX,
            CLOSE_RANGE_CLOEXEC,
        ) == -1
        {
            child_fail(launch_error, PHASE_FD_SANITIZE, seccomp.error_exit_syscall);
        }

        pid_lifecycle::become_pid_namespace_init_or_exit(
            launch_error,
            PHASE_PID_INIT_FORK,
            PHASE_PID_INIT_WAIT,
            PHASE_FD_SANITIZE,
        );
        pid_lifecycle::become_direct_target_or_reap(
            target_lifecycle,
            launch_error,
            wall_clock_milliseconds,
            prepared.cancellation_fd.as_ref().map_or(-1, |fd| fd.raw()),
            output_limit_fd,
            TargetSupervisionPhases {
                fork: PHASE_TARGET_FORK,
                kill: PHASE_PROCESS_TREE_KILL,
                reap: PHASE_PROCESS_TREE_REAP,
                close: PHASE_FD_SANITIZE,
                pidfd: PHASE_DEADLINE_PIDFD,
                timerfd: PHASE_DEADLINE_TIMERFD,
                timer_arm: PHASE_DEADLINE_TIMER_ARM,
                poll: PHASE_DEADLINE_POLL,
                cancellation_pidfd: PHASE_CANCELLATION_PIDFD,
                cancellation_poll: PHASE_CANCELLATION_POLL,
                output_limit_pidfd: PHASE_OUTPUT_LIMIT_PIDFD,
                output_limit_poll: PHASE_OUTPUT_LIMIT_POLL,
                usage: PHASE_PROCESS_TREE_USAGE,
            },
        );

        let landlock_ruleset_fd = prepare_landlock_ruleset_or_fail(
            &prepared.landlock,
            root_tree_fd,
            prepared.selected_storage_floor,
            launch_error,
            seccomp.error_exit_syscall,
        );

        apply_stdio_policy_or_fail(
            stdio,
            stdout_redirect_fd,
            capture_write_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );
        install_selected_handles_or_fail(
            &prepared.selected_handles,
            launch_error,
            seccomp.error_exit_syscall,
        );

        set_limit_or_fail(
            libc::RLIMIT_CPU,
            limits.cpu_seconds,
            launch_error,
            PHASE_RLIMIT_CPU,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_AS,
            limits.address_space_bytes,
            launch_error,
            PHASE_RLIMIT_AS,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_FSIZE,
            limits.file_size_bytes,
            launch_error,
            PHASE_RLIMIT_FSIZE,
            seccomp.error_exit_syscall,
        );
        set_limit_or_fail(
            libc::RLIMIT_NOFILE,
            limits.open_files,
            launch_error,
            PHASE_RLIMIT_NOFILE,
            seccomp.error_exit_syscall,
        );

        drop_capabilities_or_fail(launch_error, seccomp.error_exit_syscall);

        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
            child_fail(launch_error, PHASE_NO_NEW_PRIVS, seccomp.error_exit_syscall);
        }
        restrict_landlock_or_fail(
            landlock_ruleset_fd,
            launch_error,
            seccomp.error_exit_syscall,
        );

        let program = libc::sock_fprog {
            len: seccomp.filter.len() as u16,
            filter: seccomp.filter.as_ptr() as *mut libc::sock_filter,
        };
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
            0,
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_SECCOMP, seccomp.error_exit_syscall);
        }

        libc::syscall(
            libc::SYS_execveat,
            prepared.executable_fd.raw(),
            b"\0".as_ptr().cast::<libc::c_char>(),
            prepared.argv.as_ptr(),
            prepared.envp.as_ptr(),
            EXECVEAT_AT_EMPTY_PATH,
        );
        child_fail(launch_error, PHASE_EXECVEAT, seccomp.error_exit_syscall)
    }

    unsafe fn install_volume_or_fail(
        volume: &PreparedVolume,
        root_tree_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let source_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let current_source_fd = libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            volume.source_path.as_ptr(),
            &source_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if current_source_fd == -1 {
            child_fail(
                launch_error,
                PHASE_VOLUME_SOURCE_REVALIDATE,
                error_exit_syscall,
            );
        }
        let current_source_fd = current_source_fd as RawFd;
        revalidate_fd_identity_or_fail(
            volume.source_fd.raw(),
            current_source_fd,
            PHASE_VOLUME_SOURCE_REVALIDATE,
            launch_error,
            error_exit_syscall,
        );

        let volume_tree_fd = libc::syscall(
            libc::SYS_open_tree,
            current_source_fd,
            b".\0".as_ptr().cast::<libc::c_char>(),
            OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
        );
        if volume_tree_fd == -1 {
            child_fail(launch_error, PHASE_VOLUME_CLONE, error_exit_syscall);
        }
        let volume_tree_fd = volume_tree_fd as RawFd;

        if volume.access == VolumeAccess::ReadOnly {
            let volume_attr = MountAttr {
                attr_set: MOUNT_ATTR_RDONLY,
                attr_clr: 0,
                propagation: 0,
                userns_fd: 0,
            };
            if libc::syscall(
                libc::SYS_mount_setattr,
                volume_tree_fd,
                b"\0".as_ptr().cast::<libc::c_char>(),
                AT_EMPTY_PATH | AT_RECURSIVE,
                &volume_attr as *const MountAttr,
                std::mem::size_of::<MountAttr>(),
            ) == -1
            {
                child_fail(launch_error, PHASE_VOLUME_READONLY, error_exit_syscall);
            }
        }

        let target_how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let target_fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            volume.target_relative.as_ptr(),
            &target_how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if target_fd == -1 {
            child_fail(launch_error, PHASE_VOLUME_TARGET_PIN, error_exit_syscall);
        }
        let target_fd = target_fd as RawFd;

        if libc::syscall(
            libc::SYS_move_mount,
            volume_tree_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            target_fd,
            b"\0".as_ptr().cast::<libc::c_char>(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        ) == -1
        {
            child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);
        }

        for fd in [target_fd, volume_tree_fd, current_source_fd] {
            if libc::close(fd) == -1 {
                child_fail(launch_error, PHASE_VOLUME_ATTACH, error_exit_syscall);
            }
        }
    }

    unsafe fn open_stdout_redirect_or_fail(
        root_tree_fd: RawFd,
        path: &CString,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        let how = OpenHow {
            flags: (libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC) as u64,
            mode: 0o600,
            resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = libc::syscall(
            libc::SYS_openat2,
            root_tree_fd,
            path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        );
        if fd == -1 {
            child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
        }
        move_fd_above_stdio_or_fail(
            fd as RawFd,
            launch_error,
            PHASE_STDIO_REDIRECT,
            error_exit_syscall,
        )
    }

    unsafe fn move_fd_above_stdio_or_fail(
        fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) -> RawFd {
        if fd >= FIRST_NON_STDIO_FD as RawFd {
            return fd;
        }
        let moved = libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FIRST_NON_STDIO_FD as libc::c_int);
        if moved == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        if libc::close(fd) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        moved
    }

    unsafe fn revalidate_root_identity_or_fail(
        pinned_root_fd: RawFd,
        current_root_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        revalidate_fd_identity_or_fail(
            pinned_root_fd,
            current_root_fd,
            PHASE_ROOT_REVALIDATE,
            launch_error,
            error_exit_syscall,
        );
    }

    unsafe fn revalidate_fd_identity_or_fail(
        pinned_fd: RawFd,
        current_fd: RawFd,
        phase: u32,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let mut pinned = std::mem::zeroed::<libc::stat>();
        if libc::fstat(pinned_fd, &mut pinned) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        let mut current = std::mem::zeroed::<libc::stat>();
        if libc::fstat(current_fd, &mut current) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
        if pinned.st_dev != current.st_dev || pinned.st_ino != current.st_ino {
            child_fail_errno(launch_error, phase, libc::ESTALE, error_exit_syscall);
        }
    }

    unsafe fn enable_loopback_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let socket_fd = libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        );
        if socket_fd == -1 {
            child_fail(launch_error, PHASE_NETWORK_LOOPBACK, error_exit_syscall);
        }
        let socket_fd = socket_fd as RawFd;

        let mut request = IfreqFlags {
            name: [0; IFNAMSIZ],
            flags: 0,
            _padding: [0; 22],
        };
        request.name[0] = b'l' as libc::c_char;
        request.name[1] = b'o' as libc::c_char;

        if libc::syscall(
            libc::SYS_ioctl,
            socket_fd,
            SIOCGIFFLAGS,
            &mut request as *mut IfreqFlags,
        ) == -1
        {
            let errno = *libc::__errno_location();
            libc::syscall(libc::SYS_close, socket_fd);
            child_fail_errno(
                launch_error,
                PHASE_NETWORK_LOOPBACK,
                errno,
                error_exit_syscall,
            );
        }
        request.flags |= IFF_UP;
        if libc::syscall(
            libc::SYS_ioctl,
            socket_fd,
            SIOCSIFFLAGS,
            &request as *const IfreqFlags,
        ) == -1
        {
            let errno = *libc::__errno_location();
            libc::syscall(libc::SYS_close, socket_fd);
            child_fail_errno(
                launch_error,
                PHASE_NETWORK_LOOPBACK,
                errno,
                error_exit_syscall,
            );
        }
        if libc::syscall(libc::SYS_close, socket_fd) == -1 {
            child_fail(launch_error, PHASE_NETWORK_LOOPBACK, error_exit_syscall);
        }
    }

    unsafe fn write_proc_file_or_fail(
        path: &'static [u8],
        data: &[u8],
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) {
        let fd = libc::syscall(
            libc::SYS_openat,
            libc::AT_FDCWD,
            path.as_ptr().cast::<libc::c_char>(),
            libc::O_WRONLY | libc::O_CLOEXEC,
            0,
        );
        if fd == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }

        let fd = fd as RawFd;
        let mut offset = 0usize;
        while offset < data.len() {
            let written = libc::syscall(
                libc::SYS_write,
                fd,
                data.as_ptr().add(offset),
                data.len() - offset,
            );
            if written == -1 {
                let errno = *libc::__errno_location();
                libc::syscall(libc::SYS_close, fd);
                child_fail_errno(launch_error, phase, errno, error_exit_syscall);
            }
            if written == 0 {
                libc::syscall(libc::SYS_close, fd);
                child_fail_errno(launch_error, phase, libc::EIO, error_exit_syscall);
            }
            offset += written as usize;
        }
        if libc::syscall(libc::SYS_close, fd) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
    }

    unsafe fn apply_stdio_policy_or_fail(
        stdio: StdioPolicy,
        stdout_redirect_fd: RawFd,
        stdout_capture_fd: RawFd,
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let modes = [stdio.stdin, stdio.stdout, stdio.stderr];
        for (fd, mode) in modes.into_iter().enumerate() {
            let fd = fd as RawFd;
            match mode {
                StdioMode::Closed => {
                    if libc::close(fd) == -1 {
                        let errno = *libc::__errno_location();
                        if errno != libc::EBADF {
                            child_fail_errno(launch_error, PHASE_STDIO, errno, error_exit_syscall);
                        }
                    }
                }
                StdioMode::Inherit => {
                    let mut stat = std::mem::zeroed::<libc::stat>();
                    if libc::fstat(fd, &mut stat) == -1 {
                        child_fail(launch_error, PHASE_STDIO, error_exit_syscall);
                    }
                    if stat.st_mode & libc::S_IFMT == libc::S_IFDIR {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDIO,
                            libc::EISDIR,
                            error_exit_syscall,
                        );
                    }
                }
                StdioMode::Redirect => {
                    if fd != libc::STDOUT_FILENO || stdout_redirect_fd < FIRST_NON_STDIO_FD as RawFd
                    {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDIO_REDIRECT,
                            libc::EINVAL,
                            error_exit_syscall,
                        );
                    }
                    if libc::dup2(stdout_redirect_fd, fd) == -1 {
                        child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
                    }
                }
                StdioMode::Capture => {
                    if fd != libc::STDOUT_FILENO || stdout_capture_fd < FIRST_NON_STDIO_FD as RawFd
                    {
                        child_fail_errno(
                            launch_error,
                            PHASE_STDOUT_CAPTURE,
                            libc::EINVAL,
                            error_exit_syscall,
                        );
                    }
                    if libc::dup2(stdout_capture_fd, fd) == -1 {
                        child_fail(launch_error, PHASE_STDOUT_CAPTURE, error_exit_syscall);
                    }
                }
            }
        }
        if stdout_redirect_fd >= FIRST_NON_STDIO_FD as RawFd
            && libc::close(stdout_redirect_fd) == -1
        {
            child_fail(launch_error, PHASE_STDIO_REDIRECT, error_exit_syscall);
        }
        if stdout_capture_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(stdout_capture_fd) == -1
        {
            child_fail(launch_error, PHASE_STDOUT_CAPTURE, error_exit_syscall);
        }
    }

    unsafe fn install_selected_handles_or_fail(
        handles: &[PreparedSelectedHandle],
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        for handle in handles {
            if libc::syscall(
                libc::SYS_dup3,
                handle.storage_fd.raw(),
                handle.target_fd,
                0u32,
            ) == -1
            {
                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);
            }
        }
        for handle in handles {
            if libc::close(handle.storage_fd.raw()) == -1 {
                child_fail(launch_error, PHASE_SELECTED_HANDLES, error_exit_syscall);
            }
        }
    }

    unsafe fn set_limit_or_fail(
        resource: libc::c_uint,
        value: u64,
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) {
        let limit = libc::rlimit {
            rlim_cur: value as libc::rlim_t,
            rlim_max: value as libc::rlim_t,
        };
        if libc::setrlimit(resource as _, &limit) == -1 {
            child_fail(launch_error, phase, error_exit_syscall);
        }
    }

    unsafe fn drop_capabilities_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        for capability in 0..=64u64 {
            if libc::syscall(libc::SYS_prctl, PR_CAPBSET_DROP, capability, 0, 0, 0) == -1 {
                let errno = *libc::__errno_location();
                if errno == libc::EINVAL {
                    break;
                }
                child_fail_errno(launch_error, PHASE_CAP_BOUNDING, errno, error_exit_syscall);
            }
        }

        if libc::syscall(
            libc::SYS_prctl,
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) == -1
        {
            child_fail(launch_error, PHASE_CAP_AMBIENT, error_exit_syscall);
        }

        let mut header = CapabilityHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapabilityHeader,
            data.as_ptr(),
        ) == -1
        {
            child_fail(launch_error, PHASE_CAP_CURRENT, error_exit_syscall);
        }
    }

    unsafe fn child_fail(
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        error_exit_syscall: libc::c_long,
    ) -> ! {
        child_fail_errno(
            launch_error,
            phase,
            *libc::__errno_location(),
            error_exit_syscall,
        )
    }

    unsafe fn child_fail_errno(
        launch_error: *mut LaunchErrorRecord,
        phase: u32,
        errno: i32,
        error_exit_syscall: libc::c_long,
    ) -> ! {
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).errno), errno);
        ptr::write_volatile(ptr::addr_of_mut!((*launch_error).phase), phase);

        loop {
            libc::syscall(error_exit_syscall, 127);
        }
    }

    fn wait_for_child(pid: libc::pid_t) -> Result<libc::c_int, SandboxError> {
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(status);
            }
            if result == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(SandboxError::SetupFailed(format!("waitpid failed: {err}")));
            }
        }
    }

    fn decode_launch_error(record: LaunchErrorRecord) -> Result<ChildOutcome, SandboxError> {
        let message = format_launch_error(record);
        let namespace_unavailable = record.phase == PHASE_NAMESPACE
            && matches!(record.errno, libc::EPERM | libc::EACCES | libc::ENOSYS);
        let mount_boundary_unavailable = matches!(
            record.phase,
            PHASE_ROOT_CLONE
                | PHASE_ROOT_READONLY
                | PHASE_ROOT_ATTACH
                | PHASE_SCRATCH_MOUNT
                | PHASE_VOLUME_CLONE
                | PHASE_VOLUME_READONLY
                | PHASE_VOLUME_ATTACH
        ) && matches!(
            record.errno,
            libc::EPERM | libc::EACCES | libc::ENOSYS | libc::ENODEV
        );
        let loopback_unavailable = record.phase == PHASE_NETWORK_LOOPBACK
            && matches!(
                record.errno,
                libc::EPERM | libc::EACCES | libc::ENOSYS | libc::ENODEV | libc::EOPNOTSUPP
            );
        if namespace_unavailable || mount_boundary_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "required namespace/mount isolation is unavailable: {message}"
            )))
        } else if loopback_unavailable {
            Err(SandboxError::UnsupportedPlatform(format!(
                "policy-owned loopback networking is unavailable: {message}"
            )))
        } else {
            Err(SandboxError::SetupFailed(message))
        }
    }

    fn decode_wait_status(status: libc::c_int) -> Result<ChildOutcome, SandboxError> {
        if libc::WIFEXITED(status) {
            Ok(ChildOutcome::Exited(libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Ok(ChildOutcome::Signaled(libc::WTERMSIG(status)))
        } else {
            Err(SandboxError::SetupFailed(format!(
                "child returned unsupported wait status 0x{status:x}"
            )))
        }
    }

    fn format_launch_error(record: LaunchErrorRecord) -> String {
        let phase = match record.phase {
            PHASE_NAMESPACE => "user/mount/PID/network/IPC/UTS namespace creation",
            PHASE_SETGROUPS => "setgroups deny",
            PHASE_UID_MAP => "uid_map",
            PHASE_GID_MAP => "gid_map",
            PHASE_MOUNT_PRIVATE => "mount propagation isolation",
            PHASE_STDIO => "explicit stdio disposition",
            PHASE_ROOT_CLONE => "detached root mount clone",
            PHASE_ROOT_READONLY => "recursive read-only root attributes",
            PHASE_ROOT_ATTACH => "read-only root mount attachment",
            PHASE_ROOT_FCHDIR => "read-only root selection",
            PHASE_SCRATCH_MOUNT => "writable scratch tmpfs mount",
            PHASE_CWD_PIN => "working-directory pin inside read-only root",
            PHASE_CHROOT => "chroot",
            PHASE_CWD_FCHDIR => "working-directory selection",
            PHASE_FD_SANITIZE => "inherited-FD sanitization",
            PHASE_RLIMIT_CPU => "RLIMIT_CPU",
            PHASE_RLIMIT_AS => "RLIMIT_AS",
            PHASE_RLIMIT_FSIZE => "RLIMIT_FSIZE",
            PHASE_RLIMIT_NOFILE => "RLIMIT_NOFILE",
            PHASE_CAP_BOUNDING => "capability bounding-set drop",
            PHASE_CAP_AMBIENT => "ambient capability clear",
            PHASE_CAP_CURRENT => "effective/permitted/inheritable capability clear",
            PHASE_NO_NEW_PRIVS => "PR_SET_NO_NEW_PRIVS",
            PHASE_SECCOMP => "seccomp installation",
            PHASE_EXECVEAT => "execveat",
            PHASE_ROOT_REVALIDATE => "filesystem root revalidation in mount namespace",
            PHASE_STDIO_REDIRECT => "owned stdout redirection",
            PHASE_STDOUT_CAPTURE => "bounded stdout capture",
            PHASE_PID_INIT_FORK => "PID namespace init fork",
            PHASE_TARGET_FORK => "direct target fork",
            PHASE_PROCESS_TREE_KILL => "process-tree termination",
            PHASE_PROCESS_TREE_REAP => "process-tree reaping",
            PHASE_PID_INIT_WAIT => "PID namespace init wait",
            PHASE_DEADLINE_PIDFD => "wall-clock deadline pidfd supervision",
            PHASE_DEADLINE_TIMERFD => "wall-clock deadline timer creation",
            PHASE_DEADLINE_TIMER_ARM => "wall-clock deadline timer arming",
            PHASE_DEADLINE_POLL => "wall-clock deadline supervision poll",
            PHASE_HOSTNAME => "UTS hostname installation",
            PHASE_SELECTED_HANDLES => "selected non-stdio handle installation",
            PHASE_CANCELLATION_PIDFD => "external cancellation pidfd supervision",
            PHASE_CANCELLATION_POLL => "external cancellation supervision poll",
            PHASE_VOLUME_SOURCE_REVALIDATE => "persistent volume source revalidation",
            PHASE_VOLUME_CLONE => "detached persistent volume mount clone",
            PHASE_VOLUME_READONLY => "recursive read-only volume attributes",
            PHASE_VOLUME_TARGET_PIN => "persistent volume target pin",
            PHASE_VOLUME_ATTACH => "persistent volume mount attachment",
            PHASE_NETWORK_LOOPBACK => "policy-owned loopback activation",
            PHASE_LANDLOCK_RULESET => "Landlock ruleset creation",
            PHASE_LANDLOCK_PATH => "Landlock path pin",
            PHASE_LANDLOCK_RULE => "Landlock path-beneath rule installation",
            PHASE_LANDLOCK_RESTRICT => "Landlock self restriction",
            PHASE_LANDLOCK_NET_RULE => "Landlock TCP port rule installation",
            PHASE_PROCESS_TREE_USAGE => "process-tree resource usage collection",
            PHASE_OUTPUT_LIMIT_PIDFD => "stdout output-limit pidfd supervision",
            PHASE_OUTPUT_LIMIT_POLL => "stdout output-limit supervision poll",
            _ => "unknown launch phase",
        };
        format!(
            "launch failed closed during {phase}: {}",
            io::Error::from_raw_os_error(record.errno)
        )
    }

    const fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn syscall_number(name: &str) -> Option<libc::c_long> {
        Some(match name {
            "read" => libc::SYS_read,
            "write" => libc::SYS_write,
            "close" => libc::SYS_close,
            "fstat" => libc::SYS_fstat,
            "lseek" => libc::SYS_lseek,
            "mmap" => libc::SYS_mmap,
            "mprotect" => libc::SYS_mprotect,
            "munmap" => libc::SYS_munmap,
            "brk" => libc::SYS_brk,
            "rt_sigaction" => libc::SYS_rt_sigaction,
            "rt_sigprocmask" => libc::SYS_rt_sigprocmask,
            "rt_sigreturn" => libc::SYS_rt_sigreturn,
            "ioctl" => libc::SYS_ioctl,
            "socket" => libc::SYS_socket,
            "connect" => libc::SYS_connect,
            "accept" => libc::SYS_accept,
            "bind" => libc::SYS_bind,
            "listen" => libc::SYS_listen,
            "msgget" => libc::SYS_msgget,
            "pread64" => libc::SYS_pread64,
            "access" => libc::SYS_access,
            "mremap" => libc::SYS_mremap,
            "madvise" => libc::SYS_madvise,
            "getpid" => libc::SYS_getpid,
            "getppid" => libc::SYS_getppid,
            "fork" => libc::SYS_fork,
            "pause" => libc::SYS_pause,
            "sched_yield" => libc::SYS_sched_yield,
            "nanosleep" => libc::SYS_nanosleep,
            "getuid" => libc::SYS_getuid,
            "getgid" => libc::SYS_getgid,
            "geteuid" => libc::SYS_geteuid,
            "getegid" => libc::SYS_getegid,
            "getgroups" => libc::SYS_getgroups,
            "capget" => libc::SYS_capget,
            "fcntl" => libc::SYS_fcntl,
            "getcwd" => libc::SYS_getcwd,
            "readlink" => libc::SYS_readlink,
            "sigaltstack" => libc::SYS_sigaltstack,
            "arch_prctl" => libc::SYS_arch_prctl,
            "gettid" => libc::SYS_gettid,
            "futex" => libc::SYS_futex,
            "sched_getaffinity" => libc::SYS_sched_getaffinity,
            "set_tid_address" => libc::SYS_set_tid_address,
            "exit" => libc::SYS_exit,
            "tgkill" => libc::SYS_tgkill,
            "openat" => libc::SYS_openat,
            "rename" => libc::SYS_rename,
            "mkdir" => libc::SYS_mkdir,
            "rmdir" => libc::SYS_rmdir,
            "unlink" => libc::SYS_unlink,
            "symlink" => libc::SYS_symlink,
            "truncate" => libc::SYS_truncate,
            "newfstatat" => libc::SYS_newfstatat,
            "set_robust_list" => libc::SYS_set_robust_list,
            "prlimit64" => libc::SYS_prlimit64,
            "getrandom" => libc::SYS_getrandom,
            "execve" => libc::SYS_execve,
            "execveat" => libc::SYS_execveat,
            "exit_group" => libc::SYS_exit_group,
            "statx" => libc::SYS_statx,
            "rseq" => libc::SYS_rseq,
            "prctl" => libc::SYS_prctl,
            "clock_gettime" => libc::SYS_clock_gettime,
            "uname" => libc::SYS_uname,
            "readlinkat" => libc::SYS_readlinkat,
            "pidfd_open" => libc::SYS_pidfd_open,
            "pidfd_send_signal" => libc::SYS_pidfd_send_signal,
            _ => return None,
        })
    }
}

#[cfg(target_arch = "x86_64")]
pub(crate) use x86_64::run_report;
