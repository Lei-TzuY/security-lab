#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StagedCapabilityProbe {
    pub(super) available: bool,
    pub(super) errno: Option<i32>,
    pub(super) stage: &'static str,
}

impl StagedCapabilityProbe {
    const fn available(stage: &'static str) -> Self {
        Self {
            available: true,
            errno: None,
            stage,
        }
    }

    const fn unavailable(stage: &'static str, errno: Option<i32>) -> Self {
        Self {
            available: false,
            errno,
            stage,
        }
    }
}

pub(super) fn probe() -> StagedCapabilityProbe {
    platform_probe()
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
struct ProbeReport {
    stage: i32,
    errno: i32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_probe() -> StagedCapabilityProbe {
    let uid_map = format!("0 {} 1\n", unsafe { libc::geteuid() });
    let gid_map = format!("0 {} 1\n", unsafe { libc::getegid() });
    let mut pipe_fds = [-1; 2];
    if unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return StagedCapabilityProbe::unavailable(
            "probe_pipe",
            std::io::Error::last_os_error().raw_os_error(),
        );
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error();
        unsafe {
            libc::close(pipe_fds[0]);
            libc::close(pipe_fds[1]);
        }
        return StagedCapabilityProbe::unavailable("probe_fork", errno);
    }
    if child == 0 {
        unsafe {
            libc::close(pipe_fds[0]);
            probe_child(pipe_fds[1], uid_map.as_bytes(), gid_map.as_bytes());
        }
    }

    unsafe {
        libc::close(pipe_fds[1]);
    }
    let report = read_report(pipe_fds[0]);
    unsafe {
        libc::close(pipe_fds[0]);
    }

    let mut status = 0;
    let waited = loop {
        let result = unsafe { libc::waitpid(child, &mut status, 0) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        break result;
    };
    if waited != child {
        return StagedCapabilityProbe::unavailable(
            "probe_wait",
            std::io::Error::last_os_error().raw_os_error(),
        );
    }

    match report {
        Some(ProbeReport { stage: 0, errno: 0 })
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 =>
        {
            StagedCapabilityProbe::available("complete")
        }
        Some(report) => StagedCapabilityProbe::unavailable(
            stage_name(report.stage),
            if report.errno == 0 {
                None
            } else {
                Some(report.errno)
            },
        ),
        None => StagedCapabilityProbe::unavailable("probe_child", None),
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_probe() -> StagedCapabilityProbe {
    StagedCapabilityProbe::unavailable("unsupported_target", None)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_report(fd: libc::c_int) -> Option<ProbeReport> {
    let mut report = ProbeReport {
        stage: -1,
        errno: 0,
    };
    let total = std::mem::size_of::<ProbeReport>();
    let mut offset = 0usize;
    while offset < total {
        let read = unsafe {
            libc::read(
                fd,
                (&mut report as *mut ProbeReport)
                    .cast::<u8>()
                    .add(offset)
                    .cast(),
                total - offset,
            )
        };
        if read == 0 {
            return None;
        }
        if read < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        offset += read as usize;
    }
    Some(report)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn stage_name(stage: i32) -> &'static str {
    match stage {
        10 => "namespace_unshare",
        11 => "setgroups_deny",
        12 => "uid_map",
        13 => "gid_map",
        14 => "uts_hostname",
        15 => "mount_private",
        16 => "tmpfs_mount",
        17 => "probe_root_mkdir",
        18 => "probe_attach_mkdir",
        19 => "openat2_root",
        20 => "openat2_beneath",
        21 => "open_tree_clone",
        22 => "mount_setattr_readonly",
        23 => "openat2_attach",
        24 => "move_mount_attach",
        25 => "readonly_mount_oracle",
        26 => "pid_namespace_fork",
        27 => "pid_namespace_wait",
        28 => "chroot",
        29 => "chdir",
        30 => "close_range",
        31 => "rlimit_cpu",
        32 => "rlimit_address_space",
        33 => "rlimit_file_size",
        34 => "rlimit_open_files",
        35 => "capability_bounding_set",
        36 => "capability_ambient_set",
        37 => "capability_current_sets",
        38 => "no_new_privs",
        39 => "seccomp_filter",
        _ => "unknown_stage",
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn probe_child(report_fd: libc::c_int, uid_map: &[u8], gid_map: &[u8]) -> ! {
    const AT_RECURSIVE: libc::c_uint = 0x8000;
    const AT_EMPTY_PATH: libc::c_uint = 0x1000;
    const OPEN_TREE_CLONE: libc::c_uint = 1;
    const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
    const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x0000_0004;
    const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x0000_0040;
    const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const PR_CAPBSET_DROP: libc::c_int = 24;
    const PR_CAP_AMBIENT: libc::c_int = 47;
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
    const SECCOMP_MODE_FILTER: libc::c_ulong = 2;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const BPF_RET_K: u16 = 0x06;

    let namespace_flags = libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS;
    if libc::unshare(namespace_flags) != 0 {
        fail(report_fd, 10, errno());
    }
    write_file(report_fd, 11, b"/proc/self/setgroups\0", b"deny\n");
    write_file(report_fd, 12, b"/proc/self/uid_map\0", uid_map);
    write_file(report_fd, 13, b"/proc/self/gid_map\0", gid_map);

    let hostname = b"security-lab-preflight";
    if libc::sethostname(hostname.as_ptr().cast(), hostname.len()) != 0 {
        fail(report_fd, 14, errno());
    }
    if libc::mount(
        std::ptr::null(),
        b"/\0".as_ptr().cast(),
        std::ptr::null(),
        (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
        std::ptr::null(),
    ) != 0
    {
        fail(report_fd, 15, errno());
    }
    if libc::mount(
        b"tmpfs\0".as_ptr().cast(),
        b"/tmp\0".as_ptr().cast(),
        b"tmpfs\0".as_ptr().cast(),
        (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong,
        b"size=1048576,mode=0700\0".as_ptr().cast(),
    ) != 0
    {
        fail(report_fd, 16, errno());
    }
    if libc::mkdir(b"/tmp/security-lab-core-root\0".as_ptr().cast(), 0o700) != 0 {
        fail(report_fd, 17, errno());
    }
    if libc::mkdir(b"/tmp/security-lab-core-attach\0".as_ptr().cast(), 0o700) != 0 {
        fail(report_fd, 18, errno());
    }

    let root_how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let root_fd = libc::syscall(
        libc::SYS_openat2,
        libc::AT_FDCWD,
        b"/tmp/security-lab-core-root\0"
            .as_ptr()
            .cast::<libc::c_char>(),
        &root_how as *const OpenHow,
        std::mem::size_of::<OpenHow>(),
    );
    if root_fd < 0 {
        fail(report_fd, 19, errno());
    }
    let root_fd = root_fd as libc::c_int;

    let beneath_how = OpenHow {
        flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let beneath_fd = libc::syscall(
        libc::SYS_openat2,
        root_fd,
        b".\0".as_ptr().cast::<libc::c_char>(),
        &beneath_how as *const OpenHow,
        std::mem::size_of::<OpenHow>(),
    );
    if beneath_fd < 0 {
        fail(report_fd, 20, errno());
    }
    libc::close(beneath_fd as libc::c_int);

    let tree_fd = libc::syscall(
        libc::SYS_open_tree,
        root_fd,
        b".\0".as_ptr().cast::<libc::c_char>(),
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
    );
    if tree_fd < 0 {
        fail(report_fd, 21, errno());
    }
    let tree_fd = tree_fd as libc::c_int;
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_RDONLY,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    if libc::syscall(
        libc::SYS_mount_setattr,
        tree_fd,
        b"\0".as_ptr().cast::<libc::c_char>(),
        AT_EMPTY_PATH | AT_RECURSIVE,
        &attr as *const MountAttr,
        std::mem::size_of::<MountAttr>(),
    ) < 0
    {
        fail(report_fd, 22, errno());
    }

    let attach_fd = libc::syscall(
        libc::SYS_openat2,
        libc::AT_FDCWD,
        b"/tmp/security-lab-core-attach\0"
            .as_ptr()
            .cast::<libc::c_char>(),
        &root_how as *const OpenHow,
        std::mem::size_of::<OpenHow>(),
    );
    if attach_fd < 0 {
        fail(report_fd, 23, errno());
    }
    let attach_fd = attach_fd as libc::c_int;
    if libc::syscall(
        libc::SYS_move_mount,
        tree_fd,
        b"\0".as_ptr().cast::<libc::c_char>(),
        attach_fd,
        b"\0".as_ptr().cast::<libc::c_char>(),
        MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
    ) < 0
    {
        fail(report_fd, 24, errno());
    }
    libc::close(tree_fd);
    libc::close(root_fd);
    libc::close(attach_fd);

    let blocked_fd = libc::open(
        b"/tmp/security-lab-core-attach/blocked\0".as_ptr().cast(),
        libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
        0o600,
    );
    if blocked_fd >= 0 {
        libc::close(blocked_fd);
        fail(report_fd, 25, 0);
    }
    let blocked_errno = errno();
    if blocked_errno != libc::EROFS {
        fail(report_fd, 25, blocked_errno);
    }

    let pid1 = libc::fork();
    if pid1 < 0 {
        fail(report_fd, 26, errno());
    }
    if pid1 == 0 {
        libc::_exit(if libc::getpid() == 1 { 0 } else { 1 });
    }
    let mut pid_status = 0;
    let waited = libc::waitpid(pid1, &mut pid_status, 0);
    if waited != pid1 {
        fail(report_fd, 27, errno());
    }
    if !libc::WIFEXITED(pid_status) || libc::WEXITSTATUS(pid_status) != 0 {
        fail(report_fd, 27, 0);
    }

    if libc::chroot(b"/tmp/security-lab-core-attach\0".as_ptr().cast()) != 0 {
        fail(report_fd, 28, errno());
    }
    if libc::chdir(b"/\0".as_ptr().cast()) != 0 {
        fail(report_fd, 29, errno());
    }
    if libc::syscall(
        libc::SYS_close_range,
        3u32 as libc::c_uint,
        u32::MAX as libc::c_uint,
        CLOSE_RANGE_CLOEXEC,
    ) < 0
    {
        fail(report_fd, 30, errno());
    }

    probe_rlimit(report_fd, 31, libc::RLIMIT_CPU);
    probe_rlimit(report_fd, 32, libc::RLIMIT_AS);
    probe_rlimit(report_fd, 33, libc::RLIMIT_FSIZE);
    probe_rlimit(report_fd, 34, libc::RLIMIT_NOFILE);

    for capability in 0..=40 {
        if libc::prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 {
            fail(report_fd, 35, errno());
        }
    }
    if libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 {
        fail(report_fd, 36, errno());
    }
    let header = CapabilityHeader {
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
        &header as *const CapabilityHeader,
        data.as_ptr(),
    ) < 0
    {
        fail(report_fd, 37, errno());
    }
    if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
        fail(report_fd, 38, errno());
    }

    let mut filter = libc::sock_filter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    };
    let program = libc::sock_fprog {
        len: 1,
        filter: &mut filter,
    };
    if libc::prctl(
        libc::PR_SET_SECCOMP,
        SECCOMP_MODE_FILTER,
        &program as *const libc::sock_fprog,
        0,
        0,
    ) != 0
    {
        fail(report_fd, 39, errno());
    }

    write_report(report_fd, &ProbeReport { stage: 0, errno: 0 });
    libc::_exit(0)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_file(report_fd: libc::c_int, stage: i32, path: &[u8], bytes: &[u8]) {
    let fd = libc::open(path.as_ptr().cast(), libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        fail(report_fd, stage, errno());
    }
    let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    if written != bytes.len() as isize {
        let error = if written < 0 { errno() } else { 0 };
        libc::close(fd);
        fail(report_fd, stage, error);
    }
    if libc::close(fd) != 0 {
        fail(report_fd, stage, errno());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn probe_rlimit(report_fd: libc::c_int, stage: i32, resource: libc::__rlimit_resource_t) {
    let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
    if libc::getrlimit(resource, limit.as_mut_ptr()) != 0 {
        fail(report_fd, stage, errno());
    }
    let limit = limit.assume_init();
    if libc::setrlimit(resource, &limit) != 0 {
        fail(report_fd, stage, errno());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_report(fd: libc::c_int, report: &ProbeReport) {
    let total = std::mem::size_of::<ProbeReport>();
    let mut offset = 0usize;
    while offset < total {
        let written = libc::write(
            fd,
            (report as *const ProbeReport)
                .cast::<u8>()
                .add(offset)
                .cast(),
            total - offset,
        );
        if written <= 0 {
            libc::_exit(125);
        }
        offset += written as usize;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn fail(fd: libc::c_int, stage: i32, error: i32) -> ! {
    write_report(
        fd,
        &ProbeReport {
            stage,
            errno: error,
        },
    );
    libc::_exit(1)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn errno() -> i32 {
    *libc::__errno_location()
}
