use security_lab::SandboxPolicy;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ConfiguredFilesystemProbe {
    pub(super) available: bool,
    pub(super) errno: Option<i32>,
    pub(super) stage: &'static str,
}

impl ConfiguredFilesystemProbe {
    const fn available() -> Self {
        Self {
            available: true,
            errno: None,
            stage: "complete",
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

pub(super) fn probe(policy: &SandboxPolicy) -> ConfiguredFilesystemProbe {
    platform_probe(policy)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux_x86_64 {
    use super::ConfiguredFilesystemProbe;
    use security_lab::SandboxPolicy;
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    struct OwnedFd(libc::c_int);

    impl OwnedFd {
        fn raw(&self) -> libc::c_int {
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

    fn errno() -> i32 {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }

    fn cstring(path: &Path) -> Result<CString, i32> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
    }

    fn sandbox_relative(path: &Path) -> Result<CString, i32> {
        let relative = path
            .strip_prefix(Path::new("/"))
            .map_err(|_| libc::EINVAL)?;
        if relative.as_os_str().is_empty() {
            CString::new(".").map_err(|_| libc::EINVAL)
        } else {
            cstring(relative)
        }
    }

    fn open_host_directory(path: &Path) -> Result<OwnedFd, i32> {
        let path = cstring(path)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(errno())
        } else {
            Ok(OwnedFd(fd as libc::c_int))
        }
    }

    fn open_beneath(root_fd: libc::c_int, path: &Path, flags: u64) -> Result<OwnedFd, i32> {
        let relative = sandbox_relative(path)?;
        let how = OpenHow {
            flags,
            mode: 0,
            resolve: RESOLVE_BENEATH
                | RESOLVE_NO_XDEV
                | RESOLVE_NO_MAGICLINKS
                | RESOLVE_NO_SYMLINKS,
        };
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root_fd,
                relative.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            Err(errno())
        } else {
            Ok(OwnedFd(fd as libc::c_int))
        }
    }

    fn require_host_directory(
        path: &Path,
        stage: &'static str,
    ) -> Result<OwnedFd, ConfiguredFilesystemProbe> {
        open_host_directory(path)
            .map_err(|error| ConfiguredFilesystemProbe::unavailable(stage, Some(error)))
    }

    fn require_beneath_directory(
        root_fd: libc::c_int,
        path: &Path,
        stage: &'static str,
    ) -> Result<(), ConfiguredFilesystemProbe> {
        open_beneath(
            root_fd,
            path,
            (libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        )
        .map(|_| ())
        .map_err(|error| ConfiguredFilesystemProbe::unavailable(stage, Some(error)))
    }

    pub(super) fn probe(policy: &SandboxPolicy) -> ConfiguredFilesystemProbe {
        let root = match require_host_directory(&policy.root_dir, "root_open") {
            Ok(root) => root,
            Err(result) => return result,
        };

        let executable = match open_beneath(
            root.raw(),
            &policy.executable,
            (libc::O_PATH | libc::O_CLOEXEC) as u64,
        ) {
            Ok(fd) => fd,
            Err(error) => {
                return ConfiguredFilesystemProbe::unavailable("executable_open", Some(error));
            }
        };
        let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(executable.raw(), &mut stat) } != 0 {
            return ConfiguredFilesystemProbe::unavailable("executable_stat", Some(errno()));
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return ConfiguredFilesystemProbe::unavailable("executable_regular_file", None);
        }
        if stat.st_mode & 0o111 == 0 {
            return ConfiguredFilesystemProbe::unavailable("executable_execute_bit", None);
        }

        if let Err(result) =
            require_beneath_directory(root.raw(), &policy.working_dir, "working_dir_open")
        {
            return result;
        }
        if let Some(path) = &policy.scratch_dir {
            if let Err(result) = require_beneath_directory(root.raw(), path, "scratch_open") {
                return result;
            }
        }
        if policy.procfs_enabled {
            if let Err(result) =
                require_beneath_directory(root.raw(), Path::new("/proc"), "procfs_target_open")
            {
                return result;
            }
        }
        if let (Some(source), Some(target)) = (
            &policy.readonly_volume_source,
            &policy.readonly_volume_target,
        ) {
            if let Err(result) = require_host_directory(source, "readonly_volume_source_open") {
                return result;
            }
            if let Err(result) =
                require_beneath_directory(root.raw(), target, "readonly_volume_target_open")
            {
                return result;
            }
        }
        if let (Some(source), Some(target)) = (
            &policy.writable_volume_source,
            &policy.writable_volume_target,
        ) {
            if let Err(result) = require_host_directory(source, "writable_volume_source_open") {
                return result;
            }
            if let Err(result) =
                require_beneath_directory(root.raw(), target, "writable_volume_target_open")
            {
                return result;
            }
        }

        for volume in policy.persistent_volumes.values() {
            if let Err(result) =
                require_host_directory(&volume.source, "persistent_volume_source_open")
            {
                return result;
            }
            if let Err(result) = require_beneath_directory(
                root.raw(),
                &volume.target,
                "persistent_volume_target_open",
            ) {
                return result;
            }
        }

        ConfiguredFilesystemProbe::available()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_probe(policy: &SandboxPolicy) -> ConfiguredFilesystemProbe {
    linux_x86_64::probe(policy)
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_probe(_policy: &SandboxPolicy) -> ConfiguredFilesystemProbe {
    ConfiguredFilesystemProbe::unavailable("unsupported_target", None)
}
