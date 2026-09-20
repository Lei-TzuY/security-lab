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
    use crate::elf_interpreter;
    use crate::elf_needed;
    use security_lab::SandboxPolicy;
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    const MAX_EXECUTABLE_DIGEST_BYTES: u64 = 64 * 1024 * 1024;

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

        if let Some(expected_sha256) = policy.executable_sha256 {
            let readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_digest_open",
                        Some(error),
                    );
                }
            };
            let mut readable_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(readable.raw(), &mut readable_stat) } != 0 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_digest_stat",
                    Some(errno()),
                );
            }
            if readable_stat.st_dev != stat.st_dev || readable_stat.st_ino != stat.st_ino {
                return ConfiguredFilesystemProbe::unavailable("executable_digest_identity", None);
            }
            if readable_stat.st_size < 0
                || readable_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
            {
                return ConfiguredFilesystemProbe::unavailable("executable_digest_size", None);
            }
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = unsafe {
                    libc::read(
                        readable.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        buffer.len(),
                    )
                };
                if read == -1 {
                    let error = errno();
                    if error == libc::EINTR {
                        continue;
                    }
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_digest_read",
                        Some(error),
                    );
                }
                if read == 0 {
                    break;
                }
                total = match total.checked_add(read as u64) {
                    Some(total) if total <= MAX_EXECUTABLE_DIGEST_BYTES => total,
                    _ => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_digest_size",
                            None,
                        );
                    }
                };
                hasher.update(&buffer[..read as usize]);
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected_sha256 {
                return ConfiguredFilesystemProbe::unavailable("executable_digest_mismatch", None);
            }
        }

        if let (Some(interpreter), Some(expected_sha256)) = (
            &policy.executable_interpreter,
            policy.executable_interpreter_sha256,
        ) {
            let executable_readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_elf_open",
                        Some(error),
                    );
                }
            };
            let declared =
                match elf_interpreter::read_elf64_x86_64_pt_interp(executable_readable.raw()) {
                    Ok(Some(path)) => path,
                    Ok(None) => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_interpreter_missing",
                            None,
                        );
                    }
                    Err(_) => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_interpreter_elf",
                            None,
                        );
                    }
                };
            if declared.as_slice() != interpreter.as_os_str().as_bytes() {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_path_mismatch",
                    None,
                );
            }

            let loader = match open_beneath(
                root.raw(),
                interpreter,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_open",
                        Some(error),
                    );
                }
            };
            let mut loader_stat = unsafe { std::mem::zeroed::<libc::stat>() };
            if unsafe { libc::fstat(loader.raw(), &mut loader_stat) } != 0 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_stat",
                    Some(errno()),
                );
            }
            if loader_stat.st_mode & libc::S_IFMT != libc::S_IFREG
                || loader_stat.st_mode & 0o111 == 0
                || loader_stat.st_size <= 0
                || loader_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
            {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_shape",
                    None,
                );
            }
            let mut hasher = Sha256::new();
            let mut total = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = unsafe {
                    libc::read(
                        loader.raw(),
                        buffer.as_mut_ptr().cast::<libc::c_void>(),
                        buffer.len(),
                    )
                };
                if read == -1 {
                    let error = errno();
                    if error == libc::EINTR {
                        continue;
                    }
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_interpreter_digest_read",
                        Some(error),
                    );
                }
                if read == 0 {
                    break;
                }
                total = match total.checked_add(read as u64) {
                    Some(total) if total <= MAX_EXECUTABLE_DIGEST_BYTES => total,
                    _ => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_interpreter_digest_size",
                            None,
                        );
                    }
                };
                hasher.update(&buffer[..read as usize]);
            }
            let actual: [u8; 32] = hasher.finalize().into();
            if actual != expected_sha256 {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_interpreter_digest_mismatch",
                    None,
                );
            }
        }

        let needed_bindings = policy.normalized_executable_needed_bindings();
        if !needed_bindings.is_empty() {
            let executable_readable = match open_beneath(
                root.raw(),
                &policy.executable,
                (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
            ) {
                Ok(fd) => fd,
                Err(error) => {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_elf_open",
                        Some(error),
                    );
                }
            };
            let root_needed =
                match elf_needed::read_elf64_x86_64_dt_needed(executable_readable.raw()) {
                    Ok(needed) => needed,
                    Err(_) => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_needed_elf",
                            None,
                        );
                    }
                };
            let declared = needed_bindings
                .iter()
                .map(|binding| binding.path.as_os_str().as_bytes().to_vec())
                .collect::<BTreeSet<_>>();
            if elf_needed::validate_dependency_graph_roots(&root_needed, &declared).is_err() {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_graph_roots",
                    None,
                );
            }

            let mut dependency_graph = BTreeMap::new();
            for binding in &needed_bindings {
                let dependency = &binding.path;
                let object = match open_beneath(
                    root.raw(),
                    dependency,
                    (libc::O_RDONLY | libc::O_CLOEXEC) as u64,
                ) {
                    Ok(fd) => fd,
                    Err(error) => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_needed_open",
                            Some(error),
                        );
                    }
                };
                let mut object_stat = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe { libc::fstat(object.raw(), &mut object_stat) } != 0 {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_stat",
                        Some(errno()),
                    );
                }
                if object_stat.st_mode & libc::S_IFMT != libc::S_IFREG
                    || object_stat.st_mode & 0o111 == 0
                    || object_stat.st_size <= 0
                    || object_stat.st_size as u64 > MAX_EXECUTABLE_DIGEST_BYTES
                {
                    return ConfiguredFilesystemProbe::unavailable("executable_needed_shape", None);
                }
                let mut hasher = Sha256::new();
                let mut total = 0u64;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    let read = unsafe {
                        libc::read(
                            object.raw(),
                            buffer.as_mut_ptr().cast::<libc::c_void>(),
                            buffer.len(),
                        )
                    };
                    if read == -1 {
                        let error = errno();
                        if error == libc::EINTR {
                            continue;
                        }
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_needed_digest_read",
                            Some(error),
                        );
                    }
                    if read == 0 {
                        break;
                    }
                    total = match total.checked_add(read as u64) {
                        Some(total) if total <= MAX_EXECUTABLE_DIGEST_BYTES => total,
                        _ => {
                            return ConfiguredFilesystemProbe::unavailable(
                                "executable_needed_digest_size",
                                None,
                            );
                        }
                    };
                    hasher.update(&buffer[..read as usize]);
                }
                let actual: [u8; 32] = hasher.finalize().into();
                if actual != binding.sha256 {
                    return ConfiguredFilesystemProbe::unavailable(
                        "executable_needed_digest_mismatch",
                        None,
                    );
                }
                let node_needed = match elf_needed::read_elf64_x86_64_dt_needed(object.raw()) {
                    Ok(needed) => needed,
                    Err(_) => {
                        return ConfiguredFilesystemProbe::unavailable(
                            "executable_needed_dependency_elf",
                            None,
                        );
                    }
                };
                dependency_graph.insert(
                    dependency.as_os_str().as_bytes().to_vec(),
                    node_needed,
                );
            }

            if elf_needed::validate_exact_dependency_graph(&root_needed, &dependency_graph).is_err() {
                return ConfiguredFilesystemProbe::unavailable(
                    "executable_needed_graph_closure",
                    None,
                );
            }
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
        for volume in policy.normalized_readonly_volume_bindings() {
            if let Err(result) =
                require_host_directory(&volume.source, "readonly_volume_source_open")
            {
                return result;
            }
            if let Err(result) =
                require_beneath_directory(root.raw(), &volume.target, "readonly_volume_target_open")
            {
                return result;
            }
        }
        for volume in policy.normalized_writable_volume_bindings() {
            if let Err(result) =
                require_host_directory(&volume.source, "writable_volume_source_open")
            {
                return result;
            }
            if let Err(result) =
                require_beneath_directory(root.raw(), &volume.target, "writable_volume_target_open")
            {
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
