from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/platform/linux.rs",
    "    const FIRST_SELECTED_STORAGE_FD: RawFd = 64;\n",
    "",
    "remove fixed selected storage floor",
)
replace_one(
    "src/platform/linux.rs",
    '''    fn move_owned_fd_to_selected_storage(\n        fd: OwnedFd,\n        label: &str,\n    ) -> Result<OwnedFd, SandboxError> {\n        if fd.raw() >= FIRST_SELECTED_STORAGE_FD {\n            return Ok(fd);\n        }\n        let moved =\n            unsafe { libc::fcntl(fd.raw(), libc::F_DUPFD_CLOEXEC, FIRST_SELECTED_STORAGE_FD) };\n        if moved == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot move {label} into the selected-handle storage plane: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        drop(fd);\n        Ok(OwnedFd(moved))\n    }\n\n    fn pin_selected_handle(\n        source_fd: u32,\n        target_fd: u32,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n''',
    '''    fn move_owned_fd_to_selected_storage(\n        fd: OwnedFd,\n        storage_floor: RawFd,\n        label: &str,\n    ) -> Result<OwnedFd, SandboxError> {\n        if fd.raw() >= storage_floor {\n            return Ok(fd);\n        }\n        let moved = unsafe { libc::fcntl(fd.raw(), libc::F_DUPFD_CLOEXEC, storage_floor) };\n        if moved == -1 {\n            return Err(SandboxError::SetupFailed(format!(\n                "cannot move {label} into the selected-handle storage plane at fd {storage_floor} or above: {}",\n                io::Error::last_os_error()\n            )));\n        }\n        drop(fd);\n        Ok(OwnedFd(moved))\n    }\n\n    fn pin_selected_handle(\n        source_fd: u32,\n        target_fd: u32,\n        storage_floor: RawFd,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n''',
    "dynamic selected storage helper signature",
)
replace_one(
    "src/platform/linux.rs",
    '''        let pinned =\n            unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, FIRST_SELECTED_STORAGE_FD) };\n''',
    '''        let pinned = unsafe { libc::fcntl(source_fd, libc::F_DUPFD_CLOEXEC, storage_floor) };\n''',
    "dynamic selected source pin floor",
)
replace_one(
    "src/platform/linux.rs",
    '''            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n            let executable_fd =\n                move_owned_fd_to_selected_storage(executable_fd, "pinned executable")?;\n\n            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());\n            for (target_fd, source_fd) in &policy.selected_handles {\n                selected_handles.push(pin_selected_handle(*source_fd, *target_fd)?);\n            }\n''',
    '''            validate_executable_fd(executable_fd.raw(), &policy.executable)?;\n            // Keep every launcher-owned source above all target-visible handle\n            // destinations. With no selected handles this floor is only 3, so\n            // existing sandboxes do not gain an unnecessary fd>=64 requirement.\n            let selected_storage_floor = policy\n                .selected_handles\n                .keys()\n                .next_back()\n                .map_or(FIRST_NON_STDIO_FD as RawFd, |target_fd| {\n                    *target_fd as RawFd + 1\n                });\n            let executable_fd = move_owned_fd_to_selected_storage(\n                executable_fd,\n                selected_storage_floor,\n                "pinned executable",\n            )?;\n\n            let mut selected_handles = Vec::with_capacity(policy.selected_handles.len());\n            for (target_fd, source_fd) in &policy.selected_handles {\n                selected_handles.push(pin_selected_handle(\n                    *source_fd,\n                    *target_fd,\n                    selected_storage_floor,\n                )?);\n            }\n''',
    "dynamic selected storage floor computation",
)
