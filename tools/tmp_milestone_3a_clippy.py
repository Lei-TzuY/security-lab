from pathlib import Path


def replace_once(text, old, new, label):
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected one match, found {count}")
    return text.replace(old, new, 1)


helper_path = Path("src/platform/linux_pid_lifecycle.rs")
helper = helper_path.read_text()
helper = replace_once(
    helper,
    """            if reaped != u32::MAX {
                reaped += 1;
            }""",
    """            reaped = reaped.saturating_add(1);""",
    "saturating descendant count",
)
helper_path.write_text(helper)

linux_path = Path("src/platform/linux.rs")
linux = linux_path.read_text()
linux = replace_once(
    linux,
    """    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    pub(crate) fn run_report""",
    """    struct CompiledSeccomp {
        filter: Vec<libc::sock_filter>,
        error_exit_syscall: libc::c_long,
    }

    #[derive(Clone, Copy)]
    struct ChildControl {
        launch_error: *mut LaunchErrorRecord,
        target_lifecycle: *mut TargetLifecycleRecord,
        capture_read_fd: RawFd,
        capture_write_fd: RawFd,
    }

    pub(crate) fn run_report""",
    "child control type",
)
linux = replace_once(
    linux,
    """        let capture_read_fd = capture.as_ref().map_or(-1, |pipe| pipe.read_fd.raw());
        let capture_write_fd = capture.as_ref().map_or(-1, |pipe| pipe.write_fd.raw());

        let pid = unsafe { libc::fork() };""",
    """        let capture_read_fd = capture.as_ref().map_or(-1, |pipe| pipe.read_fd.raw());
        let capture_write_fd = capture.as_ref().map_or(-1, |pipe| pipe.write_fd.raw());
        let child_control = ChildControl {
            launch_error: launch_state.record,
            target_lifecycle: lifecycle.raw(),
            capture_read_fd,
            capture_write_fd,
        };

        let pid = unsafe { libc::fork() };""",
    "pre-fork child control",
)
linux = replace_once(
    linux,
    """                    &seccomp,
                    launch_state.record,
                    lifecycle.raw(),
                    capture_read_fd,
                    capture_write_fd,
                )""",
    """                    &seccomp,
                    child_control,
                )""",
    "child_exec call",
)
linux = replace_once(
    linux,
    """        seccomp: &CompiledSeccomp,
        launch_error: *mut LaunchErrorRecord,
        target_lifecycle: *mut TargetLifecycleRecord,
        capture_read_fd: RawFd,
        capture_write_fd: RawFd,
    ) -> ! {
        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {""",
    """        seccomp: &CompiledSeccomp,
        control: ChildControl,
    ) -> ! {
        let ChildControl {
            launch_error,
            target_lifecycle,
            capture_read_fd,
            capture_write_fd,
        } = control;
        if capture_read_fd >= FIRST_NON_STDIO_FD as RawFd && libc::close(capture_read_fd) == -1 {""",
    "child_exec signature",
)
linux_path.write_text(linux)
