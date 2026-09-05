use std::io;
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct LaunchErrorRecord {
    pub(super) errno: i32,
    pub(super) phase: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TargetLifecycleRecord {
    pub(super) status: libc::c_int,
    pub(super) reaped_descendants: u32,
    pub(super) ready: u32,
}

pub(super) struct SharedTargetLifecycle {
    record: *mut TargetLifecycleRecord,
}

impl SharedTargetLifecycle {
    pub(super) fn new() -> io::Result<Self> {
        let length = std::mem::size_of::<TargetLifecycleRecord>();
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
            return Err(io::Error::last_os_error());
        }

        let record = mapping.cast::<TargetLifecycleRecord>();
        unsafe {
            ptr::write_volatile(
                record,
                TargetLifecycleRecord {
                    status: 0,
                    reaped_descendants: 0,
                    ready: 0,
                },
            );
        }
        Ok(Self { record })
    }

    pub(super) fn raw(&self) -> *mut TargetLifecycleRecord {
        self.record
    }

    pub(super) fn snapshot(&self) -> TargetLifecycleRecord {
        unsafe { ptr::read_volatile(self.record) }
    }
}

impl Drop for SharedTargetLifecycle {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(
                self.record.cast::<libc::c_void>(),
                std::mem::size_of::<TargetLifecycleRecord>(),
            );
        }
    }
}

/// The caller has already unshared CLONE_NEWPID. Fork the first process in the
/// new namespace. The child returns as namespace PID 1; the bootstrap parent
/// closes all setup descriptors, waits for PID 1, then exits. Target outcome is
/// transported separately through `TargetLifecycleRecord`.
pub(super) unsafe fn become_pid_namespace_init_or_exit(
    launch_error: *mut LaunchErrorRecord,
    phase_fork: u32,
    phase_wait: u32,
    phase_close: u32,
) {
    let pid = libc::syscall(libc::SYS_fork);
    if pid == -1 {
        fail(launch_error, phase_fork);
    }
    if pid == 0 {
        return;
    }
    let pid = pid as libc::pid_t;

    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
        let errno = *libc::__errno_location();
        // Killing namespace PID 1 also tears down every process in that PID
        // namespace, so a bootstrap cleanup failure cannot leave the target
        // process tree running after a fail-closed launcher error.
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
        let _ = wait_specific(pid);
        fail_errno(launch_error, phase_close, errno);
    }

    match wait_specific(pid) {
        Ok(_) => raw_exit(0),
        Err(errno) => fail_errno(launch_error, phase_wait, errno),
    }
}

/// Called by the launcher-owned namespace init (PID 1). Fork the direct target.
/// The target child returns to the caller and continues into stdio/rlimit/
/// capability/seccomp/exec setup. PID 1 instead waits for the direct target,
/// kills and reaps every remaining descendant, publishes the target's raw wait
/// status, and exits without ever inheriting the target seccomp policy.
pub(super) unsafe fn become_direct_target_or_reap(
    lifecycle: *mut TargetLifecycleRecord,
    launch_error: *mut LaunchErrorRecord,
    phase_fork: u32,
    phase_kill: u32,
    phase_reap: u32,
    phase_close: u32,
) {
    let pid = libc::syscall(libc::SYS_fork);
    if pid == -1 {
        fail(launch_error, phase_fork);
    }
    if pid == 0 {
        return;
    }
    let pid = pid as libc::pid_t;

    if libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) == -1 {
        let errno = *libc::__errno_location();
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
        let _ = wait_specific(pid);
        let _ = kill_and_reap_remaining(launch_error, phase_kill, phase_reap);
        fail_errno(launch_error, phase_close, errno);
    }

    let direct_status = match wait_specific(pid) {
        Ok(status) => status,
        Err(errno) => fail_errno(launch_error, phase_reap, errno),
    };
    let reaped_descendants = kill_and_reap_remaining(launch_error, phase_kill, phase_reap);

    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).status), direct_status);
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).reaped_descendants),
        reaped_descendants,
    );
    // Publish readiness last: the host treats ready != 1 as an incomplete
    // process-tree lifecycle and fails closed.
    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).ready), 1);
    raw_exit(0)
}

unsafe fn kill_and_reap_remaining(
    launch_error: *mut LaunchErrorRecord,
    phase_kill: u32,
    phase_reap: u32,
) -> u32 {
    let mut reaped = 0u32;
    loop {
        let killed = libc::syscall(libc::SYS_kill, -1, libc::SIGKILL);
        if killed == -1 {
            let errno = *libc::__errno_location();
            if errno != libc::ESRCH {
                fail_errno(launch_error, phase_kill, errno);
            }
        }

        let mut status = 0;
        let waited = libc::syscall(
            libc::SYS_wait4,
            -1,
            &mut status as *mut libc::c_int,
            0,
            ptr::null_mut::<libc::rusage>(),
        );
        if waited > 0 {
            reaped = reaped.saturating_add(1);
            // Repeat kill before every reap so a racing descendant cannot fork
            // a survivor between the first signal sweep and final ECHILD.
            continue;
        }
        if waited == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            if errno == libc::ECHILD {
                return reaped;
            }
            fail_errno(launch_error, phase_reap, errno);
        }
    }
}

unsafe fn wait_specific(pid: libc::pid_t) -> Result<libc::c_int, i32> {
    loop {
        let mut status = 0;
        let waited = libc::syscall(
            libc::SYS_wait4,
            pid,
            &mut status as *mut libc::c_int,
            0,
            ptr::null_mut::<libc::rusage>(),
        );
        if waited == pid as libc::c_long {
            return Ok(status);
        }
        if waited == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
    }
}

unsafe fn fail(launch_error: *mut LaunchErrorRecord, phase: u32) -> ! {
    fail_errno(launch_error, phase, *libc::__errno_location())
}

unsafe fn fail_errno(launch_error: *mut LaunchErrorRecord, phase: u32, errno: i32) -> ! {
    ptr::write_volatile(ptr::addr_of_mut!((*launch_error).errno), errno);
    ptr::write_volatile(ptr::addr_of_mut!((*launch_error).phase), phase);
    raw_exit(127)
}

unsafe fn raw_exit(code: libc::c_int) -> ! {
    loop {
        libc::syscall(libc::SYS_exit, code);
    }
}
