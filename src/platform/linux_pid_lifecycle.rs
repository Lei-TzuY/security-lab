use std::io;
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct LaunchErrorRecord {
    pub(super) errno: i32,
    pub(super) phase: u32,
    pub(super) enforcement_bits: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct TargetLifecycleRecord {
    pub(super) status: libc::c_int,
    pub(super) reaped_descendants: u32,
    pub(super) timed_out: u32,
    pub(super) cancelled: u32,
    pub(super) output_limit_exceeded: u32,
    pub(super) user_cpu_micros: u64,
    pub(super) system_cpu_micros: u64,
    pub(super) max_child_rss_kib: u64,
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
                    timed_out: 0,
                    cancelled: 0,
                    output_limit_exceeded: 0,
                    user_cpu_micros: 0,
                    system_cpu_micros: 0,
                    max_child_rss_kib: 0,
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

#[derive(Clone, Copy)]
pub(super) struct TargetSupervisionPhases {
    pub(super) fork: u32,
    pub(super) kill: u32,
    pub(super) reap: u32,
    pub(super) close: u32,
    pub(super) pidfd: u32,
    pub(super) timerfd: u32,
    pub(super) timer_arm: u32,
    pub(super) poll: u32,
    pub(super) cancellation_pidfd: u32,
    pub(super) cancellation_poll: u32,
    pub(super) output_limit_pidfd: u32,
    pub(super) output_limit_poll: u32,
    pub(super) usage: u32,
}

/// Called by the launcher-owned namespace init (PID 1). Fork the direct target.
/// The target child returns to the caller and continues into stdio/rlimit/
/// capability/seccomp/exec setup. PID 1 instead supervises the direct target,
/// optionally enforces a monotonic wall-clock deadline, kills and reaps every
/// remaining descendant, publishes the target lifecycle, and exits without
/// ever inheriting the target seccomp policy.
pub(super) unsafe fn become_direct_target_or_reap(
    lifecycle: *mut TargetLifecycleRecord,
    launch_error: *mut LaunchErrorRecord,
    wall_clock_milliseconds: u64,
    cancellation_fd: libc::c_int,
    output_limit_fd: libc::c_int,
    phases: TargetSupervisionPhases,
) {
    let pid = libc::syscall(libc::SYS_fork);
    if pid == -1 {
        fail(launch_error, phases.fork);
    }
    if pid == 0 {
        for control_fd in [cancellation_fd, output_limit_fd] {
            if control_fd >= 3 && libc::close(control_fd) == -1 {
                fail(launch_error, phases.close);
            }
        }
        return;
    }
    let pid = pid as libc::pid_t;

    if let Err(errno) = close_nonstdio_except(cancellation_fd, output_limit_fd) {
        libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
        let _ = wait_specific(pid);
        let _ = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);
        fail_errno(launch_error, phases.close, errno);
    }

    let (direct_status, timed_out, cancelled, output_limit_exceeded) = wait_direct_target(
        pid,
        wall_clock_milliseconds,
        cancellation_fd,
        output_limit_fd,
        launch_error,
        phases,
    );
    let reaped_descendants = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);
    let (user_cpu_micros, system_cpu_micros, max_child_rss_kib) = match collect_process_tree_usage()
    {
        Ok(usage) => usage,
        Err(errno) => fail_errno(launch_error, phases.usage, errno),
    };

    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).status), direct_status);
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).reaped_descendants),
        reaped_descendants,
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).timed_out),
        u32::from(timed_out),
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).cancelled),
        u32::from(cancelled),
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).output_limit_exceeded),
        u32::from(output_limit_exceeded),
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).user_cpu_micros),
        user_cpu_micros,
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).system_cpu_micros),
        system_cpu_micros,
    );
    ptr::write_volatile(
        ptr::addr_of_mut!((*lifecycle).max_child_rss_kib),
        max_child_rss_kib,
    );
    // Publish readiness last: the host treats ready != 1 as an incomplete
    // process-tree lifecycle and fails closed.
    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).ready), 1);
    raw_exit(0)
}

unsafe fn wait_direct_target(
    pid: libc::pid_t,
    wall_clock_milliseconds: u64,
    cancellation_fd: libc::c_int,
    output_limit_fd: libc::c_int,
    launch_error: *mut LaunchErrorRecord,
    phases: TargetSupervisionPhases,
) -> (libc::c_int, bool, bool, bool) {
    if wall_clock_milliseconds == 0 && cancellation_fd < 0 && output_limit_fd < 0 {
        return match wait_specific(pid) {
            Ok(status) => (status, false, false, false),
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        };
    }

    let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0u32);
    if pidfd == -1 {
        let phase = if output_limit_fd >= 0 {
            phases.output_limit_pidfd
        } else if cancellation_fd >= 0 {
            phases.cancellation_pidfd
        } else {
            phases.pidfd
        };
        fail(launch_error, phase);
    }
    let pidfd = pidfd as libc::c_int;

    let timerfd = if wall_clock_milliseconds == 0 {
        -1
    } else {
        let timerfd = libc::syscall(
            libc::SYS_timerfd_create,
            libc::CLOCK_MONOTONIC,
            libc::TFD_CLOEXEC,
        );
        if timerfd == -1 {
            fail(launch_error, phases.timerfd);
        }
        let timerfd = timerfd as libc::c_int;
        let specification = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: (wall_clock_milliseconds / 1000) as libc::time_t,
                tv_nsec: ((wall_clock_milliseconds % 1000) * 1_000_000) as libc::c_long,
            },
        };
        if libc::syscall(
            libc::SYS_timerfd_settime,
            timerfd,
            0,
            &specification as *const libc::itimerspec,
            ptr::null_mut::<libc::itimerspec>(),
        ) == -1
        {
            fail(launch_error, phases.timer_arm);
        }
        timerfd
    };

    let mut fds = [
        libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: timerfd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: cancellation_fd,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: output_limit_fd,
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        for fd in &mut fds {
            fd.revents = 0;
        }
        let polled = libc::syscall(
            libc::SYS_poll,
            fds.as_mut_ptr(),
            fds.len(),
            -1 as libc::c_int,
        );
        if polled == -1 {
            let errno = *libc::__errno_location();
            if errno == libc::EINTR {
                continue;
            }
            let phase = if output_limit_fd >= 0 {
                phases.output_limit_poll
            } else if cancellation_fd >= 0 {
                phases.cancellation_poll
            } else {
                phases.poll
            };
            fail_errno(launch_error, phase, errno);
        }

        // Once the host has observed bytes beyond the output budget, that
        // policy violation owns the result even if the target became waitable
        // in the same poll cycle. Other control paths preserve natural-exit-first.
        if fds[3].revents & libc::POLLIN != 0 {
            let status = terminate_direct_target(pid, launch_error, phases);
            return (status, false, false, true);
        }

        // One nonblocking reap check remains the race arbiter for ordinary
        // cancellation/deadline supervision.
        match wait_specific_nohang(pid) {
            Ok(Some(status)) => return (status, false, false, false),
            Ok(None) => {}
            Err(errno) => fail_errno(launch_error, phases.reap, errno),
        }

        let invalid_events = libc::POLLERR | libc::POLLNVAL;
        if fds
            .iter()
            .any(|fd| fd.fd >= 0 && fd.revents & invalid_events != 0)
        {
            let phase = if output_limit_fd >= 0 {
                phases.output_limit_poll
            } else if cancellation_fd >= 0 {
                phases.cancellation_poll
            } else {
                phases.poll
            };
            fail_errno(launch_error, phase, libc::EIO);
        }

        if fds[2].revents & libc::POLLIN != 0 {
            let status = terminate_direct_target(pid, launch_error, phases);
            return (status, false, true, false);
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let status = terminate_direct_target(pid, launch_error, phases);
            return (status, true, false, false);
        }
    }
}

unsafe fn terminate_direct_target(
    pid: libc::pid_t,
    launch_error: *mut LaunchErrorRecord,
    phases: TargetSupervisionPhases,
) -> libc::c_int {
    let killed = libc::syscall(libc::SYS_kill, pid, libc::SIGKILL);
    if killed == -1 {
        let errno = *libc::__errno_location();
        if errno != libc::ESRCH {
            fail_errno(launch_error, phases.kill, errno);
        }
    }
    match wait_specific(pid) {
        Ok(status) => status,
        Err(errno) => fail_errno(launch_error, phases.reap, errno),
    }
}

unsafe fn collect_process_tree_usage() -> Result<(u64, u64, u64), i32> {
    let mut usage = std::mem::zeroed::<libc::rusage>();
    let result = libc::syscall(
        libc::SYS_getrusage,
        libc::RUSAGE_CHILDREN,
        &mut usage as *mut libc::rusage,
    );
    if result == -1 {
        return Err(*libc::__errno_location());
    }
    let max_child_rss_kib = if usage.ru_maxrss > 0 {
        usage.ru_maxrss as u64
    } else {
        0
    };
    Ok((
        timeval_to_micros(usage.ru_utime),
        timeval_to_micros(usage.ru_stime),
        max_child_rss_kib,
    ))
}

fn timeval_to_micros(value: libc::timeval) -> u64 {
    let seconds = if value.tv_sec > 0 {
        value.tv_sec as u64
    } else {
        0
    };
    let micros = if value.tv_usec > 0 {
        value.tv_usec as u64
    } else {
        0
    };
    seconds
        .saturating_mul(1_000_000)
        .saturating_add(micros.min(999_999))
}

unsafe fn close_nonstdio_except(keep_a: libc::c_int, keep_b: libc::c_int) -> Result<(), i32> {
    let mut keep = [keep_a, keep_b];
    keep.sort_unstable();
    let mut cursor = 3u64;
    let mut previous = -1;
    for fd in keep {
        if fd < 3 || fd == previous {
            continue;
        }
        previous = fd;
        let keep_fd = fd as u32;
        if cursor < u64::from(keep_fd)
            && libc::syscall(libc::SYS_close_range, cursor as u32, keep_fd - 1, 0u32) == -1
        {
            return Err(*libc::__errno_location());
        }
        cursor = u64::from(keep_fd) + 1;
    }
    if cursor <= u64::from(u32::MAX)
        && libc::syscall(libc::SYS_close_range, cursor as u32, u32::MAX, 0u32) == -1
    {
        return Err(*libc::__errno_location());
    }
    Ok(())
}

unsafe fn wait_specific_nohang(pid: libc::pid_t) -> Result<Option<libc::c_int>, i32> {
    loop {
        let mut status = 0;
        let waited = libc::syscall(
            libc::SYS_wait4,
            pid,
            &mut status as *mut libc::c_int,
            libc::WNOHANG,
            ptr::null_mut::<libc::rusage>(),
        );
        if waited == pid as libc::c_long {
            return Ok(Some(status));
        }
        if waited == 0 {
            return Ok(None);
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
