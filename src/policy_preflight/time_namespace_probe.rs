#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TimeNamespaceProbe {
    pub(super) available: bool,
    pub(super) errno: Option<i32>,
    pub(super) stage: &'static str,
    pub(super) monotonic_offset_seconds: u64,
    pub(super) boottime_offset_seconds: u64,
}

impl TimeNamespaceProbe {
    pub(super) const fn available(
        monotonic_offset_seconds: u64,
        boottime_offset_seconds: u64,
    ) -> Self {
        Self {
            available: true,
            errno: None,
            stage: "complete",
            monotonic_offset_seconds,
            boottime_offset_seconds,
        }
    }

    pub(super) const fn unavailable(
        stage: &'static str,
        errno: Option<i32>,
        monotonic_offset_seconds: u64,
        boottime_offset_seconds: u64,
    ) -> Self {
        Self {
            available: false,
            errno,
            stage,
            monotonic_offset_seconds,
            boottime_offset_seconds,
        }
    }
}

pub(super) fn probe(
    monotonic_offset_seconds: u64,
    boottime_offset_seconds: u64,
) -> TimeNamespaceProbe {
    platform_probe(monotonic_offset_seconds, boottime_offset_seconds)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const CLONE_NEWTIME: libc::c_int = 0x0000_0080;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct ProbeReport {
    stage: i32,
    errno: i32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Clone, Copy)]
struct ClockObservation {
    errno: i32,
    monotonic_seconds: i64,
    monotonic_nanoseconds: i64,
    boottime_seconds: i64,
    boottime_nanoseconds: i64,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_probe(
    monotonic_offset_seconds: u64,
    boottime_offset_seconds: u64,
) -> TimeNamespaceProbe {
    let uid_map = format!("0 {} 1\n", unsafe { libc::geteuid() });
    let gid_map = format!("0 {} 1\n", unsafe { libc::getegid() });
    let monotonic = format!("monotonic {monotonic_offset_seconds} 0\n");
    let boottime = format!("boottime {boottime_offset_seconds} 0\n");

    let mut report_pipe = [-1; 2];
    if unsafe { libc::pipe2(report_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return TimeNamespaceProbe::unavailable(
            "probe_pipe",
            std::io::Error::last_os_error().raw_os_error(),
            monotonic_offset_seconds,
            boottime_offset_seconds,
        );
    }

    let child = unsafe { libc::fork() };
    if child < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error();
        unsafe {
            libc::close(report_pipe[0]);
            libc::close(report_pipe[1]);
        }
        return TimeNamespaceProbe::unavailable(
            "probe_fork",
            errno,
            monotonic_offset_seconds,
            boottime_offset_seconds,
        );
    }
    if child == 0 {
        unsafe {
            libc::close(report_pipe[0]);
            probe_child(
                report_pipe[1],
                uid_map.as_bytes(),
                gid_map.as_bytes(),
                monotonic.as_bytes(),
                boottime.as_bytes(),
                monotonic_offset_seconds,
                boottime_offset_seconds,
            );
        }
    }

    unsafe {
        libc::close(report_pipe[1]);
    }
    let report = read_exact_struct::<ProbeReport>(report_pipe[0]);
    unsafe {
        libc::close(report_pipe[0]);
    }

    let mut status = 0;
    let waited = waitpid_retry(child, &mut status);
    if waited != child {
        return TimeNamespaceProbe::unavailable(
            "probe_wait",
            std::io::Error::last_os_error().raw_os_error(),
            monotonic_offset_seconds,
            boottime_offset_seconds,
        );
    }

    match report {
        Some(ProbeReport { stage: 0, errno: 0 })
            if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 =>
        {
            TimeNamespaceProbe::available(monotonic_offset_seconds, boottime_offset_seconds)
        }
        Some(report) => TimeNamespaceProbe::unavailable(
            stage_name(report.stage),
            if report.errno == 0 {
                None
            } else {
                Some(report.errno)
            },
            monotonic_offset_seconds,
            boottime_offset_seconds,
        ),
        None => TimeNamespaceProbe::unavailable(
            "probe_child",
            None,
            monotonic_offset_seconds,
            boottime_offset_seconds,
        ),
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_probe(
    monotonic_offset_seconds: u64,
    boottime_offset_seconds: u64,
) -> TimeNamespaceProbe {
    TimeNamespaceProbe::unavailable(
        "unsupported_target",
        None,
        monotonic_offset_seconds,
        boottime_offset_seconds,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn stage_name(stage: i32) -> &'static str {
    match stage {
        10 => "time_namespace_unshare",
        11 => "setgroups_deny",
        12 => "uid_map",
        13 => "gid_map",
        14 => "timens_monotonic",
        15 => "timens_boottime",
        16 => "clock_baseline",
        17 => "observation_pipe",
        18 => "time_child_fork",
        19 => "clock_observation",
        20 => "time_child_wait",
        21 => "offset_oracle",
        _ => "unknown_stage",
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn probe_child(
    report_fd: libc::c_int,
    uid_map: &[u8],
    gid_map: &[u8],
    monotonic: &[u8],
    boottime: &[u8],
    monotonic_offset_seconds: u64,
    boottime_offset_seconds: u64,
) -> ! {
    if libc::syscall(libc::SYS_unshare, libc::CLONE_NEWUSER | CLONE_NEWTIME) == -1 {
        fail(report_fd, 10, errno());
    }
    write_file(report_fd, 11, b"/proc/self/setgroups\0", b"deny\n");
    write_file(report_fd, 12, b"/proc/self/uid_map\0", uid_map);
    write_file(report_fd, 13, b"/proc/self/gid_map\0", gid_map);
    write_file(report_fd, 14, b"/proc/self/timens_offsets\0", monotonic);
    write_file(report_fd, 15, b"/proc/self/timens_offsets\0", boottime);

    let monotonic_before = clock_nanos_or_fail(report_fd, 16, libc::CLOCK_MONOTONIC);
    let boottime_before = clock_nanos_or_fail(report_fd, 16, libc::CLOCK_BOOTTIME);

    let mut observation_pipe = [-1; 2];
    if libc::pipe2(observation_pipe.as_mut_ptr(), libc::O_CLOEXEC) != 0 {
        fail(report_fd, 17, errno());
    }
    let observer = libc::fork();
    if observer < 0 {
        fail(report_fd, 18, errno());
    }
    if observer == 0 {
        libc::close(observation_pipe[0]);
        let mut monotonic_ts = std::mem::zeroed::<libc::timespec>();
        let mut boottime_ts = std::mem::zeroed::<libc::timespec>();
        let monotonic_result = libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotonic_ts);
        let monotonic_errno = if monotonic_result == 0 { 0 } else { errno() };
        let boottime_result = libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boottime_ts);
        let boottime_errno = if boottime_result == 0 { 0 } else { errno() };
        let observation = ClockObservation {
            errno: if monotonic_errno != 0 {
                monotonic_errno
            } else {
                boottime_errno
            },
            monotonic_seconds: monotonic_ts.tv_sec,
            monotonic_nanoseconds: monotonic_ts.tv_nsec,
            boottime_seconds: boottime_ts.tv_sec,
            boottime_nanoseconds: boottime_ts.tv_nsec,
        };
        write_struct_or_exit(observation_pipe[1], &observation);
        libc::_exit(if observation.errno == 0 { 0 } else { 1 });
    }

    libc::close(observation_pipe[1]);
    let observation = read_exact_struct::<ClockObservation>(observation_pipe[0]);
    libc::close(observation_pipe[0]);
    let Some(observation) = observation else {
        fail(report_fd, 19, 0);
    };
    if observation.errno != 0 {
        fail(report_fd, 19, observation.errno);
    }

    let mut observer_status = 0;
    if waitpid_retry(observer, &mut observer_status) != observer {
        fail(report_fd, 20, errno());
    }
    if !libc::WIFEXITED(observer_status) || libc::WEXITSTATUS(observer_status) != 0 {
        fail(report_fd, 20, 0);
    }

    let monotonic_after = clock_nanos_or_fail(report_fd, 16, libc::CLOCK_MONOTONIC);
    let boottime_after = clock_nanos_or_fail(report_fd, 16, libc::CLOCK_BOOTTIME);
    let observed_monotonic =
        timespec_parts_nanos(observation.monotonic_seconds, observation.monotonic_nanoseconds);
    let observed_boottime =
        timespec_parts_nanos(observation.boottime_seconds, observation.boottime_nanoseconds);
    let monotonic_adjusted =
        observed_monotonic - i128::from(monotonic_offset_seconds) * 1_000_000_000;
    let boottime_adjusted =
        observed_boottime - i128::from(boottime_offset_seconds) * 1_000_000_000;

    if monotonic_adjusted < monotonic_before
        || monotonic_adjusted > monotonic_after
        || boottime_adjusted < boottime_before
        || boottime_adjusted > boottime_after
    {
        fail(report_fd, 21, 0);
    }

    let success = ProbeReport { stage: 0, errno: 0 };
    write_struct_or_exit(report_fd, &success);
    libc::_exit(0);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn clock_nanos_or_fail(
    report_fd: libc::c_int,
    stage: i32,
    clock: libc::clockid_t,
) -> i128 {
    let mut value = std::mem::zeroed::<libc::timespec>();
    if libc::clock_gettime(clock, &mut value) != 0 {
        fail(report_fd, stage, errno());
    }
    timespec_parts_nanos(value.tv_sec, value.tv_nsec)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn timespec_parts_nanos(seconds: i64, nanoseconds: i64) -> i128 {
    i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_file(
    report_fd: libc::c_int,
    stage: i32,
    path: &'static [u8],
    bytes: &[u8],
) {
    let fd = libc::open(
        path.as_ptr().cast::<libc::c_char>(),
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        fail(report_fd, stage, errno());
    }
    if !write_all(fd, bytes.as_ptr(), bytes.len()) {
        let error = errno();
        libc::close(fd);
        fail(report_fd, stage, error);
    }
    if libc::close(fd) != 0 {
        fail(report_fd, stage, errno());
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn fail(report_fd: libc::c_int, stage: i32, error: i32) -> ! {
    let report = ProbeReport {
        stage,
        errno: error,
    };
    write_struct_or_exit(report_fd, &report);
    libc::_exit(1);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_struct_or_exit<T>(fd: libc::c_int, value: &T) {
    let _ = write_all(
        fd,
        (value as *const T).cast::<u8>(),
        std::mem::size_of::<T>(),
    );
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn write_all(fd: libc::c_int, mut bytes: *const u8, mut remaining: usize) -> bool {
    while remaining != 0 {
        let written = libc::write(fd, bytes.cast(), remaining);
        if written < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        if written == 0 {
            return false;
        }
        bytes = bytes.add(written as usize);
        remaining -= written as usize;
    }
    true
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_exact_struct<T: Copy>(fd: libc::c_int) -> Option<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut offset = 0usize;
    let total = std::mem::size_of::<T>();
    while offset < total {
        let read = unsafe {
            libc::read(
                fd,
                value.as_mut_ptr().cast::<u8>().add(offset).cast(),
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
    Some(unsafe { value.assume_init() })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn waitpid_retry(pid: libc::pid_t, status: &mut libc::c_int) -> libc::pid_t {
    loop {
        let waited = unsafe { libc::waitpid(pid, status, 0) };
        if waited < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return waited;
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}
