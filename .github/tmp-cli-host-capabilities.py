from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


Path("src/host_capabilities.rs").write_text(r'''use std::fmt::Write as _;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapabilityProbe {
    available: bool,
    errno: Option<i32>,
}

impl CapabilityProbe {
    const fn available() -> Self {
        Self {
            available: true,
            errno: None,
        }
    }

    const fn unavailable(errno: Option<i32>) -> Self {
        Self {
            available: false,
            errno,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostCapabilities {
    target_os: &'static str,
    target_arch: &'static str,
    sandbox_target_supported: bool,
    landlock_abi: Option<u32>,
    landlock_errno: Option<i32>,
    pidfd_open: CapabilityProbe,
    timerfd_monotonic: CapabilityProbe,
    cgroup_v2: bool,
}

pub(crate) fn probe() -> HostCapabilities {
    let (landlock_abi, landlock_errno, pidfd_open, timerfd_monotonic, cgroup_v2) =
        platform_probes();
    HostCapabilities {
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        sandbox_target_supported: cfg!(all(target_os = "linux", target_arch = "x86_64")),
        landlock_abi,
        landlock_errno,
        pidfd_open,
        timerfd_monotonic,
        cgroup_v2,
    }
}

impl HostCapabilities {
    pub(crate) fn to_json(&self) -> String {
        let mut output = String::from(
            "{\"ok\":true,\"host\":{\"kind\":\"runtime_capabilities\",\"policy_preflight\":false,\"target_os\":\"",
        );
        output.push_str(self.target_os);
        output.push_str("\",\"target_arch\":\"");
        output.push_str(self.target_arch);
        output.push_str("\",\"sandbox_target_supported\":");
        output.push_str(bool_json(self.sandbox_target_supported));
        output.push_str(",\"landlock\":{\"abi\":");
        push_optional_u32(&mut output, self.landlock_abi);
        output.push_str(",\"errno\":");
        push_optional_i32(&mut output, self.landlock_errno);
        output.push_str("},\"pidfd_open\":");
        push_probe_json(&mut output, self.pidfd_open);
        output.push_str(",\"timerfd_monotonic\":");
        push_probe_json(&mut output, self.timerfd_monotonic);
        output.push_str(",\"cgroup_v2\":{\"present\":");
        output.push_str(bool_json(self.cgroup_v2));
        output.push_str("}}}");
        output
    }

    pub(crate) fn to_human(&self) -> String {
        let mut output = String::from("host-capabilities:\n");
        writeln!(&mut output, "target: {}/{}", self.target_os, self.target_arch)
            .expect("write to String cannot fail");
        writeln!(
            &mut output,
            "sandbox-target-supported: {}",
            self.sandbox_target_supported
        )
        .expect("write to String cannot fail");
        output.push_str("landlock-abi: ");
        match self.landlock_abi {
            Some(abi) => writeln!(&mut output, "{abi}").expect("write to String cannot fail"),
            None => {
                output.push_str("unavailable");
                if let Some(errno) = self.landlock_errno {
                    write!(&mut output, " (errno={errno})").expect("write to String cannot fail");
                }
                output.push('\n');
            }
        }
        push_probe_human(&mut output, "pidfd-open", self.pidfd_open);
        push_probe_human(&mut output, "timerfd-monotonic", self.timerfd_monotonic);
        writeln!(
            &mut output,
            "cgroup-v2: {}",
            if self.cgroup_v2 { "present" } else { "absent" }
        )
        .expect("write to String cannot fail");
        output.push_str("policy-preflight: false\n");
        output
    }
}

fn bool_json(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

fn push_optional_u32(output: &mut String, value: Option<u32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("null"),
    }
}

fn push_optional_i32(output: &mut String, value: Option<i32>) {
    match value {
        Some(value) => write!(output, "{value}").expect("write to String cannot fail"),
        None => output.push_str("null"),
    }
}

fn push_probe_json(output: &mut String, probe: CapabilityProbe) {
    output.push_str("{\"available\":");
    output.push_str(bool_json(probe.available));
    output.push_str(",\"errno\":");
    push_optional_i32(output, probe.errno);
    output.push('}');
}

fn push_probe_human(output: &mut String, label: &str, probe: CapabilityProbe) {
    write!(output, "{label}: ").expect("write to String cannot fail");
    if probe.available {
        output.push_str("available\n");
    } else {
        output.push_str("unavailable");
        if let Some(errno) = probe.errno {
            write!(output, " (errno={errno})").expect("write to String cannot fail");
        }
        output.push('\n');
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn platform_probes() -> (
    Option<u32>,
    Option<i32>,
    CapabilityProbe,
    CapabilityProbe,
    bool,
) {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

    let landlock_result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    let (landlock_abi, landlock_errno) = if landlock_result >= 0 {
        (Some(landlock_result as u32), None)
    } else {
        (None, std::io::Error::last_os_error().raw_os_error())
    };

    let pidfd_result = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0u32) };
    let pidfd_open = fd_probe(pidfd_result);

    let timerfd_result = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
    let timerfd_monotonic = fd_probe(timerfd_result as libc::c_long);

    (
        landlock_abi,
        landlock_errno,
        pidfd_open,
        timerfd_monotonic,
        Path::new("/sys/fs/cgroup/cgroup.controllers").is_file(),
    )
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn platform_probes() -> (
    Option<u32>,
    Option<i32>,
    CapabilityProbe,
    CapabilityProbe,
    bool,
) {
    (
        None,
        None,
        CapabilityProbe::unavailable(None),
        CapabilityProbe::unavailable(None),
        false,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn fd_probe(result: libc::c_long) -> CapabilityProbe {
    if result < 0 {
        CapabilityProbe::unavailable(std::io::Error::last_os_error().raw_os_error())
    } else {
        let fd = result as libc::c_int;
        let close_result = unsafe { libc::close(fd) };
        if close_result == 0 {
            CapabilityProbe::available()
        } else {
            CapabilityProbe::unavailable(std::io::Error::last_os_error().raw_os_error())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> HostCapabilities {
        HostCapabilities {
            target_os: "linux",
            target_arch: "x86_64",
            sandbox_target_supported: true,
            landlock_abi: Some(7),
            landlock_errno: None,
            pidfd_open: CapabilityProbe::available(),
            timerfd_monotonic: CapabilityProbe::unavailable(Some(38)),
            cgroup_v2: true,
        }
    }

    #[test]
    fn serializes_capability_snapshot_without_implying_policy_preflight() {
        assert_eq!(
            fixture().to_json(),
            "{\"ok\":true,\"host\":{\"kind\":\"runtime_capabilities\",\"policy_preflight\":false,\"target_os\":\"linux\",\"target_arch\":\"x86_64\",\"sandbox_target_supported\":true,\"landlock\":{\"abi\":7,\"errno\":null},\"pidfd_open\":{\"available\":true,\"errno\":null},\"timerfd_monotonic\":{\"available\":false,\"errno\":38},\"cgroup_v2\":{\"present\":true}}}"
        );
    }

    #[test]
    fn formats_human_capability_snapshot_with_probe_errors() {
        assert_eq!(
            fixture().to_human(),
            "host-capabilities:\ntarget: linux/x86_64\nsandbox-target-supported: true\nlandlock-abi: 7\npidfd-open: available\ntimerfd-monotonic: unavailable (errno=38)\ncgroup-v2: present\npolicy-preflight: false\n"
        );
    }
}
''')

replace_one(
    "src/main.rs",
    "mod cli_json;\n",
    "mod cli_json;\nmod host_capabilities;\n",
    "main module declaration",
)

replace_one(
    "src/main.rs",
    '''    let run_json_requested = command.as_deref() == Some(OsStr::new("run-json"));
    let run_requested = command.as_deref() == Some(OsStr::new("run"));
    let check_json_requested = command.as_deref() == Some(OsStr::new("check-json"));
    let check_requested = command.as_deref() == Some(OsStr::new("check"));
    let machine_requested = run_json_requested || check_json_requested;
    let recognized_command =
        run_json_requested || run_requested || check_json_requested || check_requested;

    if !recognized_command || policy_path.is_none() || has_extra_args {
        let usage = format!(
            "usage: {} <run|run-json|check|check-json> <policy-file>",
            program.to_string_lossy()
        );
''',
    '''    let run_json_requested = command.as_deref() == Some(OsStr::new("run-json"));
    let run_requested = command.as_deref() == Some(OsStr::new("run"));
    let check_json_requested = command.as_deref() == Some(OsStr::new("check-json"));
    let check_requested = command.as_deref() == Some(OsStr::new("check"));
    let host_json_requested = command.as_deref() == Some(OsStr::new("host-json"));
    let host_requested = command.as_deref() == Some(OsStr::new("host"));
    let host_command = host_json_requested || host_requested;
    let machine_requested = run_json_requested || check_json_requested || host_json_requested;
    let recognized_command = run_json_requested
        || run_requested
        || check_json_requested
        || check_requested
        || host_json_requested
        || host_requested;
    let invalid_shape = if host_command {
        policy_path.is_some() || has_extra_args
    } else {
        policy_path.is_none() || has_extra_args
    };

    if !recognized_command || invalid_shape {
        let display_program = program.to_string_lossy();
        let usage = format!(
            "usage: {display_program} <run|run-json|check|check-json> <policy-file> | {display_program} <host|host-json>"
        );
''',
    "main command dispatch",
)

replace_one(
    "src/main.rs",
    '''    let policy_path = policy_path.expect("policy path was checked above");
''',
    '''    if host_json_requested {
        println!("{}", host_capabilities::probe().to_json());
        return;
    }
    if host_requested {
        print!("{}", host_capabilities::probe().to_human());
        return;
    }

    let policy_path = policy_path.expect("policy path was checked above");
''',
    "main host dispatch",
)

with Path("tests/cli.rs").open("a") as out:
    out.write(r'''

#[test]
fn host_json_reports_runtime_capabilities_without_reading_policy() {
    let output = Command::new(binary())
        .arg("host-json")
        .output()
        .expect("run host capability JSON CLI");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("host JSON stdout is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":true,\"host\":{\"kind\":\"runtime_capabilities\",\"policy_preflight\":false,\"target_os\":\"linux\",\"target_arch\":\"x86_64\",\"sandbox_target_supported\":true,\"landlock\":{\"abi\":"
    ));
    assert!(stdout.contains("\"pidfd_open\":{\"available\":true,\"errno\":null}"));
    assert!(stdout.contains(
        "\"timerfd_monotonic\":{\"available\":true,\"errno\":null}"
    ));
    assert!(stdout.contains("\"cgroup_v2\":{\"present\":true}"));
    assert!(stdout.ends_with("}}}\n"));
}

#[test]
fn host_human_report_is_explicitly_not_policy_preflight() {
    let output = Command::new(binary())
        .arg("host")
        .output()
        .expect("run host capability CLI");

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("host CLI stdout is UTF-8");
    assert!(stdout.starts_with(
        "host-capabilities:\ntarget: linux/x86_64\nsandbox-target-supported: true\nlandlock-abi: "
    ));
    assert!(stdout.contains("\npidfd-open: available\n"));
    assert!(stdout.contains("timerfd-monotonic: available\n"));
    assert!(stdout.contains("cgroup-v2: present\n"));
    assert!(stdout.ends_with("policy-preflight: false\n"));
}

#[test]
fn host_json_rejects_policy_argument_as_machine_usage_error() {
    let output = Command::new(binary())
        .args(["host-json", "unexpected-policy.conf"])
        .output()
        .expect("run malformed host capability invocation");

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("host usage JSON stdout is UTF-8");
    assert!(stdout.starts_with(
        "{\"ok\":false,\"error\":{\"kind\":\"usage\",\"message\":"
    ));
    assert!(stdout.contains("<host|host-json>"));
    assert!(stdout.ends_with("}}\n"));
}
''')
