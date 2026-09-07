from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Wire an independent, read-only configured-filesystem evidence source into
# policy preflight without upgrading the complete mandatory launch core.
replace_one(
    "src/policy_preflight.rs",
    "mod mandatory_core_probe;\n\nuse crate::host_capabilities",
    "mod configured_filesystem_probe;\nmod mandatory_core_probe;\n\nuse crate::host_capabilities",
    "preflight module declaration",
)
replace_one(
    "src/policy_preflight.rs",
    "use mandatory_core_probe::StagedCapabilityProbe;\n",
    "use configured_filesystem_probe::ConfiguredFilesystemProbe;\nuse mandatory_core_probe::StagedCapabilityProbe;\n",
    "configured filesystem import",
)
replace_one(
    "src/policy_preflight.rs",
    "    mandatory_launch_core: RequirementStatus,\n    mandatory_namespace_mount_core: Option<StagedCapabilityProbe>,\n",
    "    mandatory_launch_core: RequirementStatus,\n    configured_filesystem: Option<ConfiguredFilesystemProbe>,\n    mandatory_namespace_mount_core: Option<StagedCapabilityProbe>,\n",
    "preflight configured filesystem field",
)
replace_one(
    "src/policy_preflight.rs",
    "pub(crate) fn probe(policy: &SandboxPolicy) -> PolicyPreflight {\n    let mut evaluated = evaluate(policy, host_capabilities::probe());\n    evaluated.mandatory_namespace_mount_core = Some(mandatory_core_probe::probe());\n    evaluated\n}\n",
    "pub(crate) fn probe(policy: &SandboxPolicy) -> PolicyPreflight {\n    let mut evaluated = evaluate(policy, host_capabilities::probe());\n    evaluated.configured_filesystem = Some(configured_filesystem_probe::probe(policy));\n    evaluated.mandatory_namespace_mount_core = Some(mandatory_core_probe::probe());\n    evaluated\n}\n",
    "production configured filesystem probe",
)
replace_one(
    "src/policy_preflight.rs",
    "        requirements: PolicyRequirements::from_policy(policy),\n        mandatory_launch_core,\n        mandatory_namespace_mount_core: None,\n",
    "        requirements: PolicyRequirements::from_policy(policy),\n        mandatory_launch_core,\n        configured_filesystem: None,\n        mandatory_namespace_mount_core: None,\n",
    "synthetic evaluator configured filesystem default",
)
replace_one(
    "src/policy_preflight.rs",
    "            || self.mandatory_launch_core_status() == RequirementStatus::Unsupported\n            || self.landlock_status() == RequirementStatus::Unsupported\n",
    "            || self.mandatory_launch_core_status() == RequirementStatus::Unsupported\n            || matches!(self.configured_filesystem, Some(probe) if !probe.available)\n            || self.landlock_status() == RequirementStatus::Unsupported\n",
    "configured filesystem incompatibility verdict",
)
replace_one(
    "src/policy_preflight.rs",
    "        output.push('}');\n        if let Some(probe) = self.mandatory_namespace_mount_core {\n",
    "        output.push('}');\n        if let Some(probe) = self.configured_filesystem {\n            output.push_str(\",\\\"configured_filesystem_probe\\\":\");\n            push_configured_filesystem_probe_json(&mut output, probe);\n        }\n        if let Some(probe) = self.mandatory_namespace_mount_core {\n",
    "configured filesystem JSON field",
)
replace_one(
    "src/policy_preflight.rs",
    "        output.push('\\n');\n        if let Some(probe) = self.mandatory_namespace_mount_core {\n",
    "        output.push('\\n');\n        if let Some(probe) = self.configured_filesystem {\n            output.push_str(\"configured-filesystem-probe: \" );\n            if probe.available {\n                writeln!(\n                    &mut output,\n                    \"supported (stage={} read-only=true namespaces-created=false target-executed=false)\",\n                    probe.stage\n                )\n                .expect(\"write to String cannot fail\");\n            } else {\n                write!(\n                    &mut output,\n                    \"unsupported (stage={} read-only=true namespaces-created=false target-executed=false\",\n                    probe.stage\n                )\n                .expect(\"write to String cannot fail\");\n                if let Some(errno) = probe.errno {\n                    write!(&mut output, \" errno={errno}\").expect(\"write to String cannot fail\");\n                }\n                output.push_str(\")\\n\");\n            }\n        }\n        if let Some(probe) = self.mandatory_namespace_mount_core {\n",
    "configured filesystem human field",
)
replace_one(
    "src/policy_preflight.rs",
    "fn push_staged_probe_json(output: &mut String, probe: StagedCapabilityProbe) {\n",
    "fn push_configured_filesystem_probe_json(\n    output: &mut String,\n    probe: ConfiguredFilesystemProbe,\n) {\n    output.push_str(\"{\\\"status\\\":\\\"\");\n    output.push_str(if probe.available {\n        \"supported\"\n    } else {\n        \"unsupported\"\n    });\n    output.push_str(\"\\\",\\\"stage\\\":\\\"\");\n    output.push_str(probe.stage);\n    output.push_str(\"\\\",\\\"errno\\\":\");\n    push_optional_i32(output, probe.errno);\n    output.push_str(\n        \",\\\"read_only\\\":true,\\\"namespaces_created\\\":false,\\\"target_executed\\\":false}\",\n    );\n}\n\nfn push_staged_probe_json(output: &mut String, probe: StagedCapabilityProbe) {\n",
    "configured filesystem JSON renderer",
)

configured_probe = r'''use security_lab::SandboxPolicy;

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
        io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
    }

    fn cstring(path: &Path) -> Result<CString, i32> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| libc::EINVAL)
    }

    fn sandbox_relative(path: &Path) -> Result<CString, i32> {
        let relative = path.strip_prefix(Path::new("/")).map_err(|_| libc::EINVAL)?;
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
'''
Path("src/policy_preflight/configured_filesystem_probe.rs").write_text(configured_probe)

# The generic CLI preflight tests need a real read-only filesystem fixture now
# that production preflight intentionally inspects configured anchors. Static
# check/check-json tests keep their deliberately nonexistent root.
replace_one(
    "tests/cli.rs",
    "use std::path::{Path, PathBuf};\nuse std::process::{self, Command};\n",
    "use std::os::unix::fs::PermissionsExt;\nuse std::path::{Path, PathBuf};\nuse std::process::{self, Command};\n",
    "CLI permissions import",
)
replace_one(
    "tests/cli.rs",
    "fn binary() -> &'static str {\n    env!(\"CARGO_BIN_EXE_security-lab\")\n}\n",
    '''fn preflight_policy(label: &str) -> (String, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "security-lab-cli-preflight-root-{}-{label}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("bin")).expect("create preflight bin directory");
    fs::create_dir_all(root.join("work")).expect("create preflight work directory");
    let executable = root.join("bin/probe");
    fs::write(&executable, b"preflight-only-not-executed\\n").expect("write preflight executable");
    let mut permissions = fs::metadata(&executable)
        .expect("stat preflight executable")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("chmod preflight executable");

    let policy = format!(
        "filesystem.root = {}\\nidentity.hostname = preflight\\nexecutable = /bin/probe\\nworking_dir = /work\\nstdio.stdin = closed\\nstdio.stdout = capture\\nstdio.stdout_capture_bytes = 4096\\nstdio.stderr = closed\\nlimit.cpu_seconds = 1\\nlimit.address_space_bytes = 67108864\\nlimit.file_size_bytes = 1048576\\nlimit.open_files = 32\\nseccomp.allow = execveat,exit\\n",
        root.display()
    );
    (policy, root)
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}
''',
    "CLI preflight fixture helper",
)

for label in [
    "preflight_json_remains_indeterminate_without_mandatory_core_probe",
    "preflight_json_marks_requested_time_namespace_unprobed",
    "preflight_human_report_exposes_partial_scope",
]:
    marker = f"fn {label}() {{\n    let (policy, missing_root) = static_only_policy();"
    replacement = f"fn {label}() {{\n    let (policy, root) = preflight_policy(\"{label}\");"
    replace_one("tests/cli.rs", marker, replacement, f"{label} fixture")

replace_one(
    "tests/cli.rs",
    '''    assert!(
        !missing_root.exists(),
        "preflight must not materialize runtime root state"
    );
}''',
    '''    assert_eq!(
        fs::read(root.join("bin/probe")).expect("read preflight executable after probe"),
        b"preflight-only-not-executed\\n"
    );
    let _ = fs::remove_dir_all(root);
}''',
    "known preflight cleanup",
)
replace_one(
    "tests/cli.rs",
    '''    assert!(
        !missing_root.exists(),
        "indeterminate preflight must not launch the sandbox"
    );
}''',
    '''    assert_eq!(
        fs::read(root.join("bin/probe")).expect("read time-preflight executable after probe"),
        b"preflight-only-not-executed\\n"
    );
    let _ = fs::remove_dir_all(root);
}''',
    "time preflight cleanup",
)
replace_one(
    "tests/cli.rs",
    "    assert!(stdout.contains(\"time-namespace: not_requested\\n\"));\n    assert!(!missing_root.exists());\n}\n",
    "    assert!(stdout.contains(\"time-namespace: not_requested\\n\"));\n    assert_eq!(\n        fs::read(root.join(\"bin/probe\")).expect(\"read human-preflight executable after probe\"),\n        b\"preflight-only-not-executed\\n\"\n    );\n    let _ = fs::remove_dir_all(root);\n}\n",
    "human preflight cleanup",
)

core_cli = r'''#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{self, Command};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_security-lab")
}

fn policy_path(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "security-lab-preflight-core-policy-{}-{label}.conf",
        process::id()
    ))
}

#[test]
fn missing_configured_root_is_known_incompatible_without_materialization() {
    let missing_root = std::env::temp_dir().join(format!(
        "security-lab-preflight-core-missing-root-{}",
        process::id()
    ));
    let _ = fs::remove_dir_all(&missing_root);
    let policy_path = policy_path("missing-root");
    let _ = fs::remove_file(&policy_path);
    let policy = format!(
        "filesystem.root = {}\nidentity.hostname = preflight-core\nexecutable = /bin/true\nworking_dir = /\nstdio.stdin = closed\nstdio.stdout = closed\nstdio.stderr = closed\nlimit.cpu_seconds = 1\nlimit.address_space_bytes = 67108864\nlimit.file_size_bytes = 1048576\nlimit.open_files = 32\nseccomp.allow = execveat,exit\n",
        missing_root.display()
    );
    fs::write(&policy_path, policy).expect("write preflight policy");

    let output = Command::new(binary())
        .args([
            "preflight-json",
            policy_path.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run configured filesystem preflight");
    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains("\"status\":\"incompatible\""));
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"configured_filesystem_probe\":{\"status\":\"unsupported\",\"stage\":\"root_open\",\"errno\":2,\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}"
    ));
    assert!(stdout.contains(
        "\"mandatory_namespace_mount_core_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}"
    ));
    assert!(
        !missing_root.exists(),
        "configured filesystem preflight may inspect but must never materialize a missing root"
    );
}

#[test]
fn configured_filesystem_anchors_are_positively_probed_without_launch() {
    let root = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-root-{}",
        process::id()
    ));
    let readonly_source = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-readonly-{}",
        process::id()
    ));
    let writable_source = std::env::temp_dir().join(format!(
        "security-lab-preflight-filesystem-writable-{}",
        process::id()
    ));
    for path in [&root, &readonly_source, &writable_source] {
        let _ = fs::remove_dir_all(path);
    }
    for relative in ["bin", "work", "scratch", "proc", "data", "persist"] {
        fs::create_dir_all(root.join(relative)).expect("create configured filesystem anchor");
    }
    fs::create_dir_all(&readonly_source).expect("create read-only volume source");
    fs::create_dir_all(&writable_source).expect("create writable volume source");
    fs::write(readonly_source.join("marker"), b"readonly-marker\n")
        .expect("write read-only source marker");
    fs::write(writable_source.join("marker"), b"writable-marker\n")
        .expect("write writable source marker");

    let executable = root.join("bin/probe");
    fs::write(&executable, b"preflight-executable-not-run\n").expect("write executable anchor");
    let mut permissions = fs::metadata(&executable)
        .expect("stat executable anchor")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("chmod executable anchor");

    let policy_path = policy_path("positive-filesystem");
    let _ = fs::remove_file(&policy_path);
    let policy = format!(
        "filesystem.root = {}\nidentity.hostname = preflight-filesystem\nfilesystem.scratch = /scratch\nfilesystem.scratch_bytes = 4096\nfilesystem.proc = enabled\nvolume.readonly_source = {}\nvolume.readonly_target = /data\nvolume.writable_source = {}\nvolume.writable_target = /persist\nexecutable = /bin/probe\nworking_dir = /work\nstdio.stdin = closed\nstdio.stdout = closed\nstdio.stderr = closed\nlimit.cpu_seconds = 1\nlimit.address_space_bytes = 67108864\nlimit.file_size_bytes = 1048576\nlimit.open_files = 32\nseccomp.allow = execveat,exit\n",
        root.display(),
        readonly_source.display(),
        writable_source.display(),
    );
    fs::write(&policy_path, policy).expect("write positive filesystem preflight policy");

    let output = Command::new(binary())
        .args([
            "preflight-json",
            policy_path.to_str().expect("UTF-8 policy path"),
        ])
        .output()
        .expect("run positive configured filesystem preflight");
    let _ = fs::remove_file(&policy_path);

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stderr.is_empty());
    let stdout = String::from_utf8(output.stdout).expect("preflight JSON is UTF-8");
    assert!(stdout.contains("\"status\":\"indeterminate\""));
    assert!(stdout.contains(
        "\"configured_filesystem_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"read_only\":true,\"namespaces_created\":false,\"target_executed\":false}"
    ));
    assert!(stdout.contains(
        "\"mandatory_launch_core\":{\"status\":\"unprobed\",\"reason\":\"mandatory_runtime_prerequisites_not_probed\"}"
    ));
    assert!(stdout.contains(
        "\"mandatory_namespace_mount_core_probe\":{\"status\":\"supported\",\"stage\":\"complete\",\"errno\":null,\"isolated_helper\":true,\"configured_root_touched\":false,\"target_executed\":false}"
    ));
    assert_eq!(
        fs::read(&executable).expect("read executable after preflight"),
        b"preflight-executable-not-run\n"
    );
    assert_eq!(
        fs::read(readonly_source.join("marker")).expect("read read-only marker after preflight"),
        b"readonly-marker\n"
    );
    assert_eq!(
        fs::read(writable_source.join("marker")).expect("read writable marker after preflight"),
        b"writable-marker\n"
    );
    assert!(
        fs::read_dir(root.join("persist"))
            .expect("read persist target after preflight")
            .next()
            .is_none(),
        "preflight must not mount or write into the configured writable target"
    );

    for path in [&root, &readonly_source, &writable_source] {
        let _ = fs::remove_dir_all(path);
    }
}
'''
Path("tests/preflight_core_probe_cli.rs").write_text(core_cli)
