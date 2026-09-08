from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy: retain the existing UID/GID narrowing pair and add an independent
# exact Linux peer PID restriction.  This is backwards-compatible for existing
# policies while allowing the runtime broker to bind pathname resolution to the
# exact broker process rather than only its credentials.
replace_one(
    "src/policy.rs",
    "    /// Optional exact peer UID/GID required on the connected host AF_UNIX stream.\n    /// The pair only narrows an already-declared host-UNIX broker.\n    pub host_unix_stream_peer_uid: Option<u32>,\n    pub host_unix_stream_peer_gid: Option<u32>,\n",
    "    /// Optional exact peer UID/GID required on the connected host AF_UNIX stream.\n    /// The pair only narrows an already-declared host-UNIX broker.\n    pub host_unix_stream_peer_uid: Option<u32>,\n    pub host_unix_stream_peer_gid: Option<u32>,\n    /// Optional exact Linux peer PID required on the connected host AF_UNIX stream.\n    /// This independently narrows an already-declared host-UNIX broker.\n    pub host_unix_stream_peer_pid: Option<u32>,\n",
    "policy peer pid field",
)
replace_one(
    "src/policy.rs",
    "        match (\n            self.host_unix_stream_peer_uid,\n            self.host_unix_stream_peer_gid,\n        ) {\n            (None, None) => {}\n            (Some(_), Some(_)) => {\n                if self.host_unix_stream_path.is_none() || self.host_unix_stream_target_fd.is_none()\n                {\n                    return Err(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid require a brokered host-UNIX stream endpoint\",\n                    ));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                ));\n            }\n        }\n",
    "        match (\n            self.host_unix_stream_peer_uid,\n            self.host_unix_stream_peer_gid,\n        ) {\n            (None, None) => {}\n            (Some(_), Some(_)) => {\n                if self.host_unix_stream_path.is_none() || self.host_unix_stream_target_fd.is_none()\n                {\n                    return Err(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid require a brokered host-UNIX stream endpoint\",\n                    ));\n                }\n            }\n            _ => {\n                return Err(PolicyError::new(\n                    \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                ));\n            }\n        }\n        if let Some(pid) = self.host_unix_stream_peer_pid {\n            if self.host_unix_stream_path.is_none() || self.host_unix_stream_target_fd.is_none() {\n                return Err(PolicyError::new(\n                    \"ipc.host_unix_stream_peer_pid requires a brokered host-UNIX stream endpoint\",\n                ));\n            }\n            if pid == 0 || pid > i32::MAX as u32 {\n                return Err(PolicyError::new(\n                    \"ipc.host_unix_stream_peer_pid must be between 1 and 2147483647\",\n                ));\n            }\n        }\n",
    "policy peer pid validation",
)
replace_one(
    "src/policy.rs",
    "        let mut host_unix_stream_peer_uid = None;\n        let mut host_unix_stream_peer_gid = None;\n",
    "        let mut host_unix_stream_peer_uid = None;\n        let mut host_unix_stream_peer_gid = None;\n        let mut host_unix_stream_peer_pid = None;\n",
    "policy peer pid parser state",
)
replace_one(
    "src/policy.rs",
    "                \"ipc.host_unix_stream_peer_gid\" => set_once(\n                    &mut host_unix_stream_peer_gid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n",
    "                \"ipc.host_unix_stream_peer_gid\" => set_once(\n                    &mut host_unix_stream_peer_gid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n                \"ipc.host_unix_stream_peer_pid\" => set_once(\n                    &mut host_unix_stream_peer_pid,\n                    value.parse::<u32>().map_err(|_| {\n                        PolicyError::at(line_no, format!(\"{key} must be an unsigned integer\"))\n                    })?,\n                    line_no,\n                    key,\n                )?,\n",
    "policy peer pid parser key",
)
replace_one(
    "src/policy.rs",
    "            host_unix_stream_peer_uid,\n            host_unix_stream_peer_gid,\n",
    "            host_unix_stream_peer_uid,\n            host_unix_stream_peer_gid,\n            host_unix_stream_peer_pid,\n",
    "policy peer pid construction",
)
replace_one(
    "src/policy.rs",
    "            \"{base}\\nipc.host_unix_stream_path = /run/security-lab.sock\\nipc.host_unix_stream_target_fd = 14\\nipc.host_unix_stream_peer_uid = 1000\\nipc.host_unix_stream_peer_gid = 1001\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.host_unix_stream_peer_uid, Some(1000));\n        assert_eq!(policy.host_unix_stream_peer_gid, Some(1001));\n",
    "            \"{base}\\nipc.host_unix_stream_path = /run/security-lab.sock\\nipc.host_unix_stream_target_fd = 14\\nipc.host_unix_stream_peer_uid = 1000\\nipc.host_unix_stream_peer_gid = 1001\\nipc.host_unix_stream_peer_pid = 1234\"\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        assert_eq!(policy.host_unix_stream_peer_uid, Some(1000));\n        assert_eq!(policy.host_unix_stream_peer_gid, Some(1001));\n        assert_eq!(policy.host_unix_stream_peer_pid, Some(1234));\n",
    "policy peer pid parse evidence",
)
replace_one(
    "src/policy.rs",
    "        let error = detached.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains(\"require a brokered host-UNIX stream endpoint\"));\n    }\n",
    "        let error = detached.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains(\"require a brokered host-UNIX stream endpoint\"));\n\n        let detached_pid = format!(\"{base}\\nipc.host_unix_stream_peer_pid = 1234\");\n        let error = detached_pid.parse::<SandboxPolicy>().unwrap_err();\n        assert!(error\n            .to_string()\n            .contains(\"peer_pid requires a brokered host-UNIX stream endpoint\"));\n\n        for invalid_pid in [0u32, i32::MAX as u32 + 1] {\n            let invalid = format!(\n                \"{base}\\nipc.host_unix_stream_path = /run/security-lab.sock\\nipc.host_unix_stream_target_fd = 14\\nipc.host_unix_stream_peer_pid = {invalid_pid}\"\n            );\n            let error = invalid.parse::<SandboxPolicy>().unwrap_err();\n            assert!(error.to_string().contains(\"peer_pid must be between\"));\n        }\n    }\n",
    "policy peer pid rejection evidence",
)

# Keep direct SandboxPolicy literals source-compatible.
p = Path("tests/sandbox.rs")
text = p.read_text()
old = "        host_unix_stream_peer_uid: None,\n        host_unix_stream_peer_gid: None,\n"
count = text.count(old)
if count != 1:
    raise SystemExit(f"sandbox policy literal: expected exactly one match, got {count}")
p.write_text(text.replace(old, old + "        host_unix_stream_peer_pid: None,\n", 1))

# Linux connector: query SO_PEERCRED whenever either credential or PID narrowing
# is requested, then enforce both independently.
replace_one(
    "src/platform/linux.rs",
    "            let host_unix_expected_peer = match (\n                policy.host_unix_stream_peer_uid,\n                policy.host_unix_stream_peer_gid,\n            ) {\n                (Some(uid), Some(gid)) => Some((uid, gid)),\n                (None, None) => None,\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                    )));\n                }\n            };\n",
    "            let host_unix_expected_peer = match (\n                policy.host_unix_stream_peer_uid,\n                policy.host_unix_stream_peer_gid,\n            ) {\n                (Some(uid), Some(gid)) => Some((uid, gid)),\n                (None, None) => None,\n                _ => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"ipc.host_unix_stream_peer_uid and ipc.host_unix_stream_peer_gid must be specified together\",\n                    )));\n                }\n            };\n            let host_unix_expected_pid = policy.host_unix_stream_peer_pid;\n",
    "platform peer pid preparation",
)
replace_one(
    "src/platform/linux.rs",
    "                    selected_storage_floor,\n                    host_unix_expected_peer,\n                )?),\n                (None, None) if host_unix_expected_peer.is_none() => {}\n                (None, None) => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"host-UNIX peer credentials require a brokered endpoint\",\n                    )));\n                }\n",
    "                    selected_storage_floor,\n                    host_unix_expected_peer,\n                    host_unix_expected_pid,\n                )?),\n                (None, None)\n                    if host_unix_expected_peer.is_none() && host_unix_expected_pid.is_none() => {}\n                (None, None) => {\n                    return Err(SandboxError::InvalidPolicy(PolicyError::new(\n                        \"host-UNIX peer restrictions require a brokered endpoint\",\n                    )));\n                }\n",
    "platform peer pid call",
)
replace_one(
    "src/platform/linux.rs",
    "        storage_floor: RawFd,\n        expected_peer: Option<(u32, u32)>,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n",
    "        storage_floor: RawFd,\n        expected_peer: Option<(u32, u32)>,\n        expected_peer_pid: Option<u32>,\n    ) -> Result<PreparedSelectedHandle, SandboxError> {\n",
    "platform peer pid signature",
)
replace_one(
    "src/platform/linux.rs",
    "        if let Some((expected_uid, expected_gid)) = expected_peer {\n            let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };\n",
    "        if expected_peer.is_some() || expected_peer_pid.is_some() {\n            let mut credentials = unsafe { std::mem::zeroed::<libc::ucred>() };\n",
    "platform peer pid credential query",
)
replace_one(
    "src/platform/linux.rs",
    "            if credentials.uid != expected_uid || credentials.gid != expected_gid {\n                return Err(SandboxError::SetupFailed(format!(\n                    \"brokered host-UNIX peer credentials mismatch for {}: expected uid {expected_uid} gid {expected_gid}, got uid {} gid {}\",\n                    path.display(),\n                    credentials.uid,\n                    credentials.gid\n                )));\n            }\n        }\n",
    "            if let Some((expected_uid, expected_gid)) = expected_peer {\n                if credentials.uid != expected_uid || credentials.gid != expected_gid {\n                    return Err(SandboxError::SetupFailed(format!(\n                        \"brokered host-UNIX peer credentials mismatch for {}: expected uid {expected_uid} gid {expected_gid}, got uid {} gid {}\",\n                        path.display(),\n                        credentials.uid,\n                        credentials.gid\n                    )));\n                }\n            }\n            if let Some(expected_pid) = expected_peer_pid {\n                if credentials.pid <= 0 || credentials.pid as u32 != expected_pid {\n                    return Err(SandboxError::SetupFailed(format!(\n                        \"brokered host-UNIX peer PID mismatch for {}: expected pid {expected_pid}, got pid {}\",\n                        path.display(),\n                        credentials.pid\n                    )));\n                }\n            }\n        }\n",
    "platform peer pid enforcement",
)

# Static authority surfaces must include the new restriction.
replace_one(
    "src/authority_manifest.rs",
    "                _ => output.push_str(\"null\"),\n            }\n            output.push('}');\n        }\n        _ => output.push_str(\"null\"),\n    }\n    output.push('}');\n\n    output.push_str(\",\\\"descriptors\\\":{\\\"stdio\\\":{\\\"stdin\\\":\");\n",
    "                _ => output.push_str(\"null\"),\n            }\n            output.push_str(\",\\\"peer_pid\\\":\");\n            match policy.host_unix_stream_peer_pid {\n                Some(pid) => write!(&mut output, \"{pid}\").expect(\"write to String cannot fail\"),\n                None => output.push_str(\"null\"),\n            }\n            output.push('}');\n        }\n        _ => output.push_str(\"null\"),\n    }\n    output.push('}');\n\n    output.push_str(\",\\\"descriptors\\\":{\\\"stdio\\\":{\\\"stdin\\\":\");\n",
    "authority manifest peer pid",
)
replace_one(
    "src/authority_delta.rs",
    "    compare_optional_restriction(\n        \"host_ipc.unix_stream_peer_credentials\",\n        baseline\n            .host_unix_stream_peer_uid\n            .zip(baseline.host_unix_stream_peer_gid),\n        candidate\n            .host_unix_stream_peer_uid\n            .zip(candidate.host_unix_stream_peer_gid),\n        &mut changes,\n    );\n",
    "    compare_optional_restriction(\n        \"host_ipc.unix_stream_peer_credentials\",\n        baseline\n            .host_unix_stream_peer_uid\n            .zip(baseline.host_unix_stream_peer_gid),\n        candidate\n            .host_unix_stream_peer_uid\n            .zip(candidate.host_unix_stream_peer_gid),\n        &mut changes,\n    );\n    compare_optional_restriction(\n        \"host_ipc.unix_stream_peer_pid\",\n        baseline.host_unix_stream_peer_pid,\n        candidate.host_unix_stream_peer_pid,\n        &mut changes,\n    );\n",
    "authority delta peer pid",
)

# Runtime broker: configure exact server PID and force callers to bound accept.
replace_one(
    "src/runtime_fd_broker.rs",
    "use std::path::Path;\n",
    "use std::path::Path;\nuse std::time::Duration;\n",
    "runtime broker duration import",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "    InvalidConfiguration(String),\n    Policy(PolicyError),\n",
    "    InvalidConfiguration(String),\n    AcceptTimedOut,\n    Policy(PolicyError),\n",
    "runtime broker timeout error",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "            Self::InvalidConfiguration(message) => write!(f, \"invalid broker configuration: {message}\"),\n            Self::Policy(error) => write!(f, \"broker policy integration failed: {error}\"),\n",
    "            Self::InvalidConfiguration(message) => write!(f, \"invalid broker configuration: {message}\"),\n            Self::AcceptTimedOut => f.write_str(\"runtime FD broker accept timed out\"),\n            Self::Policy(error) => write!(f, \"broker policy integration failed: {error}\"),\n",
    "runtime broker timeout display",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};\n",
    "    use super::{Duration, File, Path, RuntimeFdBrokerError, SandboxPolicy};\n",
    "runtime broker duration linux import",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "    use std::path::{Component, PathBuf};\n",
    "    use std::path::{Component, PathBuf};\n    use std::time::Instant;\n",
    "runtime broker instant import",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "                || policy.host_unix_stream_peer_uid.is_some()\n                || policy.host_unix_stream_peer_gid.is_some()\n",
    "                || policy.host_unix_stream_peer_uid.is_some()\n                || policy.host_unix_stream_peer_gid.is_some()\n                || policy.host_unix_stream_peer_pid.is_some()\n",
    "runtime broker nonoverwrite pid",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "            candidate.host_unix_stream_peer_uid = Some(self.owner_uid);\n            candidate.host_unix_stream_peer_gid = Some(self.owner_gid);\n            candidate.validate().map_err(RuntimeFdBrokerError::Policy)?;\n",
    "            candidate.host_unix_stream_peer_uid = Some(self.owner_uid);\n            candidate.host_unix_stream_peer_gid = Some(self.owner_gid);\n            candidate.host_unix_stream_peer_pid = Some(u32::try_from(self.owner_pid).map_err(|_| {\n                RuntimeFdBrokerError::InvalidConfiguration(\n                    \"runtime FD broker owner PID is outside Linux policy range\".to_owned(),\n                )\n            })?);\n            candidate.validate().map_err(RuntimeFdBrokerError::Policy)?;\n",
    "runtime broker configure pid",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "        /// Accept the launcher-created broker connection and require it to come\n        /// from the exact process and effective credentials that created this\n        /// broker object. This closes accidental or cross-process queue capture;\n        /// code inside the trusted caller process remains in the trust boundary.\n        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {\n            let (stream, _) = self.listener.accept().map_err(|error| {\n                RuntimeFdBrokerError::io(\"cannot accept runtime FD broker connection\", error)\n            })?;\n            let (pid, uid, gid) = peer_credentials(stream.as_raw_fd())?;\n            if pid != self.owner_pid || uid != self.owner_uid || gid != self.owner_gid {\n                return Err(RuntimeFdBrokerError::UnexpectedPeer {\n                    expected_pid: self.owner_pid,\n                    expected_uid: self.owner_uid,\n                    expected_gid: self.owner_gid,\n                    actual_pid: pid,\n                    actual_uid: uid,\n                    actual_gid: gid,\n                });\n            }\n            Ok(RuntimeFdSession { stream })\n        }\n",
    "        /// Accept the launcher-created broker connection within a caller-owned bound\n        /// and require it to come from the exact process and effective credentials\n        /// that created this broker object.  A failed launcher setup therefore cannot\n        /// leave the host blocked forever in `accept`.\n        pub fn accept_timeout(\n            &self,\n            timeout: Duration,\n        ) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {\n            if timeout.is_zero() {\n                return Err(RuntimeFdBrokerError::AcceptTimedOut);\n            }\n            let started = Instant::now();\n            loop {\n                let elapsed = started.elapsed();\n                if elapsed >= timeout {\n                    return Err(RuntimeFdBrokerError::AcceptTimedOut);\n                }\n                let remaining = timeout - elapsed;\n                let timeout_ms = remaining\n                    .as_millis()\n                    .max(1)\n                    .min(i32::MAX as u128) as libc::c_int;\n                let mut pollfd = libc::pollfd {\n                    fd: self.listener.as_raw_fd(),\n                    events: libc::POLLIN,\n                    revents: 0,\n                };\n                let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };\n                if ready == 0 {\n                    return Err(RuntimeFdBrokerError::AcceptTimedOut);\n                }\n                if ready == -1 {\n                    let error = std::io::Error::last_os_error();\n                    if error.raw_os_error() == Some(libc::EINTR) {\n                        continue;\n                    }\n                    return Err(RuntimeFdBrokerError::io(\n                        \"cannot poll runtime FD broker listener\",\n                        error,\n                    ));\n                }\n                if pollfd.revents & libc::POLLIN == 0 {\n                    return Err(RuntimeFdBrokerError::Protocol(format!(\n                        \"runtime FD broker listener poll returned unexpected events 0x{:x}\",\n                        pollfd.revents\n                    )));\n                }\n                break;\n            }\n\n            let (stream, _) = loop {\n                match self.listener.accept() {\n                    Ok(accepted) => break accepted,\n                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,\n                    Err(error) => {\n                        return Err(RuntimeFdBrokerError::io(\n                            \"cannot accept runtime FD broker connection\",\n                            error,\n                        ))\n                    }\n                }\n            };\n            let (pid, uid, gid) = peer_credentials(stream.as_raw_fd())?;\n            if pid != self.owner_pid || uid != self.owner_uid || gid != self.owner_gid {\n                return Err(RuntimeFdBrokerError::UnexpectedPeer {\n                    expected_pid: self.owner_pid,\n                    expected_uid: self.owner_uid,\n                    expected_gid: self.owner_gid,\n                    actual_pid: pid,\n                    actual_uid: uid,\n                    actual_gid: gid,\n                });\n            }\n            Ok(RuntimeFdSession { stream })\n        }\n",
    "runtime broker bounded accept",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "    use super::{File, Path, RuntimeFdBrokerError, SandboxPolicy};\n\n    #[derive(Debug)]\n",
    "    use super::{Duration, File, Path, RuntimeFdBrokerError, SandboxPolicy};\n\n    #[derive(Debug)]\n",
    "runtime broker duration nonlinux import",
)
replace_one(
    "src/runtime_fd_broker.rs",
    "        pub fn accept(&self) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {\n            Err(RuntimeFdBrokerError::UnsupportedPlatform(\n                \"runtime FD mediation currently requires Linux x86_64\".to_owned(),\n            ))\n        }\n",
    "        pub fn accept_timeout(\n            &self,\n            _timeout: Duration,\n        ) -> Result<RuntimeFdSession, RuntimeFdBrokerError> {\n            Err(RuntimeFdBrokerError::UnsupportedPlatform(\n                \"runtime FD mediation currently requires Linux x86_64\".to_owned(),\n            ))\n        }\n",
    "runtime broker bounded accept nonlinux",
)

# Runtime broker regressions: every accept is bounded; PID mismatch is enforced
# before target execution; zero timeout is deterministic and nonblocking.
replace_one(
    "tests/runtime_fd_broker.rs",
    "use std::thread;\n",
    "use std::thread;\nuse std::time::Duration;\n",
    "runtime broker test duration import",
)
p = Path("tests/runtime_fd_broker.rs")
text = p.read_text()
count = text.count("broker.accept().expect(")
if count != 3:
    raise SystemExit(f"runtime broker accept calls: expected 3, got {count}")
text = text.replace(
    "broker.accept().expect(",
    "broker.accept_timeout(Duration::from_secs(2)).expect(",
)
p.write_text(text)
replace_one(
    "tests/runtime_fd_broker.rs",
    "#[test]\nfn broker_configuration_is_fail_closed_and_non_overwriting() {\n",
    "#[test]\nfn broker_accept_timeout_is_deterministic_without_launcher_connection() {\n    let socket_path = unique_path(\"runtime-rights-timeout.sock\");\n    let _ = std::fs::remove_file(&socket_path);\n    let broker = RuntimeFdBroker::bind(&socket_path).expect(\"bind runtime FD broker\");\n    assert!(matches!(\n        broker.accept_timeout(Duration::ZERO),\n        Err(RuntimeFdBrokerError::AcceptTimedOut)\n    ));\n    drop(broker);\n}\n\n#[test]\nfn configured_peer_pid_is_enforced_before_target_exec() {\n    let root = build_probe_root();\n    let socket_path = unique_path(\"runtime-rights-pid-pin.sock\");\n    let _ = std::fs::remove_file(&socket_path);\n    let broker = RuntimeFdBroker::bind(&socket_path).expect(\"bind runtime FD broker\");\n    let text = format!(\n        \"filesystem.root = {}\\n\\\n         identity.hostname = security-lab\\n\\\n         executable = /probe\\n\\\n         arg = X\\n\\\n         working_dir = /work\\n\\\n         stdio.stdin = closed\\n\\\n         stdio.stdout = closed\\n\\\n         stdio.stderr = closed\\n\\\n         limit.cpu_seconds = 2\\n\\\n         limit.address_space_bytes = 134217728\\n\\\n         limit.file_size_bytes = 1048576\\n\\\n         limit.open_files = 32\\n\\\n         seccomp.allow = execveat,exit\\n\",\n        root.display()\n    );\n    let mut policy: SandboxPolicy = text.parse().expect(\"parse broker PID policy\");\n    broker\n        .configure_policy(&mut policy, 10)\n        .expect(\"configure runtime broker policy\");\n    let pinned = policy\n        .host_unix_stream_peer_pid\n        .expect(\"runtime broker must pin exact owner PID\");\n    policy.host_unix_stream_peer_pid = Some(if pinned == i32::MAX as u32 {\n        pinned - 1\n    } else {\n        pinned + 1\n    });\n    match run(&policy).unwrap_err() {\n        security_lab::SandboxError::SetupFailed(message) => {\n            assert!(message.contains(\"peer PID mismatch\"));\n        }\n        other => panic!(\"unexpected broker PID mismatch result: {other}\"),\n    }\n    drop(broker);\n    std::fs::remove_dir_all(&root).expect(\"remove broker PID root\");\n}\n\n#[test]\nfn broker_configuration_is_fail_closed_and_non_overwriting() {\n",
    "runtime broker PID and timeout regressions",
)
