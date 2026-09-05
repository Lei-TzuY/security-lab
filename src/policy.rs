use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ENV: usize = 64;
const MAX_ENV_VALUE_BYTES: usize = 8192;
const MAX_SYSCALLS: usize = 128;
const MIN_SCRATCH_BYTES: u64 = 4096;
const MAX_SCRATCH_BYTES: u64 = 1024 * 1024 * 1024;
const MIN_CAPTURE_BYTES: u64 = 1;
const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;
const MIN_WALL_CLOCK_MILLISECONDS: u64 = 1;
const MAX_WALL_CLOCK_MILLISECONDS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceLimits {
    pub cpu_seconds: u64,
    pub address_space_bytes: u64,
    pub file_size_bytes: u64,
    pub open_files: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    Inherit,
    Closed,
    Redirect,
    Capture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StdioPolicy {
    pub stdin: StdioMode,
    pub stdout: StdioMode,
    pub stderr: StdioMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompPolicy {
    /// Syscall names allowed by the policy. Every other syscall is denied with
    /// `EPERM` by the Linux x86_64 enforcement layer.
    pub allowed_syscalls: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Host path pinned as the sandbox filesystem root before fork.
    pub root_dir: PathBuf,
    /// Absolute path interpreted inside `root_dir`.
    pub executable: PathBuf,
    pub args: Vec<String>,
    pub environment: BTreeMap<String, String>,
    /// Absolute path interpreted inside `root_dir`.
    pub working_dir: PathBuf,
    /// Optional absolute path inside `root_dir` replaced by a private writable
    /// tmpfs after the root mount tree has been made recursively read-only.
    pub scratch_dir: Option<PathBuf>,
    /// Maximum byte size of the private tmpfs. Must be present exactly when
    /// `scratch_dir` is present.
    pub scratch_bytes: Option<u64>,
    /// Explicit disposition for descriptors 0, 1, and 2.
    pub stdio: StdioPolicy,
    /// Sandbox path used only when stdout disposition is `Redirect`. The path
    /// must be strictly beneath the declared private scratch directory.
    pub stdout_redirect: Option<PathBuf>,
    /// Maximum number of stdout bytes retained by the parent when stdout is
    /// `Capture`. Excess output is drained and discarded rather than retained.
    pub stdout_capture_bytes: Option<u64>,
    /// Optional launcher-owned wall-clock deadline measured from PID 1
    /// beginning supervision of the direct target.
    pub wall_clock_milliseconds: Option<u64>,
    pub limits: ResourceLimits,
    pub seccomp: SeccompPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError {
    line: Option<usize>,
    message: String,
}

impl PolicyError {
    fn at(line: usize, message: impl Into<String>) -> Self {
        Self {
            line: Some(line),
            message: message.into(),
        }
    }

    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            line: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {line}: {}", self.message)
        } else {
            f.write_str(&self.message)
        }
    }
}

impl Error for PolicyError {}

impl SandboxPolicy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        validate_absolute_path("filesystem.root", &self.root_dir)?;
        validate_absolute_path("executable", &self.executable)?;
        validate_absolute_path("working_dir", &self.working_dir)?;

        match (&self.scratch_dir, self.scratch_bytes) {
            (None, None) => {}
            (Some(path), Some(bytes)) => {
                validate_absolute_path("filesystem.scratch", path)?;
                if path == Path::new("/") {
                    return Err(PolicyError::new(
                        "filesystem.scratch must not replace the sandbox root",
                    ));
                }
                if !(MIN_SCRATCH_BYTES..=MAX_SCRATCH_BYTES).contains(&bytes) {
                    return Err(PolicyError::new(format!(
                        "filesystem.scratch_bytes must be between {MIN_SCRATCH_BYTES} and {MAX_SCRATCH_BYTES}"
                    )));
                }
                if self.executable.starts_with(path) || self.working_dir.starts_with(path) {
                    return Err(PolicyError::new(
                        "filesystem.scratch must not contain the executable or working_dir",
                    ));
                }
            }
            _ => {
                return Err(PolicyError::new(
                    "filesystem.scratch and filesystem.scratch_bytes must be specified together",
                ));
            }
        }

        if matches!(self.stdio.stdin, StdioMode::Redirect | StdioMode::Capture)
            || matches!(self.stdio.stderr, StdioMode::Redirect | StdioMode::Capture)
        {
            return Err(PolicyError::new(
                "redirect and capture are currently supported only for stdio.stdout",
            ));
        }

        match self.stdio.stdout {
            StdioMode::Redirect => {
                if self.stdout_capture_bytes.is_some() {
                    return Err(PolicyError::new(
                        "stdio.stdout_capture_bytes is only valid when stdio.stdout = capture",
                    ));
                }
                let path = self.stdout_redirect.as_ref().ok_or_else(|| {
                    PolicyError::new("stdio.stdout = redirect requires stdio.stdout_path")
                })?;
                validate_absolute_path("stdio.stdout_path", path)?;
                let scratch = self.scratch_dir.as_ref().ok_or_else(|| {
                    PolicyError::new(
                        "stdio.stdout = redirect requires a declared filesystem.scratch",
                    )
                })?;
                if path == scratch || !path.starts_with(scratch) {
                    return Err(PolicyError::new(
                        "stdio.stdout_path must be strictly beneath filesystem.scratch",
                    ));
                }
            }
            StdioMode::Capture => {
                if self.stdout_redirect.is_some() {
                    return Err(PolicyError::new(
                        "stdio.stdout_path is only valid when stdio.stdout = redirect",
                    ));
                }
                let bytes = self.stdout_capture_bytes.ok_or_else(|| {
                    PolicyError::new("stdio.stdout = capture requires stdio.stdout_capture_bytes")
                })?;
                if !(MIN_CAPTURE_BYTES..=MAX_CAPTURE_BYTES).contains(&bytes) {
                    return Err(PolicyError::new(format!(
                        "stdio.stdout_capture_bytes must be between {MIN_CAPTURE_BYTES} and {MAX_CAPTURE_BYTES}"
                    )));
                }
            }
            StdioMode::Inherit | StdioMode::Closed => {
                if self.stdout_redirect.is_some() {
                    return Err(PolicyError::new(
                        "stdio.stdout_path is only valid when stdio.stdout = redirect",
                    ));
                }
                if self.stdout_capture_bytes.is_some() {
                    return Err(PolicyError::new(
                        "stdio.stdout_capture_bytes is only valid when stdio.stdout = capture",
                    ));
                }
            }
        }

        if let Some(milliseconds) = self.wall_clock_milliseconds {
            if !(MIN_WALL_CLOCK_MILLISECONDS..=MAX_WALL_CLOCK_MILLISECONDS).contains(&milliseconds)
            {
                return Err(PolicyError::new(format!(
                    "limit.wall_clock_milliseconds must be between {MIN_WALL_CLOCK_MILLISECONDS} and {MAX_WALL_CLOCK_MILLISECONDS}"
                )));
            }
        }

        if self.args.len() > MAX_ARGS {
            return Err(PolicyError::new(format!(
                "too many arguments: {} > {MAX_ARGS}",
                self.args.len()
            )));
        }
        for arg in &self.args {
            if arg.as_bytes().contains(&0) {
                return Err(PolicyError::new("arguments must not contain NUL bytes"));
            }
            if arg.len() > MAX_ARG_BYTES {
                return Err(PolicyError::new(format!(
                    "argument exceeds {MAX_ARG_BYTES} bytes"
                )));
            }
        }

        if self.environment.len() > MAX_ENV {
            return Err(PolicyError::new(format!(
                "too many environment variables: {} > {MAX_ENV}",
                self.environment.len()
            )));
        }
        for (key, value) in &self.environment {
            if !valid_env_key(key) {
                return Err(PolicyError::new(format!(
                    "invalid environment variable name: {key:?}"
                )));
            }
            if value.as_bytes().contains(&0) {
                return Err(PolicyError::new(format!(
                    "environment variable {key:?} contains a NUL byte"
                )));
            }
            if value.len() > MAX_ENV_VALUE_BYTES {
                return Err(PolicyError::new(format!(
                    "environment variable {key:?} exceeds {MAX_ENV_VALUE_BYTES} bytes"
                )));
            }
        }

        if self.limits.cpu_seconds == 0
            || self.limits.address_space_bytes == 0
            || self.limits.file_size_bytes == 0
            || self.limits.open_files < 3
        {
            return Err(PolicyError::new(
                "resource limits must be non-zero and open_files must be at least 3",
            ));
        }

        if self.seccomp.allowed_syscalls.is_empty() {
            return Err(PolicyError::new("seccomp allowlist must not be empty"));
        }
        if self.seccomp.allowed_syscalls.len() > MAX_SYSCALLS {
            return Err(PolicyError::new(format!(
                "too many seccomp syscalls: {} > {MAX_SYSCALLS}",
                self.seccomp.allowed_syscalls.len()
            )));
        }
        for name in &self.seccomp.allowed_syscalls {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(PolicyError::new(format!(
                    "invalid syscall name syntax: {name:?}"
                )));
            }
        }

        Ok(())
    }
}

impl FromStr for SandboxPolicy {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut root_dir = None;
        let mut executable = None;
        let mut args = Vec::new();
        let mut environment = BTreeMap::new();
        let mut working_dir = None;
        let mut scratch_dir = None;
        let mut scratch_bytes = None;
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut stdout_redirect = None;
        let mut stdout_capture_bytes = None;
        let mut wall_clock_milliseconds = None;
        let mut cpu_seconds = None;
        let mut address_space_bytes = None;
        let mut file_size_bytes = None;
        let mut open_files = None;
        let mut seccomp = None;

        for (index, raw_line) in input.lines().enumerate() {
            let line_no = index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (raw_key, raw_value) = line
                .split_once('=')
                .ok_or_else(|| PolicyError::at(line_no, "expected key = value"))?;
            let key = raw_key.trim();
            let value = raw_value.trim();

            match key {
                "filesystem.root" => set_once(&mut root_dir, value.to_owned(), line_no, key)?,
                "filesystem.scratch" => set_once(&mut scratch_dir, value.to_owned(), line_no, key)?,
                "filesystem.scratch_bytes" => set_once(
                    &mut scratch_bytes,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "executable" => set_once(&mut executable, value.to_owned(), line_no, key)?,
                "arg" => args.push(value.to_owned()),
                "working_dir" => set_once(&mut working_dir, value.to_owned(), line_no, key)?,
                "stdio.stdin" => set_once(
                    &mut stdin,
                    parse_stdio_mode(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "stdio.stdout" => set_once(
                    &mut stdout,
                    parse_stdio_mode(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "stdio.stderr" => set_once(
                    &mut stderr,
                    parse_stdio_mode(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "stdio.stdout_path" => {
                    set_once(&mut stdout_redirect, value.to_owned(), line_no, key)?
                }
                "stdio.stdout_capture_bytes" => set_once(
                    &mut stdout_capture_bytes,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "limit.wall_clock_milliseconds" => set_once(
                    &mut wall_clock_milliseconds,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "limit.cpu_seconds" => set_once(
                    &mut cpu_seconds,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "limit.address_space_bytes" => set_once(
                    &mut address_space_bytes,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "limit.file_size_bytes" => set_once(
                    &mut file_size_bytes,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "limit.open_files" => set_once(
                    &mut open_files,
                    parse_u64(value, line_no, key)?,
                    line_no,
                    key,
                )?,
                "seccomp.allow" => {
                    if seccomp.is_some() {
                        return Err(PolicyError::at(line_no, "duplicate seccomp.allow"));
                    }
                    let mut names = BTreeSet::new();
                    for name in value.split(',').map(str::trim) {
                        if name.is_empty() {
                            return Err(PolicyError::at(
                                line_no,
                                "seccomp.allow contains an empty syscall name",
                            ));
                        }
                        if !names.insert(name.to_owned()) {
                            return Err(PolicyError::at(
                                line_no,
                                format!("duplicate syscall in seccomp.allow: {name}"),
                            ));
                        }
                    }
                    seccomp = Some(SeccompPolicy {
                        allowed_syscalls: names,
                    });
                }
                _ => {
                    let Some(env_key) = key.strip_prefix("env.") else {
                        return Err(PolicyError::at(
                            line_no,
                            format!("unknown policy key: {key}"),
                        ));
                    };
                    if !valid_env_key(env_key) {
                        return Err(PolicyError::at(
                            line_no,
                            format!("invalid environment variable name: {env_key:?}"),
                        ));
                    }
                    if environment
                        .insert(env_key.to_owned(), value.to_owned())
                        .is_some()
                    {
                        return Err(PolicyError::at(
                            line_no,
                            format!("duplicate environment variable: {env_key}"),
                        ));
                    }
                }
            }
        }

        let policy = Self {
            root_dir: PathBuf::from(required(root_dir, "filesystem.root")?),
            executable: PathBuf::from(required(executable, "executable")?),
            args,
            environment,
            working_dir: PathBuf::from(required(working_dir, "working_dir")?),
            scratch_dir: scratch_dir.map(PathBuf::from),
            scratch_bytes,
            stdio: StdioPolicy {
                stdin: required(stdin, "stdio.stdin")?,
                stdout: required(stdout, "stdio.stdout")?,
                stderr: required(stderr, "stdio.stderr")?,
            },
            stdout_redirect: stdout_redirect.map(PathBuf::from),
            stdout_capture_bytes,
            wall_clock_milliseconds,
            limits: ResourceLimits {
                cpu_seconds: required(cpu_seconds, "limit.cpu_seconds")?,
                address_space_bytes: required(address_space_bytes, "limit.address_space_bytes")?,
                file_size_bytes: required(file_size_bytes, "limit.file_size_bytes")?,
                open_files: required(open_files, "limit.open_files")?,
            },
            seccomp: required(seccomp, "seccomp.allow")?,
        };
        policy.validate()?;
        Ok(policy)
    }
}

fn set_once<T>(
    target: &mut Option<T>,
    value: T,
    line: usize,
    key: &str,
) -> Result<(), PolicyError> {
    if target.replace(value).is_some() {
        Err(PolicyError::at(line, format!("duplicate key: {key}")))
    } else {
        Ok(())
    }
}

fn required<T>(value: Option<T>, key: &str) -> Result<T, PolicyError> {
    value.ok_or_else(|| PolicyError::new(format!("missing required key: {key}")))
}

fn parse_u64(value: &str, line: usize, key: &str) -> Result<u64, PolicyError> {
    value
        .parse::<u64>()
        .map_err(|_| PolicyError::at(line, format!("{key} must be an unsigned integer")))
}

fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {
    match value {
        "inherit" => Ok(StdioMode::Inherit),
        "closed" => Ok(StdioMode::Closed),
        "redirect" => Ok(StdioMode::Redirect),
        "capture" => Ok(StdioMode::Capture),
        _ => Err(PolicyError::at(
            line,
            format!("{key} must be inherit, closed, redirect, or capture"),
        )),
    }
}

fn validate_absolute_path(label: &str, path: &Path) -> Result<(), PolicyError> {
    if !path.is_absolute() {
        return Err(PolicyError::new(format!(
            "{label} must be an absolute path"
        )));
    }
    if path.as_os_str().as_encoded_bytes().contains(&0) {
        return Err(PolicyError::new(format!(
            "{label} must not contain NUL bytes"
        )));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PolicyError::new(format!(
            "{label} must not contain '..' components"
        )));
    }
    Ok(())
}

fn valid_env_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
        filesystem.root = /
        filesystem.scratch = /scratch
        filesystem.scratch_bytes = 16777216
        executable = /bin/echo
        arg = hello
        env.LANG = C
        working_dir = /tmp
        stdio.stdin = closed
        stdio.stdout = inherit
        stdio.stderr = inherit
        limit.cpu_seconds = 1
        limit.address_space_bytes = 268435456
        limit.file_size_bytes = 1048576
        limit.open_files = 32
        seccomp.allow = execveat,read,write,exit_group
    "#;

    #[test]
    fn parses_complete_policy() {
        let policy: SandboxPolicy = VALID.parse().unwrap();
        assert_eq!(policy.root_dir, PathBuf::from("/"));
        assert_eq!(policy.scratch_dir, Some(PathBuf::from("/scratch")));
        assert_eq!(policy.scratch_bytes, Some(16 * 1024 * 1024));
        assert_eq!(policy.executable, PathBuf::from("/bin/echo"));
        assert_eq!(policy.args, ["hello"]);
        assert_eq!(policy.stdio.stdin, StdioMode::Closed);
        assert_eq!(policy.stdio.stdout, StdioMode::Inherit);
        assert_eq!(policy.stdio.stderr, StdioMode::Inherit);
        assert_eq!(policy.stdout_redirect, None);
        assert_eq!(policy.stdout_capture_bytes, None);
        assert_eq!(policy.wall_clock_milliseconds, None);
        assert_eq!(
            policy.environment.get("LANG").map(String::as_str),
            Some("C")
        );
        assert!(policy.seccomp.allowed_syscalls.contains("execveat"));
    }

    #[test]
    fn parses_stdout_redirect_inside_scratch() {
        let text = VALID.replace(
            "stdio.stdout = inherit",
            "stdio.stdout = redirect\n        stdio.stdout_path = /scratch/stdout.log",
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.stdio.stdout, StdioMode::Redirect);
        assert_eq!(
            policy.stdout_redirect,
            Some(PathBuf::from("/scratch/stdout.log"))
        );
    }

    #[test]
    fn parses_bounded_stdout_capture() {
        let text = VALID.replace(
            "stdio.stdout = inherit",
            "stdio.stdout = capture\n        stdio.stdout_capture_bytes = 4096",
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.stdio.stdout, StdioMode::Capture);
        assert_eq!(policy.stdout_capture_bytes, Some(4096));
    }

    #[test]
    fn parses_wall_clock_deadline() {
        let text = format!("{VALID}\nlimit.wall_clock_milliseconds = 1500");
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.wall_clock_milliseconds, Some(1500));
    }

    #[test]
    fn rejects_zero_wall_clock_deadline() {
        let text = format!("{VALID}\nlimit.wall_clock_milliseconds = 0");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_oversized_wall_clock_deadline() {
        let text = format!(
            "{VALID}\nlimit.wall_clock_milliseconds = {}",
            MAX_WALL_CLOCK_MILLISECONDS + 1
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_duplicate_wall_clock_deadline() {
        let text = format!(
            "{VALID}\nlimit.wall_clock_milliseconds = 1000\nlimit.wall_clock_milliseconds = 2000"
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_redirect_path_outside_scratch() {
        let text = VALID.replace(
            "stdio.stdout = inherit",
            "stdio.stdout = redirect\n        stdio.stdout_path = /tmp/stdout.log",
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_redirect_without_path() {
        let text = VALID.replace("stdio.stdout = inherit", "stdio.stdout = redirect");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_capture_without_limit() {
        let text = VALID.replace("stdio.stdout = inherit", "stdio.stdout = capture");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_zero_capture_limit() {
        let text = VALID.replace(
            "stdio.stdout = inherit",
            "stdio.stdout = capture\n        stdio.stdout_capture_bytes = 0",
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_redirect_or_capture_on_stdin() {
        let redirected = VALID.replace("stdio.stdin = closed", "stdio.stdin = redirect");
        assert!(redirected.parse::<SandboxPolicy>().is_err());
        let captured = VALID.replace("stdio.stdin = closed", "stdio.stdin = capture");
        assert!(captured.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_unknown_key() {
        let err = format!("{VALID}\nallow_everything = true").parse::<SandboxPolicy>();
        assert!(err.unwrap_err().to_string().contains("unknown policy key"));
    }

    #[test]
    fn rejects_missing_security_field() {
        let text = VALID.replace("filesystem.root = /", "");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_missing_stdio_disposition() {
        let text = VALID.replace("stdio.stderr = inherit\n", "");
        let err = text.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("stdio.stderr"));
    }

    #[test]
    fn rejects_unknown_stdio_disposition() {
        let text = VALID.replace("stdio.stdin = closed", "stdio.stdin = magic");
        let err = text.parse::<SandboxPolicy>().unwrap_err();
        assert!(err
            .to_string()
            .contains("inherit, closed, redirect, or capture"));
    }

    #[test]
    fn rejects_relative_root() {
        let text = VALID.replace("filesystem.root = /", "filesystem.root = sandbox-root");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_relative_executable() {
        let text = VALID.replace("/bin/echo", "bin/echo");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_incomplete_scratch_policy() {
        let text = VALID.replace("filesystem.scratch_bytes = 16777216\n", "");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_scratch_overlapping_working_directory() {
        let text = VALID.replace("filesystem.scratch = /scratch", "filesystem.scratch = /tmp");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_duplicate_syscall() {
        let text = VALID.replace(
            "execveat,read,write,exit_group",
            "execveat,read,read,exit_group",
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }
}
