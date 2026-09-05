use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

const MAX_ARGS: usize = 64;
const MAX_ARG_BYTES: usize = 4096;
const MAX_ENV: usize = 64;
const MAX_ENV_VALUE_BYTES: usize = 8192;
const MAX_HOSTNAME_BYTES: usize = 63;
const MAX_SYSCALLS: usize = 128;
const MAX_SECCOMP_ARG_RULES: usize = 64;
const MAX_SELECTED_HANDLES: usize = 16;
const MIN_SELECTED_TARGET_FD: u32 = 3;
const MAX_SELECTED_TARGET_FD: u32 = 63;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompArgRule {
    /// Bits of the selected 64-bit syscall argument that participate in the
    /// equality test. Zero masks are invalid because they constrain nothing.
    pub mask: u64,
    /// Expected value after masking. Bits outside `mask` must be zero.
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompPolicy {
    /// Syscall names allowed by the policy. Every other syscall is denied with
    /// `EPERM` by the Linux x86_64 enforcement layer.
    pub allowed_syscalls: BTreeSet<String>,
    /// Optional masked-equality constraints keyed by syscall name and argument
    /// index (0 through 5). Rules only narrow syscalls already in the allowlist.
    pub argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// Host path pinned as the sandbox filesystem root before fork.
    pub root_dir: PathBuf,
    /// Launcher-owned hostname installed inside the sandbox UTS namespace.
    pub hostname: String,
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
    /// Explicit non-stdio descriptor capabilities keyed by target descriptor.
    /// Each value is an already-open descriptor in the launcher process that
    /// is pinned before fork and remapped only into the direct target.
    pub selected_handles: BTreeMap<u32, u32>,
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
        validate_hostname(&self.hostname)?;
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

        if self.selected_handles.len() > MAX_SELECTED_HANDLES {
            return Err(PolicyError::new(format!(
                "too many selected handles: {} > {MAX_SELECTED_HANDLES}",
                self.selected_handles.len()
            )));
        }
        for (target_fd, source_fd) in &self.selected_handles {
            if !(MIN_SELECTED_TARGET_FD..=MAX_SELECTED_TARGET_FD).contains(target_fd) {
                return Err(PolicyError::new(format!(
                    "selected handle target fd must be between {MIN_SELECTED_TARGET_FD} and {MAX_SELECTED_TARGET_FD}: {target_fd}"
                )));
            }
            if u64::from(*target_fd) >= self.limits.open_files {
                return Err(PolicyError::new(format!(
                    "selected handle target fd {target_fd} must be below limit.open_files {}",
                    self.limits.open_files
                )));
            }
            if *source_fd > i32::MAX as u32 {
                return Err(PolicyError::new(format!(
                    "selected handle source fd exceeds the Linux descriptor range: {source_fd}"
                )));
            }
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
            if !valid_syscall_name(name) {
                return Err(PolicyError::new(format!(
                    "invalid syscall name syntax: {name:?}"
                )));
            }
        }

        let argument_rule_count = self
            .seccomp
            .argument_rules
            .values()
            .map(BTreeMap::len)
            .sum::<usize>();
        if argument_rule_count > MAX_SECCOMP_ARG_RULES {
            return Err(PolicyError::new(format!(
                "too many seccomp argument rules: {argument_rule_count} > {MAX_SECCOMP_ARG_RULES}"
            )));
        }
        for (syscall, rules) in &self.seccomp.argument_rules {
            if !valid_syscall_name(syscall) {
                return Err(PolicyError::new(format!(
                    "invalid seccomp argument-rule syscall name: {syscall:?}"
                )));
            }
            if !self.seccomp.allowed_syscalls.contains(syscall) {
                return Err(PolicyError::new(format!(
                    "seccomp argument rule for {syscall} requires that syscall in seccomp.allow"
                )));
            }
            if matches!(syscall.as_str(), "execveat" | "exit" | "exit_group") {
                return Err(PolicyError::new(format!(
                    "seccomp argument rules may not constrain launcher-critical syscall {syscall}"
                )));
            }
            for (argument_index, rule) in rules {
                if *argument_index > 5 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument index for {syscall} must be between 0 and 5"
                    )));
                }
                if rule.mask == 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument mask for {syscall}.{argument_index} must not be zero"
                    )));
                }
                if rule.value & !rule.mask != 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument value for {syscall}.{argument_index} sets bits outside its mask"
                    )));
                }
            }
        }

        Ok(())
    }
}

impl FromStr for SandboxPolicy {
    type Err = PolicyError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut root_dir = None;
        let mut hostname = None;
        let mut executable = None;
        let mut args = Vec::new();
        let mut environment = BTreeMap::new();
        let mut working_dir = None;
        let mut scratch_dir = None;
        let mut scratch_bytes = None;
        let mut stdin = None;
        let mut stdout = None;
        let mut stderr = None;
        let mut selected_handles = BTreeMap::new();
        let mut stdout_redirect = None;
        let mut stdout_capture_bytes = None;
        let mut wall_clock_milliseconds = None;
        let mut cpu_seconds = None;
        let mut address_space_bytes = None;
        let mut file_size_bytes = None;
        let mut open_files = None;
        let mut seccomp_allow = None;
        let mut seccomp_argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>> =
            BTreeMap::new();

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
                "identity.hostname" => set_once(&mut hostname, value.to_owned(), line_no, key)?,
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
                _ if key.starts_with("handle.") => {
                    let target_text = key.strip_prefix("handle.").expect("prefix checked above");
                    let target_fd = target_text.parse::<u32>().map_err(|_| {
                        PolicyError::at(line_no, "selected handle key must be handle.<target_fd>")
                    })?;
                    let source_fd = value.parse::<u32>().map_err(|_| {
                        PolicyError::at(
                            line_no,
                            "selected handle source fd must be an unsigned integer",
                        )
                    })?;
                    if selected_handles.insert(target_fd, source_fd).is_some() {
                        return Err(PolicyError::at(
                            line_no,
                            format!("duplicate selected handle target fd: {target_fd}"),
                        ));
                    }
                }
                "seccomp.allow" => {
                    if seccomp_allow.is_some() {
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
                    seccomp_allow = Some(names);
                }
                _ if key.starts_with("seccomp.arg.") => {
                    let spec = key
                        .strip_prefix("seccomp.arg.")
                        .expect("prefix checked above");
                    let (syscall, index_text) = spec.rsplit_once('.').ok_or_else(|| {
                        PolicyError::at(
                            line_no,
                            "seccomp argument key must be seccomp.arg.<syscall>.<0..5>",
                        )
                    })?;
                    if !valid_syscall_name(syscall) {
                        return Err(PolicyError::at(
                            line_no,
                            format!("invalid seccomp argument-rule syscall name: {syscall:?}"),
                        ));
                    }
                    let argument_index = index_text.parse::<u8>().map_err(|_| {
                        PolicyError::at(line_no, "seccomp argument index must be between 0 and 5")
                    })?;
                    if argument_index > 5 {
                        return Err(PolicyError::at(
                            line_no,
                            "seccomp argument index must be between 0 and 5",
                        ));
                    }
                    let rule = parse_seccomp_arg_rule(value, line_no, key)?;
                    let syscall_rules = seccomp_argument_rules
                        .entry(syscall.to_owned())
                        .or_default();
                    if syscall_rules.insert(argument_index, rule).is_some() {
                        return Err(PolicyError::at(
                            line_no,
                            format!("duplicate seccomp argument rule: {syscall}.{argument_index}"),
                        ));
                    }
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
            hostname: required(hostname, "identity.hostname")?,
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
            selected_handles,
            stdout_redirect: stdout_redirect.map(PathBuf::from),
            stdout_capture_bytes,
            wall_clock_milliseconds,
            limits: ResourceLimits {
                cpu_seconds: required(cpu_seconds, "limit.cpu_seconds")?,
                address_space_bytes: required(address_space_bytes, "limit.address_space_bytes")?,
                file_size_bytes: required(file_size_bytes, "limit.file_size_bytes")?,
                open_files: required(open_files, "limit.open_files")?,
            },
            seccomp: SeccompPolicy {
                allowed_syscalls: required(seccomp_allow, "seccomp.allow")?,
                argument_rules: seccomp_argument_rules,
            },
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

fn parse_seccomp_arg_rule(
    value: &str,
    line: usize,
    key: &str,
) -> Result<SeccompArgRule, PolicyError> {
    let (mask, expected) = value.split_once(':').ok_or_else(|| {
        PolicyError::at(line, format!("{key} must be formatted as <mask>:<value>"))
    })?;
    Ok(SeccompArgRule {
        mask: parse_u64_literal(mask.trim(), line, key)?,
        value: parse_u64_literal(expected.trim(), line, key)?,
    })
}

fn parse_u64_literal(value: &str, line: usize, key: &str) -> Result<u64, PolicyError> {
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() {
            return Err(PolicyError::at(
                line,
                format!("{key} contains an empty hexadecimal integer"),
            ));
        }
        u64::from_str_radix(hex, 16)
            .map_err(|_| PolicyError::at(line, format!("{key} contains an invalid integer")))
    } else {
        value
            .parse::<u64>()
            .map_err(|_| PolicyError::at(line, format!("{key} contains an invalid integer")))
    }
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

fn validate_hostname(hostname: &str) -> Result<(), PolicyError> {
    let bytes = hostname.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_HOSTNAME_BYTES {
        return Err(PolicyError::new(format!(
            "identity.hostname must contain between 1 and {MAX_HOSTNAME_BYTES} bytes"
        )));
    }
    if !bytes
        .iter()
        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'.')
    {
        return Err(PolicyError::new(
            "identity.hostname may contain only ASCII letters, digits, '-' and '.'",
        ));
    }
    if matches!(bytes.first(), Some(b'-' | b'.')) || matches!(bytes.last(), Some(b'-' | b'.')) {
        return Err(PolicyError::new(
            "identity.hostname must start and end with an ASCII letter or digit",
        ));
    }
    Ok(())
}

fn valid_syscall_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
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
        identity.hostname = security-lab
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
        assert_eq!(policy.hostname, "security-lab");
        assert_eq!(policy.scratch_dir, Some(PathBuf::from("/scratch")));
        assert_eq!(policy.scratch_bytes, Some(16 * 1024 * 1024));
        assert_eq!(policy.executable, PathBuf::from("/bin/echo"));
        assert_eq!(policy.args, ["hello"]);
        assert_eq!(policy.stdio.stdin, StdioMode::Closed);
        assert_eq!(policy.stdio.stdout, StdioMode::Inherit);
        assert_eq!(policy.stdio.stderr, StdioMode::Inherit);
        assert!(policy.selected_handles.is_empty());
        assert_eq!(policy.stdout_redirect, None);
        assert_eq!(policy.stdout_capture_bytes, None);
        assert_eq!(policy.wall_clock_milliseconds, None);
        assert_eq!(
            policy.environment.get("LANG").map(String::as_str),
            Some("C")
        );
        assert!(policy.seccomp.allowed_syscalls.contains("execveat"));
        assert!(policy.seccomp.argument_rules.is_empty());
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
    fn rejects_missing_hostname() {
        let text = VALID.replace("identity.hostname = security-lab\n", "");
        let err = text.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("identity.hostname"));
    }

    #[test]
    fn rejects_invalid_hostname() {
        for hostname in ["-bad", "bad_underscore", "bad.", ""] {
            let text = VALID.replace(
                "identity.hostname = security-lab",
                &format!("identity.hostname = {hostname}"),
            );
            assert!(
                text.parse::<SandboxPolicy>().is_err(),
                "accepted {hostname:?}"
            );
        }
        let oversized = "a".repeat(MAX_HOSTNAME_BYTES + 1);
        let text = VALID.replace(
            "identity.hostname = security-lab",
            &format!("identity.hostname = {oversized}"),
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_duplicate_hostname() {
        let text = format!("{VALID}\nidentity.hostname = duplicate");
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
    fn parses_masked_seccomp_argument_rule() {
        let text = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,lseek,exit_group\n        seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008",
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        let rule = policy
            .seccomp
            .argument_rules
            .get("lseek")
            .and_then(|rules| rules.get(&1))
            .copied()
            .expect("lseek argument rule");
        assert_eq!(rule.mask, 0xffff_ffff_0000_000f);
        assert_eq!(rule.value, 0x0000_0001_0000_0008);
    }

    #[test]
    fn rejects_duplicate_seccomp_argument_rule() {
        let text = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,lseek,exit_group\n        seccomp.arg.lseek.1 = 0xff:0x08\n        seccomp.arg.lseek.1 = 0xff:0x08",
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_invalid_seccomp_argument_rule_shape() {
        for rule in [
            "seccomp.arg.lseek.6 = 0xff:0x08",
            "seccomp.arg.lseek.1 = 0:0",
            "seccomp.arg.lseek.1 = 0x0f:0x10",
        ] {
            let text = VALID.replace(
                "seccomp.allow = execveat,read,write,exit_group",
                &format!("seccomp.allow = execveat,lseek,exit_group\n        {rule}"),
            );
            assert!(text.parse::<SandboxPolicy>().is_err(), "accepted {rule}");
        }
    }

    #[test]
    fn rejects_argument_rule_for_unallowed_or_launcher_critical_syscall() {
        let unallowed = format!("{VALID}\nseccomp.arg.lseek.1 = 0xff:0x08");
        assert!(unallowed.parse::<SandboxPolicy>().is_err());

        let exec_rule = format!("{VALID}\nseccomp.arg.execveat.0 = 0xff:0x00");
        assert!(exec_rule.parse::<SandboxPolicy>().is_err());

        let exit_rule = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,read,write,exit\n        seccomp.arg.exit.0 = 0xff:0x00",
        );
        assert!(exit_rule.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn parses_selected_handle_mapping() {
        let text = format!("{VALID}\nhandle.9 = 200");
        let policy: SandboxPolicy = text.parse().unwrap();
        assert_eq!(policy.selected_handles.get(&9), Some(&200));
    }

    #[test]
    fn rejects_duplicate_selected_handle_target() {
        let text = format!("{VALID}\nhandle.9 = 200\nhandle.9 = 201");
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_selected_handle_target_outside_owned_range_or_rlimit() {
        for mapping in ["handle.2 = 200", "handle.64 = 200", "handle.32 = 200"] {
            let text = format!("{VALID}\n{mapping}");
            assert!(
                text.parse::<SandboxPolicy>().is_err(),
                "accepted invalid mapping {mapping}"
            );
        }
    }

    #[test]
    fn rejects_selected_handle_source_outside_linux_fd_range() {
        let text = format!("{VALID}\nhandle.9 = {}", u32::MAX);
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_too_many_selected_handles() {
        let mut text = VALID.to_owned();
        for target_fd in 3..20 {
            text.push_str(&format!("\nhandle.{target_fd} = 200"));
        }
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
