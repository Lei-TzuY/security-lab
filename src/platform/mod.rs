use crate::{ChildOutcome, SandboxError, SandboxPolicy};

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::run;

#[cfg(not(target_os = "linux"))]
pub(crate) fn run(_policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    Err(SandboxError::UnsupportedPlatform(
        "Milestone 1 enforcement is implemented only for Linux x86_64".to_owned(),
    ))
}
