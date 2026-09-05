#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::run;

#[cfg(not(target_os = "linux"))]
pub(crate) fn run(
    _policy: &crate::SandboxPolicy,
) -> Result<crate::ChildOutcome, crate::SandboxError> {
    Err(crate::SandboxError::UnsupportedPlatform(
        "Milestone 1 enforcement is implemented only for Linux x86_64".to_owned(),
    ))
}
