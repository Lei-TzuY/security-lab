#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::run_report;

#[cfg(not(target_os = "linux"))]
pub(crate) fn run_report(
    _policy: &crate::SandboxPolicy,
    _cancellation: Option<&crate::CancellationToken>,
) -> Result<crate::RunReport, crate::SandboxError> {
    Err(crate::SandboxError::UnsupportedPlatform(
        "sandbox enforcement currently supports Linux x86_64 only".to_owned(),
    ))
}
