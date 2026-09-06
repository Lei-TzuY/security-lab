//! Small, correctness-first process sandbox used by the security lab.
//!
//! The policy model is platform-neutral. Enforcement is delegated to a
//! platform layer which either applies every requested boundary or fails.

mod cancellation;
mod platform;
pub mod policy;
pub mod report;

use std::error::Error;
use std::fmt;

pub use cancellation::CancellationToken;
pub use policy::{
    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode,
    StdioPolicy,
};
pub use report::{CapturedOutput, ChildOutcome, ProcessTreeUsage, RunReport};

#[derive(Debug)]
pub enum SandboxError {
    InvalidPolicy(PolicyError),
    UnsupportedPlatform(String),
    SetupFailed(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(err) => write!(f, "invalid policy: {err}"),
            Self::UnsupportedPlatform(message) => write!(f, "unsupported platform: {message}"),
            Self::SetupFailed(message) => write!(f, "sandbox setup failed: {message}"),
        }
    }
}

impl Error for SandboxError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPolicy(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PolicyError> for SandboxError {
    fn from(value: PolicyError) -> Self {
        Self::InvalidPolicy(value)
    }
}

/// Validate and execute exactly the invocation described by `policy`,
/// returning terminal status plus any launcher-owned captured output.
pub fn run_report(policy: &SandboxPolicy) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, None)
}

/// Validate and execute the invocation while allowing another thread holding a
/// clone of `cancellation` to request launcher-owned process-tree termination.
pub fn run_report_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<RunReport, SandboxError> {
    policy.validate()?;
    platform::run_report(policy, Some(cancellation))
}

/// Validate and execute exactly the invocation described by `policy`.
///
/// This status-only compatibility API still drains any configured capture pipe
/// through `run_report`, then discards the retained bytes. A setup error is
/// terminal; execution never retries without the requested restrictions.
pub fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report(policy)?.outcome)
}

/// Status-only counterpart to [`run_report_with_cancel`].
pub fn run_with_cancel(
    policy: &SandboxPolicy,
    cancellation: &CancellationToken,
) -> Result<ChildOutcome, SandboxError> {
    Ok(run_report_with_cancel(policy, cancellation)?.outcome)
}
