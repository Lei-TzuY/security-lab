//! Small, correctness-first process sandbox used by the security lab.
//!
//! The policy model is platform-neutral. Enforcement is delegated to a
//! platform layer which either applies every requested boundary or fails.

mod platform;
pub mod policy;
pub mod report;

use std::error::Error;
use std::fmt;

pub use policy::{
    PolicyError, ResourceLimits, SandboxPolicy, SeccompPolicy, StdioMode, StdioPolicy,
};
pub use report::ChildOutcome;

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

/// Validate and execute exactly the invocation described by `policy`.
///
/// There is deliberately no API for caller-supplied executable or argument
/// overrides. A setup error is terminal; execution never retries without the
/// requested restrictions.
pub fn run(policy: &SandboxPolicy) -> Result<ChildOutcome, SandboxError> {
    policy.validate()?;
    platform::run(policy)
}
