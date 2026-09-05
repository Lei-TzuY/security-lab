use std::fmt;

/// Observable terminal status of a sandboxed child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited(i32),
    Signaled(i32),
}

impl fmt::Display for ChildOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exited code={code}"),
            Self::Signaled(signal) => write!(f, "signaled signal={signal}"),
        }
    }
}

/// Bounded bytes collected from a launcher-owned capture pipe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedOutput {
    pub bytes: Vec<u8>,
    /// True when the child produced more bytes than the policy capture ceiling.
    /// The launcher continues draining excess bytes so the child cannot deadlock
    /// merely because the retained capture buffer is full.
    pub truncated: bool,
}

/// Detailed result for callers that need launcher-owned captured output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub outcome: ChildOutcome,
    /// Present exactly when stdout was configured as `capture`.
    pub stdout: Option<CapturedOutput>,
}
