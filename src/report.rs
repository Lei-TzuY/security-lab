use std::fmt;

/// Observable terminal status of the direct sandbox target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited(i32),
    Signaled(i32),
    /// Launcher-owned wall-clock deadline expired before the direct target
    /// became waitable. This is distinct from an ordinary target signal.
    TimedOut,
}

impl fmt::Display for ChildOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exited code={code}"),
            Self::Signaled(signal) => write!(f, "signaled signal={signal}"),
            Self::TimedOut => f.write_str("timed out"),
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

/// Detailed result for callers that need launcher-owned captured output or process-tree lifecycle evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// Terminal status of the direct target, not of the namespace init.
    pub outcome: ChildOutcome,
    /// Present exactly when stdout was configured as `capture`.
    pub stdout: Option<CapturedOutput>,
    /// Additional orphaned descendants reaped by the launcher-owned PID 1 after the direct target terminated.
    pub reaped_descendants: u32,
}
