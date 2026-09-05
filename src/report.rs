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
