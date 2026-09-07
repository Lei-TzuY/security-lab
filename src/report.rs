use std::fmt;

/// Observable terminal status of the direct sandbox target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildOutcome {
    Exited(i32),
    Signaled(i32),
    /// Launcher-owned wall-clock deadline expired before the direct target
    /// became waitable. This is distinct from an ordinary target signal.
    TimedOut,
    /// A caller-controlled cancellation token became ready while the direct
    /// target was still running. PID 1 owns the resulting tree teardown.
    Cancelled,
    /// The host capture path observed stdout beyond the declared total-output
    /// budget and requested launcher-owned process-tree termination.
    OutputLimitExceeded,
}

impl fmt::Display for ChildOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exited(code) => write!(f, "exited code={code}"),
            Self::Signaled(signal) => write!(f, "signaled signal={signal}"),
            Self::TimedOut => f.write_str("timed out"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::OutputLimitExceeded => f.write_str("stdout output limit exceeded"),
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

/// Kernel resource usage attributed to the terminated/waited-for sandbox process tree.
///
/// CPU fields are cumulative `RUSAGE_CHILDREN` values observed by launcher-owned
/// namespace PID 1 after it has reaped the direct target and remaining descendants.
/// On Linux, `max_child_rss_kib` is the largest child's peak RSS, not a concurrent
/// whole-tree memory high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessTreeUsage {
    pub user_cpu_micros: u64,
    pub system_cpu_micros: u64,
    pub max_child_rss_kib: u64,
}

/// Kernel enforcement layers positively observed during this launcher-owned run.
///
/// Each field becomes true only after the corresponding kernel operation succeeds.
/// A false field means that layer was not observed before termination; this can be
/// expected when launcher-owned cancellation, deadline, or output-budget control
/// wins while the direct target is still in setup. The receipt intentionally does
/// not claim successful `execveat`, because a control-plane termination can race
/// between the final pre-exec setup step and the non-returning exec syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EnforcementReceipt {
    pub base_namespaces: bool,
    pub time_namespace_offsets: bool,
    pub hostname: bool,
    pub private_mount_propagation: bool,
    pub readonly_root: bool,
    pub chroot: bool,
    pub fd_sanitization: bool,
    pub rlimits: bool,
    pub capabilities_reduced: bool,
    pub no_new_privs: bool,
    pub landlock: bool,
    pub seccomp: bool,
}

/// Detailed result for callers that need launcher-owned captured output, process-tree lifecycle evidence, or a runtime enforcement receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    /// Terminal status of the direct target, not of the namespace init.
    pub outcome: ChildOutcome,
    /// Present exactly when stdout was configured as `capture`.
    pub stdout: Option<CapturedOutput>,
    /// Additional orphaned descendants reaped by the launcher-owned PID 1 after the direct target terminated.
    pub reaped_descendants: u32,
    /// Kernel resource telemetry collected by namespace PID 1 only after the sandbox tree converges.
    pub process_tree_usage: ProcessTreeUsage,
    /// Runtime receipt for setup enforcement layers positively observed before termination.
    pub enforcement: EnforcementReceipt,
}
