from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "README.md",
    "Milestone 15A added **one exact numeric host-IPv4 TCP endpoint broker**. The current Milestone 16A verified candidate adds **one exact numeric host-IPv4 UDP datagram broker**: the trusted parent creates and connects a datagram socket to a declared numeric IPv4 address and port before fork, then transfers only that socket capability into the otherwise isolated target.",
    "Milestone 15A added **one exact numeric host-IPv4 TCP endpoint broker**, and Milestone 16A added **one exact numeric host-IPv4 UDP datagram broker** while preserving target-network isolation. The current Milestone 17A verified candidate adds **launcher-owned process-tree resource telemetry**: namespace PID 1 reports cumulative waited-child user/system CPU time and Linux largest-child peak RSS after the sandbox process tree has converged.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "10. **Owned process-tree teardown** after natural target termination, deadline termination, or external cancellation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. It then publishes raw target wait status, timeout/cancellation ownership, and the number of additional descendants reaped.",
    "10. **Owned process-tree teardown and accounting** after natural target termination, deadline termination, or external cancellation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. After the tree has converged, PID 1 calls `getrusage(RUSAGE_CHILDREN)` and publishes raw target wait status, timeout/cancellation ownership, additional descendants reaped, cumulative waited-child user/system CPU microseconds, and Linux largest-child peak RSS in KiB before lifecycle readiness.",
    "README lifecycle accounting",
)
replace_one(
    "README.md",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout and `reaped_descendants`. The compatibility status-only APIs return the same `ChildOutcome`. The human `run` CLI preserves its text contract, while `run-json` emits deterministic structured success/error records with captured bytes encoded losslessly as hexadecimal; both preserve the existing outcome-to-exit-status mapping (`TimedOut` 124, `Cancelled` 130).",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout, `reaped_descendants`, and `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`. The compatibility status-only APIs return the same `ChildOutcome`. The human `run` CLI preserves its text contract, while `run-json` emits the same telemetry as unsigned decimal fields alongside deterministic outcome/capture structure; both preserve the existing outcome-to-exit-status mapping (`TimedOut` 124, `Cancelled` 130).",
    "README reporting",
)
replace_one(
    "README.md",
    "- After natural, timeout, or cancelled termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published.\n",
    "- After natural, timeout, or cancelled termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published. It then obtains `RUSAGE_CHILDREN` and publishes cumulative waited-child user/system CPU plus Linux largest-child `ru_maxrss`; this is post-mortem observability, not an enforcement mechanism.\n",
    "README usage invariant",
)
replace_one(
    "README.md",
    "Linux x86_64 integration tests prove that:\n\n",
    "Linux x86_64 integration tests prove that:\n\n- a raw target maps 8 MiB of anonymous memory, faults every 4 KiB page, exits normally, and the completed `RunReport` exposes at least 4096 KiB of `max_child_rss_kib`; CLI integration independently preserves the exact deterministic outcome/capture prefix while requiring all three resource-usage fields to be unsigned decimal values;\n",
    "README usage evidence",
)
replace_one(
    "README.md",
    "- `reaped_descendants` is not a total process-creation counter or process-limit/accounting mechanism;\n- there is no cgroup aggregate CPU/memory/process accounting or process-count quota.",
    "- `reaped_descendants` is not a total process-creation counter or process-limit/accounting mechanism;\n- `ProcessTreeUsage` is post-mortem kernel telemetry, not a benchmark or resource limit. `user_cpu_micros` / `system_cpu_micros` are cumulative `RUSAGE_CHILDREN` CPU time for waited descendants, while Linux `max_child_rss_kib` is the largest child's peak RSS rather than a concurrent whole-tree memory high-water mark;\n- there is no cgroup-enforced aggregate CPU/memory/process accounting or process-count quota.",
    "README usage limitation",
)

replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–16A threat model",
    "# Milestones 1–17A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 15A added one exact numeric host-IPv4 TCP endpoint broker. The current Milestone 16A verified candidate adds one exact numeric host-IPv4 connected UDP datagram socket capability while preserving the target network namespace's direct host separation.",
    "Milestone 15A added one exact numeric host-IPv4 TCP endpoint broker, and Milestone 16A added one exact numeric host-IPv4 connected UDP datagram socket capability while preserving target-network separation. The current Milestone 17A verified candidate adds launcher-owned post-mortem process-tree resource telemetry from `RUSAGE_CHILDREN` after PID1 teardown convergence.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "stdio, bounded capture, process-tree lifecycle, a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used, while preserving fail-closed launch/lifecycle reporting.",
    "stdio, bounded capture, process-tree lifecycle, launcher-owned post-mortem resource telemetry, a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used, while preserving fail-closed launch/lifecycle reporting.",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally, by deadline, or by external cancellation—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.\n",
    "- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally, by deadline, or by external cancellation—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`.\n- **Post-mortem process-tree resource telemetry:** only after teardown converges, PID 1 calls `getrusage(RUSAGE_CHILDREN)` and publishes cumulative waited-child user/system CPU microseconds plus Linux `ru_maxrss`. The RSS field is explicitly named `max_child_rss_kib` because Linux reports the largest child's peak RSS for this selector, not a concurrent aggregate tree high-water mark. Resource fields are written before lifecycle `ready`, so callers never accept a partially published report.\n",
    "threat usage property",
)
replace_one(
    "THREAT_MODEL.md",
    "- cgroup-backed aggregate CPU, physical-memory, I/O, or process accounting;",
    "- cgroup-backed aggregate CPU, physical-memory, I/O, or process enforcement/accounting. Milestone 17A reports waited-child CPU totals and largest-child peak RSS only; it does not turn those observations into cgroup-style limits or concurrent aggregate memory accounting;",
    "threat cgroup non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.\n",
    "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74. Milestone 17A adds a raw mode that `mmap`s 8 MiB anonymously and faults every 4 KiB page; the parent requires `max_child_rss_kib >= 4096`, while CLI integration validates the stable JSON structure plus unsigned-decimal telemetry fields without pretending live CPU/RSS values are deterministic.\n",
    "threat usage evidence",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a connectionless/message-boundary-preserving transport capability rather than another TCP endpoint alias.",
    "**Status: complete on `main`.** Adds a connectionless/message-boundary-preserving transport capability rather than another TCP endpoint alias.",
    "roadmap 16A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 16 promotion rule\n\nAfter 16A integrates, seal the bounded exact-address preconnected IPv4 TCP/UDP broker family. Do not farm more address literals, ports, target-fd aliases, or trivial socket-type variants. Promote only to a materially different topology/resource/observability boundary with executable evidence.\n\n## Later frontiers",
    "### Milestone 16 promotion rule\n\n16A is integrated; seal the bounded exact-address preconnected IPv4 TCP/UDP broker family. Do not farm more address literals, ports, target-fd aliases, or trivial socket-type variants. Promotion is now a materially different resource/observability boundary.\n\n## Milestone 17 — launcher-owned resource observability\n\n### Slice 17A — process-tree resource usage report\n\n**Current verified candidate.** Converts resource data already owned by namespace PID 1 into an explicit post-mortem report without pretending to provide cgroup enforcement or benchmarking.\n\nAcceptance evidence is executable:\n\n- `RunReport` adds `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`, and the public re-export makes the telemetry part of the library report contract;\n- namespace PID 1 performs its existing direct-target wait and remaining-descendant kill/reap convergence first, then calls `getrusage(RUSAGE_CHILDREN)` and publishes all usage fields before lifecycle `ready`;\n- user/system CPU fields are cumulative waited-child CPU microseconds. On Linux, `max_child_rss_kib` deliberately names `RUSAGE_CHILDREN.ru_maxrss` as the largest child's peak RSS rather than a concurrent whole-tree memory high-water mark;\n- a statically linked raw target maps 8 MiB anonymous memory and faults every 4 KiB page using only explicit `mmap`/`exit` target grants; the completed report must expose at least 4096 KiB of `max_child_rss_kib`;\n- `run-json` carries all three resource fields as unsigned decimal integers while preserving the exact deterministic outcome/captured-output prefix instead of hard-coding nondeterministic CPU/RSS values;\n- stable format/Clippy/full tests and the full Rust 1.74 suite are green, with all Milestones 1–16A regressions retained.\n\nBoundary: 17A is post-mortem kernel observability only. It does not provide live sampling, per-process attribution, a deterministic performance benchmark, a concurrent process-tree RSS peak, cgroup-backed aggregate CPU/memory/I/O/process accounting, or any new resource limit/enforcement mechanism.\n\n### Milestone 17 promotion rule\n\nAfter 17A integrates, do not farm more `rusage` counters or output aliases. Promote only to a materially different enforceable resource boundary when prerequisites exist, or another independent authority/observability subsystem with executable evidence. Milestone 4A remains blocked until a real writable/delegated cgroup-v2 subtree is available to the unprivileged runtime user.\n\n## Later frontiers",
    "roadmap 17A section",
)
