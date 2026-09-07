from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal integrated 21A and describe only executable 22B behavior.
replace_one(
    "README.md",
    "The current Milestone 21A verified candidate adds **inclusive unsigned full-64-bit seccomp argument ranges** that only narrow already-allowed syscalls and compose conjunctively with existing masked-equality rules.",
    "Milestone 21A added **inclusive unsigned full-64-bit seccomp argument ranges** that only narrow already-allowed syscalls and compose conjunctively with existing masked-equality rules. The current Milestone 22B verified candidate adds an optional **host-observed stdout total-output budget** for captured stdout: once the launcher observes bytes beyond the declared threshold, it asks launcher-owned PID 1 to terminate and reap the sandbox process tree and reports a distinct output-limit outcome.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "scratch, stdout redirection, stdout capture, optional `limit.stdout_total_bytes`, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "README policy summary",
)
replace_one(
    "README.md",
    "7. **Optional deadline/cancellation supervision** after forking the target, PID 1 closes inherited setup descriptors, opens a pidfd whenever deadline or external cancellation supervision is active, optionally creates and arms a `CLOCK_MONOTONIC` timerfd, and optionally retains the launcher-pinned cancellation eventfd. The direct target closes the cancellation control descriptor before stdio/rlimit/capability/seccomp/exec setup, so the token is not a target capability.\n8. **Deterministic supervision race** whenever supervision wakes, PID 1 first performs one `wait4(target, WNOHANG)`. If the direct target is already waitable, natural termination wins. Otherwise a readable cancellation eventfd wins before a simultaneously readable deadline timer; PID 1 terminates the direct target and reports `ChildOutcome::Cancelled` or `ChildOutcome::TimedOut` according to the winning control path.",
    "7. **Optional launcher supervision controls** after forking the target, PID 1 closes inherited setup descriptors and opens a pidfd whenever deadline, external cancellation, or stdout-output-budget supervision is active. It may arm a `CLOCK_MONOTONIC` timerfd and retain launcher-owned cancellation/output-limit eventfds. The direct target closes both control descriptors before stdio/rlimit/capability/seccomp/exec setup, so neither becomes a target capability.\n8. **Deterministic supervision race** preserves natural-exit-first arbitration for ordinary cancellation/deadline wakes (`natural exit > explicit cancellation > deadline`). An output-limit event is different: it exists only after the host capture path has already observed a policy violation, so a readable output-limit event owns the result before the natural-exit check in that poll cycle and reports `ChildOutcome::OutputLimitExceeded`.",
    "README supervision pipeline",
)
replace_one(
    "README.md",
    "10. **Owned process-tree teardown and accounting** after natural target termination, deadline termination, or external cancellation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. After the tree has converged, PID 1 calls `getrusage(RUSAGE_CHILDREN)` and publishes raw target wait status, timeout/cancellation ownership, additional descendants reaped, cumulative waited-child user/system CPU microseconds, and Linux largest-child peak RSS in KiB before lifecycle readiness.\n11. **Bounded stdout capture** the host parent drains capture before waiting for bootstrap completion, retains only the declared byte ceiling, and discards excess bytes. Deadline or external cancellation can still fire while that host drain is blocking because supervision lives in PID 1; terminating/reaping the target tree closes remaining capture writers and lets EOF converge.\n12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout, `reaped_descendants`, and `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`. The compatibility status-only APIs return the same `ChildOutcome`. The human `run` CLI preserves its text contract, while `run-json` emits the same telemetry as unsigned decimal fields alongside deterministic outcome/capture structure; both preserve the existing outcome-to-exit-status mapping (`TimedOut` 124, `Cancelled` 130).",
    "10. **Owned process-tree teardown and accounting** after natural target termination, deadline termination, external cancellation, or an observed stdout-budget violation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. After the tree has converged, PID 1 calls `getrusage(RUSAGE_CHILDREN)` and publishes raw target wait status, control-path ownership, additional descendants reaped, cumulative waited-child user/system CPU microseconds, and Linux largest-child peak RSS in KiB before lifecycle readiness.\n11. **Bounded stdout capture/output observation** the host parent retains at most `stdio.stdout_capture_bytes`. Without `limit.stdout_total_bytes`, excess capture remains drain-and-discard behavior. With a total-output threshold, the parent counts bytes actually read from the capture pipe and, on the first read that makes the observed total exceed the threshold, signals PID 1 and stops draining; closing the read end plus PID1 teardown converges remaining writers. This is an observed threshold, not an exact kernel emission cap.\n12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, `Cancelled`, or `OutputLimitExceeded`, plus captured stdout, `reaped_descendants`, and `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`. The compatibility status-only APIs return the same `ChildOutcome`. `run-json` emits `output_limit_exceeded` for the new outcome; the CLI maps it to status 122 while preserving `TimedOut` 124 and `Cancelled` 130.",
    "README capture/report pipeline",
)
replace_one(
    "README.md",
    "- Supervision arbitration is natural exit > explicit cancellation > deadline when readiness is observed in one poll cycle.\n- After natural, timeout, or cancelled termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published. It then obtains `RUSAGE_CHILDREN` and publishes cumulative waited-child user/system CPU plus Linux largest-child `ru_maxrss`; this is post-mortem observability, not an enforcement mechanism.",
    "- Ordinary supervision arbitration is natural exit > explicit cancellation > deadline. Once the host has observed stdout beyond a declared total-output threshold, that already-observed policy violation instead owns the output-limit result before natural-exit arbitration for that wake.\n- After natural, timeout, cancelled, or output-limited termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published. It then obtains `RUSAGE_CHILDREN` and publishes cumulative waited-child user/system CPU plus Linux largest-child `ru_maxrss`; this is post-mortem observability, not an enforcement mechanism.",
    "README supervision invariants",
)
replace_one(
    "README.md",
    "- `stdio.stdout_capture_bytes` bounds retained parent memory from 1 byte through 16 MiB; excess output is drained and discarded.\n- Launcher management syscalls used for namespaces, mounts, PID lifecycle, deadline supervision, redirection, capture, remapping, and setup are not silently added to the target seccomp allowlist.",
    "- `stdio.stdout_capture_bytes` bounds retained parent memory from 1 byte through 16 MiB. Optional `limit.stdout_total_bytes` is a separate 1-byte-through-1-GiB host-observed threshold and must be at least the retained capture ceiling; it does not allocate that amount of memory.\n- Launcher management syscalls used for namespaces, mounts, PID lifecycle, deadline/cancellation/output-limit supervision, redirection, capture, remapping, and setup are not silently added to the target seccomp allowlist.",
    "README output invariants",
)
replace_one(
    "README.md",
    "- `capture`: stdout only; requires `stdio.stdout_capture_bytes` in the range 1–16 MiB.\n\n`identity.hostname` is required.",
    "- `capture`: stdout only; requires `stdio.stdout_capture_bytes` in the range 1–16 MiB.\n\n`limit.stdout_total_bytes` is optional and valid only with stdout capture. It is an observed-total threshold in the range 1 byte–1 GiB, and `stdio.stdout_capture_bytes` may not exceed it. Once the host reads a chunk that pushes observed stdout beyond the threshold, the launcher signals PID 1 for owned process-tree teardown. Bytes may already exist in the kernel pipe beyond the threshold, so this is not an exact emitted-byte ceiling.\n\n`identity.hostname` is required.",
    "README output policy format",
)
replace_one(
    "README.md",
    "stdio.stdout_capture_bytes = 65536\nstdio.stderr = inherit\nlimit.wall_clock_milliseconds = 5000",
    "stdio.stdout_capture_bytes = 65536\nstdio.stderr = inherit\nlimit.stdout_total_bytes = 1048576\nlimit.wall_clock_milliseconds = 5000",
    "README output example",
)

# Threat model: precise claim, explicit non-goal.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–21A threat model",
    "# Milestones 1–21A + 22B threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 21A verified candidate adds inclusive unsigned full-64-bit seccomp argument ranges that compose with the existing masked-equality predicate family.",
    "Milestone 21A added inclusive unsigned full-64-bit seccomp argument ranges that compose with the existing masked-equality predicate family. The current Milestone 22B verified candidate adds a launcher-owned response to a host-observed captured-stdout threshold without claiming an exact kernel emission cap.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Bounded retained capture:** `stdio.stdout_capture_bytes` is 1 byte–16 MiB; excess bytes are drained/discarded rather than retained.\n- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally, by deadline, or by external cancellation—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`.",
    "- **Bounded retained capture:** `stdio.stdout_capture_bytes` is 1 byte–16 MiB and limits retained parent memory independently of any total-output policy.\n- **Optional observed stdout budget:** `limit.stdout_total_bytes` is valid only with capture, is bounded to 1 byte–1 GiB, and must be at least the retained capture ceiling. The host counts bytes returned by `read(2)` from the capture pipe; after the first read that makes the observed total exceed policy, it signals a launcher-owned eventfd and stops draining.\n- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After natural termination, deadline/cancellation ownership, or an observed stdout-budget violation, PID 1 kills remaining namespace processes and reaps until `ECHILD`.",
    "threat output properties",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Deterministic supervision race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. Otherwise cancellation readiness is checked before deadline readiness, yielding natural exit > explicit cancellation > deadline when multiple conditions are simultaneously observable.\n- **Distinct control results:** deadline ownership reports `ChildOutcome::TimedOut`; cancellation ownership reports `ChildOutcome::Cancelled`. Both may use `SIGKILL` after ownership is established, but neither is reported as an ordinary target signal.",
    "- **Deterministic supervision race:** ordinary cancellation/deadline wakes still use natural exit > explicit cancellation > deadline. Output-limit readiness is checked first because its eventfd can only be signalled after the host has already observed a policy violation; that violation remains reportable even if target status becomes waitable concurrently.\n- **Distinct control results:** deadline ownership reports `ChildOutcome::TimedOut`, cancellation reports `ChildOutcome::Cancelled`, and observed stdout overrun reports `ChildOutcome::OutputLimitExceeded`. These launcher-owned paths may use `SIGKILL` for teardown but are not reported as ordinary target signals.",
    "threat output race",
)
replace_one(
    "THREAT_MODEL.md",
    "- a total-output byte ceiling for captured stdout;",
    "- an exact kernel-level emitted-byte ceiling or bandwidth/CPU throttle for stdout. Milestone 22B acts only after the host observes capture bytes beyond policy, so pipe-buffered bytes may already have been emitted past the threshold; it does not cover stderr, inherited stdout, or redirected stdout;",
    "threat output non-goal",
)

# Roadmap: close 21A and record the independently executable 22B slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a materially different numeric predicate model beyond 5A masked equality without widening the syscall allowlist.",
    "**Status: complete on `main`.** Adds a materially different numeric predicate model beyond 5A masked equality without widening the syscall allowlist.",
    "roadmap 21A status",
)
replace_one(
    "ROADMAP.md",
    "After 21A integrates, seal this bounded numeric-range slice. Do not farm `<`, `<=`, `>`, `>=`, endpoint aliases, or more fixture values around the same cBPF comparison mechanism. A later seccomp slice must introduce materially different executable semantics; otherwise promote to another subsystem frontier such as routed/broader networking only when explicit topology/endpoint evidence is available.\n\n## Later frontiers",
    "21A is sealed on `main`. Do not farm `<`, `<=`, `>`, `>=`, endpoint aliases, or more fixture values around the same cBPF comparison mechanism. A later seccomp slice must introduce materially different executable semantics.\n\n## Milestone 22 — launcher-owned output enforcement\n\n### Slice 22B — observed stdout total-output budget\n\n**Current verified candidate.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.\n\nAcceptance evidence is executable:\n\n- optional `limit.stdout_total_bytes` is valid only with `stdio.stdout = capture`, is bounded to 1 byte–1 GiB, and requires the retained `stdio.stdout_capture_bytes` ceiling to be no larger than the total threshold;\n- the host creates a private output-limit eventfd only when the policy requests this control, while the direct target closes its inherited control copy before untrusted execution;\n- the capture reader counts bytes actually returned from the pipe, retains at most the existing memory ceiling, and signals PID 1 on the first read that makes observed stdout exceed the total threshold;\n- PID 1 owns termination/reaping through its existing pidfd supervision path and publishes `ChildOutcome::OutputLimitExceeded`; output-limit readiness wins once overrun was already observed, while cancellation/deadline keep their existing natural-exit-first arbitration;\n- a raw target forks one paused descendant and continuously writes stdout; with a 4 KiB observed budget and 1 KiB retained ceiling the run reports `OutputLimitExceeded`, returns exactly 1 KiB retained/truncated capture, and reports exactly one additional descendant reaped;\n- the pre-existing no-total-budget stress test still drains/discards excess output and completes naturally, proving backwards-compatible capture semantics;\n- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 22B is host-observed enforcement, not a precise kernel byte meter. Pipe-buffered bytes may already have been emitted beyond the configured threshold before the parent reads them. It does not throttle bandwidth or CPU, and it does not apply to stderr, inherited stdout, or redirected stdout.\n\n### Milestone 22B promotion rule\n\nAfter 22B integrates, do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. Re-evaluate the reserved supplementary-group/user-namespace frontier separately, or promote to another independent subsystem frontier with executable evidence.\n\n## Later frontiers",
    "roadmap 22B section",
)
