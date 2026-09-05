# Roadmap

## Milestone 1 — bounded Linux process sandbox

**Status: complete on `main`.**

Delivered strict policy validation, environment/cwd control, four rlimits, `PR_SET_NO_NEW_PRIVS`, default-deny seccomp-BPF allowlisting, explicit unsupported-platform behavior, deterministic raw-syscall fixtures, observable child status, threat model, and locked/MSRV CI.

## Milestone 2 — ambient authority, launch integrity, filesystem and descriptor authority

**Status: sealed on `main`.**

Slices 2A–2F-B removed arbitrary inherited-FD authority, introduced owned launch/error reporting, filesystem/identity confinement, recursively read-only root + bounded private scratch, explicit stdio, launcher-owned stdout redirection, and bounded launcher-owned stdout capture. Exact integrated implementations passed locked stable quality and Rust 1.74 suites. Do not farm more stdout/FD variants without a concrete new integration need.

## Milestone 3 — process-tree isolation and lifecycle ownership

### Slice 3A — PID namespace and owned process-tree lifecycle

**Status: complete on `main`.**

Linux `CLONE_NEWPID` is implemented through explicit bootstrap/init/target orchestration rather than a configuration-only flag:

- launcher-owned namespace init runs as PID 1;
- direct target runs as PID 2 and alone receives target stdio/rlimit/capability/seccomp setup;
- PID 1 waits for the direct target, then repeatedly kills remaining namespace processes and reaps children until `ECHILD`;
- shared lifecycle state preserves direct-target raw wait status and descendant-reap count;
- bootstrap/PID1 close descriptors >= 3, so descendant teardown resolves capture-writer lifetime correctly.

Raw evidence proves PID2/PID1 identity and cleanup of a live descendant retaining stdout.

### Slice 3B — policy-owned wall-clock deadline

**Current verified candidate.** Add real bounded-runtime enforcement rather than a policy-only timeout name.

Implementation:

- optional `limit.wall_clock_milliseconds`, validated in the range **1–86,400,000 ms**;
- requested deadline support is preflighted for `pidfd_open` and monotonic timerfd primitives; missing/denied mandatory support fails explicitly;
- after PID 1 forks the direct target and closes inherited setup descriptors, it opens a pidfd for the target, arms a one-shot `CLOCK_MONOTONIC` timerfd, and polls both descriptors;
- on every supervision wake, one `wait4(target, WNOHANG)` is the race arbiter: already-waitable target means natural termination wins;
- if the timer is readable while the target is still not waitable, deadline ownership wins, PID 1 sends `SIGKILL`, waits for the direct target, then performs the existing deterministic descendant kill/reap loop;
- shared lifecycle state records timeout ownership separately from the raw wait status, so callers receive `ChildOutcome::TimedOut` rather than an ordinary `Signaled(SIGKILL)`;
- pidfd/timerfd/poll remain launcher-only and do not widen target seccomp;
- timeout enforcement is independent of host-side blocking capture drain, so timeout teardown releases target-tree stdout writers and lets capture EOF converge;
- CLI maps `TimedOut` to exit status 124.

Acceptance evidence is executable:

- parser/unit tests accept an exact valid millisecond deadline and reject zero, oversized, and duplicate declarations;
- a raw target writes `deadline target started\n`, forks one descendant that blocks indefinitely in `pause()`, and keeps the direct target alive for five seconds. A **1,000 ms** deadline returns `TimedOut`, reaps exactly one additional descendant, preserves the exact captured marker, and converges capture EOF;
- the five-second direct-target path is only a test watchdog so a broken deadline cannot hang CI indefinitely;
- a raw target that exits 42 under a **5,000 ms** deadline still returns `Exited(42)`, proving natural completion is not rewritten as timeout;
- all Milestones 1–3A regressions remain green;
- exact implementation head passes stable rustfmt, Clippy `-D warnings`, the full locked stable suite, and the full Rust 1.74 suite.

Boundary: the deadline is armed by PID 1 after the direct-target fork and PID1 descriptor cleanup. It is not an end-to-end API-call latency guarantee. 3B also does **not** implement an externally-triggerable asynchronous cancellation handle.

### Milestone 3 exit condition

After 3B passes PR merge-ref and post-merge main CI, seal the basic process-lifecycle phase instead of farming timeout aliases, different timer units, or reap-count variants. PID-tree identity, post-target cleanup, capture-lifetime integration, and bounded runtime ownership will then all have executable evidence.

## Milestone 4 — aggregate resource and process accounting

### Slice 4A — cgroup-v2 bounded process-tree accounting

**Next architectural frontier after 3B integration, contingent on executable CI support for the real kernel controller.** Per-process rlimits are already useful, but they do not aggregate a process tree. The next high-value hypothesis is a launcher-owned cgroup-v2 boundary rather than another rlimit wrapper.

Initial acceptance criteria:

- detect and fail explicitly when the required writable/delegated cgroup-v2 capability is unavailable; no fake fallback or skipped enforcement claim;
- place the sandbox process tree into a launcher-owned cgroup before untrusted target execution can escape aggregate accounting;
- enforce at least one real aggregate controller/property with deterministic evidence (prefer `pids.max` first because it directly complements 3A/3B process-tree ownership; memory/CPU controllers only when CI can exercise them reliably);
- prove a target cannot exceed the declared aggregate process count while ordinary permitted process creation below the ceiling still works;
- clean up the cgroup only after PID-tree teardown and verify no sandbox processes remain attached;
- preserve deadline, capture, filesystem, seccomp, capability, descriptor, and launch-error semantics;
- stable quality and Rust 1.74 full suites remain green.

If the available CI runner does not expose a safely writable/delegated cgroup-v2 subtree, that is a real external-platform blocker for 4A; in that case promote to the next independently verifiable frontier (for example network namespace/policy) rather than claiming cgroup enforcement from mocks.

## Later frontiers

After aggregate accounting, prioritize network namespace/policy. Keep external asynchronous cancellation, selected-handle passing, syscall-argument filtering, broader persistent-volume policy, and other isolation surfaces as separate evidence-backed frontiers rather than configuration-only names.
