# Roadmap

## Milestone 1 — bounded Linux process sandbox

**Status: complete on `main`.**

Delivered strict policy validation, environment/cwd control, four rlimits, `PR_SET_NO_NEW_PRIVS`, default-deny seccomp-BPF allowlisting, explicit unsupported-platform behavior, deterministic raw-syscall fixtures, observable child status, threat model, and locked/MSRV CI.

## Milestone 2 — ambient authority, launch integrity, filesystem and descriptor authority

### Slice 2A — inherited descriptor sanitization

**Status: complete on `main`.** Arbitrary inherited descriptors >= 3 are marked `CLOEXEC` before target exec, with deterministic non-leakage evidence.

### Slice 2B — owned launch/error protocol

**Status: complete on `main`.** The Linux x86_64 launcher owns the fork/setup/seccomp/exec/wait lifecycle and reports phase-specific launch failures through shared memory without requiring target `write` permission.

### Slice 2C — filesystem and identity boundary

**Status: complete on `main`.** Root/cwd/initial-target selection is pinned with `openat2`; user/mount namespaces, UID/GID mapping, cap drop, private mount propagation, chroot, target `execveat(AT_EMPTY_PATH)`, directory-handle escape prevention, and capability reduction are enforced and integration-tested.

### Slice 2D — explicit filesystem mutability

**Status: complete on `main`.** The revalidated root is recursively cloned/read-only and policy may declare one bounded private `nosuid,nodev,noexec` tmpfs scratch area. Raw target evidence proves ordinary-root writes fail while scratch writes succeed without host write-through.

### Slice 2E — explicit standard descriptor disposition

**Status: complete on `main`.** stdin/stdout/stderr have no implicit default. Inherited descriptors must exist and not be directories; closed descriptors are actually closed. Raw evidence covers all-closed and selective inheritance while arbitrary descriptor >=3 non-leakage remains intact.

### Slice 2F-A — launcher-owned stdout redirection

**Status: complete on `main`.** `stdio.stdout = redirect` requires a destination strictly beneath private scratch. The launcher opens it only after scratch exists, keeps the temporary source `CLOEXEC`, maps only that source to fd 1, closes the source, and does not widen target seccomp. Raw target readback plus parent-side host-path absence proves usable private redirection.

### Slice 2F-B — bounded launcher-owned stdout capture

**Status: complete on `main`.** `stdio.stdout = capture` requires `stdio.stdout_capture_bytes` in the range 1 byte–16 MiB. The launcher creates `pipe2(O_CLOEXEC)` before fork, normalizes both endpoints above fd 2, closes the read side outside the host parent, preserves the write source through target setup, maps it only to fd 1, and closes temporary sources. The host parent drains stdout before waiting for launcher completion, retains no more than the declared ceiling, discards excess bytes, and reports truncation.

Acceptance evidence is executable:

- a small raw target returns exact stdout bytes with `truncated = false`;
- a stress target emits 4096 × 64-byte raw writes (**256 KiB**) under a **1 KiB retention ceiling**; the direct target exits successfully, exactly 1 KiB is retained, all retained bytes are correct, and `truncated = true`;
- all Milestones 1–2F-A regressions remain green, including arbitrary inherited high-FD absence;
- stable rustfmt, Clippy `-D warnings`, the full locked stable suite, and the full Rust 1.74 suite pass on the integrated implementation.

### Milestone 2 exit condition

**Sealed on `main`.** Descriptor/stdio authority has sufficient executable depth; do not farm more stdout/FD variants. Generic arbitrary FD remapping and selected non-stdio handle passing remain deferred capabilities that require a concrete future integration need and their own evidence-backed design.

## Milestone 3 — process-tree isolation and lifecycle ownership

### Slice 3A — PID namespace and owned process-tree lifecycle

**Current verified candidate.** Linux `CLONE_NEWPID` affects subsequently created children, so the launcher now uses explicit bootstrap/init/target orchestration rather than a configuration-only namespace flag:

- the launcher constructs user/mount/PID namespaces and filesystem state before entering the PID namespace;
- the first child in that namespace is launcher-owned PID 1;
- PID 1 forks the direct target as PID 2, while remaining outside target stdio/rlimit/capability/seccomp setup;
- PID 1 waits for the direct target, then repeatedly kills remaining namespace processes and reaps children until `ECHILD`;
- shared lifecycle state publishes the direct target raw wait status, an additional-descendant reap count, and readiness only after teardown completes;
- bootstrap/PID1 close descriptors >= 3, so they do not hold launcher capture writers open.

Acceptance evidence is executable:

- a raw target proves `getpid() == 2` and `getppid() == 1`;
- a raw target forks a descendant that blocks indefinitely in `pause()` while retaining stdout, then exits; PID 1 kills and reaps that descendant, `run_report()` reports one reaped descendant, and capture reaches EOF;
- direct-target exit-vs-signal and shared-memory launch-error semantics remain attached to the target rather than bootstrap/init status;
- all existing filesystem, capability, rlimit, seccomp, descriptor, redirection, capture, and MSRV regressions remain green;
- the exact implementation candidate passes stable rustfmt, Clippy `-D warnings`, the full locked stable suite, and the full Rust 1.74 suite before PR integration.

Boundary: 3A owns **post-target process-tree cleanup**, not target-runtime deadlines or aggregate process accounting. A direct target that never terminates can still keep the sandbox active indefinitely, subject only to already configured per-process rlimits and target behavior.

### Slice 3B — policy-owned wall-clock deadline/cancellation

**Next architectural frontier after 3A integration.** Add a real launcher-owned termination path for a direct target that never exits; do not model this as another enum without runtime enforcement.

Initial acceptance criteria:

- policy validation for a bounded wall-clock deadline with explicit units/range and fail-closed malformed values;
- launcher-side timing/control that does not require widening the target seccomp allowlist;
- on deadline expiry, terminate the direct target/process tree through the owned PID-namespace lifecycle and reap all descendants deterministically;
- report timeout/cancellation as an explicit launcher result distinct from ordinary target exit or target-delivered signal;
- captured stdout remains bounded and reaches a defined terminal state when timeout teardown occurs;
- timeout races with natural target exit have one deterministic ownership rule and no double-wait/double-report path;
- all Milestones 1–3A regressions, stable quality checks, and Rust 1.74 tests remain green.

## Later frontiers

After deadline/cancellation ownership, prioritize aggregate resource accounting/process quotas (for example cgroup-backed accounting where the supported CI platform can execute the real kernel mechanism), then network namespace/policy. Keep selected-handle passing, syscall-argument filtering, broader persistent volume policy, and other isolation surfaces as separate evidence-backed frontiers rather than configuration-only names.
