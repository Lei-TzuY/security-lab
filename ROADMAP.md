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

**Status: complete on `main`.** Root/cwd/initial-target selection is pinned with `openat2`; user/mount namespaces, UID/GID mapping, private mount propagation, chroot, target `execveat(AT_EMPTY_PATH)`, directory-handle escape prevention, and capability reduction are enforced and integration-tested.

### Slice 2D — explicit filesystem mutability

**Status: complete on `main`.** The revalidated root is recursively cloned/read-only and policy may declare one bounded private `nosuid,nodev,noexec` tmpfs scratch area. Raw target evidence proves ordinary-root writes fail while scratch writes succeed without host write-through.

### Slice 2E — explicit standard descriptor disposition

**Status: complete on `main`.** stdin/stdout/stderr have no implicit default. Inherited descriptors must exist and not be directories; closed descriptors are actually closed. Raw evidence covers all-closed and selective inheritance while arbitrary descriptor >=3 non-leakage remains intact.

### Slice 2F-A — launcher-owned stdout redirection

**Status: complete on `main`.** `stdio.stdout = redirect` requires a destination strictly beneath private scratch. The launcher opens it only after scratch exists, keeps the temporary source `CLOEXEC`, maps only that source to fd 1, closes the source, and does not widen target seccomp. Raw target readback plus parent-side host-path absence proves usable private redirection.

### Slice 2F-B — bounded launcher-owned stdout capture

**Current verified candidate.** `stdio.stdout = capture` requires `stdio.stdout_capture_bytes` in the range 1 byte–16 MiB. The launcher creates `pipe2(O_CLOEXEC)` before fork, normalizes both endpoints above fd 2, closes the read side in the child, preserves the write source through existing >=3 descriptor sanitization, maps it only to fd 1, and closes the temporary source. The parent closes its write endpoint and drains stdout before `waitpid`, retaining no more than the declared ceiling and reporting whether additional bytes were discarded.

Acceptance evidence is executable:

- a small raw target returns exact stdout bytes with `truncated = false`;
- a stress target emits 4096 × 64-byte raw writes (**256 KiB**) under a **1 KiB retention ceiling**; the direct child exits successfully, exactly 1 KiB is retained, all retained bytes are correct, and `truncated = true`;
- all Milestones 1–2F-A regressions remain green, including arbitrary inherited high-FD absence;
- the exact candidate passes stable rustfmt, Clippy `-D warnings`, the full locked stable suite, and the full Rust 1.74 suite before PR integration.

Important boundary: the capture ceiling limits retained parent memory, not total target output. Pipe EOF also follows all remaining writer processes; without PID/process-tree isolation, a policy-permitted descendant retaining stdout can prolong capture completion.

### Milestone 2 exit condition

After 2F-B passes PR merge-ref and post-merge main CI, **seal the descriptor phase instead of farming more stdout/FD variants**. Generic arbitrary FD remapping and selected non-stdio handle passing remain deferred capabilities that require a concrete future integration need and their own evidence-backed design.

## Milestone 3 — process-tree isolation and lifecycle ownership

### Slice 3A — PID namespace and owned process-tree lifecycle

**Next architectural phase after 2F-B integration.** Add real PID/process-tree isolation rather than another policy-only namespace flag. Linux `CLONE_NEWPID` applies to subsequently created children, so the launcher must introduce an explicit namespace-child/init orchestration instead of merely adding it to the existing `unshare` call.

Initial acceptance criteria:

- target-observed PID namespace identity with deterministic raw-syscall evidence;
- explicit namespace-init/reaping behavior for descendants;
- deterministic cleanup so target-created descendants cannot silently outlive the sandboxed process tree;
- preserved shared-memory launch-error reporting and exit-vs-signal semantics across the additional process layer;
- capture/redirect lifecycle integration, including a defined rule for descendant-held stdout writers;
- all existing filesystem, capability, rlimit, seccomp, descriptor, and MSRV regressions stay green.

## Later frontiers

After process-tree ownership, prioritize network namespace/policy and stronger aggregate resource accounting where the supported CI platform can execute the real kernel mechanism. Keep selected-handle passing, syscall-argument filtering, broader persistent volume policy, and cgroup accounting as separate evidence-backed frontiers rather than configuration-only names.
