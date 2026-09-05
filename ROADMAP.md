# Roadmap

## Milestone 1 — bounded Linux process sandbox

**Status: complete on `main`.**

Delivered strict policy validation, environment/cwd control, four rlimits, `PR_SET_NO_NEW_PRIVS`, default-deny seccomp-BPF allowlisting, explicit unsupported-platform behavior, deterministic raw-syscall fixtures, observable child status, threat model, and locked/MSRV CI.

## Milestone 2 — ambient authority, launch integrity, filesystem and identity

### Slice 2A — inherited descriptor sanitization

**Status: complete on `main`.** Every inherited descriptor >= 3 is marked `CLOEXEC` before target exec, with deterministic non-leakage evidence and fail-closed setup reporting.

### Slice 2B — owned launch/error protocol

**Status: complete on `main`.** The Linux x86_64 launcher owns the `fork`/setup/seccomp/exec/wait lifecycle and transports phase-specific launch failures through shared memory without requiring a target `write` grant.

### Slice 2C — filesystem and identity boundary

**Status: complete on `main`.** A mandatory `filesystem.root` bounds pathname visibility; root/cwd/initial target selection uses `openat2`; the target inode is pinned for `execveat(AT_EMPTY_PATH)`; user and mount namespaces, UID/GID mapping, private mount propagation, chroot, directory-handle escape prevention, and capability reduction are enforced and integration-tested.

### Slice 2D — explicit filesystem mutability policy

**Status: complete on `main`.** The selected root is reopened inside the child mount namespace, fail-closed revalidated against the pre-fork root pin, recursively cloned with `open_tree`, made recursively read-only with `mount_setattr`, and attached only inside the private mount namespace. Policy may declare one bounded private `nosuid,nodev,noexec` tmpfs scratch area. Raw target evidence proves ordinary-root `O_CREAT` receives `EROFS`, scratch create/write succeeds, and the scratch write does not modify the corresponding host directory.

### Slice 2E — explicit standard descriptor disposition

The current implementation requires `stdio.stdin`, `stdio.stdout`, and `stdio.stderr` with no implicit default. Each is either `inherit` or `closed`. `inherit` requires the parent descriptor to exist and not be a directory; `closed` ensures the target starts with that descriptor closed. Enforcement happens after all launcher stages that may allocate file descriptors and after the existing >=3 `CLOEXEC` sanitization, so setup cannot silently repopulate closed stdio.

Acceptance evidence is executable: a raw target with all three descriptors closed observes `EBADF` for 0/1/2, while a selective policy with only stdout inherited observes stdin/stderr closed and successfully writes through fd 1. The exact candidate must keep all Milestones 1–2D regressions green on stable and Rust 1.74, then pass PR merge-ref and post-merge main CI before this slice is considered integrated.

### Slice 2F — owned redirection and deliberate descriptor passing

**Next descriptor frontier after 2E integration.** Add explicit launcher-owned redirection and selected-handle passing without reopening arbitrary ambient authority. A declared handle must remain usable by the target, undeclared parent descriptors must remain absent, and the design must preserve the >=3 non-leakage invariant rather than disabling `close_range` wholesale. Prefer a small typed policy and deterministic pipe/file-descriptor integration evidence over a general-purpose FD remapping surface in the first slice.

## Later frontiers

After descriptor authority is explicit, prioritize PID/process-tree isolation, network namespace/policy, and stronger aggregate resource accounting where each mechanism can be demonstrated on the supported CI platform. Keep syscall-argument filtering and broader filesystem data-volume policy as separate evidence-backed frontiers rather than configuration-only claims.
