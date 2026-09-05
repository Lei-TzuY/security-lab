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

**Status: complete on `main`.** `stdio.stdin`, `stdio.stdout`, and `stdio.stderr` have no implicit default. Each is explicitly inherited or closed; inherited descriptors must exist and must not be directories, while closed descriptors are actually closed before target exec. Raw target evidence proves all-closed `EBADF` behavior and selective stdout inheritance while the arbitrary-descriptor >=3 non-leakage invariant remains intact.

### Slice 2F-A — launcher-owned stdout redirection

**Current verified candidate.** Extend stdout with a third disposition, `redirect`, paired with `stdio.stdout_path`. The path must be strictly beneath the declared private scratch mount. The launcher opens the destination only after the scratch tmpfs exists, uses `openat2` with beneath/no-symlink constraints, normalizes any temporary low-number descriptor above stdio with `F_DUPFD_CLOEXEC`, preserves the existing >=3 `CLOEXEC` sanitization, maps only the owned source to fd 1 with `dup2`, and closes the temporary source before target exec. Launcher management syscalls occur before seccomp and do not widen the target filter.

Acceptance evidence is executable: the raw target writes a byte through redirected stdout, reopens `/scratch/stdout.log`, reads the same byte back, and exits successfully; the parent verifies the corresponding host scratch path does not exist. All Milestones 1–2E regressions remain green on stable and Rust 1.74. This slice becomes complete on `main` only after PR merge-ref and post-merge main CI remain green.

### Slice 2F-B — deliberate selected handles / owned capture

**Next descriptor frontier after 2F-A integration.** Add a narrow explicit mechanism for selected non-stdio handles or launcher-owned pipe capture without disabling the arbitrary inherited-FD boundary. The design must safely normalize source descriptors, choose deterministic target fd numbers compatible with `RLIMIT_NOFILE`, avoid collisions with stdio/redirection, close temporary sources, prove declared-handle usability, and independently prove an undeclared inheritable high descriptor remains absent. Avoid a general arbitrary FD remapping language until these invariants are executable and reviewable.

## Later frontiers

After descriptor authority is explicit, prioritize PID/process-tree isolation, network namespace/policy, and stronger aggregate resource accounting where each mechanism can be demonstrated on the supported CI platform. Keep syscall-argument filtering and broader filesystem data-volume policy as separate evidence-backed frontiers rather than configuration-only claims.
