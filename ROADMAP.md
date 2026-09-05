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

**Status: complete on `main`.** A mandatory `filesystem.root` bounds pathname visibility; root/cwd/initial target selection uses `openat2`; the initial target is inode-pinned for `execveat(AT_EMPTY_PATH)`; user and mount namespaces, UID/GID mapping, private mount propagation, chroot, directory-stdio rejection and capability reduction are enforced and covered by integration tests.

### Slice 2D — explicit filesystem mutability policy

**Current verified candidate.** The selected root is reopened inside the child's mount namespace and fail-closed revalidated against the pre-fork pinned root, recursively cloned with `open_tree`, made recursively read-only with `mount_setattr`, and attached only inside the private mount namespace. Policy may declare one writable scratch directory plus a bounded tmpfs size; the launcher overlays that location with a private `nosuid,nodev,noexec` tmpfs after the root is read-only.

Acceptance evidence is executable rather than declarative: the raw-syscall target must receive `EROFS` when attempting `O_CREAT` on the ordinary root, must successfully create/write inside the declared scratch mount, and the parent must observe that the scratch write did not modify the host directory. All Milestones 1–2C regressions must remain green. The current branch has passed locked full tests on Rust 1.74 and stable plus stable rustfmt/Clippy. It becomes **complete on `main` only after PR merge-ref and post-merge main CI remain green.**

### Slice 2E — explicit standard/intentional descriptor authority

**Next architectural frontier after 2D integration.** Replace the remaining implicit stdio authority with an explicit policy for descriptor disposition: inherited, redirected, closed, or deliberately passed handles must be named by policy and enforced without reopening ambient parent authority. Acceptance must prove that undeclared descriptors—including stdio when policy closes them—cannot be used by the target, while explicitly passed handles remain usable. Do not weaken the existing `>=3` non-leakage invariant merely to add descriptor passing.

## Later frontiers

After descriptor authority is explicit, prioritize PID/process-tree isolation, network namespace/policy, and stronger aggregate resource accounting where each mechanism can be demonstrated on the supported CI platform. Keep syscall-argument filtering and stronger filesystem data-mount policy as separate evidence-backed frontiers rather than configuration-only claims.
