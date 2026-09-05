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

**Current verified candidate.** Add a mandatory `filesystem.root`, pin root/cwd/initial executable with `openat2`, create user+mount namespaces with UID/GID mapping, make mount propagation private, enter the pinned root, reject directory-valued stdio escape handles, clear capability bounding/ambient/current sets, and launch the pinned inode with `execveat(AT_EMPTY_PATH)`. Integration tests must prove host-path hiding, executable symlink-escape rejection, namespace identity/capability reduction, and preservation of all Milestones 1–2B invariants.

The branch implementation has passed the complete locked test suite on Rust 1.74 and stable plus stable rustfmt/Clippy. It becomes **complete on `main` only after PR merge-ref and post-merge main CI remain green.**

### Slice 2D — explicit filesystem mutability policy

**Next architectural frontier after 2C integration.** Convert path visibility into a stronger data-plane boundary by investigating an enforceable read-only root with narrowly declared writable scratch/data locations. The design must work within the user/mount namespace model, prove actual write denial/allowance in integration tests, and fail explicitly when required mount semantics are unavailable. Do not claim this slice merely from mount-policy types or configuration fields.

## Later frontiers

After root mutability is enforceable, prioritize explicit stdio/intentional descriptor authority, then PID/network/process-tree isolation and stronger resource accounting where each mechanism can be demonstrated on the supported CI platform.
