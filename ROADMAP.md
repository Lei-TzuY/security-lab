# Roadmap

## Milestone 1 — bounded Linux process sandbox

**Status: complete on `main`.**

Delivered strict policy validation, environment/cwd control, four rlimits, `PR_SET_NO_NEW_PRIVS`, default-deny seccomp-BPF allowlisting, explicit unsupported-platform behavior, deterministic raw-syscall fixtures, observable child status, threat model, and locked/MSRV CI.

## Milestone 2 — ambient authority, launch integrity, filesystem and identity

### Slice 2A — inherited descriptor sanitization

**Current implementation target.** Atomically mark every inherited descriptor >= 3 `CLOEXEC` before target exec, prove descriptor non-leakage, and preserve fail-closed setup reporting.

### Slice 2B — owned launch/error protocol

Replace or isolate the standard-library fork/exec management channel so setup and exec failures remain precisely observable even when the target seccomp policy denies ordinary `write`.

### Slice 2C — filesystem and identity boundary

Add testable user/mount namespace isolation, UID/GID mapping and capability dropping, a minimal root/mount policy, and TOCTOU-resistant executable selection. Promote only mechanisms that can be enforced and proven in CI; unsupported kernels/configurations must fail or skip explicitly rather than pretending isolation.
