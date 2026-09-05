# Roadmap

## Milestone 1 — bounded Linux process sandbox

**Status: complete on `main`.**

Delivered strict policy validation, environment/cwd control, four rlimits, `PR_SET_NO_NEW_PRIVS`, default-deny seccomp-BPF allowlisting, explicit unsupported-platform behavior, deterministic raw-syscall fixtures, observable child status, threat model, and locked/MSRV CI.

## Milestone 2 — ambient authority, launch integrity, filesystem and descriptor authority

**Status: sealed on `main`.**

Slices 2A–2F-B removed arbitrary inherited-FD authority, introduced owned launch/error reporting, filesystem/identity confinement, recursively read-only root + bounded private scratch, explicit stdio, launcher-owned stdout redirection, and bounded launcher-owned stdout capture. Exact integrated implementations passed locked stable quality and Rust 1.74 suites. Do not farm more stdout/FD variants without a concrete new integration need.

## Milestone 3 — process-tree isolation and lifecycle ownership

**Status: sealed on `main`.**

### Slice 3A — PID namespace and owned process-tree lifecycle

**Complete on `main`.** Launcher-owned namespace PID 1 supervises the direct target as PID 2, preserves direct-target wait semantics, kills/reaps remaining descendants, and integrates process-tree completion with capture-writer lifetime.

### Slice 3B — policy-owned wall-clock deadline

**Complete on `main`.** Optional `limit.wall_clock_milliseconds` is validated from 1–86,400,000 ms. Namespace PID 1 owns pidfd + `CLOCK_MONOTONIC` timerfd supervision, deterministic natural-exit/timeout arbitration, `SIGKILL` termination after deadline ownership, descendant teardown, and explicit `ChildOutcome::TimedOut` reporting. Timeout enforcement remains active even while the host blocks draining captured stdout.

Acceptance evidence includes a raw target with a live descendant and a one-second deadline returning `TimedOut` with deterministic teardown/capture EOF, plus a fast `exit(42)` target retaining natural completion under a five-second deadline. Exact candidate, PR merge-ref, and post-merge `main` all passed stable rustfmt/Clippy/full tests and the full Rust 1.74 suite.

Milestone 3 exit condition is satisfied. Do not farm timer-unit aliases, different kill signals, or reap-count variants.

## Milestone 4 — aggregate accounting and network isolation

### Slice 4A — cgroup-v2 bounded process-tree accounting

**Status: blocked by current CI platform delegation, not implemented.**

The intended hypothesis remains a launcher-owned cgroup-v2 boundary with `pids.max` as the first aggregate controller/property. Acceptance still requires all of the following with the actual runtime user, without test-local sudo/root substitution:

- create a child cgroup inside a writable/delegated cgroup-v2 subtree;
- set a real `pids.max` limit;
- attach the sandbox process tree before untrusted target execution can escape aggregate accounting;
- prove process creation below the ceiling works and exceeding the ceiling fails;
- clean up only after PID-tree teardown and verify no sandbox processes remain attached;
- preserve deadline, capture, filesystem, seccomp, capability, descriptor, and launch-error semantics.

Current GitHub-hosted Ubuntu runner probe evidence:

- `/sys/fs/cgroup` is cgroup v2 and includes the `pids` controller;
- workflow user is unprivileged UID 1001 (`runner`);
- current cgroup is `/system.slice/hosted-compute-agent.service`, owned by root;
- creating a child cgroup there as the workflow user fails with `Permission denied`.

Therefore 4A must not be implemented/claimed from mocks or sudo-only CI setup. The blocker is removed only when the supported CI/test environment provides a real writable/delegated cgroup-v2 subtree to the runtime user with child creation, controller configuration, process attachment, and cleanup permissions.

### Slice 4B — isolated network namespace baseline

**Current verified candidate.** Establish a real host-network-namespace boundary before designing controlled connectivity.

Implementation:

- include `CLONE_NEWNET` in the existing fail-closed `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | ...)` transition;
- do not configure a veth, host bridge, routes, DNS, or endpoint allowlist in this baseline;
- keep network-namespace creation launcher-owned and outside target seccomp;
- add `socket` and `connect` to the reviewable x86_64 syscall-name mapping so a policy may explicitly grant those target syscalls without implying host-network access;
- preserve existing capability reduction, so the executed target does not receive network-administration capabilities.

Acceptance evidence is executable:

- Rust parent binds a real TCP listener on host `127.0.0.1` and first proves that listener is reachable from the host process;
- the raw target receives the exact host listener port and is explicitly granted `execveat`, `socket`, `connect`, `close`, and `exit`;
- target `connect(127.0.0.1:<host-port>)` runs inside the new network namespace;
- the fixture accepts only network-stack separation outcomes (`ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`); seccomp `EPERM` is a test failure, so syscall denial cannot masquerade as network isolation;
- a successful connection to the host listener is also a test failure;
- a two-second launcher-owned wall-clock deadline prevents a broken connectivity path from hanging CI;
- all Milestones 1–3B regressions, stable quality checks, and Rust 1.74 full tests remain green.

Boundary: 4B proves **host network namespace separation**, not a full network-policy system. Explicitly inherited socket objects remain intentionally exposed capabilities; the launcher does not yet create controlled network topology or positive allowlisted connectivity.

### Milestone 4 promotion rule

After 4B integrates, do not farm additional unreachable errno variants or duplicate loopback tests. Choose one of two higher-value frontiers:

1. return to 4A when real unprivileged cgroup-v2 delegation becomes available; or
2. design a coherent controlled-connectivity slice that introduces explicit topology/route/endpoint policy and proves both an allowed connection and a denied connection through real networking.

## Later frontiers

External asynchronous cancellation, selected-handle passing, syscall-argument filtering, IPC/UTS isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
