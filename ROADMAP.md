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

## Milestone 4 — aggregate accounting and namespace isolation

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

**Status: complete on `main`.** Establishes a real host-network-namespace boundary before any controlled-connectivity policy is attempted.

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

### Slice 4C — isolated IPC namespace baseline

**Status: complete on `main`.** Adds `CLONE_NEWIPC` to the mandatory namespace transition and proves a real host SysV IPC object is invisible from the target namespace.

Acceptance evidence is executable:

- the trusted host creates a SysV message queue under a collision-checked explicit key and proves `msgget(key, 0)` returns that queue ID before sandbox launch;
- the raw target receives the same key and is explicitly granted `execveat`, `msgget`, and `exit`;
- inside the new IPC namespace, `msgget(key, 0)` must return `ENOENT`; seeing the host queue or receiving seccomp `EPERM` fails the fixture;
- the host removes the queue with `IPC_RMID` after the sandbox run, independent of whether the sandbox result succeeds;
- `CLONE_NEWIPC` is part of the same fail-closed unshare as user/mount/PID/network namespaces, so failure never retries in the host IPC namespace;
- all Milestones 1–4B regressions, stable quality checks, and Rust 1.74 full tests remain green.

Boundary: 4C establishes SysV IPC/POSIX message-queue namespace separation. It does not revoke pipes, sockets, or other descriptor-based IPC deliberately exposed through the existing stdio/descriptor policy.

### Slice 4D — owned UTS identity

**Current verified candidate.** Make sandbox nodename identity explicit and launcher-owned rather than inheriting the host hostname into an otherwise isolated environment.

Acceptance evidence is executable:

- policy requires `identity.hostname`; validation permits 1–63 ASCII bytes containing letters, digits, `-`, and `.`, with an alphanumeric first/last byte, and rejects missing/duplicate/empty/oversized/invalid values;
- `CLONE_NEWUTS` joins the existing mandatory user/mount/PID/network/IPC namespace transition;
- the trusted launcher owns pre-fork hostname bytes and calls `sethostname` after UID/GID mapping but before capability clearing and target seccomp;
- a raw target explicitly granted `uname` observes exactly the configured nodename;
- the trusted parent reads `/proc/sys/kernel/hostname` before and after sandbox execution and proves the host nodename remains unchanged;
- the target is not granted a launcher-only hostname mutation path, and no domainname/NIS-domain policy is claimed;
- all Milestones 1–4C regressions, stable quality checks, and the full Rust 1.74 suite remain green.

Boundary: 4D owns the sandbox UTS **nodename** only. It is not a general machine-identity service and does not claim configurable domainname.

### Milestone 4 promotion rule

After 4D integrates, do not farm hostname aliases, punctuation variants, or domainname copies. Return to 4A only when real unprivileged cgroup-v2 delegation becomes available. Otherwise select a materially different executable boundary after architecture audit; high-value candidates include enforcing/observing an empty supplementary-group set or introducing narrowly-scoped seccomp syscall-argument filtering with deterministic allow/deny evidence.

## Later frontiers

External asynchronous cancellation, selected-handle passing, syscall-argument filtering, supplementary-group isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
