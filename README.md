# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline. The current Milestone 4B candidate adds an **isolated Linux network namespace baseline**: the target no longer shares the host network stack, while target socket syscalls remain governed independently by the explicit seccomp allowlist. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.

## Current sandbox pipeline

The Linux x86_64 implementation launches one direct target under an explicit policy through a launcher-owned process hierarchy:

1. **Policy validation** requires a host `filesystem.root`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. Optional scratch, stdout redirection, stdout capture, and `limit.wall_clock_milliseconds` are validated fail-closed. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).
2. **Parent preparation** pins the root, cwd, and initial executable before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`.
3. **Owned namespace/filesystem setup** atomically creates user, mount, PID, and network namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. The launcher does not attach a veth, configure routes, or otherwise connect the new network namespace to the host network stack.
4. **Optional writable scratch** overlays one declared sandbox directory with a bounded private `nosuid,nodev,noexec` tmpfs.
5. **Owned stdout redirection/capture** may map stdout to a private-scratch file or a launcher-created `pipe2(O_CLOEXEC)`. Temporary sources remain launcher-owned and do not survive as extra target descriptors.
6. **PID-namespace lifecycle split** forks the first process in the new PID namespace as launcher-owned PID 1. That init forks the direct target as PID 2. PID 1 stays outside target stdio/rlimit/capability/seccomp setup.
7. **Optional deadline supervision** after forking the target, PID 1 closes inherited setup descriptors, opens a pidfd for the direct target, creates and arms a `CLOCK_MONOTONIC` timerfd, and polls pidfd + timerfd. The timer starts at this supervision point; it is not a claim about total host-side launch latency before the target fork.
8. **Deterministic deadline race** whenever supervision wakes, PID 1 first performs one `wait4(target, WNOHANG)`. If the direct target is already waitable, natural termination wins. Otherwise, when the timer is readable, deadline ownership begins; PID 1 sends `SIGKILL` to the direct target and the result is reported as `ChildOutcome::TimedOut`, not as an ordinary target signal.
9. **Target enforcement** the direct target alone applies explicit stdio, rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Launcher namespace/deadline operations are not silently added to the target syscall allowlist. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.
10. **Owned process-tree teardown** after natural target termination or deadline termination, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. It then publishes raw target wait status, timeout ownership, and the number of additional descendants reaped.
11. **Bounded stdout capture** the host parent drains capture before waiting for bootstrap completion, retains only the declared byte ceiling, and discards excess bytes. A deadline can still fire while that host drain is blocking because deadline enforcement lives in PID 1; killing/reaping the target tree closes remaining capture writers and lets EOF converge.
12. **Reporting** `run_report()` returns `Exited(code)`, `Signaled(signal)`, or `TimedOut`, plus captured stdout and `reaped_descendants`. The compatibility `run()` path returns the same `ChildOutcome`. The CLI maps `TimedOut` to exit status 124.
13. **Deterministic tests** use a statically linked raw-syscall x86_64 probe so syscall grants and observed behavior remain reviewable.

## Security invariants

For successful launch on a supported Linux x86_64 host:

- Initial target, cwd, scratch, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root.
- The target receives user/mount/PID/network namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.
- The target does not share the host network namespace. The launcher does not configure a network attachment in the new namespace, so host loopback listeners are not the target's loopback listeners.
- Target socket authority remains explicit at the syscall layer: `socket` and `connect` are available only when the policy names them. Network namespace creation is launcher management and does not itself widen target seccomp.
- Launcher-owned PID 1 supervises the direct target as PID 2 and owns descendant teardown.
- If no wall-clock deadline is declared, natural completion semantics remain unchanged.
- If a wall-clock deadline is declared, the runtime preflights required pidfd/timerfd kernel support before launch. Unsupported or denied mandatory mechanisms return an explicit unsupported/setup failure rather than silently dropping the deadline.
- The deadline uses `CLOCK_MONOTONIC`, is armed by PID 1 after the direct-target fork and PID1 descriptor cleanup, and has one documented natural-exit/timeout arbitration point.
- `TimedOut` is distinct from `Signaled(SIGKILL)`, even though `SIGKILL` is the kernel mechanism used after deadline ownership is established.
- After either natural or timeout termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published.
- Arbitrary inherited descriptors >= 3 do not survive successful target exec.
- stdin/stderr support explicit `inherit` or `closed`; stdout supports `inherit`, `closed`, `redirect`, or `capture`.
- `stdio.stdout_capture_bytes` bounds retained parent memory from 1 byte through 16 MiB; excess output is drained and discarded.
- Launcher management syscalls used for namespaces, mounts, PID lifecycle, deadline supervision, redirection, capture, remapping, and setup are not silently added to the target seccomp allowlist.
- Setup or lifecycle failure never causes an unrestricted retry or converts an incomplete boundary into successful target execution.

## Policy format

Standard-descriptor modes are:

- `inherit`: retain the corresponding existing parent descriptor;
- `closed`: target starts with the descriptor closed;
- `redirect`: stdout only; requires `stdio.stdout_path` strictly beneath `filesystem.scratch`;
- `capture`: stdout only; requires `stdio.stdout_capture_bytes` in the range 1–16 MiB.

`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.

Example using bounded capture and a five-second deadline:

```text
filesystem.root = /
filesystem.scratch = /var/tmp
filesystem.scratch_bytes = 16777216
executable = /usr/bin/echo
arg = hello from the sandbox
working_dir = /tmp
env.LANG = C
stdio.stdin = closed
stdio.stdout = capture
stdio.stdout_capture_bytes = 65536
stdio.stderr = inherit
limit.wall_clock_milliseconds = 5000
limit.cpu_seconds = 2
limit.address_space_bytes = 536870912
limit.file_size_bytes = 1048576
limit.open_files = 32
seccomp.allow = execveat,read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,pread64,access,madvise,arch_prctl,set_tid_address,set_robust_list,prlimit64,getrandom,openat,newfstatat,exit,exit_group
```

Library callers can distinguish deadline termination directly:

```rust
let report = security_lab::run_report(&policy)?;
match report.outcome {
    security_lab::ChildOutcome::TimedOut => {
        // The launcher-owned monotonic deadline won the termination race.
    }
    security_lab::ChildOutcome::Exited(code) => println!("exit {code}"),
    security_lab::ChildOutcome::Signaled(signal) => println!("signal {signal}"),
}
```

## Test evidence

Linux x86_64 integration tests prove that:

- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;
- a host `127.0.0.1` TCP listener is first proven reachable from the host process, then a raw sandbox target is explicitly granted `socket`, `connect`, `close`, and `exit` and attempts the same host loopback port from the new network namespace; only network-stack unreachable/refused results are accepted, while seccomp `EPERM` or a successful cross-namespace connection fails the fixture;
- zero, oversized, and duplicate wall-clock deadline declarations are rejected; a valid millisecond deadline parses exactly;
- inherited high-FD, stdio, filesystem, scratch, redirection, bounded-capture, capability, rlimit, `no_new_privs`, launch-error, and exit-vs-signal regressions remain active;
- a raw target observes `getpid() == 2` and `getppid() == 1`;
- 3A kills/reaps a descendant that retains stdout after natural direct-target exit;
- the 3B raw target writes `deadline target started\n`, forks a descendant that blocks indefinitely in `pause()`, and keeps the direct target alive for five seconds. With a **1,000 ms** policy deadline, the launcher returns `TimedOut`, reaps exactly one additional descendant, retains the exact marker, and reaches capture EOF;
- a fast raw target under a **5,000 ms** deadline still reports its natural `Exited(42)` outcome.

The probe is assembled with `cc -nostdlib -static`, so supported integration tests require a native Linux x86_64 C toolchain.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network namespaces, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`. When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required.

If mandatory kernel primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the requested boundary. CI enables the required user-namespace settings on its disposable Ubuntu runner so the real enforcement path is exercised rather than skipped.

## What this is not

This remains an educational sandbox, not a production container boundary. In particular:

- `inherit` intentionally exposes an existing parent pipe/socket/terminal/file handle; creating a new network namespace does not retroactively confine an already-exposed socket object;
- the launcher creates an isolated network namespace but does **not** configure veth devices, routes, DNS, an endpoint allowlist, or a controlled egress path. This is a network-isolation baseline, not a complete network-policy subsystem;
- only stdout has launcher-owned redirect/capture modes;
- the capture ceiling bounds retained bytes, not total bytes the target can write;
- `limit.wall_clock_milliseconds` is a launcher-owned deadline, **not** an externally-triggerable asynchronous cancellation handle or API;
- the deadline begins at PID1 supervision after the direct-target fork, not at initial API entry, and does not claim to bound all parent-side preparation latency;
- `reaped_descendants` is not a total process-creation counter or process-limit/accounting mechanism;
- there is no cgroup aggregate CPU/memory/process accounting or process-count quota. The current GitHub-hosted CI runner exposes cgroup v2 and the `pids` controller but does not delegate a writable child cgroup to the unprivileged workflow user, so cgroup-backed claims remain blocked rather than mocked;
- deliberate selected non-stdio descriptor passing is not implemented;
- IPC, UTS, and cgroup namespaces are not yet created;
- there is no device namespace, syscall argument filtering, persistent data-volume policy, or configured network endpoint policy;
- root revalidation is an identity check, not an immutable/cryptographic snapshot of the whole subtree;
- supplementary groups are not claimed to be empty, persistent executable allowlisting is not provided, and multi-architecture seccomp/side-channel resistance are out of scope;
- `RLIMIT_AS` is not cgroup-like physical-memory accounting, and `RLIMIT_FSIZE` does not limit pipe/terminal/captured output.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full boundary and [ROADMAP.md](ROADMAP.md) for phase promotion.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

`Cargo.lock` is committed. CI pins action revisions, runs locked stable fmt/Clippy/tests, and separately executes the full locked suite on Rust 1.74.
