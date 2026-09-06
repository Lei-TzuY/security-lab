# security-lab

`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated Linux network and IPC namespace baselines; Milestone 4D added owned UTS nodename identity; and Milestone 5A added full-64-bit masked numeric seccomp argument narrowing. Milestone 6A added **explicit selected non-stdio handle passing** without reopening ambient descriptor inheritance. Milestone 7A added **caller-owned external cancellation**: a cloneable one-way token can ask launcher-owned PID 1 to terminate and reap the sandbox process tree while the token itself remains outside target authority. The current Milestone 8A verified candidate adds **one explicit read-only persistent host-directory volume**: the launcher pins and revalidates the named host directory, recursively clones it read-only, and attaches it only at the declared sandbox mountpoint. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.

## Current sandbox pipeline

The Linux x86_64 implementation launches one direct target under an explicit policy through a launcher-owned process hierarchy:

1. **Policy validation** requires a host `filesystem.root`, a validated `identity.hostname`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. `identity.hostname` is 1–63 bytes, ASCII letters/digits/`-`/`.` only, and must begin/end with an alphanumeric byte. Optional read-only volume source/target, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. Selected target descriptors are limited to 3–63, must remain below `limit.open_files`, and no more than 16 mappings are accepted. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).
2. **Parent preparation** pins the root, cwd, initial executable, every declared selected-handle source, and any declared read-only volume source/target before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`. Selected source descriptors are duplicated with `CLOEXEC`, inspected with `fstat`, and directory descriptors are rejected; launcher-owned storage descriptors are placed above every declared target destination to prevent remap collisions.
3. **Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, installs the policy hostname in the new UTS namespace, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. If a read-only volume is declared, the launcher reopens its trusted absolute host source after namespace creation, revalidates `(st_dev, st_ino)` against the pre-fork pin, recursively clones that mount tree read-only, and attaches it only to the prevalidated target inside the cloned sandbox root. The launcher neither attaches the new network namespace to a host network topology nor shares host IPC/UTS identity state with the target.
4. **Optional writable scratch** overlays one declared sandbox directory with a bounded private `nosuid,nodev,noexec` tmpfs.
5. **Owned stdout redirection/capture** may map stdout to a private-scratch file or a launcher-created `pipe2(O_CLOEXEC)`. Temporary sources remain launcher-owned and do not survive as extra target descriptors.
6. **PID-namespace lifecycle split** forks the first process in the new PID namespace as launcher-owned PID 1. That init forks the direct target as PID 2. PID 1 stays outside target stdio/rlimit/capability/seccomp setup.
7. **Optional deadline/cancellation supervision** after forking the target, PID 1 closes inherited setup descriptors, opens a pidfd whenever deadline or external cancellation supervision is active, optionally creates and arms a `CLOCK_MONOTONIC` timerfd, and optionally retains the launcher-pinned cancellation eventfd. The direct target closes the cancellation control descriptor before stdio/rlimit/capability/seccomp/exec setup, so the token is not a target capability.
8. **Deterministic supervision race** whenever supervision wakes, PID 1 first performs one `wait4(target, WNOHANG)`. If the direct target is already waitable, natural termination wins. Otherwise a readable cancellation eventfd wins before a simultaneously readable deadline timer; PID 1 terminates the direct target and reports `ChildOutcome::Cancelled` or `ChildOutcome::TimedOut` according to the winning control path.
9. **Target enforcement** the direct target alone applies explicit stdio, installs declared selected handles with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`. Optional `seccomp.arg.<syscall>.<0..5>` rules further narrow already-allowed syscalls with full 64-bit masked-equality checks. Handle installation is launcher setup before target seccomp and does not add `dup3` to `seccomp.allow`; later operations on an exposed object still require the corresponding target syscalls. A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.
10. **Owned process-tree teardown** after natural target termination, deadline termination, or external cancellation, PID 1 repeatedly sends `SIGKILL` to remaining namespace processes and reaps children with `wait4` until `ECHILD`. It then publishes raw target wait status, timeout/cancellation ownership, and the number of additional descendants reaped.
11. **Bounded stdout capture** the host parent drains capture before waiting for bootstrap completion, retains only the declared byte ceiling, and discards excess bytes. Deadline or external cancellation can still fire while that host drain is blocking because supervision lives in PID 1; terminating/reaping the target tree closes remaining capture writers and lets EOF converge.
12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout and `reaped_descendants`. The compatibility status-only APIs return the same `ChildOutcome`. The CLI maps `TimedOut` to exit status 124 and `Cancelled` to 130.
13. **Deterministic tests** use a statically linked raw-syscall x86_64 probe so syscall grants and observed behavior remain reviewable.

## Security invariants

For successful launch on a supported Linux x86_64 host:

- Initial target, cwd, scratch, read-only volume target, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root; a declared read-only volume source is a separate trusted host path pinned before fork and identity-revalidated before attachment.
- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY`, visible only at its declared sandbox target, and its launcher source/temporary mount descriptors do not survive as target capabilities.
- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.
- The launcher owns the target UTS nodename: `identity.hostname` is installed after namespace/UID/GID setup but before capability clearing and target seccomp, and the host nodename remains unchanged.
- SysV IPC identifiers/keys are resolved inside the target IPC namespace rather than the host IPC namespace; a host-created message queue is not discoverable by the same key from the target.
- The target does not share the host network namespace. The launcher does not configure a network attachment in the new namespace, so host loopback listeners are not the target's loopback listeners.
- Target socket authority remains explicit at the syscall layer: `socket` and `connect` are available only when the policy names them. Network namespace creation is launcher management and does not itself widen target seccomp.
- A `seccomp.arg.<syscall>.<index>` rule can only narrow a syscall already present in `seccomp.allow`. On Linux x86_64, each rule applies `(argument & mask) == value` to the full 64-bit numeric argument; a mismatch returns `EPERM`.
- Launcher-owned PID 1 supervises the direct target as PID 2 and owns descendant teardown.
- If no wall-clock deadline is declared, natural completion semantics remain unchanged.
- If a wall-clock deadline is declared, the runtime preflights required pidfd/timerfd kernel support before launch. Unsupported or denied mandatory mechanisms return an explicit unsupported/setup failure rather than silently dropping the deadline.
- The deadline uses `CLOCK_MONOTONIC`, is armed by PID 1 after the direct-target fork and PID1 descriptor cleanup, and has one documented natural-exit/timeout arbitration point.
- `TimedOut` and `Cancelled` are distinct from `Signaled(SIGKILL)`, even though `SIGKILL` is the kernel mechanism used after either launcher control path wins.
- `CancellationToken` is cloneable and one-way: once any clone calls `cancel()`, its eventfd remains readable and later cancellable runs using that token observe the already-cancelled state. The launcher pins a duplicate before fork, bootstrap drops it, PID 1 alone retains it for supervision, and the direct target closes it before untrusted execution.
- Supervision arbitration is natural exit > explicit cancellation > deadline when readiness is observed in one poll cycle.
- After natural, timeout, or cancelled termination, PID 1 kills/reaps remaining descendants before lifecycle readiness is published.
- Undeclared inherited descriptors >= 3 do not survive successful target exec. Only policy-selected target descriptors are deliberately made non-`CLOEXEC`; their original source descriptor numbers and unrelated inherited high descriptors remain absent after exec.
- `handle.<target_fd> = <source_fd>` grants an already-open kernel object capability, not a pathname. The launcher rejects directory descriptor sources, pins the source before fork, installs it only in the direct target, and does not retain its own duplicate in the host parent, bootstrap, or namespace PID 1 while the target runs.
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

`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.

An optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`. This slice exposes one existing host directory read-only; it does not create a writable persistent store.

Optional selected handles use `handle.<target_fd> = <source_fd>`, where `source_fd` names an already-open descriptor in the calling process and `target_fd` is the descriptor number exposed to the direct target. Target descriptors are restricted to 3–63, must be below `limit.open_files`, are unique, and at most 16 mappings are accepted. Source descriptors are duplicated rather than consumed. Directory descriptors are rejected. Because an FD denotes an existing kernel object, explicitly selecting one can intentionally expose an object that is not reachable by pathname inside `filesystem.root`; the sandbox does not attenuate that object's existing open-file-description access mode, offset/state, or status flags.

Optional syscall-argument rules use `seccomp.arg.<syscall>.<0..5> = <mask>:<value>`. Mask/value integers may be decimal or `0x` hexadecimal. The syscall must also appear in `seccomp.allow`, the mask must be non-zero, `value` may not set bits outside the mask, and the launcher-critical `execveat`, `exit`, and `exit_group` syscalls may not receive argument rules. At most 64 argument rules are accepted.

`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.

Example using bounded capture and a five-second deadline:

```text
filesystem.root = /
identity.hostname = security-lab
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

Library callers can distinguish natural exit, deadline termination, and caller-requested cancellation. Existing `run` / `run_report` APIs remain unchanged; cancellable runs use `run_with_cancel` / `run_report_with_cancel`:

```rust
let cancellation = security_lab::CancellationToken::new()?;
let worker_token = cancellation.clone();
// Another thread may call `cancellation.cancel()` after an application-defined readiness event.
let report = security_lab::run_report_with_cancel(&policy, &worker_token)?;
match report.outcome {
    security_lab::ChildOutcome::TimedOut => println!("deadline"),
    security_lab::ChildOutcome::Cancelled => println!("cancelled"),
    security_lab::ChildOutcome::Exited(code) => println!("exit {code}"),
    security_lab::ChildOutcome::Signaled(signal) => println!("signal {signal}"),
}
```

## Test evidence

Linux x86_64 integration tests prove that:

- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;
- a host `127.0.0.1` TCP listener is first proven reachable from the host process, then a raw sandbox target is explicitly granted `socket`, `connect`, `close`, and `exit` and attempts the same host loopback port from the new network namespace; only network-stack unreachable/refused results are accepted, while seccomp `EPERM` or a successful cross-namespace connection fails the fixture;
- the host creates a real SysV message queue under an explicit key and proves host lookup returns that queue ID; a raw sandbox target explicitly granted `msgget` looks up the same key inside the new IPC namespace and must receive `ENOENT`. A visible host queue or seccomp `EPERM` fails the fixture;
- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;
- a raw target exercises one `lseek` syscall under `seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008`: offset `0x0000000112345678` succeeds, while a low masked-bit mismatch (`...79`) and a high-32-bit mismatch (`0x00000002...78`) each receive seccomp `EPERM`, proving both halves of the 64-bit argument are enforced;
- a host-created pipe read end is duplicated to a high source descriptor, explicitly mapped to target fd 9, and the raw target reads the exact `selected-handle-ok` marker only from fd 9. The original high source descriptor and a separate undeclared high descriptor both return `EBADF` after exec; a directory source is independently rejected before launch;
- a trusted host directory containing `volume-marker\n` is mounted only at `/data`; the raw target reads the exact marker there, receives `EROFS` when it tries to create `/data/write-must-fail`, and receives `ENOENT` when it tries the original absolute host source path. The parent then proves the marker is unchanged and no host write escaped;
- zero, oversized, and duplicate wall-clock deadline declarations are rejected; a valid millisecond deadline parses exactly;
- inherited high-FD, stdio, filesystem, scratch, redirection, bounded-capture, capability, rlimit, `no_new_privs`, launch-error, and exit-vs-signal regressions remain active;
- a raw target observes `getpid() == 2` and `getppid() == 1`;
- 3A kills/reaps a descendant that retains stdout after natural direct-target exit;
- the 3B raw target writes `deadline target started\n`, forks a descendant that blocks indefinitely in `pause()`, and keeps the direct target alive for five seconds. With a **1,000 ms** policy deadline, the launcher returns `TimedOut`, reaps exactly one additional descendant, retains the exact marker, and reaches capture EOF;
- a fast raw target under a **5,000 ms** deadline still reports its natural `Exited(42)` outcome;
- external-cancellation evidence uses an exact readiness pipe rather than a sleep: the raw target forks one descendant, writes `cancellation-target-ready\n` through selected fd 9, and pauses. Only after the parent reads the full marker does it call `CancellationToken::cancel()`. PID 1 reports `Cancelled`, reaps exactly one descendant, and an uncancelled token separately preserves a fast target's natural `Exited(42)` result.

The probe is assembled with `cc -nostdlib -static`, so supported integration tests require a native Linux x86_64 C toolchain.

## Platform support

Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC/UTS namespaces, `sethostname`, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`. Selected handles additionally use `fcntl(F_DUPFD_CLOEXEC)`, `fstat`, and `dup3`. When a wall-clock deadline is declared, `pidfd_open`, `timerfd_create`/`timerfd_settime`, `CLOCK_MONOTONIC`, and `poll` are additionally required. External cancellation additionally requires `eventfd`; cancellable supervision also uses `pidfd_open` and `poll`.

If mandatory kernel primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the requested boundary. CI enables the required user-namespace settings on its disposable Ubuntu runner so the real enforcement path is exercised rather than skipped.

## What this is not

This remains an educational sandbox, not a production container boundary. In particular:

- `inherit` intentionally exposes an existing parent pipe/socket/terminal/file handle; creating a new network namespace does not retroactively confine an already-exposed socket object;
- the launcher creates an isolated network namespace but does **not** configure veth devices, routes, DNS, an endpoint allowlist, or a controlled egress path. This is a network-isolation baseline, not a complete network-policy subsystem;
- only stdout has launcher-owned redirect/capture modes;
- the capture ceiling bounds retained bytes, not total bytes the target can write;
- external cancellation is a one-way launcher control primitive, not a resettable/rearmable token, arbitrary signal-forwarding API, general control RPC, or guarantee on end-to-end cancellation latency from API entry;
- the deadline begins at PID1 supervision after the direct-target fork, not at initial API entry, and does not claim to bound all parent-side preparation latency;
- `reaped_descendants` is not a total process-creation counter or process-limit/accounting mechanism;
- there is no cgroup aggregate CPU/memory/process accounting or process-count quota. The current GitHub-hosted CI runner exposes cgroup v2 and the `pids` controller but does not delegate a writable child cgroup to the unprivileged workflow user, so cgroup-backed claims remain blocked rather than mocked;
- selected handles are launch-time mappings only. There is no post-launch `SCM_RIGHTS`/broker API, descriptor revocation, rights attenuation, arbitrary remapping language, or directory-handle support. A deliberately selected already-open object can bypass pathname visibility because that object capability already exists;
- the IPC namespace isolates SysV IPC and POSIX message-queue namespace membership, but it does not revoke IPC channels deliberately exposed through inherited file descriptors/sockets/pipes;
- the UTS slice controls and proves only the sandbox nodename (`identity.hostname`); it does not expose a policy for NIS/domainname or claim a broader machine-identity service;
- a cgroup namespace is not yet created, and aggregate cgroup controller enforcement remains blocked by missing unprivileged delegation on the current CI runner;
- seccomp argument rules currently support masked equality over the six numeric 64-bit syscall argument slots only. Classic seccomp does not dereference pointers, so this is not pathname/string-content filtering, a pointer-target integrity guarantee, range/relational matching, or a TOCTOU solution;
- there is no device namespace, writable persistent-volume policy, multi-volume graph, or configured network endpoint policy; Milestone 8A exposes only one declared host directory read-only;
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
