# Milestones 1–3B threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 removed ambient descriptor authority, made launch reporting launcher-owned, and added filesystem/identity/stdout boundaries; Milestone 3A added PID-namespace init and descendant lifecycle ownership. The current 3B candidate adds a policy-owned monotonic wall-clock deadline enforced by launcher-owned PID 1. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.

## Security properties claimed

- **Pinned root/cwd/target:** configured sandbox paths are fail-closed; the initial executable is pinned and launched with `execveat(AT_EMPTY_PATH)`.
- **User/mount/PID namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2.
- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.
- **Inherited-FD minimization / explicit stdio:** arbitrary inherited descriptors >= 3 do not survive target exec; stdio disposition is explicit; launcher-owned redirect/capture sources are tightly remapped and closed.
- **Bounded retained capture:** `stdio.stdout_capture_bytes` is 1 byte–16 MiB; excess bytes are drained/discarded rather than retained.
- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally or by deadline—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.
- **Optional bounded deadline:** `limit.wall_clock_milliseconds` is either absent or 1–86,400,000 ms. When present, the launcher preflights pidfd/timerfd support and PID 1 arms a one-shot `CLOCK_MONOTONIC` timer after it forks the direct target and closes its inherited setup descriptors.
- **Deadline independent of host capture blocking:** the host parent may block draining capture, but timeout enforcement remains live because it executes in PID 1. Deadline teardown closes target-tree writers and allows capture EOF to converge.
- **Deterministic timeout race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. If the timer is readable and the target is not yet waitable, deadline ownership wins from that point forward.
- **Distinct timeout result:** once deadline ownership wins, PID 1 uses `SIGKILL` to terminate the direct target, but shared lifecycle state marks the event and the host reports `ChildOutcome::TimedOut`; it is not misreported as an ordinary target-delivered signal.
- **No target-policy widening:** `pidfd_open`, timerfd setup, `poll`, namespace management, mounts, capture/remapping, and teardown execute in trusted launcher processes outside the target seccomp filter.
- **Owned launch-error reporting:** pre-exec phase+errno travels through shared anonymous memory and does not depend on target stdout/stderr or a target `write` grant.
- **Fail-closed enforcement:** failed/unsupported mandatory mechanisms, invalid timeout publication, or incomplete lifecycle readiness never trigger unrestricted retry or successful fallback.

## Deadline and lifecycle orchestration

Potentially allocating policy data, argv/envp, seccomp instructions, pinned descriptors, shared lifecycle state, and capture-pipe creation occur before the initial host `fork`.

The launcher creates user/mount/PID namespaces and filesystem state, then forks launcher-owned namespace PID 1. PID 1 forks the direct target as PID 2. The target immediately returns to target-only setup; PID 1 closes inherited descriptors >= 3, so it cannot keep launcher capture writers alive.

If no deadline is declared, PID 1 uses the existing blocking direct-target wait. If a deadline is declared, PID 1 opens a pidfd for the already-forked target, creates a `TFD_CLOEXEC` timerfd using `CLOCK_MONOTONIC`, arms it for the validated interval, and polls the pidfd and timerfd. These descriptors are created **after** the target fork, so they are never inherited by the target.

When poll wakes, PID 1 performs exactly one nonblocking target reap check as the race arbiter. An already-waitable target keeps its natural raw wait status. Otherwise a readable timer transfers ownership to the deadline path; PID 1 sends `SIGKILL`, waits specifically for the direct target, then runs the existing kill/reap loop for every remaining descendant. Shared lifecycle state records raw target status, `timed_out`, descendant reap count, and publishes `ready` last.

The host parent drains captured stdout to EOF before waiting for bootstrap. This does not defeat the deadline: timeout enforcement is independent inside PID 1, and target-tree teardown releases remaining capture writers.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of objects explicitly exposed through `stdio.* = inherit`;
- stdin/stderr redirect or capture;
- a total-output byte ceiling for captured stdout;
- an externally-triggered cancellation handle/API. 3B implements policy-owned deadline expiration only;
- an end-to-end API-call latency bound. The deadline clock is armed by PID 1 after the direct-target fork and PID1 descriptor cleanup;
- aggregate process-count accounting or a fork/pid quota. `reaped_descendants` counts additional descendants reaped during teardown, not historical process creation;
- cgroup-backed aggregate CPU, physical-memory, I/O, or process accounting;
- deliberate selected non-stdio descriptor passing or a general arbitrary FD-remapping language;
- persistence of private-scratch redirect output after the mount namespace disappears;
- network, IPC, UTS, or cgroup namespaces;
- a device namespace, network endpoint policy, syscall argument filtering, or persistent data-volume policy;
- an immutable/cryptographic snapshot of the selected root subtree;
- persistent executable allowlisting, multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.

## Trust assumptions

- The Linux kernel and trusted launcher parent/bootstrap/PID1 control plane are trusted.
- The policy author is trusted to choose filesystem exposure, stdio exposure, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.
- A declared deadline intentionally authorizes launcher PID 1 to terminate the direct target and descendants when the timer wins the documented race.
- Choosing `inherit`, `redirect`, or `capture` intentionally grants their documented descriptor/output channels.
- Root device/inode revalidation is not a subtree integrity proof.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.

Evidence includes:

- exact allowed/denied syscall behavior and fail-closed malformed policy handling;
- zero/oversized/duplicate wall-clock deadline rejection and exact valid parsing;
- all Milestones 1–3A descriptor, stdio, filesystem, capability, rlimit, launch-error, capture, PID identity, descendant cleanup, and exit-vs-signal regressions;
- a raw deadline target that writes an exact stdout marker, forks a descendant that remains in `pause()`, and keeps the direct target alive for five seconds. A 1,000 ms policy deadline returns `TimedOut`, reaps one additional descendant, preserves the exact marker, and reaches capture EOF;
- a raw `exit(42)` target under a 5,000 ms deadline still reports `Exited(42)`, covering the natural-completion side of deadline arbitration.

The five-second path in the timeout fixture is a **test-only fallback** so a broken timeout cannot hang CI indefinitely; the policy deadline must preempt it at one second. It is not used as evidence for the deadline mechanism itself.

CI explicitly enables the user-namespace settings required by its disposable Ubuntu runner. The runtime never weakens host policy when mandatory primitives are unavailable.

## Failure semantics

Invalid policy is rejected before launch. Deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. Unsupported pidfd/timerfd primitives when a deadline is requested produce explicit unsupported/setup errors rather than silently running without a deadline. No failure path retries the target with weaker restrictions.

## Phase promotion

Milestone 3A owns PID namespace init and descendant lifecycle. 3B adds bounded runtime ownership: the launcher can now preempt a still-running target tree after a declared monotonic deadline and report that reason separately from target exit/signal.

After 3B integrates, do not farm timer units, signal choices, or timeout aliases. The next high-value isolation frontier is **aggregate resource/process accounting**, preferably via cgroup v2 where the supported CI environment can execute and verify the real kernel controller. External asynchronous cancellation remains a separate API/control-plane capability and must not be claimed until it has a real handle/protocol plus race/cleanup evidence.
