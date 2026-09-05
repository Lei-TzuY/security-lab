# Milestones 1–4B threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline. The current Milestone 4B candidate adds an isolated Linux network namespace baseline. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, network-namespace membership, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.

## Security properties claimed

- **Pinned root/cwd/target:** configured sandbox paths are fail-closed; the initial executable is pinned and launched with `execveat(AT_EMPTY_PATH)`.
- **User/mount/PID/network namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in a distinct network namespace rather than the host network namespace.
- **No implicit network attachment:** the launcher creates `CLONE_NEWNET` but does not create a veth, install routes, configure DNS, or connect the namespace to a host bridge. Host loopback is therefore not the target's loopback stack.
- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.
- **Inherited-FD minimization / explicit stdio:** arbitrary inherited descriptors >= 3 do not survive target exec; stdio disposition is explicit; launcher-owned redirect/capture sources are tightly remapped and closed.
- **Bounded retained capture:** `stdio.stdout_capture_bytes` is 1 byte–16 MiB; excess bytes are drained/discarded rather than retained.
- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally or by deadline—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.
- **Optional bounded deadline:** `limit.wall_clock_milliseconds` is either absent or 1–86,400,000 ms. When present, the launcher preflights pidfd/timerfd support and PID 1 arms a one-shot `CLOCK_MONOTONIC` timer after it forks the direct target and closes inherited setup descriptors.
- **Deterministic timeout race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. If the timer is readable and the target is not yet waitable, deadline ownership wins from that point forward.
- **Distinct timeout result:** once deadline ownership wins, PID 1 uses `SIGKILL` to terminate the direct target, but shared lifecycle state marks the event and the host reports `ChildOutcome::TimedOut`.
- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, and teardown execute in trusted launcher processes outside target seccomp. `socket` and `connect` are target syscalls only when the policy explicitly names them.
- **Owned launch-error reporting:** pre-exec phase+errno travels through shared anonymous memory and does not depend on target stdout/stderr or a target `write` grant.
- **Fail-closed enforcement:** failed/unsupported mandatory mechanisms or incomplete lifecycle readiness never trigger unrestricted retry or successful fallback.

## Network namespace semantics

The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without `CLONE_NEWNET`.

The launcher does not configure the new network namespace. The target therefore does not share host routes, interfaces, or host loopback listeners. This is a **network isolation baseline**, not an endpoint-routing policy. If future work adds controlled connectivity, that must introduce explicit topology/route/endpoint policy plus executable interop evidence rather than weakening this invariant implicitly.

The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect remains independently controlled by seccomp. Explicitly inherited stdio objects remain an intentional exception: if the policy exposes an already-open socket via `stdio.* = inherit`, network namespace creation does not retroactively revoke that object capability.

## Deadline and lifecycle orchestration

Potentially allocating policy data, argv/envp, seccomp instructions, pinned descriptors, shared lifecycle state, and capture-pipe creation occur before the initial host `fork`.

The launcher creates user/mount/PID/network namespaces and filesystem state, then forks launcher-owned namespace PID 1. PID 1 forks the direct target as PID 2. The target alone receives target stdio/rlimit/capability/seccomp setup; PID 1 closes inherited descriptors >= 3 so it cannot keep launcher capture writers alive.

If no deadline is declared, PID 1 uses the existing blocking direct-target wait. If a deadline is declared, PID 1 opens a pidfd for the already-forked target, creates a `TFD_CLOEXEC` timerfd using `CLOCK_MONOTONIC`, arms it for the validated interval, and polls the pidfd and timerfd. These descriptors are created after target fork and are never inherited by the target.

When poll wakes, PID 1 performs one nonblocking target reap check as the race arbiter. An already-waitable target keeps its natural raw wait status. Otherwise a readable timer transfers ownership to the deadline path; PID 1 sends `SIGKILL`, waits specifically for the direct target, then runs the existing kill/reap loop for every remaining descendant. Shared lifecycle state records raw target status, `timed_out`, descendant reap count, and publishes `ready` last.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of objects explicitly exposed through `stdio.* = inherit`, including an already-open socket;
- a configured veth/bridge, routes, DNS, endpoint allowlist, or controlled outbound/inbound network path. Milestone 4B only proves host-network-namespace separation;
- stdin/stderr redirect or capture;
- a total-output byte ceiling for captured stdout;
- an externally-triggered cancellation handle/API. Milestone 3B implements policy-owned deadline expiration only;
- an end-to-end API-call latency bound;
- aggregate process-count accounting or a fork/pid quota;
- cgroup-backed aggregate CPU, physical-memory, I/O, or process accounting;
- deliberate selected non-stdio descriptor passing or a general arbitrary FD-remapping language;
- persistence of private-scratch redirect output after the mount namespace disappears;
- IPC, UTS, or cgroup namespaces;
- a device namespace, syscall argument filtering, persistent data-volume policy, or immutable/cryptographic root-subtree snapshot;
- persistent executable allowlisting, multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.

## Cgroup-v2 blocker evidence

Milestone 4A aggregate process accounting remains intentionally blocked on the current GitHub-hosted runner. The runner exposes cgroup v2 and the `pids` controller, but the workflow process runs as unprivileged UID 1001 in `/system.slice/hosted-compute-agent.service`, owned by root, and cannot create a child cgroup there (`Permission denied`).

Therefore the project does not claim `pids.max` enforcement from root/sudo-only CI setup or mocks. 4A becomes executable again only when the supported test environment supplies a real writable/delegated cgroup-v2 subtree to the runtime user, with permission to create a child cgroup, set `pids.max`, attach the sandbox process tree, and clean it up without privileged out-of-band setup inside the test itself.

## Trust assumptions

- The Linux kernel and trusted launcher parent/bootstrap/PID1 control plane are trusted.
- The policy author is trusted to choose filesystem exposure, stdio exposure, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.
- Choosing `inherit`, `redirect`, or `capture` intentionally grants their documented descriptor/output channels.
- A declared deadline intentionally authorizes launcher PID 1 to terminate the direct target and descendants when the timer wins the documented race.
- Root device/inode revalidation is not a subtree integrity proof.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.

Evidence includes:

- exact allowed/denied syscall behavior and fail-closed malformed policy handling;
- a host `127.0.0.1` TCP listener that is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. The raw target accepts only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` and successful host-listener reachability both fail the test;
- all Milestones 1–3B descriptor, stdio, filesystem, capability, rlimit, launch-error, capture, PID identity, descendant cleanup, timeout, and exit-vs-signal regressions;
- a raw deadline target that writes an exact stdout marker, forks a descendant that remains in `pause()`, and is preempted by a 1,000 ms policy deadline while a fast target under 5,000 ms still preserves `Exited(42)`.

CI explicitly enables the user-namespace settings required by its disposable Ubuntu runner. The runtime never weakens host policy when mandatory primitives are unavailable.

## Failure semantics

Invalid policy is rejected before launch. Namespace creation, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed network-namespace transition is part of the same mandatory namespace failure path and never falls back to the host network namespace.

## Phase promotion

Milestone 3 is sealed: the launcher owns PID namespace init, descendant cleanup, bounded runtime termination, and explicit timeout reporting.

Milestone 4A cgroup-v2 aggregate process accounting is blocked by missing unprivileged delegation on the current GitHub-hosted runner. The independently verifiable Milestone 4B frontier therefore establishes host-network-namespace separation first. After 4B integrates, do not farm additional unreachable errno variants. The next network step should be a coherent controlled-connectivity hypothesis (explicit topology/route/endpoint policy with real positive and negative connectivity evidence), or return to 4A once delegated cgroup-v2 evidence becomes available.
