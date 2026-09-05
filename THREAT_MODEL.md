# Milestones 1–3A threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; 2A removed inherited non-stdio descriptor leakage; 2B made launch/error reporting an owned control-plane protocol; 2C added filesystem-path and process-identity isolation; 2D added a recursively read-only root plus bounded private scratch; 2E made standard-descriptor disposition explicit; 2F-A added launcher-owned stdout redirection; 2F-B added bounded launcher-owned stdout capture; and the current 3A candidate adds PID-namespace process-tree lifecycle ownership. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, capabilities, syscalls, selected resources, environment, cwd, inherited non-stdio descriptors, explicit standard-descriptor disposition, launcher-owned stdout redirection/capture, and post-target process-tree teardown while preserving fail-closed launch and lifecycle reporting.

## Security properties claimed

- **Pinned root/cwd/target:** configured sandbox paths are fail-closed; the initial executable is pinned and launched with `execveat(AT_EMPTY_PATH)`.
- **Current-mount root revalidation:** after mount-namespace creation the selected root is reopened and must match the pre-fork `(st_dev, st_ino)` pin.
- **User/mount/PID namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; a launcher-owned namespace init runs as PID 1 and the direct target runs as PID 2.
- **Filesystem mutability:** the revalidated root is recursively cloned/read-only; at most one declared bounded private `nosuid,nodev,noexec` scratch tmpfs is writable.
- **Filesystem path boundary:** the target is chrooted into the constructed root and switches to a re-pinned cwd.
- **Inherited-FD minimization:** arbitrary inherited descriptors >= 3 are marked `CLOEXEC` and do not survive successful target exec.
- **Explicit stdio:** inherited descriptors must exist and not be directories; closed descriptors are explicitly closed. stdout additionally supports launcher-owned redirection and capture.
- **Owned stdout redirection:** the launcher opens only a path strictly beneath private scratch after scratch exists, normalizes temporary low descriptors with `F_DUPFD_CLOEXEC`, maps only the source to fd 1 using `dup2`, then closes the source.
- **Bounded owned stdout capture:** capture creates a new pre-fork `pipe2(O_CLOEXEC)` rather than exposing an arbitrary parent descriptor. Both pipe ends are normalized above fd 2 before fork. The direct target maps the write end only to fd 1; bootstrap and PID 1 close descriptors >= 3, so launcher management layers cannot keep the capture writer alive.
- **Bounded retained memory:** `stdio.stdout_capture_bytes` is limited to 1 byte–16 MiB. At most that many bytes are retained in `CapturedOutput`; additional bytes are drained and discarded and set `truncated = true`.
- **Pipe-pressure liveness for the direct target:** because the host parent drains before waiting for bootstrap completion, a target that emits more than the kernel pipe capacity is not blocked merely because the retained capture buffer reached its policy ceiling.
- **Owned PID-tree lifecycle:** namespace PID 1 waits for the direct target, then repeatedly signals remaining namespace processes with `SIGKILL` and reaps children with `wait4` until `ECHILD`. Lifecycle completion is published only after this teardown finishes.
- **Direct-target outcome preservation:** the host reports the direct target's raw wait status through shared lifecycle state rather than substituting bootstrap/PID1 exit status. Exit-vs-signal semantics therefore remain attached to the policy-selected target.
- **Descendant-held capture release after target termination:** if a policy-permitted descendant retains stdout when the direct target exits, PID 1 kills/reaps that descendant before publishing completion, allowing the capture pipe to reach EOF without descendant cooperation.
- **No target-policy widening:** launcher management operations for namespaces, mounts, PID lifecycle, redirection/capture/remapping happen outside the target seccomp filter. The target receives only its named syscall allowlist.
- **Capability/resource controls:** capability sets are reduced, `no_new_privs` is enabled, configured rlimits are applied, and seccomp remains default-deny.
- **Owned launch-error reporting:** pre-exec phase+errno travels through shared anonymous memory and does not depend on target stdout/stderr or a target `write` grant.
- **Fail-closed enforcement:** failed or unsupported mandatory enforcement and incomplete PID lifecycle publication never trigger an unrestricted retry or successful fallback.

## Parent/bootstrap/init/target orchestration

Potentially allocating policy data, argv/envp, seccomp instructions, pinned descriptors, shared lifecycle state, and capture-pipe creation occur before the initial host `fork`.

The launcher child creates user, mount, and PID namespaces and completes filesystem construction before entering the new PID namespace. Because `CLONE_NEWPID` affects subsequently created children, it then forks a bootstrap descendant that becomes namespace PID 1. The bootstrap parent closes descriptors >= 3, waits for PID 1, and exits; target status is not inferred from this bootstrap status.

Namespace PID 1 forks the direct target as PID 2. PID 1 closes descriptors >= 3 and stays outside target stdio/rlimit/capability/seccomp setup. The direct target alone applies policy stdio, rlimits, capability reduction, `no_new_privs`, seccomp, and pinned `execveat`.

PID 1 waits specifically for the direct target. Only after that target terminates does PID 1 tear down the remaining namespace process tree. It repeats a kill sweep and `wait4(-1, ...)` until `ECHILD`, then writes the direct target status and additional-descendant reap count to shared memory and publishes `ready = 1` last. The host treats any missing readiness publication as setup/lifecycle failure.

In the host parent, capture is drained to EOF before waiting for bootstrap. Retention stops at the policy ceiling but draining continues. This ordering prevents direct-target pipe-pressure deadlock. Because bootstrap and PID 1 close capture descriptors, the only remaining writers belong to the target process tree; 3A teardown therefore resolves descendant-held capture writers after direct-target termination.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of objects explicitly exposed through `stdio.* = inherit`;
- stdin/stderr redirect or capture;
- a total-output byte ceiling for captured stdout. The configured ceiling limits retained parent memory only; excess output is discarded after being read;
- a wall-clock deadline or cancellation mechanism for a direct target that never terminates. PID-tree cleanup begins only once the direct target has produced a terminal wait status;
- aggregate process-count accounting or a fork/pid quota. `reaped_descendants` records only additional descendants reaped during teardown, not total historical process creation;
- deliberate selected non-stdio descriptor passing or a general arbitrary FD remapping language;
- persistence of private-scratch redirect output after the mount namespace disappears;
- network, IPC, UTS, or cgroup namespaces;
- cgroup-based aggregate memory/CPU/process accounting;
- a device namespace, network endpoint policy, syscall argument filtering, or persistent data-volume policy;
- an immutable or cryptographic snapshot of the selected root subtree;
- a guarantee that inherited supplementary groups are empty;
- persistent executable allowlisting after the initial pinned transition;
- multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.

## Trust assumptions

- The Linux kernel and trusted launcher parent/bootstrap/init control plane are trusted.
- The policy author is trusted to choose the filesystem root/scratch, explicit stdio exposure, target data, syscall grants, and realistic resource/capture ceilings.
- Choosing `inherit` intentionally grants the existing parent descriptor.
- Choosing `redirect` intentionally grants writes to the declared private-scratch file.
- Choosing `capture` intentionally creates a launcher-owned stdout channel. Descendants may inherit its writer, but 3A guarantees cleanup only after the direct target terminates; it does not impose a deadline on that target.
- The selected root contains only content the operator intends to expose; root device/inode revalidation is not a subtree integrity proof.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.

Evidence includes:

- exact allowed/denied syscall behavior and fail-closed malformed policy handling;
- inherited high-FD non-leakage;
- all-closed and selective-inherit stdio behavior;
- owned stdout redirection with target readback from private scratch and parent verification of no host write-through;
- exact small stdout capture returning the target bytes with `truncated = false`;
- a stress target writing 4096 raw 64-byte chunks (**256 KiB**) with a **1 KiB** capture ceiling. The target exits successfully, the parent retains exactly 1 KiB of the expected byte, and `truncated = true`, proving excess output is drained rather than allowed to block on a full pipe;
- raw `getpid`/`getppid` evidence that the direct target is PID 2 with namespace init as parent PID 1;
- a raw target that forks a descendant which blocks indefinitely in `pause()` while retaining stdout, then exits. Namespace PID 1 kills and reaps the descendant, `reaped_descendants == 1`, and capture reaches EOF;
- owned launch-error reporting, filesystem hiding/read-only enforcement, private scratch, namespace UID/GID and capability reduction, environment/cwd, all four rlimits, `RLIMIT_NOFILE`, `no_new_privs`, and exit-vs-signal regressions.

CI explicitly enables the user-namespace settings required by its disposable Ubuntu runner. The runtime itself never weakens host policy when mandatory primitives are unavailable.

## Failure semantics

Invalid policy is rejected before launch. Pipe creation, endpoint normalization, namespace/bootstrap/init forks, descriptor cleanup, child-side remapping, capture reads, namespace/mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A capture read error or incomplete PID lifecycle record is not converted into successful execution. No failure path retries the target without the requested restrictions.

## Phase promotion

Milestone 2 is sealed: inherited high-FD authority is removed, stdio is explicit, and the launcher owns private-file output plus bounded capture. Milestone 3A adds the next architectural layer by making the launcher own PID namespace init semantics and deterministic descendant cleanup instead of leaving process-tree lifetime implicit.

After 3A integrates, do not farm more PID-number or reap-count variants. The next high-value lifecycle gap is **Milestone 3B — policy-owned wall-clock deadline/cancellation**: the launcher must be able to terminate a direct target that never exits, tear down its PID namespace process tree, preserve an explicit timeout/cancellation result distinct from ordinary target exit/signal, and keep capture/error reporting fail-closed. Aggregate cgroup accounting and network isolation remain separate later frontiers.
