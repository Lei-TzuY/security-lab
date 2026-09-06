# Milestones 1–9A threat model

## Purpose

`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestones 4B–4D added network/IPC/UTS namespace and identity baselines; Milestone 5A added masked numeric syscall-argument constraints; and Milestone 6A added explicit launch-time selected non-stdio object capabilities without reopening ambient descriptor inheritance. Milestone 7A added a caller-owned external cancellation control plane whose launcher-owned PID 1 supervision terminates and reaps the sandbox process tree. Milestones 8A–8B added bounded read-only and writable persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and explicit mount attachment controls. The current Milestone 9A verified candidate adds policy-owned activation of only the isolated network namespace's loopback device, with executable proof for default-down behavior, positive intra-sandbox TCP, and continued host-loopback separation. Every claimed property must correspond to a kernel mechanism and executable evidence.

## Protected boundary

The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, capabilities, target syscall numbers and selected numeric syscall arguments, selected resources, environment, cwd, ambient inherited descriptors, explicit selected non-stdio object handles, up to one optional read-only and one optional writable persistent host-directory volume, optional isolated-loopback activation, stdio, bounded capture, process-tree lifecycle, a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used, while preserving fail-closed launch/lifecycle reporting.

## Security properties claimed

- **Pinned root/cwd/target:** configured sandbox paths are fail-closed; the initial executable is pinned and launched with `execveat(AT_EMPTY_PATH)`.
- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.
- **Owned UTS nodename:** `identity.hostname` is required and fail-closed validated to 1–63 ASCII bytes. The trusted launcher installs it with `sethostname` inside the new UTS namespace before capability clearing and target seccomp.
- **SysV IPC visibility boundary:** message-queue keys/IDs are resolved in the target IPC namespace. Host SysV queues are not discoverable by the same key from the target after `CLONE_NEWIPC`.
- **Policy-owned isolated loopback:** the launcher creates `CLONE_NEWNET` without host/external attachment. Loopback is down by default; if `network.loopback = enabled`, the trusted setup path alone uses `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set `IFF_UP` on `lo`, then closes its management socket before target execution. No veth, host bridge, routes, DNS, NAT, or endpoint attachment is introduced, so host loopback remains a different network stack.
- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.
- **Explicit read-only persistent volume:** when declared, the trusted host source's configured path must be disjoint from `filesystem.root`; the source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.
- **Explicit writable persistent volume:** when separately declared, the trusted host source's configured path must be disjoint from `filesystem.root`, then follows the same pre-fork pin, post-namespace `(st_dev, st_ino)` revalidation, detached recursive clone, target pin, and launcher-owned attachment path, but intentionally does not receive `MOUNT_ATTR_RDONLY`. This is a trusted-policy authorization for target writes to persist into that source without reopening the configured sandbox-root tree through the source path; the surrounding cloned sandbox root remains read-only.
- **Inherited-FD minimization / explicit handle authority:** undeclared inherited descriptors >= 3 do not survive target exec. Stdio disposition is explicit; launcher-owned redirect/capture sources are tightly remapped and closed; only `handle.<target_fd>` destinations declared by policy are intentionally made visible as additional descriptors.
- **Selected-object ownership:** each selected source is duplicated and inspected before fork, directory descriptors are rejected, and launcher storage descriptors are kept above every target destination. Host parent, bootstrap, and namespace PID 1 do not retain launcher-owned selected duplicates while the direct target runs.
- **Bounded retained capture:** `stdio.stdout_capture_bytes` is 1 byte–16 MiB; excess bytes are drained/discarded rather than retained.
- **Owned PID-tree lifecycle:** namespace PID 1 supervises the direct target and reaps descendants. After the direct target becomes terminal—naturally, by deadline, or by external cancellation—PID 1 repeatedly kills remaining namespace processes and reaps until `ECHILD`, then publishes readiness.
- **Optional bounded deadline:** `limit.wall_clock_milliseconds` is either absent or 1–86,400,000 ms. When present, the launcher preflights pidfd/timerfd support and PID 1 arms a one-shot `CLOCK_MONOTONIC` timer after it forks the direct target and closes inherited setup descriptors.
- **Optional external cancellation:** `CancellationToken` is a cloneable Linux eventfd-backed one-way control token. The launcher pins a duplicate before fork; only PID 1 retains that duplicate while the target runs, and the direct target closes its copy before untrusted execution.
- **Deterministic supervision race:** each PID1 supervision wake performs `wait4(target, WNOHANG)` first. If target status is already available, natural termination wins. Otherwise cancellation readiness is checked before deadline readiness, yielding natural exit > explicit cancellation > deadline when multiple conditions are simultaneously observable.
- **Distinct control results:** deadline ownership reports `ChildOutcome::TimedOut`; cancellation ownership reports `ChildOutcome::Cancelled`. Both may use `SIGKILL` after ownership is established, but neither is reported as an ordinary target signal.
- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, selected-handle installation, and teardown execute in trusted launcher processes outside target seccomp. `dup3` used to install a selected target descriptor is not silently added to `seccomp.allow`; subsequent operations on that object still require the target syscalls explicitly granted by policy. target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup does not add them implicitly.
- **Masked syscall-argument narrowing:** an argument rule applies only to a syscall already in `seccomp.allow`. Linux x86_64 cBPF evaluates the selected `seccomp_data.args[]` slot as two 32-bit words and requires the complete 64-bit `(argument & mask) == value` condition before returning `ALLOW`; a mismatch returns `EPERM`.
- **Owned launch-error reporting:** pre-exec phase+errno travels through shared anonymous memory and does not depend on target stdout/stderr or a target `write` grant.
- **Fail-closed enforcement:** failed/unsupported mandatory mechanisms or incomplete lifecycle readiness never trigger unrestricted retry or successful fallback.

## Network namespace semantics

The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without any mandatory namespace boundary.

The new network namespace starts with loopback down. Unless policy explicitly enables it, the launcher leaves it down; the raw target can directly observe that `IFF_UP` is clear. When `network.loopback = enabled`, the trusted launcher opens an IPv4 datagram management socket after the user/network namespace transition and UID/GID mapping, reads `lo` flags with `SIOCGIFFLAGS`, sets `IFF_UP` with `SIOCSIFFLAGS`, and closes the socket before capability clearing and target seccomp. This creates only intra-namespace loopback connectivity: no veth, bridge, host/external route, DNS, NAT, or endpoint policy is installed. A future externally attached networking slice must add a materially new topology/endpoint policy with positive and negative executable evidence rather than re-label this loopback mechanism.

The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect and SysV IPC syscalls remain independently controlled by seccomp. Explicitly inherited stdio objects remain an intentional exception: namespace creation does not retroactively revoke an already-open socket, pipe, or other descriptor capability exposed through `stdio.* = inherit`.

## IPC namespace semantics

`CLONE_NEWIPC` separates SysV IPC objects and the POSIX message-queue namespace from the host. The executable regression uses a host-created SysV message queue because its key lookup gives a direct positive/negative visibility oracle: the host proves the key maps to a queue ID, while the target with an explicit `msgget` grant must receive `ENOENT` for the same key. `EPERM` is not accepted as evidence.

This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.

## UTS identity semantics

`identity.hostname` is a required launcher-owned nodename, not a target request to call `sethostname`. The policy parser accepts only 1–63 ASCII bytes containing letters, digits, `-`, or `.`, and rejects leading/trailing `-` or `.`. The parent prepares the bytes before fork. After the combined namespace transition and UID/GID map setup, the trusted launcher calls `sethostname` while it still has the user-namespace authority required for setup; target capabilities are cleared and target seccomp is installed later.

Executable evidence uses raw `uname` in the target to compare `utsname.nodename` with the policy value. The trusted parent independently reads `/proc/sys/kernel/hostname` before and after the run and requires it to remain exactly unchanged. This slice does **not** claim policy control of NIS/domainname or any broader host identity service.

## Seccomp argument semantics

Milestone 5A extends the existing syscall-number allowlist with optional `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` rules. Rules only narrow already-allowed syscalls; they never introduce a syscall that is absent from `seccomp.allow`. Policy validation requires a non-zero mask, requires `value` to contain no bits outside that mask, rejects duplicate syscall/argument pairs, and forbids rules on launcher-critical `execveat`, `exit`, and `exit_group`.

On Linux x86_64 the classic-BPF compiler reads both 32-bit words of each selected 64-bit `seccomp_data.args[]` slot. A masked low-word mismatch or high-word mismatch returns `EPERM`; all declared argument rules for the matched syscall must pass before `ALLOW`. The executable oracle deliberately uses `lseek` argument 1 with mask `0xffffffff0000000f`, proving one matching offset succeeds while independent low-bit and high-32-bit mismatches are denied.

This mechanism compares numeric syscall arguments only. Classic seccomp cannot safely dereference a pathname, socket-address, or other pointer supplied by the target, so Milestone 5A does not claim pointed-to data inspection, pathname-content policy, range/relational predicates, or elimination of pointer-related TOCTOU hazards.

## Selected handle semantics

Milestone 6A adds launch-time `handle.<target_fd> = <source_fd>` mappings. The source names an already-open descriptor in the trusted calling process; the target destination must be 3–63, must be below `limit.open_files`, and at most 16 mappings are accepted. Before fork, the launcher duplicates each source with `F_DUPFD_CLOEXEC`, rejects directory objects with `fstat`, and stores the duplicate above every target-visible destination. The pinned executable uses the same collision-free storage floor.

After the namespace PID 1 forks the direct target, only that direct target remaps selected sources with `dup3(..., 0)` after stdio setup and before rlimits/capability/seccomp setup. The source-storage duplicates are then closed. The host parent drops its prepared duplicates immediately after fork; bootstrap and namespace PID 1 close all descriptors >= 3 on their non-target paths. Consequently a selected object does not gain hidden launcher/PID1 lifetime ownership while the target runs.

This is an explicit object-capability grant. It preserves the underlying open-file-description authority and state rather than mediating a new pathname lookup. Therefore a selected FD may intentionally expose an object outside the chroot/path namespace, and Milestone 6A does not claim rights attenuation, revocation, pathname confinement of that already-open object, post-launch descriptor transfer, or support for directory handles.

## Deadline, cancellation, and lifecycle orchestration

Potentially allocating policy data, argv/envp, seccomp instructions, pinned descriptors, shared lifecycle state, and capture-pipe creation occur before the initial host `fork`.

The launcher creates user/mount/PID/network/IPC/UTS namespaces, installs the policy UTS nodename, and constructs filesystem state before it forks launcher-owned namespace PID 1. PID 1 forks the direct target as PID 2. The target alone receives target stdio/rlimit/capability/seccomp setup; PID 1 closes inherited descriptors >= 3 so it cannot keep launcher capture writers alive.

If neither a deadline nor external cancellation is active, PID 1 uses the existing blocking direct-target wait. Otherwise PID 1 opens a pidfd for the already-forked target. A declared deadline adds a `TFD_CLOEXEC` timerfd using `CLOCK_MONOTONIC`; a cancellable run adds the pre-fork pinned eventfd duplicate. PID 1 polls the active supervision descriptors. The direct target closes the cancellation fd before target setup, and pidfd/timerfd are created after target fork, so none of these control descriptors become untrusted target capabilities.

When poll wakes, PID 1 performs one nonblocking target reap check as the race arbiter. An already-waitable target keeps its natural raw wait status. Otherwise a readable cancellation eventfd wins before a simultaneously readable timer; failing that, a readable timer transfers ownership to the deadline path. The winning launcher control path sends `SIGKILL`, waits specifically for the direct target, then runs the existing kill/reap loop for every remaining descendant. Shared lifecycle state records raw target status, mutually exclusive `timed_out` / `cancelled` flags, descendant reap count, and publishes `ready` last.

## Explicit non-goals and limitations

This sandbox is **not** a production multi-tenant container boundary. It does not provide:

- confinement of objects explicitly exposed through `stdio.* = inherit`, including an already-open socket;
- a configured veth/bridge, host/external routes, DNS, NAT, endpoint allowlist, or controlled outbound/inbound network path. Milestone 9A adds only policy-owned isolated loopback on top of the Milestone 4B namespace boundary;
- stdin/stderr redirect or capture;
- a total-output byte ceiling for captured stdout;
- reset/rearm semantics for external cancellation, arbitrary signal forwarding, a general bidirectional control RPC, or an end-to-end cancellation latency guarantee. Milestone 7A is deliberately one-way cancellation only;
- an end-to-end API-call latency bound;
- aggregate process-count accounting or a fork/pid quota;
- cgroup-backed aggregate CPU, physical-memory, I/O, or process accounting;
- post-launch descriptor brokering/`SCM_RIGHTS`, selected-handle revocation or rights attenuation, a general arbitrary FD-remapping language, or selected directory handles;
- persistence of private-scratch redirect output after the mount namespace disappears;
- a general policy that forbids all IPC object types or revokes descriptor-based IPC deliberately exposed to the target;
- policy control of UTS domainname/NIS domain or a general machine-identity service;
- a cgroup namespace or aggregate cgroup controller boundary on the current non-delegated runner;
- seccomp predicates beyond masked equality on numeric syscall argument values, including pointer-target/string inspection, range/relational matching, or pathname-content policy;
- a device namespace, general multi-volume graph, copy-on-write/snapshot semantics, durability/transaction/atomicity guarantees, filesystem-alias-proof volume/root disjointness, or immutable/cryptographic root-subtree snapshot; Milestones 8A/8B cover only one read-only and one writable host-directory exposure;
- persistent executable allowlisting, multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.

## Cgroup-v2 blocker evidence

Milestone 4A aggregate process accounting remains intentionally blocked on the current GitHub-hosted runner. The runner exposes cgroup v2 and the `pids` controller, but the workflow process runs as unprivileged UID 1001 in `/system.slice/hosted-compute-agent.service`, owned by root, and cannot create a child cgroup there (`Permission denied`).

Therefore the project does not claim `pids.max` enforcement from root/sudo-only CI setup or mocks. 4A becomes executable again only when the supported test environment supplies a real writable/delegated cgroup-v2 subtree to the runtime user, with permission to create a child cgroup, set `pids.max`, attach the sandbox process tree, and clean it up without privileged out-of-band setup inside the test itself.

## Trust assumptions

- The Linux kernel and trusted launcher parent/bootstrap/PID1 control plane are trusted.
- The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose whether isolated loopback is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline. Enabling loopback authorizes only connectivity through `lo` inside the private network namespace; it does not authorize host/external attachment. Selecting a handle intentionally grants the authority already represented by that open file description.
- Choosing `inherit`, `redirect`, or `capture` intentionally grants their documented descriptor/output channels.
- A declared deadline intentionally authorizes launcher PID 1 to terminate the direct target and descendants when the timer wins the documented race.
- Supplying a `CancellationToken` to a cancellable run and signalling it intentionally authorizes launcher PID 1 to terminate the direct target and descendants when cancellation wins the documented race. The token is one-way and remains cancelled after it is signalled.
- Root device/inode revalidation is not a subtree integrity proof.

## Test strategy and evidence

The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.

Evidence includes:

- exact allowed/denied syscall behavior and fail-closed malformed policy handling;
- a default-disabled loopback oracle in which a raw target explicitly granted `socket`, `ioctl`, `close`, and `exit` reads `lo` flags and requires `IFF_UP` to be clear;
- an enabled-loopback positive oracle in which a raw target performs a real intra-sandbox TCP server/client exchange on `127.0.0.1` and the server reads exact `loopback-ok` bytes;
- an enabled-loopback host-separation oracle in which a host `127.0.0.1` listener is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. Only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH` are accepted; seccomp `EPERM` and successful host-listener reachability both fail the test;
- a host-created SysV message queue whose explicit key is first proven visible from the host; a raw target explicitly granted `msgget` must receive `ENOENT` for that same key inside the IPC namespace. Seeing the host queue or receiving seccomp `EPERM` fails the test;
- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;
- masked seccomp argument-rule parser/validator regressions plus a raw `lseek` oracle whose allowed offset matches the declared low/high 64-bit mask while separate low-bit and high-32-bit mismatches both return `EPERM`;
- selected-handle policy regressions plus a raw pipe oracle in which target fd 9 reads the exact marker while the original selected source descriptor and an unrelated undeclared high descriptor both return `EBADF`; a directory descriptor source is separately rejected before launch;
- read-only-volume parser/validator regressions plus a raw mount oracle that reads the exact marker only from the declared `/data` target, requires `EROFS` for a create attempt there, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the source content was unchanged;
- writable-volume parser/validator regressions plus a raw mount oracle that writes exact `persistent-write\n` bytes at `/persist/persisted`, still requires `EROFS` outside the writable mount, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the exact bytes persisted only in the declared source;
- all Milestones 1–3B descriptor, stdio, filesystem, capability, rlimit, launch-error, capture, PID identity, descendant cleanup, timeout, and exit-vs-signal regressions;
- a raw deadline target that writes an exact stdout marker, forks a descendant that remains in `pause()`, and is preempted by a 1,000 ms policy deadline while a fast target under 5,000 ms still preserves `Exited(42)`;
- an external-cancellation target that forks one paused descendant and writes an exact readiness marker through selected fd 9. The parent waits for the full marker before signalling the token, then verifies `Cancelled` plus one reaped descendant; a separate uncancelled-token run preserves natural `Exited(42)`.

CI explicitly enables the user-namespace settings required by its disposable Ubuntu runner. The runtime never weakens host policy when mandatory primitives are unavailable.

## Failure semantics

Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, selected-target remapping, deadline/cancellation supervision preflight, cancellation eventfd pinning/signalling, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed selected-handle setup never silently preserves ambient source descriptors or retries without the declared mapping. A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity. If explicitly requested loopback activation is unsupported or denied, launch fails explicitly rather than continuing with the requested network state absent.

## Phase promotion

Milestone 3 is sealed: the launcher owns PID namespace init, descendant cleanup, bounded runtime termination, and explicit timeout reporting.

Milestones through 8B are complete on `main`; the bounded persistent-volume authority model is sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. The current Milestone 9A verified candidate adds policy-owned isolated loopback with default-down, positive intra-sandbox TCP, and host-loopback separation evidence. After 9A integrates, do not farm more loopback ports, protocols, or aliases; the next networking promotion must add a materially different topology or host/external endpoint capability with explicit positive/negative evidence. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow.
