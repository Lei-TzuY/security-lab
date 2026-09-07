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

**Status: complete on `main`.** Makes sandbox nodename identity explicit and launcher-owned rather than inheriting the host hostname into an otherwise isolated environment.

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

Milestone 4B–4D namespace/identity baselines are sealed on `main`; do not farm more loopback keys, SysV queue variants, or hostname syntax copies. Milestone 4A remains blocked until the runtime user receives a real delegated writable cgroup-v2 subtree.

## Milestone 5 — syscall semantic precision

### Slice 5A — masked seccomp syscall-argument filtering

**Status: complete on `main`.** Extends default-deny seccomp from syscall-number allowlisting to optional masked equality over selected numeric syscall arguments without widening launcher management authority.

Acceptance evidence is executable:

- policy accepts `seccomp.arg.<syscall>.<0..5> = <mask>:<value>` using decimal or `0x` hexadecimal integers;
- rules can only narrow syscalls already present in `seccomp.allow`, masks must be non-zero, values may not set bits outside the mask, duplicate syscall/argument rules are rejected, and no more than 64 rules are accepted;
- `execveat`, `exit`, and `exit_group` cannot receive argument rules, preserving pinned target start and fail-closed post-filter termination;
- the Linux x86_64 cBPF compiler checks both 32-bit words of the selected 64-bit `seccomp_data.args[]` slot and requires every declared rule for a matched syscall before returning `ALLOW`;
- a raw `lseek` target under mask `0xffffffff0000000f` accepts offset `0x0000000112345678`, rejects a low masked-bit mismatch, and separately rejects a high-32-bit mismatch with seccomp `EPERM`;
- all Milestones 1–4D regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.

Boundary: 5A is masked equality on numeric syscall argument values. Classic seccomp does not dereference target pointers, so this is not pathname/string-content inspection, range/relational policy, or a pointer TOCTOU solution.

### Milestone 5 promotion rule

Milestone 5A is sealed on `main`; do not farm identical argument masks across unrelated syscalls. Further seccomp work needs a materially new predicate model and executable authority boundary rather than copied rules. Supplementary-group clearing requires a different user-namespace mapping architecture under the current nonprivileged `setgroups=deny` flow; 4A remains blocked on cgroup delegation.

## Milestone 6 — explicit object capabilities

### Slice 6A — selected non-stdio handle passing

**Status: complete on `main`.** Adds an explicit launch-time object-capability surface without reopening ambient descriptor inheritance.

Acceptance evidence is executable:

- policy accepts `handle.<target_fd> = <source_fd>` for at most 16 unique target descriptors; target descriptors are restricted to 3–63 and must remain below `limit.open_files`;
- the launcher duplicates each already-open source before fork with `F_DUPFD_CLOEXEC`, rejects directory descriptor sources with `fstat`, and leaves the caller-owned source descriptor untouched;
- launcher-owned selected sources and the pinned executable are stored above every target-visible destination using a dynamically derived floor, avoiding destination collisions without imposing an unconditional fd>=64 requirement;
- after stdio setup, only the direct target installs selected destinations with `dup3(..., 0)` before rlimits/capability/seccomp setup. Host parent, bootstrap, and namespace PID 1 do not retain launcher-owned selected duplicates while the target runs;
- existing `close_range(..., CLOEXEC)` sanitization remains active, so undeclared inherited descriptors disappear at exec rather than being implicitly preserved;
- a raw target reads `selected-handle-ok` from declared target fd 9 while both the original high source descriptor and a separate undeclared high descriptor return `EBADF`; a directory source is rejected before launch;
- all Milestones 1–5A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.

Boundary: 6A is a deliberate grant of an already-open kernel object. It does not attenuate the source open-file-description rights/state, mediate pathname access to that object, revoke the handle after launch, transfer new descriptors after launch, or support directory handles/general arbitrary FD remapping.

### Milestone 6 promotion rule

Milestone 6A is sealed on `main`; do not farm more descriptor numbers or object types merely to repeat the same remap path.

## Milestone 7 — external control plane

### Slice 7A — external cancellation

**Status: complete on `main`.** Adds a caller-owned one-way cancellation primitive that integrates with launcher-owned PID 1 process-tree supervision without exposing the control descriptor to the target.

Acceptance evidence is executable:

- `CancellationToken` is cloneable and backed by `eventfd(EFD_CLOEXEC | EFD_NONBLOCK)` on Linux; signalling is one-way and readiness remains persistent because the launcher never drains the eventfd;
- `run_report_with_cancel` / `run_with_cancel` add cancellable execution without changing existing `run_report` / `run` behavior;
- the launcher pins a cancellation duplicate before fork, bootstrap closes it, namespace PID 1 alone retains it for supervision, and the direct target closes its copy before stdio/rlimit/capability/seccomp/exec setup;
- PID 1 polls target pidfd, optional deadline timerfd, and optional cancellation eventfd with one deterministic arbitration rule: natural target exit > explicit cancellation > deadline;
- cancellation ownership reports `ChildOutcome::Cancelled`, remains distinct from `TimedOut` and ordinary target signals, then reuses the owned process-tree kill/reap path before lifecycle readiness;
- a raw target forks one paused descendant, publishes `cancellation-target-ready\n` through selected fd 9, and pauses. The parent reads the exact marker before signalling cancellation, then observes `Cancelled` and exactly one reaped descendant;
- a separate uncancelled-token run preserves the fast target's natural `Exited(42)` outcome;
- stable format/Clippy/full tests and the full Rust 1.74 suite remain green.

Boundary: 7A is one-way cancellation only. It does not provide token reset/rearm, arbitrary signal forwarding, a bidirectional control protocol, or a bound on total latency from public API entry to termination.

### Milestone 7 promotion rule

7A is sealed on `main`; do not farm cancellation aliases, signal numbers, or alternate wake primitives that repeat the same ownership path. Promotion is now a materially different executable data-plane boundary. Milestone 4A remains blocked on real unprivileged cgroup-v2 delegation, and supplementary-group isolation still requires a different user-namespace mapping architecture.

## Milestone 8 — explicit persistent data exposure

### Slice 8A — one read-only persistent host volume

**Status: complete on `main`.** Adds one explicit read-only host-directory exposure without weakening the recursively read-only sandbox-root invariant.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `volume.readonly_source` / `volume.readonly_target`; the source is an absolute trusted host directory whose configured path must be disjoint from `filesystem.root`, while the target is an absolute sandbox path that cannot be `/`, contain the executable/working directory, or overlap private scratch;
- before fork, the launcher pins the source with `openat2(O_PATH|O_DIRECTORY|O_CLOEXEC)` while forbidding symlink/magic-link traversal, and independently verifies the target beneath the pinned sandbox root;
- after the private user/mount namespace exists, the launcher reopens the trusted source pathname and requires its `(st_dev, st_ino)` to match the pre-fork pin before using it;
- the source mount tree is recursively cloned with `open_tree`, recursively marked `MOUNT_ATTR_RDONLY`, and attached with `move_mount` only to the prevalidated target inside the cloned sandbox root;
- the raw target reads exact `volume-marker\n` bytes from `/data/marker`, requires `EROFS` when creating `/data/write-must-fail`, and requires `ENOENT` when opening the original absolute host source pathname;
- the trusted parent proves the host marker is byte-for-byte unchanged and the forbidden host file was never created;
- all Milestones 1–7A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.

Boundary: 8A is exactly one read-only existing host-directory mount. It does not provide writable persistence, multiple-volume composition, snapshots/copy-on-write, durability/atomicity guarantees, or special network-filesystem semantics.

### Slice 8B — one writable persistent host volume

**Status: complete on `main`.** Adds one explicit host-mutation capability rather than another read-only path variant.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `volume.writable_source` / `volume.writable_target`; the source's configured path must be disjoint from `filesystem.root`, sandbox `/` is forbidden as the target, the target cannot contain the executable/working directory or overlap private scratch, and configured read-only/writable source or target paths may not overlap;
- read-only and writable volumes share one launcher-owned prepared-volume path: pre-fork source pin, target validation beneath the pinned root, post-namespace source reopen and `(st_dev, st_ino)` revalidation, detached recursive mount clone, target pin, and `move_mount` attachment;
- only read-only volumes receive recursive `MOUNT_ATTR_RDONLY`; a writable volume deliberately preserves source writability as explicit policy-authorized host mutation authority;
- the raw target creates `/persist/persisted` with exact `persistent-write\n` bytes, still requires `EROFS` for `/root-write-must-fail`, and requires `ENOENT` for the original absolute host source pathname;
- the trusted parent proves the exact bytes persisted in the declared host source and that no forbidden root-side file was created;
- a dedicated public `run()` regression rejects both a writable source nested inside `filesystem.root` and a read-only source that contains the root, before any namespace/mount setup begins;
- 8A read-only evidence and all Milestones 1–7A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 8B is at most one explicitly writable existing host directory. It does not claim durability/transaction/atomicity semantics, snapshots/copy-on-write, a general mount graph, alias-proof source disjointness, special network-filesystem behavior, or automatic `nodev`/`nosuid`/`noexec` hardening for that host mount.

### Milestone 8 promotion rule

Milestone 8 is sealed at this bounded laboratory scope. Do not farm extra mountpoints or access-mode aliases.

## Milestone 9 — controlled networking

### Slice 9A — policy-owned isolated loopback

**Status: complete on `main`.** Adds real positive connectivity inside the private network namespace without attaching it to the host or an external network.

Acceptance evidence is executable:

- policy accepts optional `network.loopback = enabled|disabled`, defaults to disabled when absent, and rejects invalid or duplicate declarations;
- after the combined user/network namespace transition and UID/GID mapping, the trusted launcher may use an IPv4 datagram management socket plus `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set only `IFF_UP` on `lo`; the socket is closed before target capability clearing/seccomp/exec, and unsupported or denied mandatory activation fails explicitly rather than falling back;
- with loopback absent/default-disabled, a raw target explicitly granted `socket` and `ioctl` reads `lo` flags and requires `IFF_UP` to be clear;
- with loopback enabled, a raw target explicitly granted the required TCP syscalls performs `socket` → `bind` → `listen` → `fork` → `connect` → `accept` and transfers exact `loopback-ok` bytes over `127.0.0.1`;
- a separate enabled-loopback regression first proves a host `127.0.0.1` listener is reachable from the host, then requires the sandbox connection to that host port to fail only with network-stack separation outcomes (`ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`); seccomp `EPERM` or successful host reachability fails the oracle;
- launcher-owned activation does not add target network syscalls or capabilities implicitly: target `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` remain explicit seccomp grants;
- all Milestones 1–8B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 9A controls only `lo` inside the already-isolated network namespace. It does not configure a veth, host bridge, host/external routes, DNS, NAT, endpoint allowlist, ingress, or egress.

### Slice 9B — launcher-brokered host-loopback TCP endpoint

**Status: complete on `main`.** Adds one explicit host endpoint object capability without attaching the target network namespace to the host.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `network.host_loopback_tcp_port` / `network.host_loopback_tcp_target_fd`; the port is 1–65535, the fd is 3–63 and below `limit.open_files`, and collision with a `handle.*` target is rejected fail-closed;
- before fork and before entering the sandbox network namespace, the trusted parent creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects only to `127.0.0.1:<declared-port>`; connection failure is an explicit setup failure rather than a fallback;
- the brokered socket participates in the existing collision-safe selected-object storage floor and is installed only into the direct target at the declared fd; host parent, bootstrap, and namespace PID 1 do not retain a launcher-owned copy while the target runs;
- a host listener receives exact `brokered-host-loopback-ok` bytes written by the raw target through brokered fd 10;
- in the same run, a fresh socket created by that target attempts the same host loopback port and must still fail with `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` or successful direct host reachability fails the oracle;
- 9A default-down/intra-sandbox-loopback/host-separation evidence and all Milestones 1–8B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 9B is one launcher-created, already-connected IPv4 TCP stream to host `127.0.0.1`. It does not provide arbitrary IP/hostname endpoints, DNS, UDP, ingress/listening exposure, veth/bridge/routes/NAT, TLS/application authentication, a general network ACL, or a separate parent-preparation connection deadline. The host service may observe the broker connection before later sandbox setup completes.

### Milestone 9 promotion rule

After 9B integrates, do not farm extra ports, target-fd aliases, or protocol-name variants around the same preconnected-socket mechanism. Further networking work must add a materially different endpoint/topology authority boundary with new executable evidence; otherwise promote to a different architectural frontier. Milestone 4A aggregate cgroup accounting remains blocked until real unprivileged cgroup-v2 delegation is available; supplementary-group isolation remains a separate user-namespace mapping problem.

## Milestone 10 — pathname access narrowing

### Slice 10A — Landlock read/execute envelope

**Status: complete on `main`.** Adds a kernel-enforced pathname access layer inside the already-constructed sandbox filesystem rather than another mount or networking variant.

Acceptance evidence is executable:

- repeatable `landlock.read_execute = <absolute-sandbox-path>` entries are bounded to 32, reject `/`, duplicates, relative paths, and policies that do not cover the initial executable; an empty list preserves the pre-10A behavior;
- parent preparation fail-closed verifies each declared path beneath the pinned root as a regular file or directory and preallocates sandbox-relative path data before fork;
- when requested, the runtime queries Landlock support rather than silently dropping the restriction; known unavailable-kernel results are reported as unsupported and other setup errors fail closed;
- the direct target creates a ruleset handling only `EXECUTE`, `READ_FILE`, and `READ_DIR`, reopens declared paths against the final mounted root, stores the ruleset descriptor above all target-visible descriptor destinations, applies `PR_SET_NO_NEW_PRIVS`, then calls `landlock_restrict_self` before target seccomp and pinned `execveat`;
- the raw target reads exact `landlock-allowed\n` bytes from a declared `/landlock-allowed/marker`, while a real `/landlock-denied/secret` that remains present in the same chroot returns exact `EACCES`; seccomp grants `openat` and therefore cannot masquerade as the pathname denial;
- all Milestones 1–9B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 10A is a read/execute pathname envelope only. It does not attenuate already-open stdio/selected/brokered object capabilities, does not add write/create/remove Landlock policy, does not prove filesystem aliases/canonicalization or subtree immutability, and is not a production multi-tenant container boundary.

### Slice 10B — Landlock regular-file mutation envelope

**Status: complete on `main`.** Adds a separate pathname-mutation authority dimension that composes with the two existing writable surfaces rather than broadening them.

Acceptance evidence is executable:

- repeatable `landlock.file_mutate = <absolute-sandbox-directory>` entries are bounded to 32, reject `/`, duplicates, relative paths, and any path that is not exactly the private scratch root or equal to/beneath `volume.writable_target`;
- requested mutation enforcement requires Landlock ABI 3 or newer so `WRITE_FILE` and `TRUNCATE` are both controlled; older ABIs fail explicitly rather than degrading the security claim;
- mutation paths are pinned against the final mounted tree after scratch/persistent-volume construction, with symlink/magic-link traversal forbidden, because writable-volume subdirectories may not exist in the pre-mount root placeholder;
- the ruleset handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE` for this slice, while 10A read/execute rights remain independently optional and exact duplicate paths combine both requested authority sets;
- a raw target creates inside `/scratch`, independently calls `truncate(2)` then opens `/persist/allowed/existing` `O_WRONLY` before writing exact `landlock-persistent-write\n`, and removes `/persist/allowed/remove-me`; create, unlink, `O_WRONLY` open, and `truncate(2)` in sibling `/persist/denied` on the same writable host mount each require exact `EACCES`;
- parent-side evidence proves the exact allowed bytes persisted, the allowed removal occurred, the denied sentinel remained byte-for-byte unchanged, and no denied file was created; target seccomp explicitly grants every syscall used by the oracle;
- all Milestones 1–10A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 10B is a regular-file pathname mutation envelope only. It does not handle directory creation/removal, symlink/device/socket/FIFO creation, rename/link `REFER`, rights revocation for pre-opened descriptors, filesystem alias/canonicalization proof, or subtree immutability.

### Milestone 10 promotion rule

Milestone 10B is integrated; seal this bounded pathname-envelope phase. Do not farm more regular-file mutation aliases or path-count variants. Promote to a materially different authority or resource frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.

## Milestone 11 — host-loopback ingress object authority

### Slice 11A — one brokered host-loopback TCP listener

**Status: complete on `main`.** Adds a materially different inbound object capability without attaching the target network namespace to host or external routing.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `network.host_loopback_tcp_listen_port` / `network.host_loopback_tcp_listen_target_fd`; the port is 1–65535, the fd is 3–63 and below `limit.open_files`, and the target cannot collide with selected handles or the 9B connected-broker target;
- the trusted parent creates `SOCK_STREAM|SOCK_CLOEXEC`, binds only host IPv4 `127.0.0.1:<declared-port>`, calls `listen`, and moves the listener onto the same collision-safe launcher storage plane used by selected handles and the 9B broker; bind/listen failure is terminal rather than a fallback;
- only the direct target receives the listener at the declared fd; its use remains subject to explicit target seccomp grants such as `accept`, `read`, `write`, and `close`;
- the raw target publishes exact `brokered-host-ingress-ready\n` bytes on selected fd 9 before calling `accept` on fd 10. Only after the host reads readiness does a host-loopback client connect, send exact `brokered-host-ingress-request` bytes, and receive exact `brokered-host-ingress-ok` reply bytes;
- a separately occupied host-loopback port causes `SetupFailed` before untrusted execution, proving the listener is not silently omitted;
- the target's own sockets remain in its isolated network namespace: 11A is one pre-opened listener object capability, not a veth/bridge, host route, NAT, DNS, arbitrary endpoint allowlist, or external ingress path;
- all Milestones 1–10B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 11A grants one host-loopback TCP listening object. It does not promise exactly one accepted connection, expose non-loopback interfaces, provide UDP/TLS/application authentication, or configure general inbound routing.

### Milestone 11 promotion rule

After 11A integrates, seal the single-listener object-capability slice. Do not farm additional port numbers, backlog values, or equivalent listener aliases. Promote only to a materially different network topology/endpoint authority or another evidence-backed resource frontier.

## Milestone 12 — target-created TCP port mediation

### Slice 12A — Landlock TCP bind/connect port envelope

**Status: complete on `main`.** Adds an independent kernel access-control layer for target-created TCP bind/connect operations rather than another launcher-brokered socket alias.

Acceptance evidence is executable:

- repeatable `landlock.tcp_bind_port = <1..65535>` and `landlock.tcp_connect_port = <1..65535>` entries are independently bounded to 32 unique ports; duplicate values, port 0, and malformed values are rejected fail-closed;
- each non-empty list activates only its matching Landlock access class (`LANDLOCK_ACCESS_NET_BIND_TCP` or `LANDLOCK_ACCESS_NET_CONNECT_TCP`); an empty list leaves that class unhandled, so policy intent is explicit instead of silently denying unrelated networking;
- requested TCP-port enforcement requires Landlock ABI 4 or newer. The parent preflights the ABI and older/unavailable kernels fail explicitly rather than dropping the restriction;
- the direct target builds `handled_access_net` alongside any existing pathname rights, adds `LANDLOCK_RULE_NET_PORT` rules for declared ports, applies `no_new_privs`, and restricts itself before target seccomp and pinned exec. Landlock rules do not add `socket`, `bind`, `connect`, or any other syscall to the target seccomp allowlist;
- with isolated loopback explicitly enabled and the raw target granted the necessary TCP syscalls, local bind/listen/connect/accept on declared port 42421 succeeds and transfers the expected bytes, while otherwise-identical bind and connect attempts to undeclared port 42422 must each return exact `EACCES`;
- the oracle therefore distinguishes Landlock denial from seccomp `EPERM` and from an unreachable/refused network endpoint; all earlier sandbox regressions plus the deterministic `run-json` CLI tests remain active, and stable format/Clippy/full tests plus the full Rust 1.74 suite are green.

Boundary: Landlock ABI 4 TCP network rules match **ports, not IP addresses**. 12A therefore does not claim an IP/hostname destination firewall, UDP mediation, external routing, veth/bridge/NAT/DNS, TLS/application authentication, or attenuation of already-connected/listening sockets passed as explicit object capabilities. Port 0/ephemeral-bind authorization is deliberately outside this initial slice.

### Milestone 12 promotion rule

12A is sealed on `main`. Do not farm more test ports, IPv4/IPv6 aliases, or port-count variants. A later networking slice must add a materially different, verifiable address/topology or protocol authority boundary; otherwise promote to another subsystem frontier.

## Milestone 13 — cross-domain IPC authority

### Slice 13A — Landlock signal scope

**Status: complete on `main`.** Adds a process-to-process authority boundary rather than another pathname, port, or brokered-socket variant.

Acceptance evidence is executable:

- policy accepts one optional `landlock.scope_signal = enabled|disabled`, defaults to disabled, and rejects invalid or duplicate declarations;
- enabling the scope requires Landlock ABI 6 or newer; older or unavailable kernels fail explicitly rather than silently dropping the requested restriction;
- the direct target adds only `LANDLOCK_SCOPE_SIGNAL` to the Landlock ruleset `scoped` field, preserves historical shorter ruleset structure sizes when the scope is unused, applies `no_new_privs`, and restricts itself before target seccomp and pinned exec;
- signal scoping does not grant signal authority through seccomp: `pidfd_open` and `pidfd_send_signal` are available only when the target policy explicitly names them;
- an unscoped raw target opens a pidfd for launcher-owned namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with signal scope enabled must receive exact `EPERM`; signal number 0 proves the permission boundary without delivering a signal or changing PID 1 state;
- all Milestones 1–12A regressions plus deterministic `run-json` and offline `check`/`check-json` CLI tests remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 13A is one Landlock signal scope with no per-process exception list. It does not grant signalling syscalls, replace PID-namespace lifecycle supervision, provide arbitrary signal forwarding/brokering, or claim Landlock scoping for abstract Unix sockets or another IPC class.

### Slice 13B — Landlock abstract UNIX socket scope

**Status: complete on `main`.** Adds a distinct cross-domain socket-object boundary and deliberately composes with existing selected-handle authority rather than inventing another broker path.

Acceptance evidence is executable:

- policy accepts optional `landlock.scope_abstract_unix_socket = enabled|disabled`, defaults to disabled, rejects invalid/duplicate declarations, and can coexist with the independent signal scope;
- enabling abstract-UNIX scope requires Landlock ABI 6 or newer. Older or unavailable kernels fail explicitly rather than dropping the request;
- the direct target ORs `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` into the ABI-6 ruleset `scoped` bitmask and may combine it with `LANDLOCK_SCOPE_SIGNAL`; historical shorter ruleset structure sizes remain unchanged when neither scope is requested;
- the scope does not grant socket authority: target seccomp must explicitly include `connect`, and the oracle uses an already-open AF_UNIX client delivered through existing selected-handle fd 9 rather than adding `socket`;
- the host binds/listens on a real abstract AF_UNIX stream endpoint. The unscoped raw target connects through selected fd 9 and the parent successfully accepts that connection; the otherwise-identical scoped target must exit with exact `EPERM`, and a nonblocking parent `accept4` must then return `EAGAIN`, proving no connection was queued;
- all Milestones 1–13A regressions plus deterministic CLI tests remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 13B is the kernel-defined cross-domain abstract-UNIX `connect` scope. It does not provide pathname UNIX-socket filtering, per-address/per-peer exceptions, a general AF_UNIX broker, implicit `socket`/`connect` grants, or revocation of already-connected stream traffic. Stream-vs-datagram variants are not separate roadmap milestones for this same scope bit.

### Milestone 13 promotion rule

13B is integrated; seal the ABI-6 Landlock scope surface at this bounded laboratory scope. Do not farm signal syscall aliases, signal numbers, or AF_UNIX socket-type variants that repeat the same scoped-field mechanism. Promote only to a materially different executable authority frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.

## Milestone 14 — device operation authority

### Slice 14A — Landlock device-ioctl envelope

**Status: complete on `main`.** Adds a distinct device-driver operation boundary rather than another pathname, network-port, or IPC-scope variant.

Acceptance evidence is executable:

- policy accepts repeatable `landlock.device_ioctl = <absolute-sandbox-device>` entries, bounded to 32 unique paths; `/`, relative paths, duplicates, and oversized lists are rejected fail-closed;
- requested enforcement requires Landlock ABI 5 or newer. Older or unavailable kernels fail explicitly rather than silently dropping `LANDLOCK_ACCESS_FS_IOCTL_DEV`;
- after final namespace/mount construction, the direct target resolves each declared path with `openat2` beneath the sandbox root while rejecting symlink/magic-link traversal, verifies with `fstat` that it is a character or block device, and adds a `LANDLOCK_RULE_PATH_BENEATH` rule carrying only `IOCTL_DEV`;
- host-side baselines first prove `RNDGETENTCNT` succeeds on both `/dev/urandom` and `/dev/random`; the sandbox then exposes host `/dev` read-only at `/devices`, so both device nodes are real and visible without creating a device namespace;
- the raw target opens `/devices/urandom` after Landlock restriction and the same ioctl succeeds, proving positive declared authority; it separately opens undeclared `/devices/random` after restriction and requires exact `EACCES` for the same ioctl, proving Landlock denial rather than pathname invisibility;
- target seccomp explicitly grants `openat`, `ioctl`, `close`, and `exit`, so seccomp `EPERM` cannot masquerade as device-ioctl evidence; all earlier sandbox/CLI regressions remain active, and the exact synced candidate passes stable format/Clippy/full tests plus the full Rust 1.74 suite.

Boundary: Landlock ABI-5 `IOCTL_DEV` is a coarse right bound when a character/block device is opened after restriction. 14A does not provide a per-ioctl-command allowlist, revoke ioctl authority already attached to a pre-restriction fd, create/filter device nodes, provide a device namespace, or widen target seccomp.

### Milestone 14 promotion rule

14A is integrated; seal this coarse device-ioctl layer. Do not farm extra device names or ioctl request codes through the same rule.

## Milestone 15 — address-aware network object authority

### Slice 15A — exact numeric host-IPv4 TCP broker

**Status: complete on `main`.** Adds address discrimination to launcher-brokered outbound object authority without joining the target network namespace to host routing.

Acceptance evidence is executable:

- policy accepts the all-or-nothing triple `network.host_ipv4_tcp_address` / `network.host_ipv4_tcp_port` / `network.host_ipv4_tcp_target_fd`; the address must be numeric unicast IPv4, the port is 1–65535, and the fd is 3–63 below `limit.open_files` without collisions against selected handles or existing broker destinations;
- the trusted parent reuses one generic host-IPv4 TCP connector: legacy 9B still fixes the address to `127.0.0.1`, while 15A passes the declared address. Connection failure remains a setup error and never falls back to target-side networking;
- the connected socket is stored above every target-visible destination and installed only in the direct target as an already-open object capability. No target `socket` or `connect` grant is added implicitly;
- the integration oracle binds the same TCP port on host `127.0.0.1` and `127.0.0.2`, declares `127.0.0.2`, requires the exact broker marker only on the selected listener, and requires no connection queued on `127.0.0.1`;
- the raw target then independently attempts a fresh connection through its own isolated network namespace and still requires an ordinary unreachable/refused result, preserving the no-host-route invariant;
- all Milestones 1–14A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 15A is one preconnected IPv4 TCP socket to an exact numeric endpoint. It does not provide DNS/hostname resolution, IPv6, UDP/raw sockets, CIDR/range allowlists, dynamic post-launch brokering, veth/bridge/NAT/routing, TLS/application authentication, or an external-network reachability guarantee. The deterministic address oracle uses host-local `127/8`; it proves endpoint selection, not Internet egress.

### Milestone 15 promotion rule

After 15A integrates, seal this single exact-address preconnected TCP broker. Do not farm more IPv4 literals, ports, or target-fd aliases around the same connector. Promote only to a materially different protocol/topology authority, resource boundary, or observability surface with executable evidence.

## Milestone 16 — datagram network object authority

### Slice 16A — exact numeric host-IPv4 UDP datagram broker

**Status: complete on `main`.** Adds a connectionless/message-boundary-preserving transport capability rather than another TCP endpoint alias.

Acceptance evidence is executable:

- policy accepts the all-or-nothing triple `network.host_ipv4_udp_address` / `network.host_ipv4_udp_port` / `network.host_ipv4_udp_target_fd`; the address must be numeric unicast IPv4, the port is 1–65535, and the fd is 3–63 below `limit.open_files` without collisions against selected handles or any existing broker destination;
- the trusted parent creates `SOCK_DGRAM|SOCK_CLOEXEC` in the host network namespace and calls `connect(2)` to fix the socket's default peer to exactly the declared numeric IPv4 address and port, then stores that socket above every target-visible destination and remaps it only into the direct target;
- UDP `connect()` is treated only as peer selection: it is not a handshake and does not claim service availability or delivery;
- the deterministic oracle binds the same UDP port on host `127.0.0.1` and `127.0.0.2`, selects `127.0.0.2`, and observes one exact `brokered-host-udp-ok` datagram only at the selected address, preserving one-datagram message boundaries;
- the raw target independently creates a fresh UDP socket inside its isolated network namespace and attempts the same host address/port; host-side observation proves no second datagram crosses into either host endpoint, preserving the no-host-route invariant even when target `socket`, `connect`, and `write` are explicitly granted;
- all Milestones 1–15A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 16A is one preconnected IPv4 UDP socket to an exact numeric endpoint. It does not provide DNS/hostname resolution, IPv6, raw sockets, UDP listeners/bind brokering, multicast/broadcast policy, CIDR/range allowlists, dynamic post-launch brokering, veth/bridge/NAT/routing, application authentication, or an external-network reachability/delivery guarantee. The deterministic oracle uses host-local `127/8`; it proves endpoint selection and datagram semantics, not Internet egress.

### Milestone 16 promotion rule

16A is integrated; seal the bounded exact-address preconnected IPv4 TCP/UDP broker family. Do not farm more address literals, ports, target-fd aliases, or trivial socket-type variants. Promotion is now a materially different resource/observability boundary.

## Milestone 17 — launcher-owned resource observability

### Slice 17A — process-tree resource usage report

**Status: complete on `main`.** Converts resource data already owned by namespace PID 1 into an explicit post-mortem report without pretending to provide cgroup enforcement or benchmarking.

Acceptance evidence is executable:

- `RunReport` adds `ProcessTreeUsage { user_cpu_micros, system_cpu_micros, max_child_rss_kib }`, and the public re-export makes the telemetry part of the library report contract;
- namespace PID 1 performs its existing direct-target wait and remaining-descendant kill/reap convergence first, then calls `getrusage(RUSAGE_CHILDREN)` and publishes all usage fields before lifecycle `ready`;
- user/system CPU fields are cumulative waited-child CPU microseconds. On Linux, `max_child_rss_kib` deliberately names `RUSAGE_CHILDREN.ru_maxrss` as the largest child's peak RSS rather than a concurrent whole-tree memory high-water mark;
- a statically linked raw target maps 8 MiB anonymous memory and faults every 4 KiB page using only explicit `mmap`/`exit` target grants; the completed report must expose at least 4096 KiB of `max_child_rss_kib`;
- `run-json` carries all three resource fields as unsigned decimal integers while preserving the exact deterministic outcome/captured-output prefix instead of hard-coding nondeterministic CPU/RSS values;
- stable format/Clippy/full tests and the full Rust 1.74 suite are green, with all Milestones 1–16A regressions retained.

Boundary: 17A is post-mortem kernel observability only. It does not provide live sampling, per-process attribution, a deterministic performance benchmark, a concurrent process-tree RSS peak, cgroup-backed aggregate CPU/memory/I/O/process accounting, or any new resource limit/enforcement mechanism.

### Milestone 17 promotion rule

17A is integrated; do not farm more `rusage` counters or output aliases. Promote only to a materially different enforceable resource boundary when prerequisites exist, or another independent authority/observability subsystem with executable evidence. Milestone 4A remains blocked until a real writable/delegated cgroup-v2 subtree is available to the unprivileged runtime user.

## Milestone 18 — exact host-local IPC object authority

### Slice 18A — one exact host-path AF_UNIX stream broker

**Status: complete on `main`.** Adds a host-local IPC authority surface that is distinct from the sealed IPv4 TCP/UDP broker family and from Landlock's abstract-UNIX cross-domain scope.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `ipc.host_unix_stream_path` / `ipc.host_unix_stream_target_fd`; the pathname must be absolute, contain no NUL or `..`, fit Linux `sockaddr_un.sun_path` at no more than 107 pathname bytes, and be lexically disjoint from `filesystem.root`;
- the target fd remains bounded to 3–63, below `limit.open_files`, and cannot collide with a selected handle or any existing TCP/UDP/listener broker destination;
- before fork and before entering the target namespaces/chroot, the trusted parent creates `AF_UNIX` `SOCK_STREAM|SOCK_CLOEXEC`, connects to exactly the configured host pathname, and moves the connected stream onto the existing collision-safe selected-handle storage/remap plane; setup/connect failure is terminal rather than a fallback;
- a real host `UnixListener` accepts that connection. The raw target writes exact `brokered-host-unix-ok` bytes through fd 10 and reads exact `host-unix-reply` bytes back;
- the same raw target then creates a fresh AF_UNIX stream socket with explicit `socket` and `connect` seccomp grants and attempts the original absolute host pathname. Exact `ENOENT` is required, proving the host pathname was not made directly reachable through the sandbox chroot and that seccomp `EPERM` is not masquerading as path confinement;
- all Milestones 1–17A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 18A is exactly one preconnected filesystem-path AF_UNIX stream capability. It does not support abstract addresses, datagram/seqpacket variants, SCM_RIGHTS descriptor brokering, pathname alias/canonical-inode proof, per-peer credential policy, a general AF_UNIX graph, or dynamic post-launch connection brokering.

### Milestone 18 promotion rule

18A is integrated; seal the exact-path stream object-capability slice. Do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants. The next AF_UNIX work must add a materially different enforcement property rather than another transport spelling. Supplementary-group isolation and cgroup-backed aggregate accounting remain blocked on their documented kernel/environment prerequisites.

## Milestone 19 — host-local IPC peer identity enforcement

### Slice 19A — exact peer UID/GID for the host AF_UNIX broker

**Status: complete on `main`.** Narrows the already-bounded 18A object capability with kernel-provided peer identity evidence before target authority exists.

Acceptance evidence is executable:

- policy accepts optional all-or-nothing `ipc.host_unix_stream_peer_uid` / `ipc.host_unix_stream_peer_gid` unsigned integers and rejects incomplete pairs or credentials declared without the exact-path host-UNIX broker;
- the trusted parent performs the existing exact host-path `connect(2)`, then calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` before the connected socket is moved onto the selected-handle storage plane; query failure, unexpected credential size, or UID/GID mismatch is a terminal setup failure;
- target seccomp authority is unchanged because peer inspection occurs entirely in trusted parent preparation and does not add target `getsockopt`, `socket`, or `connect`;
- a real `UnixListener` run pins the launcher's actual UID/GID, completes the exact 18A request/reply oracle, and retains the fresh-target-socket `ENOENT` host-path confinement proof;
- a separate real listener run deliberately declares the wrong UID with the real GID and requires public `run()` to return peer-credential `SetupFailed` before target execution;
- all Milestones 1–18A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: `SO_PEERCRED` is Linux kernel credential metadata captured for the connected peer. 19A matches UID/GID only; it does not provide cryptographic authentication, service-unique identity among processes sharing credentials, peer-PID enforcement, pathname alias/canonical-inode proof, SCM_RIGHTS mediation, or dynamic post-launch brokering.

### Milestone 19 promotion rule

19A is integrated; peer UID/GID matching is sealed at this bounded scope. Do not farm PID/credential field variants around the same `SO_PEERCRED` query. Promotion moves to a materially different executable authority/enforcement frontier. Supplementary-group isolation and delegated cgroup accounting remain blocked on their documented prerequisites.

## Milestone 20 — Landlock pathname topology authority

### Slice 20A — bounded directory/symlink/reparent mutation

**Status: complete on `main`.** Extends the existing 10B regular-file mutation envelope with an explicit topology authority bitset rather than implicitly widening every writable directory.

Acceptance evidence is executable:

- repeatable `landlock.path_topology_mutate = <absolute-sandbox-directory>` entries are bounded to 32 unique non-root paths and each must exactly match a declared `landlock.file_mutate` directory; topology policy therefore cannot introduce a writable path that did not already pass the regular-file mutation surface checks;
- the direct target reuses the same post-mount pinned Landlock path rule and adds only `LANDLOCK_ACCESS_FS_MAKE_DIR`, `REMOVE_DIR`, `MAKE_SYM`, and `REFER`; regular-file rights remain the 10B set and socket/FIFO/device creation rights are not granted;
- target syscall authority remains independently explicit: `mkdir`, `rmdir`, `symlink`, and `rename` are recognized by the x86_64 seccomp compiler but are not auto-added to any allowlist;
- a raw target creates and removes `/persist/allowed/newdir`, creates `/persist/allowed/newlink`, and renames `/persist/allowed/from/item` to `/persist/allowed/to/item`; host-side assertions prove exact renamed bytes and symlink target;
- equivalent mkdir/symlink operations beneath `/persist/denied` and a rename from the allowed subtree into that denied sibling must return exact Landlock `EACCES`, while the trusted parent proves no denied-side objects were created;
- the existing 10B file-mutation oracle and all Milestones 1–19A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 20A is a narrow augmentation of an existing `landlock.file_mutate` directory. It does not grant socket/FIFO/device creation, general metadata mutation, filesystem alias/canonicalization proof, rights revocation for pre-opened descriptors, or a general mount/filesystem transaction model.

### Milestone 20 promotion rule

After 20A integrates, seal this bounded pathname-topology slice. Do not farm additional topology syscall spellings that map to the same Landlock rights. Promote to a materially different capability such as a broader routed network model only with explicit topology/endpoint evidence, or revisit blocked cgroup/supplementary-group work only when its environment/namespace prerequisites become real.

## Milestone 21 — richer numeric syscall semantics

### Slice 21A — inclusive unsigned 64-bit seccomp argument ranges

**Status: complete on `main`.** Adds a materially different numeric predicate model beyond 5A masked equality without widening the syscall allowlist.

Acceptance evidence is executable:

- policy accepts `seccomp.range.<syscall>.<0..5> = <minimum>:<maximum>` using decimal or `0x` literals; a range only applies to an already-allowed syscall, launcher-critical `execveat`/`exit`/`exit_group` remain unconstrainable, argument indexes stay 0–5, `minimum` may not exceed `maximum`, and the full unconstrained `0..=u64::MAX` interval is rejected;
- masked-equality and range rules retain separate per-syscall/per-argument maps but share the existing aggregate 64-predicate ceiling; when both families constrain the same argument, they compose conjunctively rather than one overriding the other;
- Linux x86_64 cBPF compares each bound as unsigned high/low 32-bit words and performs the low-word comparison only when the high word equals that bound, implementing full-64-bit inclusive comparison before the syscall's final `ALLOW`;
- the raw `lseek` oracle uses range `0x00000000fffffff0..=0x0000000100000010` plus an even-value mask on the same argument: exact lower/interior-cross-boundary/upper values succeed, an in-range odd value receives `EPERM` from the mask, and even below/above plus a high-32-bit outlier receive `EPERM` from the range;
- the existing 5A masked-value oracle, Milestone 17A resource-usage mode, all Milestones 1–20A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.

Boundary: 21A compares one raw syscall argument against an unsigned inclusive interval. It does not provide signed ranges, relations between arguments, pointed-to/string/path inspection, arbitrary Boolean expressions, or pointer-target TOCTOU protection.

### Milestone 21 promotion rule

21A is sealed on `main`. Do not farm `<`, `<=`, `>`, `>=`, endpoint aliases, or more fixture values around the same cBPF comparison mechanism. A later seccomp slice must introduce materially different executable semantics.

## Milestone 22 — launcher-owned output enforcement

### Slice 22B — observed stdout total-output budget

**Status: complete on `main`.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.

Acceptance evidence is executable:

- optional `limit.stdout_total_bytes` is valid only with `stdio.stdout = capture`, is bounded to 1 byte–1 GiB, and requires the retained `stdio.stdout_capture_bytes` ceiling to be no larger than the total threshold;
- the host creates a private output-limit eventfd only when the policy requests this control, while the direct target closes its inherited control copy before untrusted execution;
- the capture reader counts bytes actually returned from the pipe, retains at most the existing memory ceiling, and signals PID 1 on the first read that makes observed stdout exceed the total threshold;
- PID 1 owns termination/reaping through its existing pidfd supervision path and publishes `ChildOutcome::OutputLimitExceeded`; output-limit readiness wins once overrun was already observed, while cancellation/deadline keep their existing natural-exit-first arbitration;
- a raw target forks one paused descendant and continuously writes stdout; with a 4 KiB observed budget and 1 KiB retained ceiling the run reports `OutputLimitExceeded`, returns exactly 1 KiB retained/truncated capture, and reports exactly one additional descendant reaped;
- the pre-existing no-total-budget stress test still drains/discards excess output and completes naturally, proving backwards-compatible capture semantics;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 22B is host-observed enforcement, not a precise kernel byte meter. Pipe-buffered bytes may already have been emitted beyond the configured threshold before the parent reads them. It does not throttle bandwidth or CPU, and it does not apply to stderr, inherited stdout, or redirected stdout.

### Milestone 22B promotion rule

22B is sealed on `main`. Do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. The supplementary-group frontier remains blocked by the current unprivileged user-namespace mapping semantics, so promotion moves to an independently executable kernel boundary.

## Milestone 23 — policy-owned time domain

### Slice 23A — descendant monotonic/boottime offsets

**Current verified candidate.** Adds an optional Linux child time namespace rather than another resource/output variant.

Acceptance evidence is executable:

- policy accepts only the all-or-nothing pair `time.monotonic_offset_seconds` / `time.boottime_offset_seconds`; each value is nonnegative and bounded to 31,536,000 seconds, and an all-zero pair is rejected;
- without the pair, the existing namespace flags and all prior execution behavior remain unchanged; with the pair, launcher setup adds `CLONE_NEWTIME`;
- offset records are fully prepared before the initial fork, then written to `/proc/self/timens_offsets` after UID/GID mapping and before namespace PID 1 is created, so no policy formatting/allocation is introduced into the post-fork setup path;
- Linux time-namespace child semantics keep the bootstrap in the parent clock domain while namespace PID 1 and the direct target inherit the configured child time namespace;
- a raw target explicitly granted `clock_gettime`, `write`, `execveat`, and `exit` emits binary `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` timespecs. With +3600/+7200 second policy, each value must land inside the trusted host-before/host-after window plus its declared offset; the host monotonic interval itself must remain unshifted;
- a five-second launcher-owned deadline is active in the same run, while all Milestones 1–22B regressions remain green; stable format/Clippy/full tests and the full Rust 1.74 suite pass on the exact implementation head.

Boundary: 23A does not alter `CLOCK_REALTIME`, support negative offsets, rate scaling/freezing, clock stepping, deterministic virtual time, or a general scheduler/time API. The launcher wall-clock deadline remains a relative supervision control rather than a target-visible absolute time claim.

### Milestone 23 promotion rule

After 23A integrates, seal basic Linux time-offset ownership. Do not farm more offset values or clock-read fixture variants. Promote to a materially different executable subsystem; revisit supplementary groups, routed host networking, or cgroup accounting only when their documented environment prerequisites change.

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
