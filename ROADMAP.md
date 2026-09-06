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

**Current verified candidate.** Adds a process-to-process authority boundary rather than another pathname, port, or brokered-socket variant.

Acceptance evidence is executable:

- policy accepts one optional `landlock.scope_signal = enabled|disabled`, defaults to disabled, and rejects invalid or duplicate declarations;
- enabling the scope requires Landlock ABI 6 or newer; older or unavailable kernels fail explicitly rather than silently dropping the requested restriction;
- the direct target adds only `LANDLOCK_SCOPE_SIGNAL` to the Landlock ruleset `scoped` field, preserves historical shorter ruleset structure sizes when the scope is unused, applies `no_new_privs`, and restricts itself before target seccomp and pinned exec;
- signal scoping does not grant signal authority through seccomp: `pidfd_open` and `pidfd_send_signal` are available only when the target policy explicitly names them;
- an unscoped raw target opens a pidfd for launcher-owned namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with signal scope enabled must receive exact `EPERM`; signal number 0 proves the permission boundary without delivering a signal or changing PID 1 state;
- all Milestones 1–12A regressions plus deterministic `run-json` and offline `check`/`check-json` CLI tests remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 13A is one Landlock signal scope with no per-process exception list. It does not grant signalling syscalls, replace PID-namespace lifecycle supervision, provide arbitrary signal forwarding/brokering, or claim Landlock scoping for abstract Unix sockets or another IPC class.

### Milestone 13 promotion rule

After 13A integrates, seal this signal-scope mechanism. Do not farm signal numbers, `kill`/`tgkill` aliases, or pidfd variants that repeat the same permission boundary. Promote only to a materially different IPC object boundary with executable positive/negative evidence or to another subsystem frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, address-aware or broader protocol network authority beyond the existing brokered sockets and Landlock TCP port envelope, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
