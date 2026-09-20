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

22B is sealed on `main`. Do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. Promote to another independent subsystem frontier with executable evidence.

## Milestone 23 — descendant time virtualization

### Slice 23A — policy-owned MONOTONIC/BOOTTIME offsets

**Status: complete on `main`.** Adds one optional Linux time namespace for subsequently created sandbox descendants without changing host clocks or the launcher's own clock view.

Acceptance evidence is executable:

- policy accepts the all-or-nothing pair `time.monotonic_offset_seconds` / `time.boottime_offset_seconds`, bounds each nonnegative value to 365 days, and rejects an all-zero pair;
- only when requested, launcher namespace setup adds `CLONE_NEWTIME`; after UID/GID mapping and before namespace PID 1 exists, bootstrap writes the declared `monotonic` and `boottime` offsets to `/proc/self/timens_offsets`;
- launcher-owned PID 1 and the direct target are created after offset installation and therefore enter the prepared child time namespace, while bootstrap and trusted host samples remain on the original clock view;
- a raw target explicitly granted `clock_gettime` emits `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`; the parent requires values within two seconds of host samples plus exact 3,600-second and 7,200-second configured offsets;
- static `manifest` / `manifest-json` output exposes the declared time-namespace authority without changing `runtime_preflight=false`;
- all prior sandbox/tooling regressions, stable rustfmt/Clippy/full tests, and the full Rust 1.74 suite are green on the exact integrated candidate.

Boundary: 23A does not virtualize `CLOCK_REALTIME`, set RTC/wall-clock time, support negative offsets or clock-rate scaling, or claim deterministic virtual scheduling.

### Milestone 23 promotion rule

After 23A integrates, seal this bounded clock-offset model. Do not farm more clock IDs, unit aliases, or offset spellings; promote only to a materially different executable frontier.

## Milestone 24 — policy observability tooling

### Slice 24A — static policy authority manifest

**Status: complete on `main`.** `manifest` and `manifest-json` validate policy fail-closed and emit deterministic declared-authority summaries without launching the sandbox or probing kernel support. Argument contents and environment values remain redacted, while authority-bearing filesystem, broker, Landlock, resource, output, seccomp, and time-namespace fields are reviewable.

Boundary: this is static observability, not runtime capability preflight or proof of effective kernel state.

### Slice 24B — conservative policy-specific host preflight

**Status: complete on `main`.** Adds non-destructive policy/host capability matching without claiming that partial probing proves the full sandbox launch path.

Acceptance evidence is executable:

- `preflight` / `preflight-json` validate the policy first, derive requested Landlock ABI plus deadline/stdout-budget/time-namespace requirements, and compare them with the existing host capability snapshot; `eventfd` is now also probed and surfaced because stdout-total enforcement depends on it;
- Slice 24B itself never launched the target, created sandbox namespaces, materialized the configured root, or mutated runtime filesystem state; machine and human reports explicitly carried `launch_attempted=false` and `launch_preflight_complete=false`;
- the mandatory launch core is first-class evidence state. The real probe path currently marks it `unprobed` with reason `mandatory_runtime_prerequisites_not_probed`, so green optional probes cannot produce a false-positive `satisfied` verdict;
- known unavailable represented prerequisites produce `incompatible` with exit status 3; any unprobed mandatory prerequisite produces `indeterminate` with exit status 4. Exit status 0 / `satisfied` is reserved for evaluator state where complete mandatory-core evidence is explicitly present, and is unreachable from the current production probe path;
- deterministic evaluator regressions prove Linux/x86_64 plus available Landlock/pidfd/timerfd/eventfd still remains indeterminate when the mandatory core is unknown, while an explicitly unavailable mandatory core is incompatible;
- CLI regressions use a deliberately nonexistent filesystem root and prove `preflight` leaves it absent while reporting the mandatory-core gap, preserving the distinction between static manifest, partial host preflight, and actual `run` evidence;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 24B is a conservative partial preflight, not a dry-run, launch simulator, or complete kernel compatibility oracle. It does not independently establish unprivileged user/mount/PID/network/IPC/UTS/time namespace creation, `openat2`/mount API behavior, descriptor sanitization, final filesystem identity, or target enforcement. Those mechanisms remain authoritative only when the real launch path executes successfully.

### Slice 24C — isolated mandatory launch-primitive probe

**Status: complete on `main`.** Adds positive compatibility evidence for a representative mandatory Linux setup core without relabeling that evidence as a complete launch preflight.

Acceptance evidence is executable:

- `preflight` / `preflight-json` fork a throwaway helper on Linux x86_64; the helper never receives the configured policy root, never executes the target, and confines its filesystem mutation to child-owned namespaces and a private tmpfs;
- the staged helper exercises the production-relevant primitive classes for user/mount/PID/network/IPC/UTS namespace creation, `setgroups`/UID/GID mapping, UTS hostname setup, private mount propagation, `openat2`, `open_tree`, recursive read-only `mount_setattr`, `move_mount`, an `EROFS` write oracle, PID-namespace PID1 creation, `chroot`/`chdir`, `close_range(..., CLOEXEC)`, all four rlimit syscalls, capability bounding/ambient/current-set reduction, `no_new_privs`, and seccomp-filter installation;
- the first failed stage plus errno is surfaced as an explicit unsupported probe result; a supported result requires a complete report and clean helper exit;
- a deterministic CLI regression uses a deliberately nonexistent `filesystem.root`, requires the helper to report `supported` / `stage=complete`, requires `configured_root_touched=false` and `target_executed=false`, and proves the configured root remains absent;
- the primary `mandatory_launch_core` state deliberately remains `unprobed`, `launch_attempted=false`, and `launch_preflight_complete=false`, so the real CLI remains `indeterminate` with exit status 4 rather than converting isolated primitive success into a false-positive `satisfied` verdict;
- the exact implementation candidate passed stable rustfmt/Clippy/full tests and the full Rust 1.74 suite.

Boundary: 24C is an isolated primitive-compatibility probe, not a launch dry-run or complete kernel compatibility oracle. It does not establish that the configured root exists or is pinnable, prove the exact configured executable/cwd/volume/Landlock/time/procfs path, reproduce the full launcher/PID1 orchestration, prove the production seccomp program for a policy, or prove successful `execveat`. Actual successful runtime execution remains authoritative for those properties.

### Slice 24D — configured filesystem anchor preflight

**Status: complete on `main`.** Adds a policy-specific read-only prerequisite probe for configured filesystem anchors without converting preflight into a launch dry-run.

Acceptance evidence is executable:

- production `preflight` / `preflight-json` independently probe `filesystem.root`, the sandbox executable and working directory, optional scratch and `/proc` targets, and any declared read-only/writable persistent-volume source and target anchors;
- host root/volume-source directories use `openat2(O_PATH|O_DIRECTORY|O_CLOEXEC)` with symlink/magic-link traversal forbidden, while sandbox-internal anchors are resolved beneath the opened root with `RESOLVE_BENEATH|RESOLVE_NO_XDEV|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS`;
- the executable must additionally `fstat` as a regular file with at least one execute bit, mirroring the corresponding parent-preparation prerequisite without executing it;
- the configured-filesystem probe creates no namespaces or mounts, writes no configured state, and never executes the target; its machine report explicitly carries `read_only=true`, `namespaces_created=false`, and `target_executed=false`;
- a deliberately nonexistent root now yields `incompatible` / exit status 3 with `stage=root_open` and `ENOENT`, while the independent 24C isolated helper can still report `supported` and the missing path remains absent;
- a positive fixture resolves executable/cwd/scratch/proc plus both volume source/target pairs, preserves fixture bytes and empty writable target state, reports the configured-filesystem probe `supported`, but the overall preflight remains `indeterminate` / exit status 4 because `mandatory_launch_core` is still `unprobed`;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 24D is point-in-time read-only path/type/mode prerequisite evidence. It does not pin these descriptors for a later launch, prove cross-time inode identity, inspect the final post-mount Landlock tree, establish time/procfs mount success, reproduce PID1/target orchestration, validate the exact production seccomp program, or prove successful `execveat`.

### Slice 24E — configured time-namespace offset preflight

**Status: complete on `main`.** Closes the separately requested time-namespace prerequisite without converting preflight into target execution or a privileged launch simulation.

Acceptance evidence is executable:

- when both policy time offsets are requested, `preflight` / `preflight-json` fork a throwaway helper that receives only those numeric offsets; the helper never receives the configured root and never executes the target;
- the helper mirrors the production permission sequence with `unshare(CLONE_NEWUSER | CLONE_NEWTIME)`, `setgroups=deny`, UID/GID mapping, then writes exact `monotonic <seconds> 0` and `boottime <seconds> 0` entries to `/proc/self/timens_offsets`;
- because the caller of `unshare(CLONE_NEWTIME)` remains on the original clock view while subsequently created descendants enter the prepared child time namespace, the helper brackets host `CLOCK_MONOTONIC` / `CLOCK_BOOTTIME` immediately before and after one observer descendant reads both clocks; subtracting each declared offset from the observer value must fall inside the matching host-clock bracket;
- the probe reports its exact first failed stage plus errno. A requested unsupported/denied time prerequisite is `incompatible`; a complete observer oracle reports `supported`;
- machine evidence records `isolated_helper=true`, `configured_root_touched=false`, `target_executed=false`, and the exact requested offset pair. Existing CLI regression coverage requires even 1/2-second offsets to pass the strict bracket oracle rather than relying on a broad timing tolerance;
- the primary `mandatory_launch_core` deliberately remains `unprobed`, so real production preflight with otherwise positive 24C/24D/24E evidence remains `indeterminate` / exit status 4 and keeps `launch_attempted=false` / `launch_preflight_complete=false`;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 24E proves that the current host can create an isolated user/time namespace and install/observe the exact requested MONOTONIC/BOOTTIME offsets in a descendant. It does not prove private procfs setup, the complete namespace/mount/PID1/target orchestration, final filesystem/Landlock state, the exact production seccomp program, or successful `execveat`; actual runtime execution and enforcement receipts remain a separate evidence class.

### Milestone 24 promotion rule

24A–24E are sealed on `main`. Do not farm clock IDs, offset values, path aliases, errno cases, or duplicate isolated probes. Another preflight slice is justified only if it closes a materially different mandatory prerequisite without turning preflight into a privileged/destructive launch simulation; otherwise promote to a different executable authority/enforcement frontier. Milestone 25A remains a separate evidence class because it records stages positively observed during an actual run.

## Milestone 25 — runtime enforcement evidence

### Slice 25A — post-attempt enforcement receipt

**Status: complete on `main`.** Adds structured positive evidence for launcher-owned setup stages that actually completed during a sandbox invocation.

Acceptance evidence is executable:

- `RunReport` gains an `EnforcementReceipt` covering base namespaces, optional time-namespace offsets, hostname, private mount propagation, read-only root, chroot, FD sanitization, all configured rlimits, capability reduction, `no_new_privs`, optional Landlock restriction, and seccomp installation;
- each bit is published only after the corresponding kernel/setup stage returns success through the existing shared launch-state channel; unknown bits, impossible predecessor progressions, unrequested optional bits, and missing requested optional predecessors fail closed during receipt decoding;
- early launcher-owned termination may therefore yield a valid partial receipt. A false field means only `not positively observed before termination`, not `unsupported`, `disabled`, or `failed`;
- the receipt intentionally does not record successful `execveat`: a deadline/cancellation/output-limit control path can win after seccomp is installed but before the non-returning exec syscall, so claiming exec success from setup progress would be unsound;
- time-namespace and Landlock integration tests require their respective positive receipt bits after successful real runs, while receipt-decoder unit tests reject corrupted/impossible progressions;
- `run-json` serializes the complete receipt in deterministic field order, and the real example-policy CLI regression requires the expected true/false stage set rather than merely checking JSON shape;
- Milestone 24B preflight remains distinct and non-destructive, while 25A is post-attempt evidence from the actual run path; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact candidate.

Boundary: 25A is positive setup-stage telemetry, not a cryptographic attestation, kernel-state snapshot, complete conformance proof, successful-exec receipt, or guarantee that a stage remains effective after its observation point. It does not turn false bits into negative capability claims.

### Milestone 25 promotion rule

After 25A integrates, seal this receipt schema at the current stage granularity. Do not farm aliases, duplicate per-syscall bits, or relabel the receipt as attestation/conformance. Promote to a materially different executable authority/enforcement frontier unless a new receipt field corresponds to a genuinely new kernel boundary.

## Milestone 26 — PID namespace observability surface

### Slice 26A — private procfs with PID1 control-descriptor closure

**Status: complete on `main`.** Adds an optional procfs view backed by the sandbox PID namespace while preserving launcher-owned PID 1 control authority.

Acceptance evidence is executable:

- policy accepts `filesystem.proc = enabled|disabled`, defaults to disabled, requires an existing `/proc` directory beneath the selected root, and rejects overlap with executable/working directory, private scratch, or persistent-volume targets;
- after the process becomes namespace PID 1 and before the direct target is forked, PID 1 mounts a fresh procfs at `/proc` with `MS_NOSUID|MS_NODEV|MS_NOEXEC`;
- PID 1 immediately sets `PR_SET_DUMPABLE=0`; failure is a distinct fail-closed launch phase, and the `private_procfs` enforcement-receipt bit is published only after both the procfs mount and PID1 descriptor-access hardening succeed;
- the original raw oracle proves `/proc/1` and `/proc/2` exist while a trusted host PID path is `ENOENT`, and the host-side mountpoint returns to its empty fixture state after the private mount namespace exits;
- a separate control-plane raw oracle runs with an unsignalled `CancellationToken` plus a five-second deadline, preserves `/proc/1/status` readability, and requires exact `EACCES` when opening `/proc/1/fd`; natural `Exited(0)` still wins, proving the hardening composes with real cancellation/deadline supervision instead of disabling that lifecycle path;
- all prior sandbox/tooling regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact candidate.

Boundary: 26A is PID-namespace proc observability with explicit closure of PID1's proc descriptor-table route. It does not claim that PID1 cmdline/status metadata is secret, hide the existence of PID1, implement arbitrary procfs mount options, provide a per-process visibility policy, or prevent a sufficiently privileged external host process from observing the sandbox.

### Milestone 26 promotion rule

After 26A integrates, seal the private-procfs/PID-visibility slice. Do not farm proc mount-option aliases or additional metadata files. Promote to a materially different executable authority/enforcement frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their prerequisites change.

## Milestone 27 — policy/runtime assurance tooling

### Slice 27C — conservative static authority delta

**Status: complete on `main`.** The standalone `security-lab-authority-delta` validates both policies fail-closed, classifies modeled declaration changes as unchanged/reduced/widened/incomparable, and uses distinct CI exit codes without launching the sandbox. Ambiguous endpoint/path substitutions and mixed widen/reduce changes remain incomparable rather than being guessed safe.

Boundary: 27C is static declaration analysis. It explicitly does not claim effective kernel-state comparison, filesystem alias proof, theorem-proved implication, or a code-review waiver.

### Slice 27D — runtime receipt completeness gate

**Status: complete on `main`.** The standalone `security-lab-runtime-receipt-gate` performs a real `run_report`, derives the receipt-modeled enforcement stages required by the validated policy, rejects missing required stages and unexpected optional evidence, and preserves distinct runtime/setup failure reporting.

Boundary: 27D checks only the current enforcement-receipt model. It explicitly does not claim full-policy attestation, successful exec, continued kernel-state effectiveness, or cryptographic/conformance certification.

### Milestone 27 promotion rule

27C–27D are sealed tooling slices. Do not farm comparator status aliases, receipt-field aliases, or extra output encodings. Future 27-series work must add a materially different executable authority/enforcement boundary or a genuinely stronger evidence model with implementation-backed semantics.

## Milestone 29 — negative seccomp argument predicates

### Slice 29A — forbidden masked bit patterns

**Status: complete on `main`.** Adds a negative raw-argument predicate that cannot be expressed by the existing single conjunctive masked-equality/range rule families without enumerating allowed alternatives.

Acceptance evidence is executable:

- policy accepts `seccomp.deny_mask.<syscall>.<0..5> = <mask>:<value>` only for a syscall already present in `seccomp.allow`; zero masks, values with bits outside the mask, invalid argument indices, launcher-critical syscalls, duplicates, and aggregate predicate counts above the existing ceiling fail closed;
- Linux x86_64 cBPF evaluates the complete raw 64-bit selected argument and returns seccomp `EPERM` only when every masked bit matches the forbidden value; a non-match continues through the remaining conjunctive constraints and can reach `ALLOW`;
- a raw `mmap` oracle declares `mask=0x6,value=0x6` on protection argument 2, proves RW and RX anonymous mappings succeed, and requires exact `EPERM` for RWX;
- a second raw `lseek` oracle declares `mask=0xffffffff00000001,value=0x0000000200000001`, proves a low participating-bit mismatch and a high-word mismatch each continue successfully, and requires exact `EPERM` only when both 32-bit halves match the forbidden 64-bit pattern;
- the static authority manifest emits forbidden masks deterministically, and the authority-delta checker classifies adding the restriction as `reduced` and removing it as `widened` rather than silently treating the new predicate as unchanged;
- all prior seccomp, sandbox, manifest, delta, preflight, receipt, and runtime regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 29A is one additional numeric predicate family, not pointer/string inspection, signed comparison, cross-argument relations, a general Boolean expression language, or pathname/socket-address content filtering. Rules still only narrow syscalls already named by `seccomp.allow`.

### Milestone 29 promotion rule

After 29A integrates, do not farm inverse-equality aliases, extra masks, W^X-specific names, or Boolean spelling variants. A later seccomp slice must add materially different executable semantics with raw positive/negative evidence; otherwise promote to another independent authority/enforcement frontier.

## Milestone 30 — ephemeral filesystem mutation

### Slice 30A — bounded copy-on-write root

**Status: complete on `main`.** Adds one materially different filesystem authority mode: policy may explicitly widen the default recursively read-only root into bounded, private, ephemeral target-side mutation without granting host-lower write-through authority.

Acceptance evidence is executable:

- `filesystem.cow_root_bytes` is optional and fail-closed validated from 4096 bytes through 1 GiB; absence preserves the existing read-only-root behavior;
- the launcher pins/revalidates the configured root, recursively clones and marks the lower tree read-only, then for COW mode creates a size-bounded private tmpfs backing mount, `upper`/`work` directories, and an OverlayFS merged mount through `fsopen`/`fsconfig`/`fsmount`, finally attaching it with `move_mount`; every construction phase has explicit launch-error reporting and no writable-host-root fallback;
- the backing tmpfs receives `nosuid,nodev,noexec`; the project does not claim that the merged OverlayFS root itself is globally `noexec`;
- a raw target modifies, creates, and removes paths in the merged root while the trusted parent proves the original lower marker remains byte-for-byte unchanged and no new file persists across two independent runs;
- a separate 64 KiB COW-budget oracle writes real 4 KiB chunks until exact `ENOSPC`, fails if successful payload bytes exceed the declared ceiling, and proves the budget-test file does not persist into the host lower tree;
- the existing private scratch mount composes above the COW root, and an explicit read-only persistent volume attached afterward still returns `EROFS` on mutation and leaves its host source unchanged;
- the runtime enforcement receipt publishes `copy_on_write_root` only after final OverlayFS attachment and rejects simultaneous `readonly_root`; the runtime receipt-completeness gate binds the required final-root bit to policy;
- static preflight reports requested COW support as `unprobed` because the real user/mount namespace is required, the authority manifest records its byte budget, and authority-delta classifies enabling or enlarging COW authority as widening;
- fixture dispatch selectors are regression-checked for uniqueness; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 30A is ephemeral root mutation only. It does not provide persistence, export/commit, snapshots, copy-on-write image management, transaction/atomicity/durability semantics, immutable/cryptographic lower-tree identity, or generalized OverlayFS policy.

### Milestone 30 promotion rule

30A is sealed on `main`; do not farm byte-ceiling variants, extra upper/work directory names, or repeated mutation path oracles. Promotion requires materially different executable semantics.

## Milestone 31 — bounded ephemeral filesystem change export

### Slice 31A — bounded post-run COW diff

**Status: complete on `main`.** Adds a launcher-owned, bounded change-export capability for the existing ephemeral COW root without turning the private upper layer into persistent host state.

Acceptance evidence is executable:

- `filesystem.cow_diff_bytes` is optional, valid only with `filesystem.cow_root_bytes`, and fail-closed bounded; an undersized export budget returns a setup failure rather than a truncated successful `CowDiff`;
- namespace PID 1 retains the private upper-tree descriptor outside target authority and exports only after the direct target has terminated and remaining descendants have been killed/reaped, so the walk observes converged post-run COW state;
- COW mount construction explicitly fixes `metacopy=off` and `redirect_dir=nofollow` instead of inheriting host OverlayFS defaults, keeping supported upper records self-contained for the exporter rather than relying on omitted metacopy/redirect xattrs;
- the raw COW oracle replaces an existing file, creates `/cow-new` with mode `0600`, chmods an unchanged lower file to `0640`, requires exact `EXDEV` for lower/merged directory rename, removes an existing child, and leaves the trusted host lower tree content/mode/topology unchanged across independent runs; the public `RunReport` regression requires exact replaced/created bytes, the metadata-only file's original bytes plus exported `0640` mode, the exact new-file `0600` mode, and the removal record;
- supported canonical records cover regular-file upserts, directory existence/mode, symlink targets, whiteout removals, and opaque-directory topology; regular files and directories preserve Unix permission bits as `st_mode & 0o7777`;
- `run-json` exposes the same file/directory permission modes numerically, with a deterministic unit regression proving `0600`/`0750` serialization rather than asking a consumer to guess creator umask;
- unsupported upper-layer object kinds fail closed with `EOPNOTSUPP`, and the canonical encoding budget includes the exported mode metadata;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 31A is a bounded content/topology/permission-mode export for supported upper-layer object classes under the explicitly pinned `metacopy=off` / `redirect_dir=nofollow` COW semantics. It does not preserve UID/GID ownership, timestamps, other xattrs/ACLs, hard-link identity, device/FIFO/socket nodes, or filesystem aliases; it does not supply a replay/commit executor, transaction/atomicity/durability semantics, persistent image lifecycle, or cryptographic snapshot integrity.

### Milestone 31 promotion rule

31A is sealed on `main`; do not farm more record tags or metadata fields unless they close a demonstrated replay/integrity boundary. Promotion is now a materially different COW lifecycle capability.

## Milestone 32 — COW diff replay lifecycle

### Slice 32A — atomic new-snapshot replay

**Status: complete on `main`.** Adds a bounded host-side apply path for the canonical 31A diff without mutating the trusted base directory in place.

Acceptance evidence is executable:

- `apply_cow_diff_atomic(base, destination, diff, limits)` accepts only absolute trusted host paths, requires a previously absent destination, validates canonical diff path/order/record shape plus exact `encoded_bytes`, and rejects malformed/root-replacement inputs before staging mutation;
- replay work is fail-closed bounded by explicit `CowDiffApplyLimits`: canonical diff plus copied regular-file/symlink bytes consume the byte budget, while base nodes plus diff records consume the node budget;
- the launcher-side helper copies supported base regular files/directories/symlinks into a private sibling staging directory and rejects unsupported node kinds instead of silently dropping them;
- every diff parent is resolved fd-by-fd with `O_DIRECTORY|O_NOFOLLOW`; a copied symlink used as a parent therefore fails rather than redirecting a replay write outside staging;
- replay implements regular-file upsert with bytes/mode, directory ensure/mode, symlink replacement, recursive removal, and opaque-directory clearing; supported directory modes are restored after topology mutation;
- success publishes the completed tree with one Linux `renameat2(RENAME_NOREPLACE)` and no fallback to a non-atomic overwrite path;
- deterministic tests prove a mixed replay preserves the base while producing exact replacement/new-file bytes, modes, removals, opaque-directory semantics and symlink target; a symlink-parent escape attempt fails with no outside mutation or destination publication; and a byte-budget failure leaves the base unchanged, destination absent, and staging cleaned;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation candidate.

Boundary: 32A provides failure-atomic publication of a **new** snapshot up to the final rename boundary. It does not overwrite an existing destination, fsync data/metadata, provide crash-recovery or durability guarantees, preserve UID/GID/timestamps/xattrs/ACLs/hard links/special nodes, prove cryptographic identity of the base/diff, defend against hostile concurrent host writers, or claim that preserved symlink objects are confinement-safe for later consumers that choose to follow them.

### Milestone 32 promotion rule

32A is sealed on `main`; do not farm replay path aliases, extra failure codes, or duplicate record variants. Promotion is now stronger snapshot identity/integrity evidence or another independent executable authority/enforcement frontier; any durability or overwrite-transaction phase requires its own fsync/crash semantics and deterministic evidence.

## Milestone 33 — canonical snapshot identity

### Slice 33A — bounded SHA-256 identity for supported snapshot trees

**Status: complete on `main`.** Adds deterministic cryptographic content identity for the exact regular-file/directory/symlink tree model already preserved by the 31A/32A lifecycle, without claiming authenticity or a broader metadata snapshot.

Acceptance evidence is executable:

- `snapshot_sha256(root, limits)` requires an absolute trusted host root and exposes `SnapshotIdentityLimits` with fail-closed byte and node ceilings;
- one versioned/domain-separated canonical stream hashes sorted raw path bytes plus node type; directories commit to Unix permission bits, regular files commit to permission bits plus exact length/content, and symlinks commit to exact target bytes;
- traversal opens child directories and regular files without following symlinks, verifies opened object type, detects regular-file shrink/growth across the committed size/read boundary, and rejects unsupported special-node kinds instead of omitting them;
- two independently materialized equivalent fixture trees produce the exact fixed SHA-256 `b3ff412811f2f9298015ab9320339ab3d35bd53a531b6b4e645ae8656d3c1c85`, with 5 accounted nodes and 140 canonical bytes;
- independent mutations to regular-file content, permission mode, symlink target, and topology each produce a different identity;
- a 32A diff replay leaves the trusted base identity unchanged and produces a destination identity exactly equal to an independently materialized expected tree;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation candidate.

Boundary: 33A is canonical SHA-256 identity evidence for the supported tree model. It is not a signature, MAC, trusted provenance statement, or automatic replay precondition; it omits UID/GID ownership, timestamps, xattrs/ACLs, hard-link identity, and special nodes, and it does not establish a point-in-time snapshot against hostile concurrent host writers or any durability/crash guarantee.

### Milestone 33 promotion rule

33A is sealed on `main`; do not farm hash-algorithm names, vector variants, or metadata aliases that repeat the same identity model. The next COW-lifecycle capability must consume identity as a real executable precondition or add independently evidenced provenance/authenticity.

## Milestone 34 — replay precondition binding

### Slice 34A — expected-base identity gate

**Status: complete on `main`.** Binds the 32A new-snapshot replay path to one explicitly supplied 33A canonical base identity without changing the legacy unbound replay API.

Acceptance evidence is executable:

- `apply_cow_diff_atomic_with_expected_base(base, destination, diff, expected_base, identity_limits, replay_limits)` requires one explicit expected `SnapshotIdentity` plus independent bounded identity/replay work ceilings;
- replay limits validate first, then the current canonical SHA-256 of `base` is computed with the 33A traversal before any destination-parent inspection or replay staging creation; identity-scan failures remain explicit base-identity check failures;
- a digest mismatch returns distinct `BaseIdentityMismatch { expected, actual }` and does not enter the 32A replay path;
- the deterministic mismatch regression captures a valid base identity, mutates the base, and deliberately chooses a destination beneath a nonexistent parent. `BaseIdentityMismatch` must win instead of destination-parent lookup, while the parent/destination stay absent and no `.security-lab-cow-apply-*` staging entry appears;
- a matching expected identity continues through the existing failure-atomic replay, returns the exact checked base identity plus normal replay accounting, publishes the expected changed snapshot, and leaves the trusted base unchanged;
- the original `apply_cow_diff_atomic` remains available with unchanged unbound semantics; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation candidate.

Boundary: 34A is an optimistic precondition for a trusted/stable base. It does not freeze, lock, or snapshot the base between identity calculation and replay, so it does not close a hostile concurrent-writer race. It is not a signature, MAC, provenance/authenticity statement, attestation, durability/crash-recovery mechanism, or overwrite transaction.

### Milestone 34 promotion rule

34A is sealed on `main`; do not farm expected-digest aliases or mismatch variants. The current promotion is 35A, which closes the check-to-replay mis-binding for the actual private replay input by requiring the completed materialized canonical identity to match before diff application. Stronger later work must add independently evidenced authenticity/provenance, a true frozen/serialized source snapshot, or separately specified durability/versioned-publication semantics.


## Milestone 35 — materialized replay-input binding

### Slice 35A — verified materialized base

**Status: complete on `main`.** Binds expected-base replay to the exact supported metadata and bytes materialized into the private staging tree before diff application, rather than trusting only the earlier live-source scan.

Acceptance evidence is executable:

- the existing 34A early gate remains first: replay limits validate, then `snapshot_sha256(base, identity_limits)` must match before destination-parent inspection or staging creation, preserving fail-fast stale-base behavior;
- after that gate, the 32A base-copy walk derives the same 33A canonical stream in sorted traversal order while it materializes staging, using opened directory/regular-file permission modes, exact symlink targets, and the exact regular-file bytes written to staging;
- independent 33A identity byte/node ceilings remain fail-closed during materialization; opened regular files commit to one observed size and fail closed if they shrink or grow across the copy boundary;
- the completed materialized `SnapshotIdentity` must match the caller-supplied expectation before any diff entry is applied. Mismatch returns `BaseIdentityMismatch`, removes the private staging tree, and publishes no destination;
- successful checked replay returns the materialized replay-input identity plus the existing bounded replay accounting; the unbound `apply_cow_diff_atomic` API remains available with unchanged semantics;
- a deterministic private regression models a source mutation after the first gate, requires materialized mismatch and zero staging residue, while the public 34A matching/early-mismatch regressions and the 33A fixed canonical SHA-256 vector remain active;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 35A closes the 34A identity-check-to-replay **mis-binding for the input that is actually replayed**: diff application cannot begin unless the completed private materialization reproduces the expected supported-tree identity. It does not freeze, lock, or serialize the live source tree as a point-in-time filesystem snapshot while copying, does not add authenticity/provenance/attestation, and does not add durability/crash recovery or versioned publication. The identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes.

### Milestone 35 promotion rule

After 35A integrates, do not farm second-hash placements or identity API aliases. A stronger COW-lifecycle phase must add independently evidenced authenticity/provenance, a real frozen/serialized source snapshot, or separately specified durability/versioned publication. A separate architectural promotion may instead move to launcher-owned dynamic host-local IPC mediation; target-side self-inspection must not be relabeled as broker enforcement.

## Milestone 36 — keyed canonical snapshot authentication

### Slice 36A — HMAC-SHA256 snapshot authentication

**Status: complete on `main`.** Adds a symmetric authentication property over the existing bounded canonical snapshot identity rather than another digest placement or replay gate.

Acceptance evidence is executable:

- `snapshot_hmac_sha256(root, key, limits)` and `verify_snapshot_hmac_sha256(root, key, expected_tag, limits)` require an exact 32-byte caller-supplied key and reuse the bounded 33A canonical snapshot scan;
- the tag is HMAC-SHA256 using pinned `hmac` 0.12.1 and `sha2` 0.10.9, over the versioned domain `security-lab-snapshot-hmac-sha256-v1\0` plus canonical SHA-256, `encoded_bytes` little-endian `u64`, and `nodes` little-endian `u64`;
- verification uses the HMAC implementation's constant-time tag comparison path and reports `AuthenticationFailed` without exposing a computed replacement tag;
- the existing 33A reference tree with key bytes `00..1f` produces fixed tag `70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743`; the unchanged tree verifies, while content mutation and a distinct 32-byte key fail authentication;
- identity byte/node budget exhaustion remains a distinct fail-closed `SnapshotIdentityError` path before tag comparison;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 36A is symmetric key-possession authentication for the existing canonical identity model. It is not a digital signature, public-key provenance, attestation, certificate/key-distribution system, key-generation/storage/rotation mechanism, or guarantee of caller key entropy. It does not freeze the live source tree, extend the identity metadata model, or add durability/crash recovery.

### Milestone 36 promotion rule

After 36A integrates, do not farm tag encodings, key-length aliases, MAC algorithm names, or extra verification wrappers. A stronger authentication/provenance phase must add independently evidenced public-key identity/signature semantics or a real trusted key lifecycle; otherwise promote to a frozen/serialized source snapshot, durability/versioned publication, or launcher-owned dynamic host-local IPC mediation.

## Milestone 37 — public-key canonical snapshot signatures

### Slice 37A — Ed25519 signature over canonical snapshot identity

**Status: complete on `main`.** Adds independently verifiable public-key signature semantics to the existing bounded canonical snapshot identity rather than another symmetric tag encoding.

Acceptance evidence is executable:

- `sign_snapshot_ed25519(root, signing_key, limits)` accepts exactly one caller-supplied 32-byte Ed25519 signing seed, reuses the bounded 33A canonical scan, and returns the checked `SnapshotIdentity`, corresponding 32-byte public key, and 64-byte signature;
- the signature message is unambiguous and versioned: `security-lab-snapshot-ed25519-v1\0` followed by canonical SHA-256, `encoded_bytes` little-endian `u64`, and `nodes` little-endian `u64`;
- `verify_snapshot_ed25519(root, public_key, signature, limits)` independently recomputes the bounded identity, rejects malformed public keys, and uses pinned `ed25519-dalek` 2.1.1 `verify_strict` rather than permissive verification;
- backend evidence reproduces RFC 8032 test vector 1; deterministic same-seed/same-identity signing reproduces the same evidence; content mutation, a different public key, and signature-bit mutation each fail verification;
- public-API integration evidence proves an Edwards-identity weak key is decoded/classified as weak and that the classic `R=B, S=1` universal-forgery shape is rejected by the snapshot verification path;
- identity byte/node budget failures remain distinct `SnapshotIdentityError` failures rather than being converted into signature mismatch;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite must remain green on the exact candidate head.

Boundary: 37A proves signature validity under the exact supplied public key for the existing canonical identity tuple. It does not provide certificate/trust-store semantics, signer provenance beyond possession of the corresponding secret key, hardware/remote attestation, key generation/storage/rotation/revocation, immutable point-in-time source capture, a broader metadata identity model, or durability/crash recovery.

### Milestone 37 promotion rule

37A is sealed on `main`; do not farm key encodings, signature text formats, algorithm aliases, or extra verify wrappers. A stronger provenance phase requires an independently specified trust/key lifecycle or attestation model. The active promotion is instead a serialized snapshot artifact with executable round-trip/publication evidence.

## Milestone 38 — bounded serialized snapshot artifact

### Slice 38A — deterministic canonical snapshot archive

**Status: complete on `main`.** Freezes the supported snapshot object model into bounded deterministic bytes and can materialize those bytes into a new failure-atomically published host tree.

Acceptance evidence is executable:

- `serialize_snapshot_archive` walks the supported Linux tree fd-relatively, preserves directory/regular-file permission bits and exact symlink target bytes, rejects unsupported node kinds, and enforces explicit archive-byte, canonical-identity-byte, and node ceilings;
- the completed archive is reparsed before success, and `snapshot_archive_identity` derives the existing Milestone 33A canonical identity from archive records alone without consulting the live tree;
- parser canonicality requires root-first records, strictly increasing raw path order, directory-before-child topology, safe absolute snapshot-relative paths, bounded symlink targets, exact declared node count, and no trailing bytes;
- two captures of one unchanged tree produce byte-identical archives, archive identity equals an independent live-tree `snapshot_sha256`, later source mutation diverges from but cannot alter the captured bytes, and materialization reproduces the captured contents, modes, symlink target, and canonical identity;
- `materialize_snapshot_archive_atomic` validates the entire artifact before mutation, builds a private sibling staging tree through fd-relative non-symlink parent resolution, restores supported modes, and publishes only with `renameat2(RENAME_NOREPLACE)`; malformed/budget failures, an existing destination, and a symlink-parent archive leave no published destination or staging residue;
- exact candidate stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 38A freezes the bytes returned after a successful capture, not an atomic point-in-time view against a hostile concurrent source writer. Publication is failure-atomic at the rename boundary but not `fsync` durability/crash consistency. The archive intentionally omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes, and preserved symlink objects are not a confinement guarantee for later consumers that follow them.

### Milestone 38 promotion rule

38A is sealed on `main`; do not farm archive encodings, filename suffixes, compression wrappers, or duplicate identity helpers. The active promotion is authenticated use of the frozen artifact rather than another serialization variant.

## Milestone 39 — authenticated snapshot archive publication

### Slice 39A — Ed25519 verification before atomic publication

**Status: complete on `main`.** Composes the existing 37A strict public-key signature verifier with the 38A frozen archive/materialization path so unauthenticated archive bytes cannot reach destination inspection or staging.

Acceptance evidence is executable:

- `materialize_snapshot_archive_ed25519_atomic` validates the complete bounded/canonical archive and derives its 33A identity directly from artifact records before signature verification;
- the exact caller-supplied 32-byte public key and 64-byte signature are checked by the existing `ed25519-dalek` strict verifier over the same versioned 37A identity message;
- only successful verification may enter 38A fd-relative staging and `renameat2(RENAME_NOREPLACE)` publication;
- an archive signed before later live-source mutation still publishes the original captured bytes and reproduces the captured canonical identity;
- a wrong public key fails before a deliberately missing destination parent is inspected, while a parse-valid archive content tamper fails verification with no destination or staging residue;
- existing 37A strict-verification security regressions and all 38A malformed/budget/publication regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite remain green.

Boundary: 39A proves signature validity under the exact supplied public key for the frozen supported archive semantics. It does not establish public-key ownership/provenance, certificate or trust-store policy, key generation/storage/rotation/revocation, remote/hardware attestation, authenticated transport, `fsync` crash durability, overwrite/version-retention semantics, or a broader metadata/object model.

### Milestone 39 promotion rule

39A is sealed on `main`; the bounded verified publication CLI is integrated tooling over the same gate and does not widen the trust model. Do not farm signature encodings, duplicate verify wrappers, key-file spelling, or extra tamper vectors that exercise the same gate.

## Milestone 40 — authenticated content-addressed snapshot storage

### Slice 40A — immutable identity-addressed frozen archive objects

**Status: complete on `main`.** Adds a bounded host-local object lifecycle for already-authenticated frozen archives rather than another signature or publication wrapper.

Acceptance evidence is executable:

- `store_snapshot_archive_ed25519_atomic(store_root, archive, public_key, signature, limits)` lexically validates a trusted absolute store root, fully validates the canonical archive under the existing byte/identity/node limits, and strictly verifies its Ed25519 evidence before store filesystem inspection or mutation;
- the deterministic object address encodes the complete canonical identity tuple `(sha256, encoded_bytes, nodes)`, preserving the accounting covered by the signature message rather than treating the digest alone as the whole identity;
- insertion creates a private sibling temporary object, writes the exact archive bytes, sets mode `0444`, and publishes only with Linux `renameat2(RENAME_NOREPLACE)`; there is no overwrite fallback;
- an existing object at the same address is accepted as an idempotent deduplication hit only if it is a regular file with no write bits, has the exact archive length, and matches every archive byte. Any mismatch is `ObjectConflict`;
- `materialize_snapshot_store_object_ed25519_atomic` opens the exact requested address, enforces the archive byte ceiling, re-derives the canonical identity and requires an exact tuple match, re-verifies the supplied Ed25519 signature, and only then delegates to the existing failure-atomic authenticated materialization path;
- deterministic integration evidence proves first insert plus dedup, materialization of frozen bytes after the live source changes, wrong-key failure before a deliberately missing store root is inspected, and rejection of a same-size parse-valid stored-object tamper with no destination publication;
- rustfmt, Clippy with `-D warnings`, the full stable suite, and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 40A is a trusted host-local bounded object store. Mode `0444` is an API immutability convention, not protection from a privileged writer controlling the store root. 40A by itself does not provide success-return `fsync` durability, trust-store or key provenance/rotation/revocation, garbage collection/indexing, version retention, remote/distributed CAS, replication, or hostile concurrent store-writer protection.

### Slice 40B — success-return durable content-addressed publication

**Status: complete on `main`.** Adds a real durability barrier to the authenticated 40A object lifecycle rather than another content-address or tamper variant.

Acceptance evidence is executable:

- `store_snapshot_archive_ed25519_durable` first executes the existing bounded archive validation, strict Ed25519 verification, no-replace publication, and exact-object dedup path; no unauthenticated archive gains a durability shortcut;
- after the 40A result, Linux code reopens the exact identity-addressed object beneath the store, checks that it is a regular read-only file with the expected archive length, then requires `fsync` success in order on the object, the `objects/` directory, and the store root before returning success;
- a normal new insertion crosses those barriers and remains materializable through the existing identity re-derivation plus Ed25519 verification path;
- a child test process installs a narrow seccomp filter that returns `EPERM` only for `fsync`; the durable API observes that real syscall failure at the object barrier and fails rather than silently acknowledging durability;
- after that deliberately ambiguous state, where the 40A rename may already have published the exact object but 40B returned no durable acknowledgement, retrying the same authenticated archive converges through byte-for-byte deduplication with `inserted = false`, reruns all durability barriers, and remains materializable;
- rustfmt, Clippy with `-D warnings`, the complete stable suite, and the complete Rust 1.74 suite are green on the exact implementation head.

Boundary: 40B claims only success-return durability under the local Linux kernel/filesystem `fsync` contract. It does not claim a physical power-loss experiment, storage-device cache behavior beyond that contract, a write-ahead journal, transactional multi-object commit, stale temporary-object recovery/scavenging, garbage collection, remote replication, trust/key lifecycle, or protection from a privileged hostile writer controlling the store root.

### Milestone 40 promotion rule

40B is sealed on `main`; do not farm additional `fsync` orderings, filenames, or repeated failure aliases. The project is promoted to an independent trust/key lifecycle boundary.

## Milestone 41 — explicit snapshot trust lifecycle

### Slice 41A — key identity, policy provenance, rotation, and revocation

**Status: complete on `main`.** Adds an explicit authorization layer above the existing strict Ed25519 verifier and durable content-addressed store instead of treating an arbitrary caller-supplied public key as the whole trust decision.

Acceptance evidence is executable:

- `SnapshotTrustKeyId` is a domain-separated SHA-256 identity of the exact 32-byte Ed25519 public key; `SnapshotTrustPolicy` requires a non-zero generation, at least one key, and at most 64 keys, rejects duplicate key IDs and invalid public-key encodings, and canonicalizes records by key ID;
- the deterministic `SnapshotTrustPolicyIdentity` hashes a versioned domain, generation, key count, and the complete sorted `(key_id, state, public_key)` records, so changing generation or `Active`/`Revoked` state changes the reported trust snapshot while input ordering does not;
- `rotate(next_generation, new_active_keys, revoke)` requires a strictly advancing generation, rejects unknown revocations, carries old keys forward, marks selected keys revoked, adds new active keys, and refuses to reactivate a revoked key through that transition;
- trusted durable-store and materialization wrappers resolve the signer as active before touching the store and then reuse the existing 37A strict Ed25519 verification plus 40A/40B object identity, atomic publication, deduplication, and durability mechanisms; trust membership is not a signature-verification bypass;
- an end-to-end rotation regression publishes one archive under generation 1/key A, rotates to generation 2 with A revoked and key B active, proves the still-cryptographically-valid A signature fails as `RevokedSigner` before a deliberately missing store root is inspected, proves an unknown signer fails at the same pre-store gate, then uses B to deduplicate and materialize the exact frozen object;
- successful trusted reports expose the exact policy generation/hash plus signer key ID, and stable rustfmt/Clippy/full tests plus the complete Rust 1.74 suite are green on the exact implementation head.

Boundary: 41A authenticates decisions only relative to the exact trust-policy snapshot supplied by the caller. It does not persist or authenticate the policy itself, prevent a caller from reusing an older snapshot, provide a monotonic anti-rollback counter, certificate/PKI semantics, key generation/custody, validity times, secure distribution, hardware roots of trust, or key-compromise recovery.

### Slice 41B — authenticated persisted policy identity and stale-policy rollback gate

**Status: complete on `main`.** Adds host-owned authenticated state for the exact trust-policy identity so cooperating state-backed operations cannot silently reuse an older caller-supplied policy while that state and its authentication key remain intact.

Acceptance evidence is executable:

- `SnapshotTrustStateKey` is a fixed 32-byte host-held key and the persisted state is a fixed-size versioned record containing the exact `SnapshotTrustPolicyIdentity`, authenticated with domain-separated HMAC-SHA256; malformed size/version/count and authentication failure are fail-closed;
- Linux initialization serializes through an exclusive `flock`, writes a fresh `0600` temporary regular file, `fsync`s it, installs with `renameat2(RENAME_NOREPLACE)`, and `fsync`s the state directory. Repeating the exact initialized identity converges without replacing it;
- rotation constructs the successor only through the existing 41A `rotate()` rules, holds the exclusive state lock, rejects a persisted identity that matches neither supplied current nor computed successor as `StalePolicy`, atomically replaces state only after temp-file `fsync`, and allows an exact retry to converge when the successor is already persisted;
- `SnapshotTrustStateContext` binds the state root/key to one exact caller-supplied policy. State-backed durable store and atomic materialization hold a shared state lock from authenticated identity comparison through the delegated 41A/40B operation, so a cooperating rotation cannot overtake an accepted operation;
- end-to-end evidence initializes generation 1, publishes under key A, persists generation 2 with A revoked/key B active, proves the generation-1 context returns `StalePolicy` before deliberately missing store/destination paths are touched, then uses generation 2/key B to deduplicate and materialize the authenticated frozen object;
- separate evidence rejects a wrong HMAC key and a same-length state-byte tamper as `AuthenticationFailed`, proves stale rotation cannot overwrite a newer persisted generation, and proves exact rotation retry convergence; stable rustfmt/Clippy/full tests and the complete Rust 1.74 suite are green on the exact candidate head.

Boundary: 41B persists and authenticates only the policy identity, not the full policy/key set. Its stale-caller rollback resistance assumes the trusted state directory and host-held HMAC key remain intact. It does not resist privileged whole-directory rollback/restoration, key disclosure, or hostile replacement of the trusted host environment; it provides no hardware/external monotonic counter, PKI/certificate semantics, key custody/distribution, validity clock, or compromise-recovery protocol.

### Milestone 41 promotion rule

After 41B integrates, seal the current host-local snapshot trust lifecycle. Do not farm state filenames, HMAC encodings, generation aliases, or wrappers around the same persisted-identity gate. A stronger rollback phase requires an independently anchored monotonic state or other evidence not restorable with the local directory; otherwise promote to another materially different executable authority/integration frontier.

## Milestone 42 — bounded content-addressed store integrity audit

### Slice 42A — read-only bounded inventory validation

**Status: complete on `main`.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.

Acceptance evidence is executable:

- `audit_snapshot_store(store_root, limits)` requires a trusted absolute non-root store path and explicit non-zero entry, aggregate archive-byte, per-object archive-byte, canonical identity-byte, and archive-node ceilings;
- Linux opens the store root and `objects/` with `O_NOFOLLOW`, enumerates through the already-open directory, opens every observed object fd-relatively with `O_NOFOLLOW`, and rejects non-canonical names, symlink/special entries, non-regular files, multi-link objects, or files retaining write bits;
- every canonical filename is parsed as the complete `(sha256, encoded_bytes, nodes)` identity tuple; the complete bounded archive is read, required not to change length during that read, validated by the existing canonical archive parser, and its derived identity must exactly match the filename identity;
- a healthy two-object store reports exact object and aggregate-byte counts; deterministic regressions reject content tamper, canonical filename/identity mismatch, a symlink entry, a writable object, an external hard-link alias, entry-budget overflow, and aggregate-byte overflow;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 42A is a read-only integrity inventory for a quiescent or cooperatively serialized trusted host-local store. It does not verify signer provenance/trust-policy membership or persisted signatures, lock out independent concurrent publishers, repair/quarantine/delete/garbage-collect objects, provide a point-in-time concurrent snapshot, or strengthen rollback/remote-replica guarantees.

### Milestone 42 promotion rule

After 42A integrates, do not farm more malformed filenames, tamper bytes, link counts, or budget aliases that repeat the same audit path. Promote only to a materially different executable store-lifecycle or authority boundary with safe mutation/concurrency semantics and deterministic evidence, or to another independent frontier if that evidence is not yet available.


## Milestone 43 — canonical audited store inventory commitment

### Slice 43A — deterministic whole-store membership identity

**Status: complete on `main`.** Adds a cross-run store-membership commitment above the complete 42A integrity audit rather than another malformed-object variant.

Acceptance evidence is executable:

- `snapshot_store_inventory_identity(store_root, limits)` reuses the exact bounded 42A scan and receives a record only after that object passes canonical filename, object-type/link/mode, archive-byte, canonical-parser, and archive-derived identity checks;
- every accepted record commits to the complete snapshot identity tuple `(sha256, encoded_bytes, nodes)` plus exact archive byte length; records are sorted before hashing so filesystem enumeration and insertion order do not affect the result;
- the versioned SHA-256 stream commits to `security-lab-snapshot-store-inventory-v1\0`, exact object count, aggregate archive bytes, and all sorted records;
- two equivalent two-object stores populated in opposite orders produce the fixed golden identity `74ac767d1be69f143d68b88a8202214af6cf464aa2307b4397f84eb9baef0af1` with exactly 2 objects and 198 archive bytes;
- `verify_snapshot_store_inventory_identity` accepts an unchanged independently expected inventory, while deterministic addition/deletion evidence changes the identity and returns `IdentityMismatch` with the newly observed counts;
- existing 42A content-tamper failure propagates as the original audit error rather than being hidden behind an inventory mismatch;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 43A is an unkeyed commitment to one successfully audited observed store inventory. It does not authenticate signer/trust-policy provenance, persist or independently protect the expected identity, prevent rollback when expected state is restored with the store, serialize independent publishers, provide a point-in-time concurrent snapshot, or repair/quarantine/delete/garbage-collect objects.

### Milestone 43 promotion rule

After 43A integrates, seal this inventory-commitment encoding. Do not farm digest renderings, record-order aliases, or more add/delete variants. A stronger store-lifecycle phase must introduce materially new safe concurrency/mutation semantics or an independently anchored authentication/rollback boundary with executable evidence; otherwise promote to another independent authority frontier.

## Milestone 44 — cooperative snapshot-store transaction serialization

### Slice 44A — shared-read / exclusive-write store transactions

**Status: complete on `main`.** Adds an explicit host-local cooperation protocol around durable publication and whole-store read operations instead of pretending the existing read-only audit is a concurrent filesystem snapshot.

Acceptance evidence is executable:

- `SnapshotStoreReadTransaction::{begin,try_begin}` opens the pre-existing store-root directory and holds Linux `flock(LOCK_SH)` on that directory inode for the transaction lifetime; multiple cooperating readers can coexist;
- `SnapshotStoreWriteTransaction::{begin,try_begin}` uses `flock(LOCK_EX)` on the same store-root inode, and nonblocking lock contention returns the typed `SnapshotStoreTransactionError::LockContended` rather than falling through to an unlocked operation;
- read transactions expose the existing complete store audit, deterministic inventory identity, and expected-inventory verification while the shared lock remains live;
- write transactions expose the existing authenticated `fsync`-backed durable publication path while the exclusive lock remains live;
- deterministic Linux regressions prove two shared readers coexist, a writer cannot acquire while either reader is live, a reader or second writer cannot acquire while the writer is live, and locks become available after RAII release;
- a durable two-publication regression proves the cooperating inventory advances from a complete one-object state to a complete two-object state, while nonblocking writers/readers are rejected at the opposite lock boundary;
- legacy direct store/audit/inventory functions remain API-compatible and intentionally do not acquire this lock automatically, avoiding hidden nested-lock semantics. Callers requiring cooperative linearization must enter the transaction API explicitly;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 44A is advisory cooperation among callers that use these transaction APIs against the same local store-root inode. It is not a mandatory-access-control boundary, does not stop privileged or non-cooperating writers, does not provide a filesystem point-in-time snapshot, database isolation/rollback, distributed leases, remote-filesystem lock guarantees, or independently anchored rollback protection.

### Milestone 44 promotion rule

44A is sealed on `main`. Do not farm lock-name aliases, timeout knobs, or more reader-count variants. Stronger store-lifecycle work must add materially new mutation/concurrency semantics rather than another lock spelling.

## Milestone 45 — inventory-guarded cooperative mutation

### Slice 45A — optimistic whole-store precondition for durable publication

**Status: complete on `main`.** Composes the 43A complete-store commitment, the 44A exclusive transaction, and the 40B authenticated durable publication path into one compare-and-publish boundary for cooperating writers.

Acceptance evidence is executable:

- `SnapshotStoreWriteTransaction::inventory_identity` derives the complete bounded audited inventory while the exclusive transaction lock remains live, allowing a writer to retain a successor identity before releasing serialization;
- `store_ed25519_durable_if_inventory` recomputes that inventory under the same exclusive lock and compares it with a caller-retained expected identity before invoking the object publication path;
- mismatch returns typed `SnapshotStoreTransactionError::InventoryConflict { expected, actual }`, preserving both complete identities for caller conflict handling;
- deterministic regression captures a one-object identity, lets an intervening cooperating writer advance the store to two objects, then proves a stale guarded attempt reports expected=one/actual=two and leaves the candidate third-object content address absent;
- using the current two-object identity permits authenticated `fsync`-backed publication of that third object, after which the same still-live writer derives a distinct three-object successor identity while a cooperating reader remains lock-contended;
- after writer release, an independent read transaction observes exactly that successor identity; existing audit, inventory, transaction, durable-store, trust, sandbox, and tooling regressions remain active;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 45A is optimistic concurrency control only among callers that cooperate with the 44A store-root lock and carry a previously observed 43A inventory identity. It is not an independently authenticated or monotonic rollback anchor, does not stop privileged/non-cooperating filesystem mutation, does not roll back a publication after its durable path begins, and does not provide general database transactions, multi-object atomic commits, or distributed compare-and-swap.

### Milestone 45 promotion rule

After 45A integrates, seal simple expected-inventory guarded single-object publication. Do not farm extra conflict spellings, retry helpers, or token wrappers. A stronger snapshot-store phase must add independently anchored history/rollback semantics, hostile-writer detection, multi-object atomic mutation, or a genuine point-in-time filesystem/store mechanism with executable evidence; otherwise promote to another authority frontier.

## Milestone 46 — independently authenticated store head

### Slice 46A — persisted authenticated whole-store head state

**Status: complete on `main`.** Adds one independently persisted host-side generation/inventory anchor outside the snapshot object store, rather than another caller-retained comparison token.

Acceptance evidence is executable:

- `SnapshotStoreHeadStateKey` holds exactly 32 host-supplied bytes and redacts them from `Debug`; the fixed state encoding authenticates a versioned domain, non-zero generation, complete inventory SHA-256, object count, and aggregate archive bytes with HMAC-SHA256;
- configured `state_root` and `store_root` must be absolute, non-root, `..`-free, and lexically disjoint; Linux state access is fd-relative and protected by a dedicated `flock` lock;
- initialization establishes generation 1 from the complete audited inventory while holding the head-state exclusive lock and a cooperative store read transaction, then publishes the authenticated state with fsync-backed state-file/directory barriers;
- load authenticates persisted state independently of the store, while verify authenticates the state and requires a complete audited store inventory derived under a read transaction to match exactly;
- guarded publication acquires the head-state lock before the exclusive store transaction, rejects pre-existing inventory divergence before candidate publication, reuses the authenticated durable object-store path, advances the generation only for a newly inserted object, and leaves the generation unchanged for exact deduplication;
- deleting a previously anchored object while keeping the independent state intact produces typed `StoreDiverged`; a later guarded publication is rejected before its candidate object appears;
- a wrong HMAC key and direct head-state byte tamper both fail authentication; overlapping configured state/store roots fail validation;
- the public durable-publication API uses a coherent `SnapshotStoreHeadPublishRequest`, and transaction errors are boxed so the public result type does not carry the large underlying transaction error inline;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 46A detects store-only rollback/divergence only while the separately persisted state root and host-held HMAC key remain trustworthy. It does not resist coordinated rollback/replacement of both roots, provide TPM/secure-counter or remote-witness monotonicity, freeze a hostile live filesystem into a point-in-time view, or make object-store publication plus state-head publication one crash-atomic transaction. If the store advances and a later state write fails, the operation fails and the resulting mismatch is intentionally detected on subsequent verification.

### Milestone 46 promotion rule

After 46A integrates, seal caller-hosted local HMAC head-state rollback detection. Do not farm generation formatting, extra MAC encodings, or retry wrappers. A stronger snapshot-store phase must add materially different hostile-writer/point-in-time semantics, genuine multi-object atomic mutation, or an external/hardware monotonic witness with executable evidence; otherwise promote to another independent authority frontier.

## Milestone 47 — bounded authenticated multi-object publication

### Slice 47A — one-generation batch head publication

**Status: complete on `main`.** Extends the authenticated head from one-object guarded publication to a bounded cooperative batch without claiming crash-atomic rollback of durable members.

Acceptance evidence is executable:

- the public batch request accepts 1 through `SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS` (16) members; each member carries one archive, Ed25519 public key/signature, and archive limits;
- every archive/signature pair is completely validated before either durable store or head-state mutation, and duplicate canonical identities are rejected during the same preflight;
- one authenticated head-state exclusive lock is acquired before one exclusive snapshot-store transaction that remains held across the whole batch; the current audited store inventory must exactly equal the authenticated head before the first member is published;
- a two-object valid batch durably inserts both objects, re-audits the complete successor inventory, and advances the authenticated head exactly once from generation 1 to generation 2; replaying the same batch deduplicates both objects and leaves the generation unchanged;
- an invalid second signature is rejected before the first object is published, and a duplicate canonical identity is rejected before store mutation;
- a deterministic post-store failure oracle uses a successor inventory budget that passes the initial empty-store check but fails only after two valid objects have been durably inserted. The call returns an error, both objects remain in the store, the authenticated head stays at its prior generation, and a later normal-budget verification returns typed `StoreDiverged` with two actual objects;
- exact formal rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 47A is a bounded cooperative publication unit, not a crash-atomic all-or-nothing filesystem transaction. A failure after one or more durable object insertions may leave those objects present while the authenticated head remains old; the supported guarantee is fail-closed divergence detection on later verification, not rollback. It does not serialize hostile non-cooperating writers, freeze a hostile live filesystem, provide coordinated store+state rollback resistance, or add TPM/secure-counter/remote-witness monotonicity.

### Milestone 47 promotion rule

47A is sealed on `main`. Do not farm larger caps, batch aliases, retry wrappers, or alternate duplicate spellings. A stronger snapshot-store phase must add true crash-atomic/point-in-time semantics or an external/hardware monotonic witness with executable evidence; otherwise promote to another independent authority frontier.

## Milestone 48 — initial executable content binding and bootstrap execution authority

### Slice 48A — policy-bound sealed initial executable

**Status: complete on `main`.** Adds an optional exact content restriction for the initial executable and executes the verified bytes from an immutable launcher-owned image instead of merely pinning a mutable host inode.

Acceptance evidence is executable:

- `executable.sha256` accepts exactly 64 hexadecimal characters and decodes to the exact 32 expected bytes; malformed lengths or non-hex input fail policy parsing;
- the static authority manifest exposes the canonical lowercase digest, while authority-delta models adding a digest as a restriction, removing one as a widening, and changing one exact digest to another as incomparable;
- the configured-filesystem preflight reopens the executable beneath the pinned root with read-only `openat2`, requires the same `(st_dev, st_ino)`, bounds the read to 64 MiB, and requires the complete streamed SHA-256 to match without creating namespaces, mounts, executable images, or target processes;
- production first retains the existing path pin/execute-bit checks, then reopens that same inode read-only, hashes and copies the identical byte stream into `memfd_create(MFD_EXEC | MFD_ALLOW_SEALING)`, rejects empty/oversized/mismatched images, and applies plus verifies `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`;
- when the digest is requested, unsupported executable-memfd/sealing support fails explicitly instead of falling back to the host inode; successful launch continues through `execveat(AT_EMPTY_PATH)` using the sealed descriptor;
- a raw fixture under its exact digest exits successfully, while a one-bit digest mismatch returns a pre-launch setup failure; exact PR merge-ref and post-merge `main` stable quality plus Rust 1.74 suites are green.

Boundary: 48A binds only the byte content of the initial executable file selected by policy. SHA-256 here is an expected-content restriction, not a digital signature, provenance statement, or trust-distribution mechanism. The slice does not bind an ELF `PT_INTERP`, dynamic loader/shared libraries, later target execution, or the rest of the root filesystem.

### Slice 48B — one-shot bootstrap `execveat`

**Status: complete on `main`.** Separates the launcher-required initial `execveat` transition from persistent target `execveat` authority.

Acceptance evidence is executable:

- target `seccomp.allow` no longer has to contain `execveat` merely so the launcher can start the pinned initial executable; the target still must explicitly grant an exit syscall for fail-closed post-filter setup errors;
- when target `execveat` is absent, the launcher moves its bootstrap executable descriptor to a `CLOEXEC` fd number at or above the future `limit.open_files` / `RLIMIT_NOFILE` ceiling before the target limit is lowered;
- the generated cBPF program adds one launcher-internal exception that admits `execveat` only when argument 0 exactly equals that bootstrap fd and argument 4 exactly equals `AT_EMPTY_PATH`; any fd/flag mismatch reloads the syscall number and falls through to normal target policy/default `EPERM`;
- after the successful non-returning bootstrap exec, `CLOEXEC` removes that descriptor. With `RLIMIT_NOFILE` already active, target code cannot create, duplicate, or receive a replacement fd at or above the ceiling;
- the 48A sealed-image regression now launches successfully with only target `exit` authority, proving sealed content binding composes with the one-shot bootstrap exception;
- a raw target under `limit.open_files=32` opens a valid lower executable fd, requires `fcntl(F_DUPFD_CLOEXEC, 32)` to fail with `EINVAL`, then requires a later `execveat(..., AT_EMPTY_PATH)` through that lower fd to fail with seccomp `EPERM`;
- a separate policy explicitly granting target `execveat` re-execs the same raw fixture and exits 42, proving the change does not silently revoke authority that policy deliberately grants;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 48B narrows only implicit `execveat` authority needed for the initial launcher transition. It does not remove an explicit target `execveat` grant, does not restrict a separately granted `execve`, and does not bind dynamic interpreters/shared libraries or provide process-lifetime executable identity enforcement. The fd-number isolation relies on Linux `RLIMIT_NOFILE` allocation semantics plus the launcher-held descriptor being `CLOEXEC`.

### Milestone 48 promotion rule

48A–48B are sealed on `main`. Do not farm hash aliases, descriptor-number variants, copy ceilings, or alternate seal masks. Stronger execution integrity must bind a materially different dependency or execution transition with executable evidence.

## Milestone 49 — content-bound initial ELF interpreter

### Slice 49A — sealed exact `PT_INTERP` loader

**Status: complete on `main`.** Extends initial-executable content binding to the dynamic ELF loader named by that exact executable rather than trusting a mutable host loader pathname at exec time.

Acceptance evidence is executable:

- `executable.interpreter` and `executable.interpreter_sha256` are an all-or-nothing restriction and require `executable.sha256`; the interpreter path is absolute, differs from the main executable, and cannot overlap private procfs, scratch, or persistent-volume targets;
- the launcher parses `PT_INTERP` from the already content-bound ELF64 little-endian x86_64 initial executable, rejects malformed/multiple/oversized interpreter segments, and requires the embedded path to equal the policy path byte-for-byte;
- the declared loader is pinned beneath `filesystem.root`, required to be a regular executable, identity-revalidated during sealed copying, SHA-256 checked under the existing 64 MiB ceiling, and retained as an immutable sealed memfd image;
- before chroot, the child copies only those sealed bytes into a private tmpfs file, clones that file as a detached mount, applies read-only + `nosuid` + `nodev`, and attaches it exactly over the declared `PT_INTERP` target path;
- configured-filesystem preflight read-only validates the content-bound executable's `PT_INTERP`, interpreter shape, and interpreter digest; static authority manifest/delta surfaces include the interpreter path+digest restriction;
- a deliberately dynamic PIE fixture embeds `/loader`, launches successfully through the sealed loader and exits 73, while a wrong loader digest and a policy path different from the content-bound `PT_INTERP` both fail before target execution; the trusted parent also proves the host loader copy is unchanged;
- exact branch rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 49A binds only the initial ELF64 x86_64 `PT_INTERP` loader selected by the already content-bound main image. The expected digest is not signer/provenance evidence. This slice does not bind shared libraries opened by the loader, statically linked images without `PT_INTERP`, later target `execve` or explicitly granted later `execveat`, or provide a process-lifetime executable closure.

### Slice 49B — one sealed path-qualified direct `DT_NEEDED`

**Status: complete on `main`.** Extends the sealed initial-execution chain to one direct shared object whose pathname is selected by the content-bound main ELF itself, without claiming general dynamic-loader search or a transitive library closure.

Acceptance evidence is executable:

- `executable.needed` / `executable.needed_sha256` are an all-or-nothing restriction that requires both `executable.sha256` and the sealed `PT_INTERP` binding; the dependency path is absolute, not `/`, differs from the main executable/interpreter, rejects dynamic-linker `$` tokens, and cannot overlap private procfs, scratch, or persistent-volume targets;
- the launcher parses bounded little-endian ELF64 x86_64 `PT_DYNAMIC` metadata from the already content-bound main image, resolves `DT_STRTAB` only through a containing `PT_LOAD`, bounds the dynamic/string tables and direct-needed count, requires a terminating `DT_NULL`, and when the binding is enabled requires the complete direct `DT_NEEDED` set to contain exactly one entry whose bytes equal the configured path;
- the matched object is pinned beneath `filesystem.root`, required to be a regular executable, identity-revalidated while copying, SHA-256 checked under the existing 64 MiB ceiling, and retained as an immutable sealed memfd image;
- before target execution, the child reuses the sealed-image mount path to copy only those verified bytes into private tmpfs state, clone the file, apply read-only + `nosuid` + `nodev`, and attach it exactly over the declared dependency pathname;
- configured-filesystem preflight independently validates direct-needed membership, object shape, and digest; static authority manifest/delta surfaces include the direct-needed path+digest restriction;
- a dynamic PIE fixture containing `DT_NEEDED=/dependency` executes through the sealed main + interpreter + dependency chain and exits 91. A one-bit dependency-digest mismatch and a configured path absent from the sealed main's direct-needed list both fail before target execution; the trusted parent proves the host dependency bytes remain unchanged;
- the exact candidate retains all prior regressions and has passed stable rustfmt, Clippy with `-D warnings`, the complete stable suite, and the complete Rust 1.74 suite.

Boundary: 49B/64A bind the complete direct dependency set only for sealed main executables whose direct `DT_NEEDED` topology is exactly one **path-qualified** object. If any second direct dependency is present, the binding fails closed before target execution rather than leaving that loader input mutable. This intentionally does not resolve ordinary slashless SONAME dependencies, `DT_RPATH`/`DT_RUNPATH`, `ld.so.cache`, dependency search order, transitive `DT_NEEDED` edges, dynamic-string token expansion, `LD_PRELOAD`, `dlopen`, later exec transitions, or a process-lifetime shared-library closure. The expected digest remains content evidence, not signer/provenance identity.

### Milestone 49 promotion rule

49A–49B are sealed on `main`. Do not farm extra direct paths, parser tags, SONAME spellings, or mount aliases. A stronger execution-integrity phase must either model materially broader loader resolution/transitive closure with executable evidence, bind explicitly authorized later execution, or move to another independent authority frontier.

## Milestone 50 — recoverable authenticated snapshot-store head publication

### Slice 50A — one recoverable single-object head transition

**Status: complete on `main`.** The single-object store-head path durably records one HMAC-authenticated exact predecessor/successor/candidate intent before store mutation, and explicit recovery converges only predecessor/predecessor, predecessor/successor, or successor/successor while preserving unknown-state evidence.

Acceptance evidence remains the established 50A suite: pre-store intent cleanup, exact durable-successor advancement with renewed object/directory/root durability barriers, post-head cleanup, unknown-state preservation, wrong-key/tamper rejection, and a real seccomp-denied `fsync` recovery retry.

Boundary: 50A is single-object forward recovery only. It is not rollback, a two-root crash-atomic transaction, non-cooperating-writer serialization, a point-in-time filesystem snapshot, stale object-temp scavenging, or a hardware/remote monotonic witness.

### Slice 50B — bounded recoverable batch head transition

**Status: complete on `main`.** Retrofitting the 47A batch path adds a materially stronger recovery boundary rather than another pending-file spelling.

Acceptance evidence is executable:

- all 1–16 members are archive/signature-prevalidated and duplicate identities rejected before locking/mutation; an ordered batch projection derives the exact current inventory, final successor, and every new-member intermediate inventory under the existing canonical audit ordering and budgets;
- members already present in the predecessor are exact-byte durable-dedup validated before the journal. A batch that is entirely deduplicated creates no recovery state and does not advance the head;
- before any **new** object publication, the state root durably receives a fixed-size HMAC-authenticated batch journal committing to predecessor, successor, member identity/length, public key/signature, preexisting classification, and every new-member intermediate inventory, plus read-only staged copies of all member archives; each stage and then the state directory cross `fsync` barriers;
- normal publication inserts new members in request order and re-audits after each insertion against the exact journaled intermediate inventory. The head advances exactly once only after the final inventory equals the authenticated successor; cleanup durably removes stages before removing the journal;
- recovery uses the same head-exclusive → store-write lock order. Predecessor/predecessor aborts an unmutated staged batch. Predecessor plus an exact authenticated durable-prefix inventory validates **every** staged archive/signature before mutation, idempotently resynchronizes already-present members, publishes remaining members, checks each remaining intermediate inventory, then publishes the exact successor head. Successor/successor only finishes cleanup;
- no arbitrary subset/order is promoted: any non-journaled inventory returns `PendingStateDiverged` without adding expected objects or clearing evidence. A tampered batch journal fails HMAC authentication, and a tampered stage fails before forward replay;
- deterministic tests cover ordinary two-object publication/dedup, mixed preexisting+new publication, pre-mutation aggregate-budget rejection, staged-predecessor abort, exact partial-prefix completion, unknown-inventory refusal, staged-archive tamper refusal, and batch-journal authentication tamper. Stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 50B is **bounded authenticated forward recovery**, not rollback or atomic commit. It does not accept non-prefix partial states, serialize callers bypassing the cooperative transaction layer, make the store and state roots one crash-atomic resource, scavenge arbitrary stale object-store temp files, provide a hostile-writer point-in-time snapshot, or add external/hardware monotonicity. Recovery remains relative to an intact independent state root/HMAC key and local filesystem durability semantics.

### Milestone 50 promotion rule

50B is sealed on `main`. Do not farm larger batch counts, alternate stage filenames, retry aliases, or more recovery-state names. Promotion must add a qualitatively stronger property such as true point-in-time/crash-atomic semantics, stale-temp-safe recovery, or an external/hardware monotonic witness; otherwise move to another independent authority frontier.

## Milestone 51 — cooperative stale snapshot-store temporary recovery

### Slice 51A — bounded stale object-temp recovery

**Status: complete on `main`.** Adds a crash-residue lifecycle for the content-addressed store's existing temporary-object publication namespace without turning cleanup into general garbage collection.

Acceptance evidence is executable:

- every runtime publisher that can create `.tmp-<pid>-<counter>` first acquires a shared store-root `.snapshot-store-temp-recovery.lock` flock and retains it through temporary creation, sealing, final `renameat2(RENAME_NOREPLACE)`, or cleanup; after waiting for that lock it rechecks the final object before creating a temp;
- blocking recovery acquires the exclusive form of the same lock, while the nonblocking API returns typed `RecoveryLockContended` instead of deleting concurrently with a cooperating publisher;
- recovery performs a complete bounded enumeration before mutation. Exceeding `max_entries` returns `RecoveryBudgetExceeded` with every candidate preserved;
- only canonical reserved names `.tmp-<pid>-<counter>` are candidates. Every candidate must be a single-link regular file under fd-relative `fstatat(..., AT_SYMLINK_NOFOLLOW)`; a reserved-name symlink or other unsafe object fails closed before any candidate is deleted;
- canonical content-addressed objects and unrelated entries are left untouched. Successful removal crosses `fsync` barriers for `objects/` and the pre-existing store root before the report acknowledges removed files;
- deterministic integration tests cover exact stale-temp removal with canonical/unrelated preservation, pre-mutation entry-budget failure, unsafe reserved-name rejection with evidence preservation, and nonblocking contention/retry. Stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 51A is **cooperative reserved-temp crash-residue recovery**. It is not general orphan detection/GC, age-based cleanup, hostile/non-cooperating writer serialization, canonical-object repair, head/journal rollback, a point-in-time filesystem snapshot, or proof of physical power-loss behavior beyond the local Linux `fsync` contract.

### Milestone 51 promotion rule

After 51A integrates, do not farm alternate temp prefixes, higher scan counts, or cleanup aliases. A stronger snapshot-store phase must add a qualitatively new property such as point-in-time/crash-atomic semantics or an external/hardware monotonic witness, or promote to another independent authority frontier.

## Independent host-local IPC frontier — post-launch object transfer

### Receive-only SCM_RIGHTS over the exact-path AF_UNIX broker

**Status: complete on `main`.** This is a materially new runtime object-capability handoff, not another AF_UNIX address spelling and not a new configuration-only broker name.

Acceptance evidence is executable:

- target seccomp may now explicitly name Linux x86_64 `recvmsg`; `sendmsg` is intentionally not added to the target syscall-name surface;
- the capability channel reuses the existing exact host-path AF_UNIX stream broker and its optional exact `SO_PEERCRED` UID/GID narrowing rather than attaching a new host IPC namespace or exposing the host pathname inside chroot;
- a raw target publishes one readiness byte from executed target code on broker fd 10; only after the host peer reads that byte does it call real `sendmsg(SCM_RIGHTS)` with one regular-file descriptor, proving the object handoff occurs after target exec rather than being preloaded before launch;
- the raw target calls `recvmsg(..., MSG_CMSG_CLOEXEC)`, requires a non-truncated `SOL_SOCKET` / `SCM_RIGHTS` control message containing exactly one descriptor, reads exact `runtime-fd-handoff-ok\n` bytes through that descriptor, and closes it;
- the same target then attempts the original absolute host file pathname and requires exact `ENOENT`, proving the descriptor grant does not make that host pathname reachable through the sandbox root;
- existing broker, namespace, Landlock, seccomp, lifecycle, COW, and authority regressions remain active; exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: this slice is receive-only target-side capability transfer over one already-authorized connected AF_UNIX stream. It does not add target `sendmsg`, a launcher-owned post-launch broker API, descriptor-rights attenuation/revocation, object-type policy for arbitrary received FDs, multiple broker channels, or a general bidirectional IPC/RPC graph. The peer UID/GID pin is kernel credential evidence, not cryptographic service identity.

Promotion rule: do not farm additional payload bytes, target descriptor numbers, or ancillary-message spelling variants. A stronger host-local IPC phase must add materially new mediation such as bounded object-type/rights policy, launcher-owned dynamic brokering, revocation/lifetime control, or a generalized endpoint/object graph with executable evidence.


## Milestone 52 — launcher-owned runtime object mediation

### Slice 52A — one-shot read-only regular-file runtime grant

**Status: complete on `main`.** Converts the previously peer-driven receive-only `SCM_RIGHTS` channel into a bounded trusted-caller mediation API for one regular-file data capability.

Acceptance evidence is executable:

- `RuntimeFdBroker::configure_policy()` reuses the existing exact-path AF_UNIX broker rather than adding a second transport surface; it refuses an already-configured host-UNIX broker, requires `recvmsg` to already be explicit in target `seccomp.allow`, validates a cloned candidate, and never partially mutates the caller policy on failure;
- `RuntimeFdBroker::bind()` records the broker owner's process/effective credentials and exact socket inode. `accept()` requires Linux `SO_PEERCRED` to match that exact PID/UID/GID before producing a session, while the existing launcher-side AF_UNIX preparation independently retains its exact peer UID/GID check;
- `prepare_readonly_regular_file()` accepts only regular files that already carry read authority, rejects `O_WRONLY`, `O_PATH`, directories/devices/pipes/sockets, reopens `/proc/self/fd/<n>` as `O_RDONLY|O_CLOEXEC`, revalidates `(st_dev, st_ino)`, and therefore gives the target an independent open-file description rather than sharing the caller's file offset;
- `RuntimeFdSession` is a fail-closed state machine: a grant before the exact target readiness byte is rejected, readiness can be consumed only once, one successful `SCM_RIGHTS` grant moves the session terminally to `GrantSent`, and a second grant is rejected. A readiness/protocol I/O failure poisons the session instead of permitting an ambiguous retry;
- the real sandbox target receives the grant only after executed target code publishes readiness, receives it with `MSG_CMSG_CLOEXEC`, gets exact `EBADF` when it attempts `write(2)` despite `write` being explicitly allowed for the readiness handshake, reads the exact marker bytes successfully, and still gets `ENOENT` for the original host pathname;
- host-side evidence proves the caller's original source offset remains unchanged, while deterministic local regressions also reject write-only, path-only, and non-regular sources plus premature/duplicate session operations;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 52A attenuates the transferred regular file's **open-file-description data access mode** to `O_RDONLY`; it does not make the underlying inode immutable, revoke metadata-changing authority independently granted by target syscalls/kernel ownership/Landlock state, provide descriptor revocation after transfer, accept directory/device/socket capabilities, multiplex multiple grants per session, add target `sendmsg`, provide cryptographic peer identity, or create a general post-launch IPC/RPC broker.

### Slice 53A — bounded sealed runtime byte snapshot grant

**Status: complete on `main`.** Adds content-lifetime isolation after preparation rather than another regular-file descriptor-number or access-mode variant.

Acceptance evidence is executable:

- `prepare_sealed_regular_file_snapshot(source, max_bytes)` accepts only the existing readable regular-file source class and requires an explicit 1-byte through 64-MiB ceiling; zero, ceilings above the public maximum, and a source that actually exceeds the chosen ceiling fail closed;
- preparation first reuses the 52A independent `O_RDONLY` procfd reopen, then copies through that separate description into `memfd_create(MFD_CLOEXEC|MFD_ALLOW_SEALING)`; the copy loop is byte-bounded, checked for overflow, handles `EINTR`, and refuses zero-progress writes;
- before the snapshot becomes transferable, the launcher sets mode `0400`, applies `F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL`, verifies every required seal with `F_GET_SEALS`, reopens the same memfd inode as an independent `O_RDONLY|O_CLOEXEC` description, and verifies identity/access-mode/seals again;
- the sealed snapshot grant shares the exact 52A one-shot `RuntimeFdSession` state machine, so readiness-before-grant and one-successful-grant-per-session remain enforced across both regular-file grant kinds;
- local executable evidence prepares exact `runtime-fd-handoff-ok\n` bytes, mutates the original host file after preparation, then proves the received object still has the complete required seal set, mode `0400`, `O_RDONLY`, exact `EBADF` on write, and the original frozen bytes while the caller's source offset remains unchanged;
- a real sandbox run repeats the mutate-after-preparation oracle: target-executed readiness occurs first, the sealed object is transferred with the existing `SCM_RIGHTS` path, target write is denied by the received descriptor's access mode, the target reads the frozen pre-mutation marker, and the original host pathname remains hidden even though the trusted parent proves that host file now contains different bytes;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 53A freezes the **completed copied byte sequence and length** after preparation. It is not a point-in-time/atomic source snapshot while copying, does not serialize or detect a hostile concurrent source writer, does not authenticate/hash/sign the bytes, does not make memfd mode or other metadata immutable, provides no post-transfer revocation, and still permits only one successful grant on one 52A session.

### Milestone 53 promotion rule

53A is sealed on `main`; do not farm alternative byte ceilings, seal spelling, or immutable-copy aliases.

### Slice 54A — bounded ordered sealed snapshot bundle

**Status: complete on `main`.** Adds a bounded multi-object runtime protocol with explicit ordering and fail-closed partial-failure semantics rather than another single-object grant alias.

Acceptance evidence is executable:

- `prepare_sealed_snapshot_bundle(grants, max_total_bytes)` consumes 2–8 already-prepared 53A sealed snapshots and requires an explicit aggregate ceiling from 1 byte through 64 MiB; too few/many members, zero/oversized ceilings, checked-add overflow, or aggregate bytes above the chosen ceiling fail closed before transfer;
- bundle membership and order are fixed by consuming the prepared snapshots, and the public bundle reports exact member count plus aggregate copied-byte length;
- one readiness event gates the whole bundle, then one `sendmsg(MSG_NOSIGNAL)` carries payload `B` plus one `SCM_RIGHTS` control message containing the ordered descriptor list; the ancillary buffer is statically bounded for at most eight Linux x86_64 file descriptors;
- a successful bundle consumes the same terminal `RuntimeFdSession` transition as every 52A/53A grant; any send error poisons the session and a later retry is rejected instead of attempting to infer which receiver-side capabilities survived;
- local executable evidence receives two descriptors in order, verifies both remain `O_RDONLY` with all four 53A seals, reads distinct first/second markers, and proves a later single-object grant is rejected on that already-consumed session;
- a separate failure regression closes the peer before bundle send, requires an I/O failure, then proves the session is terminally failed and rejects a later retry;
- the real raw-syscall sandbox target publishes post-exec readiness, receives exactly two descriptors with `MSG_CMSG_CLOEXEC`, requires payload `B`, rejects `MSG_CTRUNC`, validates the exact `SCM_RIGHTS` header/count, gets `EBADF` on writes, reads the two frozen markers in declared order, and still gets `ENOENT` for both original host source pathnames;
- a negative real-target run sends three descriptors to that two-descriptor receive contract and must exit through the fail-closed oracle when ancillary control is truncated rather than accepting the surviving subset;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 54A bounds and orders one sender-side multi-FD ancillary message; it is not a distributed transaction or receiver-acknowledged commit. A successful `sendmsg` does not prove the receiver consumed or retained every descriptor, and a receiver can always close granted descriptors. The slice adds no post-transfer revocation, no multiple successful grants per session, no arbitrary object-class mixture, and no general RPC protocol.

### Slice 55A — bounded revocable runtime byte stream

**Status: complete on `main`.** Adds an explicit runtime-capability lifetime property rather than another immutable-file or multi-FD handoff variant.

Acceptance evidence is executable:

- `prepare_revocable_byte_stream(max_bytes)` requires an explicit 1-byte through 64-MiB lifetime byte ceiling and creates one private `AF_UNIX/SOCK_STREAM` socketpair; the endpoint prepared for the target is write-shutdown and the trusted controller peer is read-shutdown before transfer;
- the prepared target endpoint uses the existing one-readiness/one-successful-grant runtime broker state machine and is transferred only after executed target code publishes the exact readiness byte;
- `RevocableByteStreamController::send_all()` checks the complete requested slice against the remaining lifetime byte budget before sending, accounts only bytes actually sent, retries `EINTR`, uses `MSG_NOSIGNAL`, and poisons the controller after an ambiguous I/O/zero-progress failure so callers cannot retry an uncertain partial send;
- `revoke()` is one-shot and performs `shutdown(SHUT_WR)` on the trusted controller peer. Bytes already queued remain readable; after they drain, the target observes EOF. Revocation does not remotely close/invalidate the target descriptor and does not roll back already delivered bytes;
- local executable evidence proves the received endpoint cannot send (`EPIPE`), an over-budget send fails before any byte is supplied, exact marker bytes arrive, revoke converges to EOF, later sends/double-revoke fail, and the runtime session still permits only one successful grant;
- the raw-syscall sandbox target explicitly grants `recvmsg` and `sendmsg`, publishes post-exec readiness, receives exactly one endpoint with `MSG_CMSG_CLOEXEC`, proves the endpoint is send-disabled with `sendmsg(MSG_NOSIGNAL) -> EPIPE`, reads the exact `runtime-revocable-stream\n` marker, then requires EOF after host revocation;
- the Linux x86_64 syscall-name table includes `sendmsg` only as an explicit policy-resolvable syscall; the runtime broker does not silently add it to target seccomp authority;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 55A revokes only **future host-to-target byte supply** on one bounded stream. It does not revoke bytes already queued or read, remotely invalidate/close the target descriptor, provide target-to-host request traffic, reset/rearm a revoked stream, transfer a replacement stream on the consumed session, or provide a general long-lived RPC/control protocol.

### Milestone 55 promotion rule

55A is sealed on `main`; do not farm stream byte ceilings, extra EOF spellings, or equivalent one-way socket wrappers.

## Milestone 56 — bounded runtime message protocol

### Slice 56A — one-shot request/response exchange

**Status: complete on `main`.** Adds a materially different message-oriented runtime protocol property rather than extending the 55A byte stream.

Acceptance evidence is executable:

- `prepare_runtime_message_exchange(max_request_bytes, max_response_bytes)` requires independent 1-byte through 64-KiB ceilings and creates one private `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` pair, giving kernel-preserved packet boundaries in both directions;
- the target endpoint reuses the existing exact-peer, post-exec readiness gate and one-successful-grant `RuntimeFdSession` transition; no new target syscall is silently added;
- `RuntimeMessageExchangeController::receive_request()` accepts exactly one non-empty packet, uses a bounded buffer plus `MSG_TRUNC` evidence to reject oversized requests, and makes empty/closed-peer, truncation, and I/O failure terminal;
- `send_response()` is legal only after a valid request, rejects an empty or over-budget complete response before send, uses `MSG_NOSIGNAL`, and makes any send failure terminal; one successful response completes the controller and later request/response calls are rejected;
- local regressions prove exact request/response bytes, preserved one-message boundaries, invalid configuration rejection, oversized-request failure, oversized-response failure, one-round lifecycle, and I/O-failure poisoning;
- the raw-syscall sandbox target explicitly grants `recvmsg` and `sendmsg`, publishes post-exec readiness, receives exactly one endpoint with `MSG_CMSG_CLOEXEC`, sends exact `runtime-request\n`, receives exact `runtime-response\n` with no `MSG_TRUNC`, and exits successfully;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 56A is one bounded target-to-host request followed by one bounded host-to-target response. It does not provide multiple rounds, multiplexing, streaming, message authentication, replay/ordering identifiers beyond the single kernel packet boundary, request cancellation, request-wait deadlines, peer attestation, or a general long-lived RPC/control protocol.

### Slice 56B — launcher-owned bounded request wait

**Status: complete on `main`.** Adds a lifecycle bound to the 56A controller without changing target syscall authority or turning the one-round exchange into a general RPC protocol.

Acceptance evidence is executable:

- `RuntimeMessageExchangeController::receive_request_with_deadline(wait_milliseconds)` accepts an explicit 1–86,400,000 ms bound while the existing `receive_request()` blocking semantics remain unchanged; zero or larger values fail as `InvalidConfiguration` without consuming an otherwise-awaiting exchange;
- each bounded call creates and arms a launcher-owned `timerfd(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)`; the deadline therefore continues across interrupted `poll` calls instead of restarting after `EINTR`;
- the controller polls only its private request socket and timer. When request/peer readiness and timer readiness are observed in the same poll cycle, socket readiness is handled first and the existing bounded `recvmsg` path remains the packet-versus-peer-shutdown arbiter;
- an expired wait returns typed `RuntimeRequestTimedOut { wait_milliseconds }`, transitions the controller terminally to failed state, and later request/response attempts are rejected rather than reviving an ambiguous exchange; mandatory timer creation/arming/poll failure also fails closed, with `ENOSYS` reported as unsupported rather than falling back to an unbounded requested wait;
- deterministic local regressions prove a 1 ms no-request timeout is terminal, invalid wait bounds do not consume protocol state, and a request already queued before a 1 ms bounded receive wins the documented request-first arbitration and completes normally;
- the real raw-syscall sandbox request/response oracle now receives `runtime-request\n` through the 1,000 ms bounded API and returns the exact response while retaining the existing explicit target `recvmsg`/`sendmsg` policy;
- exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 56B bounds only the trusted controller's blocking wait beginning when `receive_request_with_deadline()` is invoked. It is not an endpoint-grant-to-request or end-to-end API deadline, does not terminate the sandbox process tree, does not bound response computation/delivery, and does not add multiple rounds, multiplexing, authentication, cancellation, or peer attestation.

### Milestone 56 promotion rule

56A–56B are sealed on `main`. Do not farm deadline units, timeout values, packet sizes, message tags, or equivalent one-round wrappers. Further runtime-protocol work must add a materially different capability lifecycle or authority property with executable evidence; otherwise promote to another architectural frontier.

## Milestone 58 — bounded multi-round runtime message lifecycle

### Slice 58A — bounded sequential multi-round exchange

**Status: complete on `main`.** Promotes the one-round request/response mechanism into a bounded sequential session without changing the existing target endpoint-grant authority.

Acceptance evidence is executable:

- `prepare_runtime_multi_message_exchange(max_request_bytes, max_response_bytes, max_rounds)` reuses the existing private `AF_UNIX/SOCK_SEQPACKET|SOCK_CLOEXEC` endpoint and requires `max_rounds` from 2 through 32; each request and response independently retains the existing 1-byte–64-KiB ceiling;
- the new controller wraps the proven one-round receive/timer/send primitives rather than duplicating packet parsing. A successful response increments `completed_rounds`; only when more configured rounds remain does it transition back to `AwaitingRequest`, while the final response leaves the underlying controller complete;
- `receive_request_with_deadline()` remains available on every awaiting round with the existing 1–86,400,000 ms `CLOCK_MONOTONIC` timerfd semantics and request/peer-readiness-before-timer arbitration;
- any empty/truncated/oversized request, invalid/oversized response, I/O ambiguity, or request-wait timeout leaves the underlying controller terminally failed. The wrapper never resets a failed controller into a later round;
- broker-level integration evidence performs the real readiness handshake and `SCM_RIGHTS` transfer of the prepared endpoint, then completes two exact ordered request/response packets and rejects any third round at the configured limit;
- deterministic regressions reject round counts outside 2–32, prove a second-round oversized request poisons the whole session after one completed round, and prove a second-round timeout is likewise terminal;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 58A is a bounded **sequential** message lifecycle over one already-granted endpoint. It does not add a new sandbox grant path, multiplexing, concurrent in-flight requests, request IDs, out-of-order responses, authentication, replay protection, an endpoint-grant-to-request deadline, a response deadline, or an unbounded/general RPC transport. The executable multi-round evidence is at the broker/controller integration layer; existing full sandbox regressions remain green, but this slice does not claim a new dedicated multi-round raw-target oracle.

### Milestone 58 promotion rule

58A is sealed on `main`. Do not farm larger round caps, per-round aliases, message tags, or request-timeout wrappers. Further runtime work must close a distinct lifecycle/authority gap with executable evidence rather than repackage the same state machine.

## Milestone 59 — bounded response publication liveness

### Slice 59A — launcher-owned bounded response-publication wait

**Status: complete on `main`.** Closes the trusted controller's distinct blocking-send liveness gap under real peer receive-queue backpressure without changing target syscall authority or claiming target consumption.

Acceptance evidence is executable:

- `send_response_with_deadline(bytes, wait_milliseconds)` is separate from the existing blocking `send_response()`; valid waits are 1–86,400,000 ms, while invalid bounds return `InvalidConfiguration` without consuming the already-received request state;
- each bounded send creates launcher/controller-owned `timerfd(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)` state and polls the private response socket plus timer, so `EINTR` does not restart the deadline;
- socket readiness is attempted before a simultaneously readable timer, but the final arbiter is an atomic `send(..., MSG_NOSIGNAL|MSG_DONTWAIT)`; `EAGAIN` is never treated as publication success and the loop retains the original timer state;
- exact full-packet send completes the one-round controller; expiration returns typed `RuntimeResponseTimedOut { wait_milliseconds }`, and timer/poll/send ambiguity fails closed;
- the multi-round wrapper exposes the same bounded publication operation and increments `completed_rounds` / reopens `AwaitingRequest` only after successful publication, so timeout cannot revive the session into another round;
- deterministic broker integration performs the real readiness handshake and SCM_RIGHTS endpoint transfer, repeatedly sends one-byte requests while deliberately never draining maximum-size responses, and observes actual SOCK_SEQPACKET backpressure produce the typed publication timeout before the 32-round ceiling; the poisoned controller rejects later use;
- a separate regression proves zero and above-maximum response wait bounds leave a valid received request usable, after which a 1,000 ms bounded publication succeeds and the peer reads exact response bytes;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 59A bounds only the trusted controller's wait until the complete response packet is accepted into the peer socket's kernel receive queue. It does not prove target read, processing, acknowledgment, or application progress; it does not add an endpoint-grant-to-request deadline, target-side response deadline, whole-session lifetime bound, multiplexing, authentication, replay protection, or general RPC semantics.

### Milestone 59 promotion rule

59A is sealed on `main`. Simple per-operation request/response wait bounds are complete at this laboratory scope; do not farm timeout values, deadline units, or duplicate send wrappers.

## Milestone 60 — bounded multi-round session lifetime

### Slice 60A — one non-resettable monotonic whole-session budget

**Status: complete on `main`.** Adds one lifecycle-wide liveness bound across the existing bounded multi-round controller rather than another per-operation timeout variant.

Acceptance evidence is executable:

- `start_session_deadline(limit_milliseconds)` accepts 1–86,400,000 ms, must be called before the first request, and can be armed only once; invalid limits do not alter protocol state, while an already-armed deadline cannot be reset;
- the controller owns one `timerfd(CLOCK_MONOTONIC, TFD_CLOEXEC|TFD_NONBLOCK)` for the remainder of the session, so round completion and `EINTR` never recreate or extend the lifetime budget;
- while active, ordinary multi-round `receive_request()` and `send_response()` poll the existing private SOCK_SEQPACKET endpoint together with that same timer; per-operation request/response deadline methods are deliberately rejected instead of composing ambiguous independent clocks;
- after the session timer becomes observably expired, expiration wins over a simultaneously queued request or writable response socket. The controller returns typed `RuntimeSessionTimedOut { limit_milliseconds }`, does not advance the round, and remains terminal for later ordinary or per-operation-deadline calls;
- deterministic regressions complete an initial round, allow the persistent timer to expire, then prove a pre-queued second request cannot revive the session; a separate response-side regression proves an otherwise writable socket cannot publish after the lifetime budget has expired;
- configuration regressions prove zero/above-maximum limits, reset attempts, and per-operation deadline mixing fail without silently disabling the active lifetime boundary;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 60A starts its budget when the trusted caller explicitly invokes `start_session_deadline`, not at endpoint preparation, readiness, SCM_RIGHTS grant, or target exec. It bounds controller progress only when the next request/response operation observes the persistent timer; it is not a hard real-time cutoff, does not prove target response consumption/processing/acknowledgment, and does not add request IDs, concurrent in-flight operations, multiplexing, authentication, replay protection, or general RPC semantics.

### Milestone 60 promotion rule

60A is sealed on `main`. Request, response-publication, and whole-session time bounds are complete at this laboratory scope. Do not farm reset modes, alternate units, clock aliases, or more timeout wrappers.

## Milestone 61 — bounded correlated in-flight runtime exchange

### Slice 61A — explicit request IDs and out-of-order response correlation

**Status: complete on `main`.** Adds a materially different protocol property over the existing readiness-gated private `SOCK_SEQPACKET` capability without changing sandbox grant authority.

Acceptance evidence is executable:

- `prepare_runtime_correlated_exchange(max_request_bytes, max_response_bytes, max_requests, max_in_flight)` keeps request and response payload ceilings at 1 byte–64 KiB, bounds total accepted requests to 2–32, and bounds simultaneous pending requests to 2–8 with `max_in_flight <= max_requests`;
- each request/response packet is exactly an 8-byte little-endian `u64` request ID followed by a non-empty payload, preserving kernel packet boundaries instead of adding a stream parser;
- the controller retains every observed request ID for the session and tracks the pending subset separately. A duplicate request ID returns typed `RuntimeDuplicateRequestId` and terminally closes the controller;
- trusted responses name the request ID they complete and may be published out of request order. An unknown or already-completed ID returns typed `RuntimeUnknownRequestId` and terminally closes the controller;
- reaching the configured in-flight ceiling rejects another controller receive before `recvmsg`, so the queued target packet remains untouched until a response frees a slot;
- correlated response publication is one atomic `MSG_DONTWAIT|MSG_NOSIGNAL` packet. A would-block condition is a terminal protocol failure rather than hidden controller buffering;
- broker-level integration performs the real readiness handshake and `SCM_RIGHTS` endpoint grant, accepts request IDs 41 and 42 concurrently, publishes response 42 first, admits ID 43 after that slot is freed, then publishes 43 before 41; target-side receives prove each exact response ID/payload pairing and final controller completion;
- dedicated regressions prove duplicate request IDs and unknown response IDs are terminal, configuration bounds fail closed, and all existing sandbox/runtime regressions remain green;
- exact candidate stable format/Clippy/full tests and the complete Rust 1.74 suite are green.

Boundary: 61A is bounded correlation over one already-granted endpoint. It does not compose the 56B/59A/60A deadline APIs into this controller, provide target acknowledgment/processing evidence, authenticate requests, prevent replay across sessions, expose an async/concurrent trusted-host API, buffer responses under backpressure, or provide an unbounded/general RPC transport. Its executable correlation evidence is at the real broker/controller integration layer rather than a new dedicated raw-target fixture.

### Milestone 61 promotion rule

61A is sealed on `main`. Do not farm ID widths, larger caps, or more response-order permutations. Promote only to a materially different protocol authority property such as authenticated application framing/replay resistance, or to another independent architecture frontier.

## Milestone 62 — authenticated correlated runtime framing

### Slice 62A — fresh-challenge HMAC-SHA256 request/response authentication

**Status: complete on `main`.** Adds application-frame authenticity and bounded cross-session replay separation to the 61A correlated exchange without changing target syscall authority or replacing its bounded in-flight lifecycle.

Acceptance evidence is executable:

- `prepare_runtime_authenticated_correlated_exchange(max_request_bytes, max_response_bytes, max_requests, max_in_flight, key)` keeps the 61A 1-byte–64-KiB payload bounds, 2–32 total-request bound, and 2–8 in-flight bound while requiring exactly 32 caller-supplied HMAC key bytes;
- preparation obtains a fresh 32-byte challenge directly from Linux `getrandom(2)`, failing closed on unavailable/failed randomness instead of substituting a predictable nonce;
- after the existing readiness-gated `SCM_RIGHTS` endpoint transfer, the controller must publish exactly one `C || version=1 || challenge[32]` packet before any authenticated request can be accepted;
- request and response frames use distinct direction bytes and HMAC-SHA256 over the versioned domain `security-lab-runtime-correlated-hmac-sha256-v1\0`, the session challenge, direction/version, little-endian request ID, little-endian payload length, and complete non-empty payload;
- request MAC verification uses the pinned HMAC implementation's constant-time verification path and occurs before the request ID enters the seen/pending sets. A bad tag returns typed `RuntimeAuthenticationFailed` and terminally poisons the exchange;
- trusted responses are authenticated under the same session challenge and key while retaining 61A out-of-order completion and atomic nonblocking publication semantics;
- the controller's custom `Debug` representation omits both the secret HMAC key and session challenge rather than exposing key material through derived debug output;
- broker-level regressions exercise the real readiness handshake and `SCM_RIGHTS` endpoint grant, authenticate two simultaneous requests, publish an out-of-order authenticated response, admit another request after a slot is freed, and verify each response tag at the peer;
- negative regressions require a one-bit tag corruption and a frame authenticated under a different challenge to fail authentication terminally, while pre-challenge receive and double challenge publication are rejected without silently consuming request state;
- exact-head stable rustfmt, Clippy with `-D warnings`, complete stable tests, and the Rust 1.74 suite are the integration gate for this candidate.

Boundary: 62A provides shared-key frame authentication plus per-session freshness binding. The challenge is public, payloads are not encrypted, and the caller remains responsible for HMAC key generation, secrecy, distribution, rotation, revocation, and memory lifecycle. Fresh-challenge binding rejects frames authenticated for another challenge but is not a persistent replay ledger or hardware monotonic counter. This slice does not prove target processing/acknowledgment, compose the 56B/59A/60A deadline APIs into the correlated controller, expose an async host execution API, buffer responses under backpressure, or provide general RPC/attestation semantics. Its executable evidence remains at the real broker/controller integration layer rather than adding a new policy-level raw-target key-distribution mechanism.

### Milestone 62 promotion rule

62A is sealed on `main`. Do not farm tag sizes, alternate MAC encodings, nonce widths, or direction-byte variants. Further runtime-protocol work must add a materially different property such as authenticated target acknowledgment/processing evidence, a genuinely concurrent host execution surface, or move to another independent architecture frontier.

## Milestone 63 — authenticated exact-response acknowledgment

### Slice 63A — one-response acknowledgment barrier

**Status: complete on `main`.** Composes 62A instead of duplicating its transport and adds a distinct peer-evidence step after each authenticated response publication.

Acceptance evidence is executable:

- `prepare_runtime_acknowledged_correlated_exchange(...)` reuses the exact 62A request/response bounds, fresh challenge, HMAC framing, request-ID uniqueness, and out-of-order response selection through a wrapper around the authenticated controller;
- after a successful authenticated response publication, the wrapper records exactly one outstanding tuple of request ID plus SHA-256 of the complete response bytes. No second response may be published while that barrier is active, and the peer's next packet must be the matching acknowledgment; any request or other frame before that acknowledgment is a terminal protocol-ordering failure;
- the peer acknowledgment frame is fixed-size `A || version=1 || request_id_le || sha256(response) || tag`. Its HMAC uses the same versioned domain/session challenge but a distinct acknowledgment direction byte and authenticates the full 32-byte response digest as payload;
- acknowledgment HMAC verification occurs before expected request-ID/digest comparison. A bad MAC inherits 62A's terminal `RuntimeAuthenticationFailed`; a validly authenticated but wrong request ID or response digest returns typed `RuntimeAcknowledgmentMismatch` and terminally closes the controller;
- successful acknowledgment increments a separate acknowledgment count and clears the barrier. Controller completion requires every configured request to have been accepted, every response to have been published, and every published response to have received its exact matching authenticated acknowledgment;
- broker-level integration uses the real readiness handshake and `SCM_RIGHTS` endpoint grant, refuses host-side request/response progression while response 42 awaits acknowledgment, clears that barrier only after the exact response digest is authenticated, then accepts the next request and completes later response/acknowledgment pairs;
- a dedicated ordering regression sends another valid authenticated request packet before the required acknowledgment and proves the shared ordered `SOCK_SEQPACKET` stream fails closed rather than skipping/reordering peer packets;
- a dedicated negative regression signs the SHA-256 of different response bytes with the correct session key/challenge and proves that cryptographic authenticity alone does not bypass exact-response binding;
- exact-head stable rustfmt, Clippy with `-D warnings`, complete stable tests, and the Rust 1.74 suite are the integration gate.

Boundary: 63A proves only that a peer possessing the shared session key emitted a valid acknowledgment frame bound to the exact response digest and session challenge. It does not prove that the peer actually performed a kernel read, executed business logic, committed side effects, durably persisted state, or could not precompute an acknowledgment for response bytes it already knew. The acknowledgment wait has no independent deadline in this slice, only one published response may await acknowledgment at a time, and the protocol remains non-encrypted shared-key messaging rather than attestation or general RPC.

### Milestone 63 promotion rule

After 63A integrates, do not farm acknowledgment digest algorithms, extra ACK flags, or larger outstanding-ACK counts. Further runtime work must change the host execution/liveness model materially—such as a bounded acknowledgment deadline or genuinely event-oriented concurrent host API—or move to another independent architecture frontier.

## Milestone 64 — strict direct dynamic-loader closure

### Slice 64A — fail closed on unbound direct `DT_NEEDED` edges

**Status: complete on `main`.** Strengthens the existing 49B binding from one selected direct dependency to complete direct-dependency closure for the supported single-path topology, without adding another policy slot or pretending to resolve general loader search.

Acceptance evidence is executable:

- the existing `executable.needed` + digest pair remains the only configuration surface; no count/path alias is added;
- production launch parses the sealed main ELF's complete bounded direct `DT_NEEDED` vector and requires its total length to be exactly one and that sole entry to equal the declared absolute dependency path byte-for-byte;
- configured-filesystem preflight enforces the same whole-set invariant before checking the dependency object and digest, reporting an explicit closure mismatch rather than treating one matching entry among several as sufficient evidence;
- the existing single-dependency dynamic fixture still executes through the sealed main + interpreter + dependency chain;
- a new real PIE fixture contains both `DT_NEEDED=/dependency` and `DT_NEEDED=/dependency-extra`; policy binds and hashes only `/dependency`, and launch must fail before target execution with direct-closure evidence instead of silently leaving `/dependency-extra` mutable;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and the Rust 1.74 suite are the integration gate.

Boundary: 64A is complete **direct** closure only for the already-supported one absolute path-qualified dependency topology. It deliberately rejects rather than resolves multiple direct dependencies. Slashless SONAME resolution, `DT_RPATH`/`DT_RUNPATH`, loader cache/default search, transitive dependencies, `LD_PRELOAD`, `dlopen`, and later exec remain separate future work.

### Milestone 64 promotion rule

After 64A integrates, do not add second/third direct path slots. The next execution-integrity promotion must model a bounded dependency set or real loader-resolution/transitive-closure semantics end-to-end, or move to another independent architecture frontier.

## Milestone 65 — sealed direct-dependency leaf closure

### Slice 65A — reject transitive `DT_NEEDED` beneath the sealed direct object

**Status: complete on `main`.** Extends the execution-integrity chain one real loader edge beyond 64A without adding another configured dependency slot: the sole sealed direct dependency must itself be a bounded ELF64 x86_64 `DT_NEEDED` leaf.

Acceptance evidence is executable:

- production first retains the 64A whole-set invariant on the content-bound main ELF, then SHA-256 verifies/copies the declared direct dependency into its sealed executable memfd;
- the launcher parses `DT_NEEDED` from that exact sealed dependency image, not from a later mutable host pathname, and requires the complete vector to be empty before constructing the private dependency mount;
- configured-filesystem preflight independently parses the same declared dependency after its bounded digest check and reports an explicit transitive-dependency incompatibility when any `DT_NEEDED` entry remains;
- the existing single path-qualified dependency fixture remains a valid leaf and continues to execute through the sealed main + interpreter + dependency chain;
- a new dependency fixture exports the symbol consumed by the main PIE but itself links to `/dependency-extra`; the main ELF therefore has exactly one valid direct edge while the sealed direct object has one transitive edge, and launch must fail before target execution with leaf-closure evidence;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and the Rust 1.74 suite are the integration gate.

Boundary: 65A does not resolve or seal a transitive dependency. It deliberately accepts only the supported one-direct-object topology when that object is an ELF leaf and rejects deeper loader graphs. It still does not model the interpreter's own loader inputs, slashless SONAME resolution, `DT_RPATH`/`DT_RUNPATH`, loader cache/default search, multiple direct dependencies, `LD_PRELOAD`, `dlopen`, or later exec transitions.

### Milestone 65 promotion rule

65A is sealed on `main`. Do not farm deeper fixed recursion depths. A further execution-integrity phase must model an explicitly bounded dependency graph/resolution algorithm end-to-end, or move to another independent architecture frontier.

## Milestone 66 — bounded exact direct dependency sets

### Slice 66A — seal an exact set of up to eight path-qualified direct dependencies

**Status: complete on `main`.** Generalizes the 64A/65A one-direct-object topology into one bounded exact direct-dependency set without introducing fixed second/third dependency slots or claiming general loader search.

Acceptance evidence is executable:

- repeated `executable.needed` and `executable.needed_sha256` entries form ordered pairs at parse time and normalize into 1–8 dependency bindings; the legacy single pair remains compatible;
- policy validation rejects unequal path/digest counts, duplicate dependency paths, more than eight bindings, mixed legacy/vector construction, missing sealed main/interpreter prerequisites, dynamic-linker token paths, and existing filesystem-overlap violations;
- production parses the sealed main ELF's complete direct `DT_NEEDED` vector, rejects duplicate ELF entries, and requires exact set equality with the declared paths independent of declaration order;
- every declared dependency is independently pinned, executable-shape checked, SHA-256 verified into its own sealed executable memfd, required to be a 65A leaf, and privately mounted at its declared path;
- configured-filesystem preflight enforces the same exact-set equality plus per-member object, digest, and leaf invariants;
- authority manifest output canonicalizes the normalized binding set, while authority-delta comparison treats absent/present as restriction changes and differing non-empty sets as incomparable;
- a real two-direct-dependency PIE succeeds only when both exact bindings are declared, while incomplete-set and transitive-edge regressions remain fail-closed;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 66A models only an exact bounded set of 1–8 absolute path-qualified direct dependencies, each of which must itself be an ELF leaf. It does not resolve slashless SONAMEs, RPATH/RUNPATH, loader cache/default search, interpreter dependency closure, transitive graphs, preload/dlopen behavior, or later exec transitions.

### Milestone 66 promotion rule

After 66A integrates, do not farm larger set ceilings or more declaration-order permutations. The next execution-integrity promotion must introduce a bounded loader-resolution/transitive graph model end-to-end, or move to another independent architecture frontier.

## Milestone 67 — bounded persistent-volume sets

### Slice 67A — generalize persistent host-directory grants into bounded RO/RW sets

**Status: complete on `main`.** Generalizes the legacy one-read-only plus one-writable volume surface into one bounded declarative set while preserving the same pinned-object mount architecture.

Acceptance evidence is executable:

- repeated `volume.readonly_source`/`volume.readonly_target` and `volume.writable_source`/`volume.writable_target` entries form ordered pairs and normalize into at most eight aggregate persistent-volume bindings; a single pair remains legacy-compatible;
- validation rejects unequal source/target counts, legacy-plus-vector mixing, aggregate counts above eight, any source overlap across RO/RW grants, any target overlap across RO/RW grants, root/scratch/procfs/executable/working-directory conflicts, and Landlock mutation paths outside the complete writable-target set;
- production prepares every normalized source through the existing pinned/reopened `(st_dev, st_ino)` identity path, recursively clones each mount tree, applies read-only mount attributes only to RO members, and attaches each object only at its declared sandbox target;
- configured-filesystem preflight independently checks every normalized source and target;
- authority JSON canonicalizes normalized RO/RW volume arrays, human output reports normalized counts, and authority-delta comparison uses set inclusion so added grants widen authority, removed grants reduce it, and partial replacement is incomparable;
- a raw-syscall target in one sandbox invocation reads two independent RO mounts, proves writes to both fail with `EROFS`, and persists independent writes through two RW mounts;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 67A still exposes only trusted-policy host directories as explicit bind-mount object capabilities. It does not infer filesystem alias equivalence beyond the existing lexical checks and pinned inode identity, does not make writable volumes transactional or snapshot-isolated, does not support per-volume quotas, and does not grant pathname mutation outside explicitly declared writable targets.

### Milestone 67 promotion rule

After 67A integrates, do not farm larger volume-count ceilings or fixed third/fourth slots. Promote to a distinct storage architecture capability such as per-volume bounded resource accounting/snapshot semantics, or move to another independent frontier.

## Milestone 68 — bounded exact dynamic-loader dependency graph

### Slice 68A — close a bounded reachable graph of sealed path-qualified DT_NEEDED nodes

**Status: complete on `main`.** Promotes the 66A exact direct set into one bounded transitive graph without adding fixed depth slots or claiming general dynamic-loader name resolution.

Acceptance evidence is executable:

- the existing repeated `executable.needed` / `executable.needed_sha256` surface remains the only dependency declaration and still normalizes to at most eight exact path/digest bindings; those bindings now define the complete sealed graph-node set rather than only direct leaves;
- a shared graph validator requires every main-image and transitive `DT_NEEDED` edge to be a literal absolute path naming one declared node, rejects duplicate edges, bounds cycles with visited-node tracking, and rejects declared nodes that are unreachable from the main executable;
- launch validates all main root edges against the declared node set before opening dependency objects, then independently pins, executable-shape checks, SHA-256 verifies, and seals every node before parsing that node's `DT_NEEDED` edges from the exact sealed bytes;
- only after full graph closure succeeds are all sealed graph nodes installed as private read-only `nosuid,nodev` mounts at their exact paths before the dynamic loader runs;
- configured-filesystem preflight uses the same root/graph validator after read-only per-node shape and digest verification, preventing policy/runtime closure drift;
- pure regressions cover reachable cycles plus undeclared, unreachable, duplicate, and non-literal edges;
- executable integration upgrades the existing transitive fixture: a main PIE reaches `/dependency-transitive -> /dependency-extra` and succeeds only when both exact sealed graph nodes are declared; missing the transitive node fails closed, and an extra unreachable declared node also fails closed;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 68A models only the already-bounded set of 1–8 literal absolute path-qualified graph nodes. It does not resolve slashless SONAMEs, `DT_RPATH`/`DT_RUNPATH`, loader cache/default search, the interpreter's own dependency graph, dynamic-string expansion, `LD_PRELOAD`, `dlopen`, or later target exec transitions.

### Milestone 68 promotion rule

After 68A integrates, do not farm deeper graph shapes, larger node ceilings, or more traversal-order variants. A further execution-integrity promotion must model a materially new loader-resolution surface such as bounded SONAME/search semantics or interpreter closure, or move to later-exec authority or another independent architectural frontier.

## Milestone 69 — bounded copy-on-write persistent volumes

### Slice 69A — private bounded writable overlays over trusted host directories

**Status: complete on `main`.** Promotes the 67A persistent-volume set from only immutable host exposure or explicit host write-through into a third materially different storage mode: bounded target-side mutation over a trusted host directory without mutating that host lower tree.

Acceptance evidence is executable:

- repeated `volume.cow_source`, `volume.cow_target`, and `volume.cow_bytes` entries form occurrence-indexed triples; every byte ceiling is 4 KiB–1 GiB and COW/RO/RW members share the existing aggregate ceiling of eight persistent-volume grants;
- validation requires equal triple counts, rejects source overlap with `filesystem.root`, root/scratch/executable/working-directory conflicts, and enforces pairwise non-overlap across every RO/RW/COW source and target; Landlock file-mutation paths may select directories only inside scratch, an explicit writable target, or an explicit COW target;
- parent preparation pins every COW source and target before fork. After namespace creation, launch reopens the absolute host source without symlink/magic-link traversal, revalidates `(st_dev, st_ino)`, recursively clones it, and applies recursive `MOUNT_ATTR_RDONLY` before any writable overlay is constructed;
- each COW member receives a private size-bounded `nosuid,nodev,noexec` tmpfs upper/work backing plus an OverlayFS merged mount with `metacopy=off` and `redirect_dir=nofollow`; only that merged mount is attached at the declared sandbox target, so target copy-up/new-file writes cannot write through to the configured host source;
- configured-filesystem preflight independently verifies every COW source and target anchor but reports the actual OverlayFS mount requirement as `unprobed` until a real user/mount-namespace launch succeeds, avoiding a false static compatibility claim;
- authority JSON canonicalizes COW bindings including byte ceilings; authority-delta comparison treats `(source,target)` as capability identity, added bindings or larger ceilings as widening, removed bindings or smaller ceilings as reduction, and partial replacement as incomparable;
- one raw-syscall executable reads lower bytes, mutates/copy-ups an existing file, creates another file, observes the private changes inside the run, and is executed twice while the host source remains byte-for-byte/topology unchanged between runs;
- a separate raw-syscall executable drives a 4-KiB COW backing until the kernel returns `ENOSPC`, proving the declared byte ceiling is enforced rather than documented only;
- exact-head stable rustfmt, Clippy with `-D warnings`, complete stable tests including the real namespace/mount integration oracles, and Rust 1.74 are the integration gate.

Boundary: 69A is an ephemeral per-volume OverlayFS capability, not a persistence/transaction layer. It does not export or replay a per-volume COW diff, commit changes back to the host source, provide overwrite transactions or fsync-backed crash durability, freeze the lower tree against concurrent hostile host mutation, preserve/attest metadata beyond normal filesystem semantics, prove filesystem alias separation beyond the existing lexical/inode checks, or claim the merged volume is globally `noexec`.

### Milestone 69 promotion rule

69A is sealed on `main`. Do not farm larger volume ceilings, fixed additional COW slots, alternate tmpfs sizes, or more copy-up permutations. A further storage promotion must add a materially new lifecycle property such as bounded per-volume diff/export plus explicit commit/replay semantics, or move to another independent architecture frontier.

## Milestone 71 — post-launch host-local stream capability

### Slice 71A — readiness-gated exact host AF_UNIX stream grant

**Status: complete on `main`.** Extends the existing RuntimeFdBroker from file/private-channel grants to one externally connected host-local stream object without widening target pathname or connect authority.

Acceptance evidence is executable:

- `prepare_host_unix_stream(path, expected_peer)` accepts one absolute bounded filesystem AF_UNIX pathname, connects in the trusted caller's host namespace, and snapshots Linux `SO_PEERCRED`;
- optional expected UID/GID mismatch returns a typed fail-closed error before a grant exists, while the prepared object exposes observed peer PID/UID/GID to the trusted caller;
- transfer reuses the existing exact target readiness byte, one-successful-grant session state, and one-descriptor `SCM_RIGHTS` path;
- the sandbox policy needs only the already-existing runtime broker `recvmsg` plus ordinary I/O syscalls; no `socket`, `connect`, or persistent target `execveat` grant is added;
- a raw-syscall target receives the connected descriptor after exec, exchanges exact request/response bytes with a real host AF_UNIX service, and independently requires `ENOENT` for the original host socket pathname inside the chroot;
- local regression proves peer credential evidence, typed mismatch, bidirectional stream behavior, and one-shot session reuse rejection;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 71A is one trusted-caller-selected connected stream object, not a target-selected service-discovery or routing API. It does not support abstract addresses, datagram/seqpacket modes, multiple connections per session, reconnect/failover, revocation after transfer, cryptographic service identity, or a general post-launch host IPC graph.

### Milestone 71 promotion rule

After 71A integrates, do not farm socket-type variants or fixed extra stream slots. A further host-local IPC promotion must add a materially different lifecycle such as a bounded trusted-controller connection set/reconnect policy or another independently mediated object class, or move to another architecture frontier.

## Milestone 73 — bounded host-local reconnect lifecycle

### Slice 73A — trusted-controller reconnects to one exact host AF_UNIX service

**Status: complete on `main`.** Promotes the 71A one-shot connected-stream grant into one explicitly bounded reconnect lifecycle without changing the existing one-shot `RuntimeFdSession` contract.

Acceptance evidence is executable:

- `accept_host_unix_reconnect_controller(service_path, expected_peer, max_connections)` accepts one exact absolute filesystem AF_UNIX service path and a connection ceiling restricted to 2–8;
- the controller reuses one already-verified long-lived runtime-broker control stream, but each grant round first consumes one exact target readiness byte and only then performs a fresh host-namespace `connect(2)`;
- every fresh connection independently re-reads Linux `SO_PEERCRED` and re-applies the same optional expected UID/GID pin before the connected descriptor can enter `SCM_RIGHTS` transfer;
- readiness mismatch, broker I/O failure, service connect failure, credential mismatch, or descriptor-transfer failure makes the whole reconnect controller terminally failed; exhausted connection bounds reject later grants;
- the original `RuntimeFdSession` remains one-readiness/one-successful-grant and is not silently converted into a reusable session type;
- local regressions prove two distinct fresh connections, per-round credential evidence, exact bound exhaustion, readiness-before-connect ordering, invalid-bound rejection, and terminal failure after a bad readiness byte;
- a dedicated raw-syscall sandbox target receives two distinct connected streams over one long-lived broker fd, exchanges different exact request/response bytes on each round, closes each granted stream, and still requires `ENOENT` for the original host service pathname;
- the target policy needs `recvmsg` plus ordinary stream I/O only and explicitly carries no `socket`, `connect`, or persistent `execveat` authority;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 73A is a bounded trusted-controller reconnect loop to one fixed filesystem AF_UNIX service. It is not target-selected service discovery, multi-service routing, failover policy, backoff/retry policy after an ambiguous failed round, abstract/datagram/seqpacket mediation, cryptographic service identity, revocation of an already-transferred descriptor, or a general host IPC graph.

### Milestone 73 promotion rule

After 73A integrates, do not farm larger reconnect ceilings, more readiness-byte variants, or fixed additional service slots. A further host-local IPC promotion must add a materially different authority/lifecycle property such as explicitly modeled multi-service selection with independent bounds, post-transfer lifetime mediation, or another object class, or move to another architecture frontier.

## Milestone 74 — post-transfer host-stream lifetime mediation

### Slice 74A — revoke one transferred host AF_UNIX stream object

**Status: complete on `main`.** Adds opt-in trusted-controller revocation for one already-prepared 71A connected stream without changing the ordinary one-shot transfer or the 73A bounded reconnect controller.

Acceptance evidence is executable:

- `RuntimeFdSession::send_revocable_host_unix_stream(grant)` consumes the same readiness-gated one-successful-grant state transition as the existing one-shot host-stream transfer and returns a controller only after successful `SCM_RIGHTS` publication;
- the controller retains a trusted descriptor for the same connected socket object plus the already-observed `SO_PEERCRED` PID/UID/GID evidence;
- `revoke()` performs exactly one `shutdown(SHUT_RDWR)`; a second explicit revoke is a protocol error and a shutdown error terminally marks the controller failed;
- dropping a still-active controller attempts the same bidirectional shutdown, so accidental controller loss fails closed instead of silently abandoning revocation authority;
- local kernel regressions prove the transferred descriptor exchanges bytes before revocation, then observes EOF on reads and `EPIPE` on `MSG_NOSIGNAL` sends after explicit revoke, and the same EOF/EPIPE state after active-controller drop;
- a dedicated raw-syscall sandbox target reaches the exact prepared host service before revocation, blocks in `read`, wakes to EOF after trusted shutdown, and still requires `ENOENT` for the original host service pathname;
- the target policy continues to require only the existing broker `recvmsg` plus ordinary stream I/O and explicitly carries no target `socket`, `connect`, or persistent `execveat` authority;
- stable rustfmt, Clippy with `-D warnings`, complete stable tests, and Rust 1.74 are the integration gate.

Boundary: 74A changes only the shutdown state of one already-authorized connected AF_UNIX socket object. It does not close or invalidate the target's numeric descriptor, retract bytes already consumed, undo remote service side effects, cryptographically authenticate the service, revoke unrelated descriptors/connections, add target-selected service discovery, or provide a general descriptor-revocation framework.

### Milestone 74 promotion rule

After 74A integrates, do not farm shutdown-mode variants or revocation aliases. A further host-local IPC promotion must add a materially different capability such as independently bounded multi-service selection/routing, explicit application-level revocation acknowledgment, or another mediated object class.

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, routed/broader network authority beyond the bounded IPv4 brokers, broader dynamic host-local IPC mediation beyond one exact bounded reconnect/revocation lifecycle, bounded loader search/interpreter closure or later-exec authority, per-volume COW diff/commit or stronger storage lifecycle semantics, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
