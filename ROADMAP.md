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

**Current verified candidate.** Adds a symmetric authentication property over the existing bounded canonical snapshot identity rather than another digest placement or replay gate.

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

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, broader host-local IPC mediation beyond the bounded receive-only SCM_RIGHTS handoff, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
