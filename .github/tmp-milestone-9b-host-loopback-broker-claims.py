from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README — claim only the verified launcher-brokered connected-socket capability.
replace_one(
    "README.md",
    "The current Milestone 9A verified candidate adds **policy-owned isolated loopback networking**: `network.loopback = enabled` activates only `lo` inside the already-private network namespace, while the default keeps loopback down and no host/external network attachment is created.",
    "Milestone 9A added **policy-owned isolated loopback networking** inside the private network namespace. The current Milestone 9B verified candidate adds **one launcher-brokered host-loopback TCP endpoint capability**: the trusted parent connects to exactly `127.0.0.1:<declared-port>` in the host network namespace and remaps that already-connected socket to one declared target descriptor without attaching the target network namespace to the host.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only or writable volume source/target pairs, `network.loopback`, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. `network.loopback` accepts only `enabled` or `disabled` and defaults to disabled. Selected target descriptors are limited to 3–63, must remain below `limit.open_files`, and no more than 16 mappings are accepted.",
    "Optional read-only or writable volume source/target pairs, `network.loopback`, one brokered host-loopback TCP port/target-fd pair, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. `network.loopback` accepts only `enabled` or `disabled` and defaults to disabled. A brokered TCP port must be 1–65535; its target fd must be 3–63, below `limit.open_files`, and distinct from every `handle.*` destination. Selected-handle mappings remain limited to 16.",
    "README policy summary",
)
replace_one(
    "README.md",
    "2. **Parent preparation** pins the root, cwd, initial executable, every declared selected-handle source, and any declared read-only or writable volume source/target before `fork`. `openat2` rejects symlink/magic-link traversal and constrains configured paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`. Selected source descriptors are duplicated with `CLOEXEC`, inspected with `fstat`, and directory descriptors are rejected; launcher-owned storage descriptors are placed above every declared target destination to prevent remap collisions.",
    "2. **Parent preparation** pins the root, cwd, initial executable, every declared selected-handle source, and any declared read-only or writable volume source/target before `fork`. If a brokered host-loopback endpoint is declared, the trusted parent also creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects it to exactly `127.0.0.1:<declared-port>` while still in the host network namespace; failure is a setup error rather than a fallback. `openat2` rejects symlink/magic-link traversal and constrains configured filesystem paths beneath the selected root. The target inode is retained for `execveat(AT_EMPTY_PATH)`. Selected sources and the brokered socket use the same collision-safe launcher storage plane above every declared target destination.",
    "README parent preparation",
)
replace_one(
    "README.md",
    "9. **Target enforcement** the direct target alone applies explicit stdio, installs declared selected handles with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`.",
    "9. **Target enforcement** the direct target alone applies explicit stdio, installs declared selected handles and any brokered connected socket with `dup3`, then applies rlimits, capability reduction, `no_new_privs`, default-deny seccomp, and pinned `execveat`.",
    "README target enforcement",
)
replace_one(
    "README.md",
    "- Target network authority remains explicit at the syscall layer: networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when policy names them. Namespace creation and launcher-owned loopback activation do not widen target seccomp.\n",
    "- Target network authority remains explicit at the syscall layer: networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when policy names them. Namespace creation and launcher-owned loopback activation do not widen target seccomp.\n- A declared brokered host-loopback TCP endpoint is a single already-connected socket capability, not host routing: the launcher connects only to the declared IPv4 `127.0.0.1` port before fork, stores the socket collision-free, and exposes it only at the declared target fd. The target's own fresh sockets remain in the isolated network namespace.\n",
    "README broker invariant",
)
replace_one(
    "README.md",
    "`network.loopback` is optional and accepts only `enabled` or `disabled`; absence is equivalent to `disabled`. Enabling it authorizes the trusted launcher to bring up only `lo` inside the already-isolated network namespace. It does not attach a veth/bridge, install host/external routes or DNS, or grant target networking syscalls.\n",
    "`network.loopback` is optional and accepts only `enabled` or `disabled`; absence is equivalent to `disabled`. Enabling it authorizes the trusted launcher to bring up only `lo` inside the already-isolated network namespace. It does not attach a veth/bridge, install host/external routes or DNS, or grant target networking syscalls.\n\nOne optional host-loopback TCP endpoint is declared with the all-or-nothing pair `network.host_loopback_tcp_port = <1..65535>` and `network.host_loopback_tcp_target_fd = <3..63>`. The target fd must be below `limit.open_files` and must not collide with a `handle.*` target. The trusted launcher connects to IPv4 `127.0.0.1` during parent preparation and exposes only that already-connected stream at the declared fd. This is explicit object authority to one host service; it does not give the target a host route or arbitrary host-network socket access.\n",
    "README broker policy",
)
replace_one(
    "README.md",
    "- separately, a host `127.0.0.1` TCP listener is first proven reachable from the host process, then an enabled-loopback sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempts that same host port; only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH` are accepted, while seccomp `EPERM` or successful cross-namespace reachability fails the fixture;\n",
    "- separately, a host `127.0.0.1` TCP listener is first proven reachable from the host process, then an enabled-loopback sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempts that same host port; only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH` are accepted, while seccomp `EPERM` or successful cross-namespace reachability fails the fixture;\n- for the brokered endpoint, the trusted parent binds a real host `127.0.0.1` listener and declares its port plus target fd 10. The raw target writes exact `brokered-host-loopback-ok` bytes through fd 10, while a fresh target-created socket attempting the same host port must still fail with `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; the host then accepts the brokered connection and reads the exact marker.\n",
    "README broker evidence",
)
replace_one(
    "README.md",
    "When policy-owned loopback is enabled, the launcher additionally requires an IPv4 datagram management socket plus `SIOCGIFFLAGS`/`SIOCSIFFLAGS` support for the private namespace's `lo` device.",
    "When policy-owned loopback is enabled, the launcher additionally requires an IPv4 datagram management socket plus `SIOCGIFFLAGS`/`SIOCSIFFLAGS` support for the private namespace's `lo` device. A brokered host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation.",
    "README platform requirements",
)
replace_one(
    "README.md",
    "- the launcher creates an isolated network namespace and may explicitly activate only its private loopback device, but it still does **not** configure veth devices, a host bridge, host/external routes, DNS, NAT, an endpoint allowlist, or a controlled egress path. Milestone 9A is isolated intra-sandbox loopback, not a complete network-policy subsystem;\n",
    "- the launcher creates an isolated network namespace and may explicitly activate only its private loopback device. Milestone 9B can broker one already-connected IPv4 `127.0.0.1` TCP stream, but it still does **not** configure veth devices, a host bridge, host/external routes, DNS, NAT, arbitrary IP/hostname egress, UDP, ingress/listening exposure, TLS, or a general endpoint allowlist. The broker connection is established during parent preparation, so a host service can observe that connection even if a later sandbox setup phase fails;\n",
    "README networking limitations",
)
replace_one(
    "README.md",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or configured host/external network endpoint policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory, while Milestone 9A only controls isolated loopback activation;\n",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or general host/external network routing policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory, while Milestones 9A/9B cover isolated loopback plus one launcher-brokered host-loopback TCP stream;\n",
    "README later limitations",
)

# ROADMAP — seal 9A and promote the executable broker slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds real positive connectivity inside the private network namespace without attaching it to the host or an external network.",
    "**Status: complete on `main`.** Adds real positive connectivity inside the private network namespace without attaching it to the host or an external network.",
    "ROADMAP 9A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 9 promotion rule\n\nAfter 9A integrates, do not farm loopback ports, protocol variants, or aliases. The next networking slice must add a materially different topology or host/external endpoint capability with explicit positive and negative executable evidence. Milestone 4A aggregate cgroup accounting remains blocked until real unprivileged cgroup-v2 delegation is available; supplementary-group isolation remains a separate user-namespace mapping problem.\n",
    "### Slice 9B — launcher-brokered host-loopback TCP endpoint\n\n**Current verified candidate.** Adds one explicit host endpoint object capability without attaching the target network namespace to the host.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `network.host_loopback_tcp_port` / `network.host_loopback_tcp_target_fd`; the port is 1–65535, the fd is 3–63 and below `limit.open_files`, and collision with a `handle.*` target is rejected fail-closed;\n- before fork and before entering the sandbox network namespace, the trusted parent creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects only to `127.0.0.1:<declared-port>`; connection failure is an explicit setup failure rather than a fallback;\n- the brokered socket participates in the existing collision-safe selected-object storage floor and is installed only into the direct target at the declared fd; host parent, bootstrap, and namespace PID 1 do not retain a launcher-owned copy while the target runs;\n- a host listener receives exact `brokered-host-loopback-ok` bytes written by the raw target through brokered fd 10;\n- in the same run, a fresh socket created by that target attempts the same host loopback port and must still fail with `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` or successful direct host reachability fails the oracle;\n- 9A default-down/intra-sandbox-loopback/host-separation evidence and all Milestones 1–8B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 9B is one launcher-created, already-connected IPv4 TCP stream to host `127.0.0.1`. It does not provide arbitrary IP/hostname endpoints, DNS, UDP, ingress/listening exposure, veth/bridge/routes/NAT, TLS/application authentication, a general network ACL, or a separate parent-preparation connection deadline. The host service may observe the broker connection before later sandbox setup completes.\n\n### Milestone 9 promotion rule\n\nAfter 9B integrates, do not farm extra ports, target-fd aliases, or protocol-name variants around the same preconnected-socket mechanism. Further networking work must add a materially different endpoint/topology authority boundary with new executable evidence; otherwise promote to a different architectural frontier. Milestone 4A aggregate cgroup accounting remains blocked until real unprivileged cgroup-v2 delegation is available; supplementary-group isolation remains a separate user-namespace mapping problem.\n",
    "ROADMAP 9B section",
)
replace_one(
    "ROADMAP.md",
    "Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, externally attached controlled networking, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers.",
    "Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, network authority beyond one preconnected host-loopback stream, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers.",
    "ROADMAP later frontiers",
)

# THREAT MODEL — distinguish route authority from an already-connected object capability.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–9A threat model",
    "# Milestones 1–9B threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 9A verified candidate adds policy-owned activation of only the isolated network namespace's loopback device, with executable proof for default-down behavior, positive intra-sandbox TCP, and continued host-loopback separation.",
    "Milestone 9A added policy-owned activation of only the isolated network namespace's loopback device. The current Milestone 9B verified candidate adds one launcher-created, already-connected IPv4 TCP socket to a declared host-loopback port while preserving the target network namespace's direct host separation.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "optional isolated-loopback activation, stdio, bounded capture",
    "optional isolated-loopback activation, one optional brokered host-loopback TCP socket capability, stdio, bounded capture",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Policy-owned isolated loopback:** the launcher creates `CLONE_NEWNET` without host/external attachment. Loopback is down by default; if `network.loopback = enabled`, the trusted setup path alone uses `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set `IFF_UP` on `lo`, then closes its management socket before target execution. No veth, host bridge, routes, DNS, NAT, or endpoint attachment is introduced, so host loopback remains a different network stack.\n",
    "- **Policy-owned isolated loopback:** the launcher creates `CLONE_NEWNET` without host/external attachment. Loopback is down by default; if `network.loopback = enabled`, the trusted setup path alone uses `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set `IFF_UP` on `lo`, then closes its management socket before target execution. No veth, host bridge, routes, DNS, or endpoint attachment is introduced, so host loopback remains a different network stack.\n- **Brokered host-loopback TCP capability:** when the port/fd pair is declared, the trusted parent connects a `SOCK_CLOEXEC` IPv4 TCP socket to exactly host `127.0.0.1:<port>` before fork, stores it above target-visible destinations, and remaps it only into the direct target at the declared fd. This grants one connected object capability; it does not attach the target netns or create host routing.\n",
    "threat broker property",
)
replace_one(
    "THREAT_MODEL.md",
    "This creates only intra-namespace loopback connectivity: no veth, bridge, host/external route, DNS, NAT, or endpoint policy is installed. A future externally attached networking slice must add a materially new topology/endpoint policy with positive and negative executable evidence rather than re-label this loopback mechanism.",
    "This creates only intra-namespace loopback connectivity: no veth, bridge, host/external route, DNS, or NAT is installed. Separately, a declared 9B broker endpoint is connected by the trusted parent while it is still in the host network namespace and then passed as an already-connected object capability. The target's own sockets remain in the isolated network namespace, so this broker does not turn into a host route.",
    "threat network semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- a configured veth/bridge, host/external routes, DNS, NAT, endpoint allowlist, or controlled outbound/inbound network path. Milestone 9A adds only policy-owned isolated loopback on top of the Milestone 4B namespace boundary;\n",
    "- a configured veth/bridge, host/external routes, DNS, NAT, arbitrary IP/hostname endpoint policy, UDP, ingress/listening exposure, TLS/application authentication, or a general controlled outbound/inbound network path. Milestone 9B adds only one launcher-preconnected IPv4 `127.0.0.1` TCP stream; that host connection may be observed before later sandbox setup completes and has no separate parent-preparation deadline;\n",
    "threat network non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, selected-handle installation, and teardown execute in trusted launcher processes outside target seccomp. `dup3` used to install a selected target descriptor is not silently added to `seccomp.allow`; subsequent operations on that object still require the target syscalls explicitly granted by policy. target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup does not add them implicitly.\n",
    "- **No target-policy widening:** namespace management, pidfd/timerfd/poll, mounts, capture/remapping, selected-handle/broker installation, and teardown execute in trusted launcher processes outside target seccomp. `dup3` used to install a target descriptor is not silently added to `seccomp.allow`; subsequent operations on an exposed object still require the target syscalls explicitly granted by policy. Target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup and host-side broker creation do not add them implicitly.\n",
    "threat no widening",
)
replace_one(
    "THREAT_MODEL.md",
    "The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect and SysV IPC syscalls remain independently controlled by seccomp. Explicitly inherited stdio objects remain an intentional exception: namespace creation does not retroactively revoke an already-open socket, pipe, or other descriptor capability exposed through `stdio.* = inherit`.",
    "The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect and SysV IPC syscalls remain independently controlled by seccomp. Already-open descriptor capabilities are intentional exceptions to pathname/network-namespace reachability: this includes inherited stdio objects and the explicitly declared 9B broker socket. Namespace creation does not retroactively revoke those object capabilities.",
    "threat object capability semantics",
)
