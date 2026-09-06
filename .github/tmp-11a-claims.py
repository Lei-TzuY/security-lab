from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal already-integrated 10B and describe only verified 11A authority.
replace_one(
    "README.md",
    "The current Milestone 10B verified candidate adds an independent **Landlock regular-file mutation envelope** that can only narrow already-writable scratch or persistent-volume surfaces.",
    "Milestone 10B added an independent **Landlock regular-file mutation envelope** that can only narrow already-writable scratch or persistent-volume surfaces. The current Milestone 11A verified candidate adds **one launcher-brokered host-loopback TCP listener capability** without attaching the target network namespace to host routing.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "one brokered host-loopback TCP port/target-fd pair",
    "one brokered connected host-loopback TCP port/target-fd pair, one brokered host-loopback TCP listener port/target-fd pair",
    "README policy broker list",
)
replace_one(
    "README.md",
    "A brokered TCP port must be 1–65535; its target fd must be 3–63, below `limit.open_files`, and distinct from every `handle.*` destination.",
    "Each brokered TCP port must be 1–65535; each target fd must be 3–63, below `limit.open_files`, and distinct from every `handle.*` destination. Connected-stream and listener target fds must also be distinct from each other.",
    "README broker validation",
)
replace_one(
    "README.md",
    "If a brokered host-loopback endpoint is declared, the trusted parent also creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects it to exactly `127.0.0.1:<declared-port>` while still in the host network namespace; failure is a setup error rather than a fallback.",
    "If a brokered connected host-loopback endpoint is declared, the trusted parent creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects it to exactly `127.0.0.1:<declared-port>` while still in the host network namespace. If a brokered listener is declared, the parent separately creates a `SOCK_CLOEXEC` IPv4 TCP socket, binds it only to `127.0.0.1:<declared-listen-port>`, and calls `listen`; connect/bind/listen failure is a setup error rather than a fallback.",
    "README parent broker setup",
)
replace_one(
    "README.md",
    "Selected sources and the brokered socket use the same collision-safe launcher storage plane above every declared target destination.",
    "Selected sources and brokered sockets use the same collision-safe launcher storage plane above every declared target destination.",
    "README broker storage",
)
replace_one(
    "README.md",
    "installs declared selected handles and any brokered connected socket with `dup3`",
    "installs declared selected handles and any brokered connected/listening sockets with `dup3`",
    "README target broker install",
)
replace_one(
    "README.md",
    "- A declared brokered host-loopback TCP endpoint is a single already-connected socket capability, not host routing: the launcher connects only to the declared IPv4 `127.0.0.1` port before fork, stores the socket collision-free, and exposes it only at the declared target fd. The target's own fresh sockets remain in the isolated network namespace.\n",
    "- A declared brokered host-loopback TCP endpoint is a single already-connected socket capability, not host routing: the launcher connects only to the declared IPv4 `127.0.0.1` port before fork, stores the socket collision-free, and exposes it only at the declared target fd. The target's own fresh sockets remain in the isolated network namespace.\n- A declared brokered host-loopback TCP listener is a separate listening-socket object capability: the launcher binds only host `127.0.0.1:<declared-port>` before fork and exposes that listener only at the declared target fd. Host-local clients can reach that explicit listener, but this does not install a host route, veth, bridge, DNS, NAT, or general inbound network path in the target namespace.\n",
    "README listener invariant",
)
replace_one(
    "README.md",
    "One optional host-loopback TCP endpoint is declared with the all-or-nothing pair `network.host_loopback_tcp_port = <1..65535>` and `network.host_loopback_tcp_target_fd = <3..63>`. The target fd must be below `limit.open_files` and must not collide with a `handle.*` target. The trusted launcher connects to IPv4 `127.0.0.1` during parent preparation and exposes only that already-connected stream at the declared fd. This is explicit object authority to one host service; it does not give the target a host route or arbitrary host-network socket access.\n",
    "One optional host-loopback TCP endpoint is declared with the all-or-nothing pair `network.host_loopback_tcp_port = <1..65535>` and `network.host_loopback_tcp_target_fd = <3..63>`. The target fd must be below `limit.open_files` and must not collide with a `handle.*` target. The trusted launcher connects to IPv4 `127.0.0.1` during parent preparation and exposes only that already-connected stream at the declared fd. This is explicit object authority to one host service; it does not give the target a host route or arbitrary host-network socket access.\n\nOne optional host-loopback TCP ingress listener is independently declared with `network.host_loopback_tcp_listen_port = <1..65535>` and `network.host_loopback_tcp_listen_target_fd = <3..63>`. The pair is all-or-nothing; its target fd must be below `limit.open_files`, must not collide with `handle.*`, and must differ from the connected-broker target fd when both are present. The trusted parent binds/listens only on IPv4 `127.0.0.1` and passes the listener as an object capability. The policy author must separately grant target `accept`/I/O syscalls; this is not arbitrary inbound routing or external-network exposure.\n",
    "README listener policy format",
)
replace_one(
    "README.md",
    "- for the brokered endpoint, the trusted parent binds a real host `127.0.0.1` listener and declares its port plus target fd 10. The raw target writes exact `brokered-host-loopback-ok` bytes through fd 10, while a fresh target-created socket attempting the same host port must still fail with `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; the host then accepts the brokered connection and reads the exact marker.\n",
    "- for the brokered endpoint, the trusted parent binds a real host `127.0.0.1` listener and declares its port plus target fd 10. The raw target writes exact `brokered-host-loopback-ok` bytes through fd 10, while a fresh target-created socket attempting the same host port must still fail with `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; the host then accepts the brokered connection and reads the exact marker.\n- for brokered ingress, the raw target first publishes exact `brokered-host-ingress-ready\\n` bytes through selected fd 9, then blocks in `accept` on brokered listener fd 10. Only after the parent reads that readiness marker does a host `127.0.0.1` client connect, send exact `brokered-host-ingress-request` bytes, and require exact `brokered-host-ingress-ok` reply bytes. A separate occupied-port regression requires launcher setup to return `SetupFailed` rather than running without the declared listener.\n",
    "README listener evidence",
)
replace_one(
    "README.md",
    "A brokered host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation.",
    "A brokered connected host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation; a brokered ingress listener additionally requires host-side IPv4 TCP `socket`/`bind`/`listen`.",
    "README platform broker requirements",
)
replace_one(
    "README.md",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or general host/external network routing policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory, while Milestones 9A/9B cover isolated loopback plus one launcher-brokered host-loopback TCP stream;",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or general host/external network routing policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory, while Milestones 9A/9B/11A cover isolated loopback plus one launcher-brokered connected host-loopback TCP stream and one host-loopback listener capability;",
    "README networking limitation",
)

# Threat model: seal 10B, add 11A as explicit listener object authority.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–10B threat model",
    "# Milestones 1–11A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 10B verified candidate adds an independent regular-file mutation envelope constrained to already-writable scratch or persistent-volume authority.",
    "Milestone 10B added an independent regular-file mutation envelope constrained to already-writable scratch or persistent-volume authority. The current Milestone 11A verified candidate adds one host-loopback TCP listener object capability while preserving the target network namespace's lack of host routing.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered host-loopback TCP socket capability",
    "one optional brokered connected host-loopback TCP socket capability and one optional brokered host-loopback TCP listener capability",
    "threat protected broker boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP capability:** when the port/fd pair is declared, the trusted parent connects a `SOCK_CLOEXEC` IPv4 TCP socket to exactly host `127.0.0.1:<port>` before fork, stores it above target-visible destinations, and remaps it only into the direct target at the declared fd. This grants one connected object capability; it does not attach the target netns or create host routing.\n",
    "- **Brokered host-loopback TCP capability:** when the port/fd pair is declared, the trusted parent connects a `SOCK_CLOEXEC` IPv4 TCP socket to exactly host `127.0.0.1:<port>` before fork, stores it above target-visible destinations, and remaps it only into the direct target at the declared fd. This grants one connected object capability; it does not attach the target netns or create host routing.\n- **Brokered host-loopback TCP ingress listener:** when the listener port/fd pair is declared, the trusted parent creates a separate `SOCK_CLOEXEC` IPv4 TCP socket, binds it only to host `127.0.0.1:<port>`, calls `listen`, stores it on the same collision-safe launcher plane, and remaps it only into the direct target at the declared fd. Host-local clients may connect to that explicit listener; no host/external route is installed in the target namespace.\n",
    "threat listener property",
)
replace_one(
    "THREAT_MODEL.md",
    "or the 9B broker.",
    "or the 9B/11A brokered sockets.",
    "threat object capability exception",
)
replace_one(
    "THREAT_MODEL.md",
    "Separately, a declared 9B broker endpoint is connected by the trusted parent while it is still in the host network namespace and then passed as an already-connected object capability. The target's own sockets remain in the isolated network namespace, so this broker does not turn into a host route.",
    "Separately, a declared 9B broker endpoint is connected by the trusted parent while it is still in the host network namespace and then passed as an already-connected object capability. A declared 11A ingress broker is likewise created in the host network namespace, but is bound only to host `127.0.0.1` and passed as a listening object capability; accepted streams derive from that explicit listener. The target's own sockets remain in the isolated network namespace, so neither broker turns into a host route.",
    "threat network semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "this includes inherited stdio objects and the explicitly declared 9B broker socket.",
    "this includes inherited stdio objects, the explicitly declared 9B connected broker socket, and the 11A listener/accepted-stream authority derived from the declared listener.",
    "threat network object exception",
)
replace_one(
    "THREAT_MODEL.md",
    "- a configured veth/bridge, host/external routes, DNS, NAT, arbitrary IP/hostname endpoint policy, UDP, ingress/listening exposure, TLS/application authentication, or a general controlled outbound/inbound network path. Milestone 9B adds only one launcher-preconnected IPv4 `127.0.0.1` TCP stream; that host connection may be observed before later sandbox setup completes and has no separate parent-preparation deadline;",
    "- a configured veth/bridge, host/external routes, DNS, NAT, arbitrary IP/hostname endpoint policy, UDP, TLS/application authentication, or a general controlled outbound/inbound network path. Milestone 9B adds only one launcher-preconnected IPv4 `127.0.0.1` TCP stream and Milestone 11A adds only one launcher-bound IPv4 `127.0.0.1` TCP listener capability; broker creation occurs during parent preparation and has no separate preparation deadline;",
    "threat network non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 8B are complete on `main`; the bounded persistent-volume authority model is sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. The current Milestone 9A verified candidate adds policy-owned isolated loopback with default-down, positive intra-sandbox TCP, and host-loopback separation evidence. After 9A integrates, do not farm more loopback ports, protocols, or aliases; the next networking promotion must add a materially different topology or host/external endpoint capability with explicit positive/negative evidence. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow.",
    "Milestones through 10B are complete on `main`; the bounded persistent-volume and pathname-envelope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 11A verified candidate adds one host-loopback TCP ingress listener object capability with exact positive request/reply evidence and fail-closed bind failure. After 11A integrates, do not farm additional ports, backlog values, or protocol aliases; the next networking promotion must materially change endpoint/routing authority and carry explicit positive/negative evidence.",
    "threat phase promotion",
)

# Roadmap: seal integrated 10B and promote the existing verified 11A implementation.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a separate pathname-mutation authority dimension that composes with the two existing writable surfaces rather than broadening them.",
    "**Status: complete on `main`.** Adds a separate pathname-mutation authority dimension that composes with the two existing writable surfaces rather than broadening them.",
    "roadmap 10B status",
)
replace_one(
    "ROADMAP.md",
    "After 10B integrates, seal this bounded pathname-envelope phase. Do not farm more regular-file mutation aliases or path-count variants. Promote to a materially different authority or resource frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.",
    "Milestone 10B is integrated; seal this bounded pathname-envelope phase. Do not farm more regular-file mutation aliases or path-count variants. Promote to a materially different authority or resource frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.",
    "roadmap 10 promotion",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, network authority beyond one preconnected host-loopback stream, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "## Milestone 11 — host-loopback ingress object authority\n\n### Slice 11A — one brokered host-loopback TCP listener\n\n**Current verified candidate.** Adds a materially different inbound object capability without attaching the target network namespace to host or external routing.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `network.host_loopback_tcp_listen_port` / `network.host_loopback_tcp_listen_target_fd`; the port is 1–65535, the fd is 3–63 and below `limit.open_files`, and the target cannot collide with selected handles or the 9B connected-broker target;\n- the trusted parent creates `SOCK_STREAM|SOCK_CLOEXEC`, binds only host IPv4 `127.0.0.1:<declared-port>`, calls `listen`, and moves the listener onto the same collision-safe launcher storage plane used by selected handles and the 9B broker; bind/listen failure is terminal rather than a fallback;\n- only the direct target receives the listener at the declared fd; its use remains subject to explicit target seccomp grants such as `accept`, `read`, `write`, and `close`;\n- the raw target publishes exact `brokered-host-ingress-ready\\n` bytes on selected fd 9 before calling `accept` on fd 10. Only after the host reads readiness does a host-loopback client connect, send exact `brokered-host-ingress-request` bytes, and receive exact `brokered-host-ingress-ok` reply bytes;\n- a separately occupied host-loopback port causes `SetupFailed` before untrusted execution, proving the listener is not silently omitted;\n- the target's own sockets remain in its isolated network namespace: 11A is one pre-opened listener object capability, not a veth/bridge, host route, NAT, DNS, arbitrary endpoint allowlist, or external ingress path;\n- all Milestones 1–10B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 11A grants one host-loopback TCP listening object. It does not promise exactly one accepted connection, expose non-loopback interfaces, provide UDP/TLS/application authentication, or configure general inbound routing.\n\n### Milestone 11 promotion rule\n\nAfter 11A integrates, seal the single-listener object-capability slice. Do not farm additional port numbers, backlog values, or equivalent listener aliases. Promote only to a materially different network topology/endpoint authority or another evidence-backed resource frontier.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, network authority beyond one preconnected host-loopback stream plus one host-loopback listener, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 11A section",
)
