from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal integrated 14A and describe only verified 15A behavior.
replace_one(
    "README.md",
    "The current Milestone 14A verified candidate adds an optional **Landlock device-ioctl envelope** that narrows ioctl authority for character/block devices opened after the target enters its Landlock domain.",
    "Milestone 14A added an optional **Landlock device-ioctl envelope** that narrows ioctl authority for character/block devices opened after the target enters its Landlock domain. The current Milestone 15A verified candidate adds **one exact numeric host-IPv4 TCP endpoint broker**: the trusted parent connects to a declared IPv4 address and port before fork and transfers only that already-connected socket capability into the otherwise isolated target.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "one brokered connected host-loopback TCP port/target-fd pair, one brokered host-loopback TCP listener port/target-fd pair, scratch",
    "one brokered connected host-loopback TCP port/target-fd pair, one exact numeric host-IPv4 TCP address/port/target-fd triple, one brokered host-loopback TCP listener port/target-fd pair, scratch",
    "README policy surface",
)
replace_one(
    "README.md",
    "If a brokered connected host-loopback endpoint is declared, the trusted parent creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects it to exactly `127.0.0.1:<declared-port>` while still in the host network namespace. If a brokered listener is declared,",
    "If a brokered connected host-loopback endpoint is declared, the trusted parent creates a `SOCK_CLOEXEC` IPv4 TCP socket and connects it to exactly `127.0.0.1:<declared-port>` while still in the host network namespace. If an exact host-IPv4 broker is declared, the same launcher-owned path instead connects to exactly the configured numeric unicast IPv4 address and port; address, port, and target fd are all-or-nothing and the target receives only the connected socket object. If a brokered listener is declared,",
    "README parent broker",
)
replace_one(
    "README.md",
    "- A declared brokered host-loopback TCP endpoint is a single already-connected socket capability, not host routing: the launcher connects only to the declared IPv4 `127.0.0.1` port before fork, stores the socket collision-free, and exposes it only at the declared target fd. The target's own fresh sockets remain in the isolated network namespace.\n",
    "- A declared brokered host-loopback TCP endpoint is a single already-connected socket capability, not host routing: the launcher connects only to the declared IPv4 `127.0.0.1` port before fork, stores the socket collision-free, and exposes it only at the declared target fd. The target's own fresh sockets remain in the isolated network namespace.\n- A declared exact host-IPv4 TCP endpoint is the same object-capability model with address selection added: the launcher connects to exactly one numeric unicast IPv4 address plus port in the host network namespace, stores the connected socket on the collision-safe launcher plane, and exposes only that object at the declared target fd. The executable oracle binds the same TCP port on host `127.0.0.1` and `127.0.0.2`, selects `127.0.0.2`, proves only that listener receives the brokered stream, and separately preserves direct target-netns isolation.\n",
    "README IPv4 invariant",
)
replace_one(
    "README.md",
    "Milestone 9B can broker one already-connected IPv4 `127.0.0.1` TCP stream, Milestone 11A can broker one host-loopback listener, and Milestone 12A can narrow target-created TCP bind/connect ports, but none of these configure veth devices, a host bridge, host/external routes, DNS, NAT, arbitrary IP/hostname egress, UDP, TLS, or a general endpoint allowlist.",
    "Milestone 9B can broker one already-connected IPv4 `127.0.0.1` TCP stream, Milestone 11A can broker one host-loopback listener, Milestone 12A can narrow target-created TCP bind/connect ports, and Milestone 15A can broker one already-connected stream to an exact numeric host IPv4 address and port, but none of these configure veth devices, a host bridge, host/external routes, DNS, NAT, hostname policy, UDP, TLS, or a general CIDR/endpoint allowlist.",
    "README networking limitation",
)

# Threat model: exact object capability, not target-side firewalling.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–14A threat model",
    "# Milestones 1–15A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 14A verified candidate adds ABI-5 device-ioctl mediation for character/block devices opened after Landlock restriction.",
    "Milestone 14A added ABI-5 device-ioctl mediation for character/block devices opened after Landlock restriction. The current Milestone 15A verified candidate adds one exact numeric host-IPv4 TCP endpoint broker while preserving the target network namespace's direct host separation.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered connected host-loopback TCP socket capability and one optional brokered host-loopback TCP listener capability,",
    "one optional brokered connected host-loopback TCP socket capability, one optional exact numeric host-IPv4 connected TCP socket capability, and one optional brokered host-loopback TCP listener capability,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP capability:** when the port/fd pair is declared, the trusted parent connects a `SOCK_CLOEXEC` IPv4 TCP socket to exactly host `127.0.0.1:<port>` before fork, stores it above target-visible destinations, and remaps it only into the direct target at the declared fd. This grants one connected object capability; it does not attach the target netns or create host routing.\n",
    "- **Brokered host-loopback TCP capability:** when the port/fd pair is declared, the trusted parent connects a `SOCK_CLOEXEC` IPv4 TCP socket to exactly host `127.0.0.1:<port>` before fork, stores it above target-visible destinations, and remaps it only into the direct target at the declared fd. This grants one connected object capability; it does not attach the target netns or create host routing.\n- **Exact host-IPv4 TCP capability:** when the numeric IPv4/port/fd triple is declared, the trusted parent connects in the host network namespace to exactly that unicast IPv4 endpoint, stores the resulting socket on the same collision-safe plane, and remaps only that connected object into the target. Same-port listeners on `127.0.0.1` and `127.0.0.2` provide executable address-discrimination evidence; no target route, DNS resolver, CIDR policy, or generic IP firewall is introduced.\n",
    "threat IPv4 property",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered connected host-loopback TCP socket capability",
    "one optional brokered connected host-loopback TCP socket capability",
    "threat identity no-op guard",
)

# Roadmap: 14A is integrated; 15A becomes the verified executable frontier.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a distinct device-driver operation boundary rather than another pathname, network-port, or IPC-scope variant.",
    "**Status: complete on `main`.** Adds a distinct device-driver operation boundary rather than another pathname, network-port, or IPC-scope variant.",
    "roadmap 14A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 14 promotion rule\n\nAfter 14A integrates, seal this coarse device-ioctl layer. Do not farm extra device names or ioctl request codes through the same rule. Promote only to a materially different executable frontier with kernel/runtime evidence.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, address-aware or broader protocol network authority beyond the existing brokered sockets and Landlock TCP port envelope, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "### Milestone 14 promotion rule\n\n14A is integrated; seal this coarse device-ioctl layer. Do not farm extra device names or ioctl request codes through the same rule.\n\n## Milestone 15 — address-aware network object authority\n\n### Slice 15A — exact numeric host-IPv4 TCP broker\n\n**Current verified candidate.** Adds address discrimination to launcher-brokered outbound object authority without joining the target network namespace to host routing.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing triple `network.host_ipv4_tcp_address` / `network.host_ipv4_tcp_port` / `network.host_ipv4_tcp_target_fd`; the address must be numeric unicast IPv4, the port is 1–65535, and the fd is 3–63 below `limit.open_files` without collisions against selected handles or existing broker destinations;\n- the trusted parent reuses one generic host-IPv4 TCP connector: legacy 9B still fixes the address to `127.0.0.1`, while 15A passes the declared address. Connection failure remains a setup error and never falls back to target-side networking;\n- the connected socket is stored above every target-visible destination and installed only in the direct target as an already-open object capability. No target `socket` or `connect` grant is added implicitly;\n- the integration oracle binds the same TCP port on host `127.0.0.1` and `127.0.0.2`, declares `127.0.0.2`, requires the exact broker marker only on the selected listener, and requires no connection queued on `127.0.0.1`;\n- the raw target then independently attempts a fresh connection through its own isolated network namespace and still requires an ordinary unreachable/refused result, preserving the no-host-route invariant;\n- all Milestones 1–14A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 15A is one preconnected IPv4 TCP socket to an exact numeric endpoint. It does not provide DNS/hostname resolution, IPv6, UDP/raw sockets, CIDR/range allowlists, dynamic post-launch brokering, veth/bridge/NAT/routing, TLS/application authentication, or an external-network reachability guarantee. The deterministic address oracle uses host-local `127/8`; it proves endpoint selection, not Internet egress.\n\n### Milestone 15 promotion rule\n\nAfter 15A integrates, seal this single exact-address preconnected TCP broker. Do not farm more IPv4 literals, ports, or target-fd aliases around the same connector. Promote only to a materially different protocol/topology authority, resource boundary, or observability surface with executable evidence.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, broader-protocol or routed network authority beyond the bounded preconnected TCP brokers and Landlock TCP port envelope, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 15A section",
)
