from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, addition: str, label: str) -> None:
    replace_one(path, marker, addition + marker, label)


# README: seal 15A and describe only the executable 16A UDP broker evidence.
replace_one(
    "README.md",
    "The current Milestone 15A verified candidate adds **one exact numeric host-IPv4 TCP endpoint broker**: the trusted parent connects to a declared IPv4 address and port before fork and transfers only that already-connected socket capability into the otherwise isolated target.",
    "Milestone 15A added **one exact numeric host-IPv4 TCP endpoint broker**. The current Milestone 16A verified candidate adds **one exact numeric host-IPv4 UDP datagram broker**: the trusted parent creates and connects a datagram socket to a declared numeric IPv4 address and port before fork, then transfers only that socket capability into the otherwise isolated target.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "one brokered connected host-loopback TCP port/target-fd pair, one exact numeric host-IPv4 TCP address/port/target-fd triple, one brokered host-loopback TCP listener port/target-fd pair",
    "one brokered connected host-loopback TCP port/target-fd pair, one exact numeric host-IPv4 TCP address/port/target-fd triple, one exact numeric host-IPv4 UDP address/port/target-fd triple, one brokered host-loopback TCP listener port/target-fd pair",
    "README policy surface",
)
replace_one(
    "README.md",
    "If an exact host-IPv4 broker is declared, the same launcher-owned path instead connects to exactly the configured numeric unicast IPv4 address and port; address, port, and target fd are all-or-nothing and the target receives only the connected socket object.",
    "If an exact host-IPv4 TCP broker is declared, the same launcher-owned stream path instead connects to exactly the configured numeric unicast IPv4 address and port; address, port, and target fd are all-or-nothing and the target receives only the connected stream object. If an exact host-IPv4 UDP broker is declared, the parent separately creates `SOCK_DGRAM|SOCK_CLOEXEC`, applies `connect(2)` only to fix that socket's default peer, and places it on the same collision-safe selected-handle plane. UDP `connect()` is not a handshake and does not prove that a service exists or that any later datagram is delivered.",
    "README parent UDP preparation",
)
insert_before(
    "README.md",
    "- A declared brokered host-loopback TCP listener is a separate listening-socket object capability:",
    "- A declared exact host-IPv4 UDP endpoint is one already-connected datagram-socket object capability: the trusted parent selects exactly one numeric unicast IPv4 address plus port in the host network namespace and exposes only that socket at the declared target fd. The executable oracle binds the same UDP port on host `127.0.0.1` and `127.0.0.2`, selects `127.0.0.2`, observes one exact `brokered-host-udp-ok` datagram only there, and proves a separate fresh target-netns UDP attempt does not become a host-visible second datagram. This proves peer/address selection and preserved datagram boundaries, not Internet reachability or delivery guarantees.\n",
    "README UDP invariant",
)

# Threat model: add the object capability without claiming remote reachability.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–15A threat model",
    "# Milestones 1–16A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 15A verified candidate adds one exact numeric host-IPv4 TCP endpoint broker while preserving the target network namespace's direct host separation.",
    "Milestone 15A added one exact numeric host-IPv4 TCP endpoint broker. The current Milestone 16A verified candidate adds one exact numeric host-IPv4 connected UDP datagram socket capability while preserving the target network namespace's direct host separation.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered connected host-loopback TCP socket capability, one optional exact numeric host-IPv4 connected TCP socket capability, and one optional brokered host-loopback TCP listener capability",
    "one optional brokered connected host-loopback TCP socket capability, one optional exact numeric host-IPv4 connected TCP socket capability, one optional exact numeric host-IPv4 connected UDP socket capability, and one optional brokered host-loopback TCP listener capability",
    "threat protected network boundary",
)
insert_before(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP ingress listener:**",
    "- **Exact host-IPv4 UDP capability:** when the numeric IPv4/port/fd triple is declared, the trusted parent creates a host-network-namespace `SOCK_DGRAM|SOCK_CLOEXEC` socket, calls `connect(2)` to bind its default peer to exactly that unicast IPv4 endpoint, stores it on the collision-safe launcher plane, and remaps only that object into the target. UDP connect performs no handshake and is not service-availability or delivery evidence. The deterministic oracle instead observes an exact datagram at the selected `127.0.0.2` same-port endpoint, no datagram at `127.0.0.1`, and no second host-visible datagram from a separately created target-netns UDP socket.\n",
    "threat UDP property",
)
replace_one(
    "THREAT_MODEL.md",
    "the 9B/11A brokered sockets",
    "the 9B/11A/15A/16A brokered sockets",
    "threat object capability scope",
)

# Roadmap: 15A is on main; 16A is the verified candidate and then the exact
# preconnected IPv4 endpoint-broker family is sealed.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds address discrimination to launcher-brokered outbound object authority without joining the target network namespace to host routing.",
    "**Status: complete on `main`.** Adds address discrimination to launcher-brokered outbound object authority without joining the target network namespace to host routing.",
    "roadmap 15A status",
)
insert_before(
    "ROADMAP.md",
    "## Later frontiers\n",
    """## Milestone 16 — datagram network object authority

### Slice 16A — exact numeric host-IPv4 UDP datagram broker

**Current verified candidate.** Adds a connectionless/message-boundary-preserving transport capability rather than another TCP endpoint alias.

Acceptance evidence is executable:

- policy accepts the all-or-nothing triple `network.host_ipv4_udp_address` / `network.host_ipv4_udp_port` / `network.host_ipv4_udp_target_fd`; the address must be numeric unicast IPv4, the port is 1–65535, and the fd is 3–63 below `limit.open_files` without collisions against selected handles or any existing broker destination;
- the trusted parent creates `SOCK_DGRAM|SOCK_CLOEXEC` in the host network namespace and calls `connect(2)` to fix the socket's default peer to exactly the declared numeric IPv4 address and port, then stores that socket above every target-visible destination and remaps it only into the direct target;
- UDP `connect()` is treated only as peer selection: it is not a handshake and does not claim service availability or delivery;
- the deterministic oracle binds the same UDP port on host `127.0.0.1` and `127.0.0.2`, selects `127.0.0.2`, and observes one exact `brokered-host-udp-ok` datagram only at the selected address, preserving one-datagram message boundaries;
- the raw target independently creates a fresh UDP socket inside its isolated network namespace and attempts the same host address/port; host-side observation proves no second datagram crosses into either host endpoint, preserving the no-host-route invariant even when target `socket`, `connect`, and `write` are explicitly granted;
- all Milestones 1–15A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 16A is one preconnected IPv4 UDP socket to an exact numeric endpoint. It does not provide DNS/hostname resolution, IPv6, raw sockets, UDP listeners/bind brokering, multicast/broadcast policy, CIDR/range allowlists, dynamic post-launch brokering, veth/bridge/NAT/routing, application authentication, or an external-network reachability/delivery guarantee. The deterministic oracle uses host-local `127/8`; it proves endpoint selection and datagram semantics, not Internet egress.

### Milestone 16 promotion rule

After 16A integrates, seal the bounded exact-address preconnected IPv4 TCP/UDP broker family. Do not farm more address literals, ports, target-fd aliases, or trivial socket-type variants. Promote only to a materially different topology/resource/observability boundary with executable evidence.

""",
    "roadmap 16A section",
)
replace_one(
    "ROADMAP.md",
    "broader-protocol or routed network authority beyond the bounded preconnected TCP brokers and Landlock TCP port envelope",
    "broader-protocol or routed network authority beyond the bounded preconnected IPv4 TCP/UDP brokers and Landlock TCP port envelope",
    "roadmap later network frontier",
)
