from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 8B and document only the executable 9A loopback boundary.
replace_one(
    "README.md",
    "Milestone 8A added **one explicit read-only persistent host-directory volume** with pinned/revalidated source identity and recursive read-only attachment. The current Milestone 8B verified candidate adds **one explicit writable persistent host-directory volume**: the trusted policy author deliberately grants host-mutation authority to exactly one declared directory while the sandbox root outside that mount remains recursively read-only.",
    "Milestones 8A–8B added **explicit read-only and writable persistent host-directory volumes** with pinned/revalidated source identity, bounded mount attachment, and a recursively read-only sandbox root outside authorized writable exposure. The current Milestone 9A verified candidate adds **policy-owned isolated loopback networking**: `network.loopback = enabled` activates only `lo` inside the already-private network namespace, while the default keeps loopback down and no host/external network attachment is created.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only or writable volume source/target pairs, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "Optional read-only or writable volume source/target pairs, `network.loopback`, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. `network.loopback` accepts only `enabled` or `disabled` and defaults to disabled.",
    "README policy summary",
)
replace_one(
    "README.md",
    "The launcher neither attaches the new network namespace to a host network topology nor shares host IPC/UTS identity state with the target.",
    "The launcher never attaches the new network namespace to a host or external topology. By default its loopback device remains down; when `network.loopback = enabled`, the trusted launcher activates only `lo` with `SIOCGIFFLAGS`/`SIOCSIFFLAGS` while it still owns network-namespace setup authority, then closes that management socket before untrusted execution. Host IPC/UTS identity state also remains separate.",
    "README loopback setup",
)
replace_one(
    "README.md",
    "A policy may explicitly grant target `socket`/`connect`, but those syscalls execute inside the isolated network namespace.",
    "Target networking remains separately explicit: `socket`, `connect`, `bind`, `listen`, `accept`, or `ioctl` are available only when the target seccomp policy names them, and they execute inside the isolated network namespace. Launcher-owned loopback activation does not silently add any of those syscalls to target authority.",
    "README target network authority",
)
replace_one(
    "README.md",
    "- The target does not share the host network namespace. The launcher does not configure a network attachment in the new namespace, so host loopback listeners are not the target's loopback listeners.\n- Target socket authority remains explicit at the syscall layer: `socket` and `connect` are available only when the policy names them. Network namespace creation is launcher management and does not itself widen target seccomp.",
    "- The target does not share the host network namespace. `network.loopback` defaults to disabled, and executable evidence observes `lo` without `IFF_UP` in that state. If explicitly enabled, the launcher brings up only the private namespace's `lo`; no veth, bridge, host route, DNS, or external attachment is created, so host loopback listeners remain distinct.\n- Target network authority remains explicit at the syscall layer: networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when policy names them. Namespace creation and launcher-owned loopback activation do not widen target seccomp.",
    "README network invariants",
)
replace_one(
    "README.md",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\n`network.loopback` is optional and accepts only `enabled` or `disabled`; absence is equivalent to `disabled`. Enabling it authorizes the trusted launcher to bring up only `lo` inside the already-isolated network namespace. It does not attach a veth/bridge, install host/external routes or DNS, or grant target networking syscalls.\n",
    "README loopback policy format",
)
replace_one(
    "README.md",
    "- a host `127.0.0.1` TCP listener is first proven reachable from the host process, then a raw sandbox target is explicitly granted `socket`, `connect`, `close`, and `exit` and attempts the same host loopback port from the new network namespace; only network-stack unreachable/refused results are accepted, while seccomp `EPERM` or a successful cross-namespace connection fails the fixture;",
    "- with `network.loopback` absent/default-disabled, a raw target explicitly granted `socket`, `ioctl`, `close`, and `exit` reads `lo` flags with `SIOCGIFFLAGS` and requires `IFF_UP` to be clear;\n- with `network.loopback = enabled`, a raw target explicitly granted the necessary TCP syscalls performs a real intra-sandbox `socket` → `bind` → `listen` → `fork` → `connect` → `accept` exchange on `127.0.0.1`, and the server reads exact `loopback-ok` bytes from the client;\n- separately, a host `127.0.0.1` TCP listener is first proven reachable from the host process, then an enabled-loopback sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempts that same host port; only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH` are accepted, while seccomp `EPERM` or successful cross-namespace reachability fails the fixture;",
    "README networking evidence",
)
replace_one(
    "README.md",
    "External cancellation additionally requires `eventfd`; cancellable supervision also uses `pidfd_open` and `poll`.",
    "External cancellation additionally requires `eventfd`; cancellable supervision also uses `pidfd_open` and `poll`. When policy-owned loopback is enabled, the launcher additionally requires an IPv4 datagram management socket plus `SIOCGIFFLAGS`/`SIOCSIFFLAGS` support for the private namespace's `lo` device.",
    "README platform loopback requirement",
)
replace_one(
    "README.md",
    "- the launcher creates an isolated network namespace but does **not** configure veth devices, routes, DNS, an endpoint allowlist, or a controlled egress path. This is a network-isolation baseline, not a complete network-policy subsystem;",
    "- the launcher creates an isolated network namespace and may explicitly activate only its private loopback device, but it still does **not** configure veth devices, a host bridge, host/external routes, DNS, NAT, an endpoint allowlist, or a controlled egress path. Milestone 9A is isolated intra-sandbox loopback, not a complete network-policy subsystem;",
    "README network limitation",
)
replace_one(
    "README.md",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or configured network endpoint policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory;",
    "- there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or configured host/external network endpoint policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory, while Milestone 9A only controls isolated loopback activation;",
    "README remaining frontier",
)

# Threat model: extend the claimed boundary to exactly the verified loopback semantics.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–8B threat model",
    "# Milestones 1–9A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 8A added one explicit read-only persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and recursive read-only mount attachment. The current Milestone 8B verified candidate adds one separate writable host-directory exposure that intentionally grants host-mutation authority while reusing the same source identity and target attachment controls.",
    "Milestones 8A–8B added bounded read-only and writable persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and explicit mount attachment controls. The current Milestone 9A verified candidate adds policy-owned activation of only the isolated network namespace's loopback device, with executable proof for default-down behavior, positive intra-sandbox TCP, and continued host-loopback separation.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "up to one optional read-only and one optional writable persistent host-directory volume, stdio, bounded capture, process-tree lifecycle",
    "up to one optional read-only and one optional writable persistent host-directory volume, optional isolated-loopback activation, stdio, bounded capture, process-tree lifecycle",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **No implicit network attachment:** the launcher creates `CLONE_NEWNET` but does not create a veth, install routes, configure DNS, or connect the namespace to a host bridge. Host loopback is therefore not the target's loopback stack.",
    "- **Policy-owned isolated loopback:** the launcher creates `CLONE_NEWNET` without host/external attachment. Loopback is down by default; if `network.loopback = enabled`, the trusted setup path alone uses `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set `IFF_UP` on `lo`, then closes its management socket before target execution. No veth, host bridge, routes, DNS, NAT, or endpoint attachment is introduced, so host loopback remains a different network stack.",
    "threat loopback property",
)
replace_one(
    "THREAT_MODEL.md",
    "`socket` and `connect` are target syscalls only when the policy explicitly names them.",
    "target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup does not add them implicitly.",
    "threat target network authority",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher does not configure the new network namespace. The target therefore does not share host routes, interfaces, or host loopback listeners. This is a **network isolation baseline**, not an endpoint-routing policy. If future work adds controlled connectivity, that must introduce explicit topology/route/endpoint policy plus executable interop evidence rather than weakening this invariant implicitly.",
    "The new network namespace starts with loopback down. Unless policy explicitly enables it, the launcher leaves it down; the raw target can directly observe that `IFF_UP` is clear. When `network.loopback = enabled`, the trusted launcher opens an IPv4 datagram management socket after the user/network namespace transition and UID/GID mapping, reads `lo` flags with `SIOCGIFFLAGS`, sets `IFF_UP` with `SIOCSIFFLAGS`, and closes the socket before capability clearing and target seccomp. This creates only intra-namespace loopback connectivity: no veth, bridge, host/external route, DNS, NAT, or endpoint policy is installed. A future externally attached networking slice must add a materially new topology/endpoint policy with positive and negative executable evidence rather than re-label this loopback mechanism.",
    "threat network semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- a configured veth/bridge, routes, DNS, endpoint allowlist, or controlled outbound/inbound network path. Milestone 4B only proves host-network-namespace separation;",
    "- a configured veth/bridge, host/external routes, DNS, NAT, endpoint allowlist, or controlled outbound/inbound network path. Milestone 9A adds only policy-owned isolated loopback on top of the Milestone 4B namespace boundary;",
    "threat network non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "- The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose whether isolated loopback is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline. Enabling loopback authorizes only connectivity through `lo` inside the private network namespace; it does not authorize host/external attachment.",
    "threat network trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- a host `127.0.0.1` TCP listener that is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. The raw target accepts only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` and successful host-listener reachability both fail the test;",
    "- a default-disabled loopback oracle in which a raw target explicitly granted `socket`, `ioctl`, `close`, and `exit` reads `lo` flags and requires `IFF_UP` to be clear;\n- an enabled-loopback positive oracle in which a raw target performs a real intra-sandbox TCP server/client exchange on `127.0.0.1` and the server reads exact `loopback-ok` bytes;\n- an enabled-loopback host-separation oracle in which a host `127.0.0.1` listener is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. Only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH` are accepted; seccomp `EPERM` and successful host-listener reachability both fail the test;",
    "threat networking evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity.",
    "A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity. If explicitly requested loopback activation is unsupported or denied, launch fails explicitly rather than continuing with the requested network state absent.",
    "threat loopback failure semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestones 4B–4D and 5A are complete on `main`, including network/IPC/UTS isolation and evidence-backed full-64-bit masked seccomp argument narrowing. The current Milestone 6A frontier turns selected non-stdio descriptors into an explicit launch-time object-capability surface while preserving ambient FD sanitization. After 6A integrates, do not farm more destination-number variants; promote to a materially different controlled-connectivity, persistence, or lifecycle/control-plane boundary. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow.",
    "Milestones through 8B are complete on `main`; the bounded persistent-volume authority model is sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. The current Milestone 9A verified candidate adds policy-owned isolated loopback with default-down, positive intra-sandbox TCP, and host-loopback separation evidence. After 9A integrates, do not farm more loopback ports, protocols, or aliases; the next networking promotion must add a materially different topology or host/external endpoint capability with explicit positive/negative evidence. Supplementary-group clearing remains a separate architecture problem under the current unprivileged `setgroups=deny`/`gid_map` flow.",
    "threat phase promotion",
)

# Roadmap: seal 8B and promote the verified executable 9A candidate.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds one explicit host-mutation capability rather than another read-only path variant.",
    "**Status: complete on `main`.** Adds one explicit host-mutation capability rather than another read-only path variant.",
    "roadmap 8B status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 8 promotion rule\n\nAfter 8B integrates, the persistent-volume authority model is sealed at this bounded laboratory scope. Do not farm extra mountpoints or access-mode aliases. Promote to a materially different executable frontier such as controlled networking with positive connectivity evidence, or revisit aggregate cgroup accounting only when real unprivileged delegation becomes available.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, and controlled networking remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "### Milestone 8 promotion rule\n\nMilestone 8 is sealed at this bounded laboratory scope. Do not farm extra mountpoints or access-mode aliases.\n\n## Milestone 9 — controlled networking\n\n### Slice 9A — policy-owned isolated loopback\n\n**Current verified candidate.** Adds real positive connectivity inside the private network namespace without attaching it to the host or an external network.\n\nAcceptance evidence is executable:\n\n- policy accepts optional `network.loopback = enabled|disabled`, defaults to disabled when absent, and rejects invalid or duplicate declarations;\n- after the combined user/network namespace transition and UID/GID mapping, the trusted launcher may use an IPv4 datagram management socket plus `SIOCGIFFLAGS`/`SIOCSIFFLAGS` to set only `IFF_UP` on `lo`; the socket is closed before target capability clearing/seccomp/exec, and unsupported or denied mandatory activation fails explicitly rather than falling back;\n- with loopback absent/default-disabled, a raw target explicitly granted `socket` and `ioctl` reads `lo` flags and requires `IFF_UP` to be clear;\n- with loopback enabled, a raw target explicitly granted the required TCP syscalls performs `socket` → `bind` → `listen` → `fork` → `connect` → `accept` and transfers exact `loopback-ok` bytes over `127.0.0.1`;\n- a separate enabled-loopback regression first proves a host `127.0.0.1` listener is reachable from the host, then requires the sandbox connection to that host port to fail only with network-stack separation outcomes (`ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`); seccomp `EPERM` or successful host reachability fails the oracle;\n- launcher-owned activation does not add target network syscalls or capabilities implicitly: target `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` remain explicit seccomp grants;\n- all Milestones 1–8B regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 9A controls only `lo` inside the already-isolated network namespace. It does not configure a veth, host bridge, host/external routes, DNS, NAT, endpoint allowlist, ingress, or egress.\n\n### Milestone 9 promotion rule\n\nAfter 9A integrates, do not farm loopback ports, protocol variants, or aliases. The next networking slice must add a materially different topology or host/external endpoint capability with explicit positive and negative executable evidence. Milestone 4A aggregate cgroup accounting remains blocked until real unprivileged cgroup-v2 delegation is available; supplementary-group isolation remains a separate user-namespace mapping problem.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, externally attached controlled networking, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 9A promotion",
)
