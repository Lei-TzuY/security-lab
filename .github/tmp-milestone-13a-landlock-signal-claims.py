from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal integrated 12A and document only the verified 13A signal-scope boundary.
replace_one(
    "README.md",
    "The current Milestone 12A verified candidate adds **Landlock TCP bind/connect port envelopes for target-created sockets** without granting networking syscalls or attaching external routing.",
    "Milestone 12A added **Landlock TCP bind/connect port envelopes for target-created sockets** without granting networking syscalls or attaching external routing. The current Milestone 13A verified candidate adds an optional **Landlock signal scope** that attenuates target signal authority toward processes outside the target's Landlock domain, including launcher-owned namespace PID 1.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "repeatable `landlock.tcp_bind_port` and `landlock.tcp_connect_port` entries, `network.loopback`",
    "repeatable `landlock.tcp_bind_port` and `landlock.tcp_connect_port` entries, optional `landlock.scope_signal`, `network.loopback`",
    "README policy field list",
)
replace_one(
    "README.md",
    "Each Landlock TCP list is independently limited to 32 unique ports in the range 1–65535; a non-empty list activates deny-by-default handling only for its corresponding bind or connect access class.",
    "Each Landlock TCP list is independently limited to 32 unique ports in the range 1–65535; a non-empty list activates deny-by-default handling only for its corresponding bind or connect access class. `landlock.scope_signal` accepts only `enabled` or `disabled`, defaults to disabled, and never grants a target signalling syscall by itself.",
    "README signal policy validation",
)
replace_one(
    "README.md",
    "optionally builds a Landlock ruleset for the requested pathname and TCP-port access classes against the final sandbox state",
    "optionally builds a Landlock ruleset for the requested pathname/TCP-port access classes and signal scope against the final sandbox state",
    "README target Landlock setup",
)
replace_one(
    "README.md",
    "Launcher-owned loopback activation does not silently add any of those syscalls to target authority.",
    "Launcher-owned loopback activation does not silently add any of those syscalls to target authority. Likewise, Landlock signal scoping only narrows an explicitly granted signalling interface; it does not silently add `kill`, `tgkill`, `pidfd_open`, `pidfd_send_signal`, or another signal path to `seccomp.allow`.",
    "README no signal widening",
)
replace_one(
    "README.md",
    "- When `landlock.tcp_bind_port` or `landlock.tcp_connect_port` is non-empty, the runtime requires Landlock ABI 4 or newer and handles only the requested TCP bind/connect access class. Rules authorize the declared local bind or remote connect ports and all other ports for that handled class receive Landlock `EACCES`; the lists do not grant `socket`, `bind`, or `connect` through seccomp and do not match IP addresses.\n",
    "- When `landlock.tcp_bind_port` or `landlock.tcp_connect_port` is non-empty, the runtime requires Landlock ABI 4 or newer and handles only the requested TCP bind/connect access class. Rules authorize the declared local bind or remote connect ports and all other ports for that handled class receive Landlock `EACCES`; the lists do not grant `socket`, `bind`, or `connect` through seccomp and do not match IP addresses.\n- When `landlock.scope_signal = enabled`, the runtime requires Landlock ABI 6 or newer and sets only `LANDLOCK_SCOPE_SIGNAL` in the ruleset scope field. The target may signal only processes in the same or a nested Landlock domain; launcher-owned namespace PID 1 remains outside the target domain, so an otherwise permitted target signal operation toward PID 1 receives Landlock `EPERM`. Signal scoping is a narrowing layer and does not grant signalling syscalls through seccomp.\n",
    "README signal invariant",
)
replace_one(
    "README.md",
    "- Landlock is an additional pathname restriction, not revocation of explicit object capabilities:",
    "- Landlock is an additional restriction layer, not revocation of explicit object capabilities:",
    "README Landlock wording",
)
replace_one(
    "README.md",
    "`landlock.tcp_bind_port = <port>` and `landlock.tcp_connect_port = <port>` are independently optional and repeatable up to 32 entries each. Ports are 1–65535; duplicates and port 0 are rejected. A non-empty bind list makes `LANDLOCK_ACCESS_NET_BIND_TCP` deny-by-default except for its declared local ports; a non-empty connect list independently does the same for `LANDLOCK_ACCESS_NET_CONNECT_TCP` and declared remote ports. Leaving one list empty leaves that access class unhandled rather than denying it. Requested TCP-port enforcement requires Landlock ABI 4 or newer and fails explicitly on older kernels. Landlock network rules match TCP **ports, not IP addresses**; this slice therefore does not claim an address-aware firewall or replace the destination-specific 9B launcher broker. Target networking syscalls remain separately gated by seccomp.\n",
    "`landlock.tcp_bind_port = <port>` and `landlock.tcp_connect_port = <port>` are independently optional and repeatable up to 32 entries each. Ports are 1–65535; duplicates and port 0 are rejected. A non-empty bind list makes `LANDLOCK_ACCESS_NET_BIND_TCP` deny-by-default except for its declared local ports; a non-empty connect list independently does the same for `LANDLOCK_ACCESS_NET_CONNECT_TCP` and declared remote ports. Leaving one list empty leaves that access class unhandled rather than denying it. Requested TCP-port enforcement requires Landlock ABI 4 or newer and fails explicitly on older kernels. Landlock network rules match TCP **ports, not IP addresses**; this slice therefore does not claim an address-aware firewall or replace the destination-specific 9B launcher broker. Target networking syscalls remain separately gated by seccomp.\n\n`landlock.scope_signal = enabled|disabled` is independently optional and defaults to `disabled`. Enabling it requires Landlock ABI 6 or newer and places the direct target in a signal scope that permits signalling only processes in the same or a nested Landlock domain. It has no per-process exception list and does not grant a signalling syscall; the relevant `kill`/pidfd-style interface must still be explicitly present in target seccomp policy.\n",
    "README signal policy format",
)
replace_one(
    "README.md",
    "- with private loopback enabled and target seccomp explicitly granting the required TCP syscalls, Landlock TCP rules allow bind/connect on declared port 42421, require exact `EACCES` for bind and connect on undeclared port 42422, and complete an exact intra-sandbox request path on the allowed port;\n",
    "- with private loopback enabled and target seccomp explicitly granting the required TCP syscalls, Landlock TCP rules allow bind/connect on declared port 42421, require exact `EACCES` for bind and connect on undeclared port 42422, and complete an exact intra-sandbox request path on the allowed port;\n- an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` opens a pidfd for namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with `landlock.scope_signal = enabled` must receive exact `EPERM`. Signal number 0 is a permission check, so the oracle proves outward signal-authority attenuation without changing PID 1 process state;\n",
    "README signal test evidence",
)
replace_one(
    "README.md",
    "Landlock read/execute enforcement requires ABI 1 or newer; requested regular-file mutation enforcement requires ABI 3 or newer because truncation was not restrictable before ABI 3.",
    "Landlock read/execute enforcement requires ABI 1 or newer; requested regular-file mutation enforcement requires ABI 3 or newer because truncation was not restrictable before ABI 3; Landlock TCP port enforcement requires ABI 4 or newer; and Landlock signal scoping requires ABI 6 or newer.",
    "README Landlock platform ABIs",
)
replace_one(
    "README.md",
    "Milestone 9B can broker one already-connected IPv4 `127.0.0.1` TCP stream, but it still does **not** configure veth devices, a host bridge, host/external routes, DNS, NAT, arbitrary IP/hostname egress, UDP, ingress/listening exposure, TLS, or a general endpoint allowlist.",
    "Milestone 9B can broker one already-connected IPv4 `127.0.0.1` TCP stream, Milestone 11A can broker one host-loopback listener, and Milestone 12A can narrow target-created TCP bind/connect ports, but none of these configure veth devices, a host bridge, host/external routes, DNS, NAT, arbitrary IP/hostname egress, UDP, TLS, or a general endpoint allowlist.",
    "README network non-goal",
)
replace_one(
    "README.md",
    "- external cancellation is a one-way launcher control primitive, not a resettable/rearmable token, arbitrary signal-forwarding API, general control RPC, or guarantee on end-to-end cancellation latency from API entry;\n",
    "- external cancellation is a one-way launcher control primitive, not a resettable/rearmable token, arbitrary signal-forwarding API, general control RPC, or guarantee on end-to-end cancellation latency from API entry;\n- Landlock signal scope is one-way signal-authority attenuation with no per-process exception list. It is not a general signal broker, does not replace PID-namespace lifecycle ownership, and does not claim Landlock scoping for abstract Unix sockets or other IPC mechanisms;\n",
    "README signal non-goal",
)

# Threat model: promote the integrated TCP envelope and record the verified signal-scope authority boundary.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–12A threat model",
    "# Milestones 1–13A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 12A verified candidate adds optional Landlock TCP bind/connect port envelopes for target-created sockets; these are port-only restrictions and do not match remote IP addresses.",
    "Milestone 12A added optional Landlock TCP bind/connect port envelopes for target-created sockets; these are port-only restrictions and do not match remote IP addresses. The current Milestone 13A verified candidate adds optional Landlock signal scoping that attenuates the direct target's signal authority toward processes outside its Landlock domain.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "optional Landlock read/execute and regular-file mutation pathname envelopes plus independently optional Landlock TCP bind/connect port envelopes, stdio",
    "optional Landlock read/execute and regular-file mutation pathname envelopes, independently optional Landlock TCP bind/connect port envelopes, and optional Landlock signal scope, stdio",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock TCP port envelope:** non-empty `landlock.tcp_bind_port` and `landlock.tcp_connect_port` lists independently activate `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP` handling on Landlock ABI 4+. Only declared local bind or remote connect ports are allowed for the handled class; undeclared ports return `EACCES`. These rules narrow target-created TCP operations without granting their seccomp syscalls and without matching an IP address.\n",
    "- **Optional Landlock TCP port envelope:** non-empty `landlock.tcp_bind_port` and `landlock.tcp_connect_port` lists independently activate `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP` handling on Landlock ABI 4+. Only declared local bind or remote connect ports are allowed for the handled class; undeclared ports return `EACCES`. These rules narrow target-created TCP operations without granting their seccomp syscalls and without matching an IP address.\n- **Optional Landlock signal scope:** `landlock.scope_signal = enabled` requires Landlock ABI 6+ and places `LANDLOCK_SCOPE_SIGNAL` in the ruleset `scoped` field. The direct target can then signal only processes in the same or a nested Landlock domain. Launcher-owned namespace PID 1 is outside that target domain, so an otherwise permitted signal operation toward PID 1 receives `EPERM`. The scope narrows authority and does not grant a signal syscall through seccomp.\n",
    "threat signal property",
)
replace_one(
    "THREAT_MODEL.md",
    "Target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup and host-side broker creation do not add them implicitly.",
    "Target networking syscalls such as `socket`, `connect`, `bind`, `listen`, `accept`, and `ioctl` are available only when the policy explicitly names them; launcher-owned loopback setup and host-side broker creation do not add them implicitly. Signal interfaces such as `kill`, `tgkill`, `pidfd_open`, and `pidfd_send_signal` likewise remain explicit target seccomp grants; enabling Landlock signal scope does not add them.",
    "threat no signal widening",
)
replace_one(
    "THREAT_MODEL.md",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n\n## UTS identity semantics",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n\n## Landlock signal-scope semantics\n\n`landlock.scope_signal` is independently optional and defaults to disabled. When enabled, parent preflight requires Landlock ABI 6 or newer; older or unavailable kernels fail explicitly instead of silently dropping the requested scope. The direct target includes only `LANDLOCK_SCOPE_SIGNAL` in the ruleset `scoped` field and activates that ruleset after `no_new_privs` but before target seccomp and pinned exec. Policies that do not use signal scope retain the shorter historical Landlock ruleset structure size for older ABI compatibility.\n\nThe scope is directional: the target may signal processes in its own or a nested Landlock domain, but not processes outside that domain. Launcher-owned namespace PID 1 does not enter the direct target's Landlock domain. Executable evidence opens a pidfd for PID 1 from an unscoped target and proves `pidfd_send_signal(..., 0, ...)` succeeds; the otherwise-identical scoped target must receive exact `EPERM`. Target seccomp explicitly grants `pidfd_open` and `pidfd_send_signal`, and signal number 0 performs only the permission check, so neither syscall denial nor an actual delivered signal can masquerade as the Landlock result.\n\n13A does not provide per-process exceptions, arbitrary signal forwarding, a signal broker, or Landlock scoping for abstract Unix sockets or another IPC object class. It narrows an already-explicit signalling interface and does not replace launcher-owned PID namespace lifecycle supervision.\n\n## UTS identity semantics",
    "threat signal semantics section",
)
replace_one(
    "THREAT_MODEL.md",
    "- a configured veth/bridge, host/external routes, DNS, NAT, arbitrary IP/hostname endpoint policy, UDP, TLS/application authentication, or a general controlled outbound/inbound network path. Milestone 9B adds only one launcher-preconnected IPv4 `127.0.0.1` TCP stream and Milestone 11A adds only one launcher-bound IPv4 `127.0.0.1` TCP listener capability; broker creation occurs during parent preparation and has no separate preparation deadline;\n",
    "- a configured veth/bridge, host/external routes, DNS, NAT, arbitrary IP/hostname endpoint policy, UDP, TLS/application authentication, or a general controlled outbound/inbound network path. Milestone 9B adds only one launcher-preconnected IPv4 `127.0.0.1` TCP stream, Milestone 11A adds only one launcher-bound IPv4 `127.0.0.1` TCP listener capability, and Milestone 12A narrows only TCP ports rather than IP addresses; broker creation occurs during parent preparation and has no separate preparation deadline;\n",
    "threat network non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- a general policy that forbids all IPC object types or revokes descriptor-based IPC deliberately exposed to the target;\n",
    "- a general policy that forbids all IPC object types or revokes descriptor-based IPC deliberately exposed to the target. Milestone 13A scopes only signal authority; it has no per-process exception list and does not claim abstract-Unix-socket or other Landlock IPC scoping;\n",
    "threat IPC non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "The policy author is also trusted to choose whether isolated loopback is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "The policy author is also trusted to choose whether isolated loopback or Landlock signal scoping is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "threat signal trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- an enabled-loopback positive oracle in which a raw target performs a real intra-sandbox TCP server/client exchange on `127.0.0.1` and the server reads exact `loopback-ok` bytes;\n",
    "- an enabled-loopback positive oracle in which a raw target performs a real intra-sandbox TCP server/client exchange on `127.0.0.1` and the server reads exact `loopback-ok` bytes;\n- a Landlock signal-scope oracle in which an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` succeeds at signal-number-0 permission checking against namespace PID 1, while the otherwise-identical scoped target requires exact `EPERM`;\n",
    "threat signal evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "mount/capability/seccomp setup",
    "mount/Landlock/capability/seccomp setup",
    "threat failure semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 10B are complete on `main`; the bounded persistent-volume and pathname-envelope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 11A verified candidate adds one host-loopback TCP ingress listener object capability with exact positive request/reply evidence and fail-closed bind failure. After 11A integrates, do not farm additional ports, backlog values, or protocol aliases; the next networking promotion must materially change endpoint/routing authority and carry explicit positive/negative evidence.",
    "Milestones through 12A are complete on `main`; the bounded persistent-volume, pathname-envelope, brokered-loopback, and TCP-port-envelope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 13A verified candidate adds Landlock signal-scope attenuation with exact unscoped-success/scoped-`EPERM` evidence against launcher-owned namespace PID 1. After 13A integrates, do not farm signal numbers or equivalent signal syscalls around the same scope mechanism; promote only to a materially different IPC object boundary with executable evidence or to another subsystem frontier.",
    "threat phase promotion",
)

# Roadmap: seal integrated 12A and promote the verified 13A candidate.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds an independent kernel access-control layer for target-created TCP bind/connect operations rather than another launcher-brokered socket alias.",
    "**Status: complete on `main`.** Adds an independent kernel access-control layer for target-created TCP bind/connect operations rather than another launcher-brokered socket alias.",
    "roadmap 12A status",
)
replace_one(
    "ROADMAP.md",
    "After 12A integrates, seal this bounded port-envelope mechanism. Do not farm more test ports, IPv4/IPv6 aliases, or port-count variants. A later networking slice must add a materially different, verifiable address/topology or protocol authority boundary; otherwise promote to another subsystem frontier.",
    "12A is sealed on `main`. Do not farm more test ports, IPv4/IPv6 aliases, or port-count variants. A later networking slice must add a materially different, verifiable address/topology or protocol authority boundary; otherwise promote to another subsystem frontier.",
    "roadmap 12 promotion",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n",
    "## Milestone 13 — cross-domain IPC authority\n\n### Slice 13A — Landlock signal scope\n\n**Current verified candidate.** Adds a process-to-process authority boundary rather than another pathname, port, or brokered-socket variant.\n\nAcceptance evidence is executable:\n\n- policy accepts one optional `landlock.scope_signal = enabled|disabled`, defaults to disabled, and rejects invalid or duplicate declarations;\n- enabling the scope requires Landlock ABI 6 or newer; older or unavailable kernels fail explicitly rather than silently dropping the requested restriction;\n- the direct target adds only `LANDLOCK_SCOPE_SIGNAL` to the Landlock ruleset `scoped` field, preserves historical shorter ruleset structure sizes when the scope is unused, applies `no_new_privs`, and restricts itself before target seccomp and pinned exec;\n- signal scoping does not grant signal authority through seccomp: `pidfd_open` and `pidfd_send_signal` are available only when the target policy explicitly names them;\n- an unscoped raw target opens a pidfd for launcher-owned namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with signal scope enabled must receive exact `EPERM`; signal number 0 proves the permission boundary without delivering a signal or changing PID 1 state;\n- all Milestones 1–12A regressions plus deterministic `run-json` and offline `check`/`check-json` CLI tests remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 13A is one Landlock signal scope with no per-process exception list. It does not grant signalling syscalls, replace PID-namespace lifecycle supervision, provide arbitrary signal forwarding/brokering, or claim Landlock scoping for abstract Unix sockets or another IPC class.\n\n### Milestone 13 promotion rule\n\nAfter 13A integrates, seal this signal-scope mechanism. Do not farm signal numbers, `kill`/`tgkill` aliases, or pidfd variants that repeat the same permission boundary. Promote only to a materially different IPC object boundary with executable positive/negative evidence or to another subsystem frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n\n## Later frontiers\n",
    "roadmap 13A section",
)
