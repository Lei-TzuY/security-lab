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


# README: seal 11A, describe verified 12A semantics, and synchronize the
# already-integrated deterministic JSON reporting surface.
replace_one(
    "README.md",
    "The current Milestone 11A verified candidate adds **one launcher-brokered host-loopback TCP listener capability** without attaching the target network namespace to host routing.",
    "Milestone 11A added **one launcher-brokered host-loopback TCP listener capability** without attaching the target network namespace to host routing. The current Milestone 12A verified candidate adds **Landlock TCP bind/connect port envelopes for target-created sockets** without granting networking syscalls or attaching external routing.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "repeatable `landlock.read_execute` and `landlock.file_mutate` paths, `network.loopback`,",
    "repeatable `landlock.read_execute` and `landlock.file_mutate` paths, repeatable `landlock.tcp_bind_port` and `landlock.tcp_connect_port` entries, `network.loopback`,",
    "README policy surface",
)
replace_one(
    "README.md",
    "Each Landlock list is limited to 32 absolute sandbox paths and rejects `/` and duplicates.",
    "Each Landlock pathname list is limited to 32 absolute sandbox paths and rejects `/` and duplicates. Each Landlock TCP list is independently limited to 32 unique ports in the range 1–65535; a non-empty list activates deny-by-default handling only for its corresponding bind or connect access class.",
    "README Landlock bounds",
)
replace_one(
    "README.md",
    "the direct target alone optionally builds a Landlock ruleset against the final mounted root, applies explicit stdio,",
    "the direct target alone optionally builds a Landlock ruleset for the requested pathname and TCP-port access classes against the final sandbox state, applies explicit stdio,",
    "README target enforcement",
)
insert_before(
    "README.md",
    "- Landlock is an additional pathname restriction, not revocation of explicit object capabilities:",
    "- When `landlock.tcp_bind_port` or `landlock.tcp_connect_port` is non-empty, the runtime requires Landlock ABI 4 or newer and handles only the requested TCP bind/connect access class. Rules authorize the declared local bind or remote connect ports and all other ports for that handled class receive Landlock `EACCES`; the lists do not grant `socket`, `bind`, or `connect` through seccomp and do not match IP addresses.\n",
    "README TCP invariant",
)
insert_before(
    "README.md",
    "`network.loopback` is optional and accepts only `enabled` or `disabled`;",
    "`landlock.tcp_bind_port = <port>` and `landlock.tcp_connect_port = <port>` are independently optional and repeatable up to 32 entries each. Ports are 1–65535; duplicates and port 0 are rejected. A non-empty bind list makes `LANDLOCK_ACCESS_NET_BIND_TCP` deny-by-default except for its declared local ports; a non-empty connect list independently does the same for `LANDLOCK_ACCESS_NET_CONNECT_TCP` and declared remote ports. Leaving one list empty leaves that access class unhandled rather than denying it. Requested TCP-port enforcement requires Landlock ABI 4 or newer and fails explicitly on older kernels. Landlock network rules match TCP **ports, not IP addresses**; this slice therefore does not claim an address-aware firewall or replace the destination-specific 9B launcher broker. Target networking syscalls remain separately gated by seccomp.\n\n",
    "README TCP policy format",
)
replace_one(
    "README.md",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout and `reaped_descendants`. The compatibility status-only APIs return the same `ChildOutcome`. The CLI maps `TimedOut` to exit status 124 and `Cancelled` to 130.",
    "12. **Reporting** `run_report()` / `run_report_with_cancel()` return `Exited(code)`, `Signaled(signal)`, `TimedOut`, or `Cancelled`, plus captured stdout and `reaped_descendants`. The compatibility status-only APIs return the same `ChildOutcome`. The human `run` CLI preserves its text contract, while `run-json` emits deterministic structured success/error records with captured bytes encoded losslessly as hexadecimal; both preserve the existing outcome-to-exit-status mapping (`TimedOut` 124, `Cancelled` 130).",
    "README JSON reporting",
)
insert_before(
    "README.md",
    "- a host `127.0.0.1` TCP listener is first proven reachable from the host process,",
    "- with private loopback enabled and target seccomp explicitly granting the required TCP syscalls, Landlock TCP rules allow bind/connect on declared port 42421, require exact `EACCES` for bind and connect on undeclared port 42422, and complete an exact intra-sandbox request path on the allowed port;\n",
    "README TCP evidence",
)

# Threat model: seal 11A and make 12A's port-only authority precise.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–11A threat model",
    "# Milestones 1–12A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 11A verified candidate adds one host-loopback TCP listener object capability while preserving the target network namespace's lack of host routing.",
    "Milestone 11A added one host-loopback TCP listener object capability while preserving the target network namespace's lack of host routing. The current Milestone 12A verified candidate adds optional Landlock TCP bind/connect port envelopes for target-created sockets; these are port-only restrictions and do not match remote IP addresses.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "optional Landlock read/execute and regular-file mutation pathname envelopes, stdio, bounded capture,",
    "optional Landlock read/execute and regular-file mutation pathname envelopes plus independently optional Landlock TCP bind/connect port envelopes, stdio, bounded capture,",
    "threat protected boundary",
)
insert_before(
    "THREAT_MODEL.md",
    "- **Object-capability exception:** Landlock does not retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B/11A brokered sockets.",
    "- **Optional Landlock TCP port envelope:** non-empty `landlock.tcp_bind_port` and `landlock.tcp_connect_port` lists independently activate `LANDLOCK_ACCESS_NET_BIND_TCP` and `LANDLOCK_ACCESS_NET_CONNECT_TCP` handling on Landlock ABI 4+. Only declared local bind or remote connect ports are allowed for the handled class; undeclared ports return `EACCES`. These rules narrow target-created TCP operations without granting their seccomp syscalls and without matching an IP address.\n",
    "threat TCP property",
)
insert_before(
    "THREAT_MODEL.md",
    "The target later drops effective/permitted/inheritable capabilities before exec.",
    "When either Landlock TCP list is non-empty, the runtime first requires ABI 4 or newer. The direct target includes only the requested TCP access classes in `handled_access_net`, adds `LANDLOCK_RULE_NET_PORT` rules for the declared ports, and activates the same ruleset after `no_new_privs` but before target seccomp/exec. Each list is independent: an empty bind list leaves bind unhandled, and an empty connect list leaves connect unhandled. The executable oracle uses private IPv4 loopback because the namespace intentionally has no host/external topology: port 42421 must support positive bind/listen/connect/accept, while otherwise-identical bind and connect attempts to undeclared 42422 must return exact Landlock `EACCES`. Landlock's TCP network object is a port, not an address, so 12A is not an IP/hostname allowlist and does not replace the destination-specific 9B broker.\n\n",
    "threat network semantics",
)

# Roadmap: seal 11A and promote the successful 12A executable slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a materially different inbound object capability without attaching the target network namespace to host or external routing.",
    "**Status: complete on `main`.** Adds a materially different inbound object capability without attaching the target network namespace to host or external routing.",
    "roadmap 11A status",
)
insert_before(
    "ROADMAP.md",
    "## Later frontiers\n",
    "## Milestone 12 — target-created TCP port mediation\n\n### Slice 12A — Landlock TCP bind/connect port envelope\n\n**Current verified candidate.** Adds an independent kernel access-control layer for target-created TCP bind/connect operations rather than another launcher-brokered socket alias.\n\nAcceptance evidence is executable:\n\n- repeatable `landlock.tcp_bind_port = <1..65535>` and `landlock.tcp_connect_port = <1..65535>` entries are independently bounded to 32 unique ports; duplicate values, port 0, and malformed values are rejected fail-closed;\n- each non-empty list activates only its matching Landlock access class (`LANDLOCK_ACCESS_NET_BIND_TCP` or `LANDLOCK_ACCESS_NET_CONNECT_TCP`); an empty list leaves that class unhandled, so policy intent is explicit instead of silently denying unrelated networking;\n- requested TCP-port enforcement requires Landlock ABI 4 or newer. The parent preflights the ABI and older/unavailable kernels fail explicitly rather than dropping the restriction;\n- the direct target builds `handled_access_net` alongside any existing pathname rights, adds `LANDLOCK_RULE_NET_PORT` rules for declared ports, applies `no_new_privs`, and restricts itself before target seccomp and pinned exec. Landlock rules do not add `socket`, `bind`, `connect`, or any other syscall to the target seccomp allowlist;\n- with isolated loopback explicitly enabled and the raw target granted the necessary TCP syscalls, local bind/listen/connect/accept on declared port 42421 succeeds and transfers the expected bytes, while otherwise-identical bind and connect attempts to undeclared port 42422 must each return exact `EACCES`;\n- the oracle therefore distinguishes Landlock denial from seccomp `EPERM` and from an unreachable/refused network endpoint; all earlier sandbox regressions plus the deterministic `run-json` CLI tests remain active, and stable format/Clippy/full tests plus the full Rust 1.74 suite are green.\n\nBoundary: Landlock ABI 4 TCP network rules match **ports, not IP addresses**. 12A therefore does not claim an IP/hostname destination firewall, UDP mediation, external routing, veth/bridge/NAT/DNS, TLS/application authentication, or attenuation of already-connected/listening sockets passed as explicit object capabilities. Port 0/ephemeral-bind authorization is deliberately outside this initial slice.\n\n### Milestone 12 promotion rule\n\nAfter 12A integrates, seal this bounded port-envelope mechanism. Do not farm more test ports, IPv4/IPv6 aliases, or port-count variants. A later networking slice must add a materially different, verifiable address/topology or protocol authority boundary; otherwise promote to another subsystem frontier.\n\n",
    "roadmap 12A section",
)
replace_one(
    "ROADMAP.md",
    "network authority beyond one preconnected host-loopback stream plus one host-loopback listener,",
    "address-aware or broader protocol network authority beyond the existing brokered sockets and Landlock TCP port envelope,",
    "roadmap later network frontier",
)
