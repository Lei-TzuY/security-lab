from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 13A and document only the executable 13B scope behavior.
replace_one(
    "README.md",
    "The current Milestone 13A verified candidate adds an optional **Landlock signal scope** that attenuates target signal authority toward processes outside the target's Landlock domain, including launcher-owned namespace PID 1.",
    "Milestone 13A added an optional **Landlock signal scope** that attenuates target signal authority toward processes outside the target's Landlock domain, including launcher-owned namespace PID 1. The current Milestone 13B verified candidate adds an independent **Landlock abstract UNIX socket scope** that can attenuate `connect` authority on an explicitly selected, already-open AF_UNIX socket when the remote abstract socket belongs to an outside Landlock domain.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "optional `landlock.scope_signal`, `network.loopback`",
    "optional `landlock.scope_abstract_unix_socket` and `landlock.scope_signal`, `network.loopback`",
    "README policy option list",
)
replace_one(
    "README.md",
    "`landlock.scope_signal` accepts only `enabled` or `disabled`, defaults to disabled, and never grants a target signalling syscall by itself.",
    "`landlock.scope_abstract_unix_socket` and `landlock.scope_signal` each accept only `enabled` or `disabled`, default independently to disabled, and never grant target `connect` or signalling syscalls by themselves.",
    "README scope parser semantics",
)
replace_one(
    "README.md",
    "optionally builds a Landlock ruleset for the requested pathname/TCP-port access classes and signal scope against the final sandbox state",
    "optionally builds a Landlock ruleset for the requested pathname/TCP-port access classes and IPC scopes against the final sandbox state",
    "README target Landlock pipeline",
)
replace_one(
    "README.md",
    "Likewise, Landlock signal scoping only narrows an explicitly granted signalling interface; it does not silently add `kill`, `tgkill`, `pidfd_open`, `pidfd_send_signal`, or another signal path to `seccomp.allow`.",
    "Likewise, Landlock signal scoping only narrows an explicitly granted signalling interface; it does not silently add `kill`, `tgkill`, `pidfd_open`, `pidfd_send_signal`, or another signal path to `seccomp.allow`. Landlock abstract-UNIX scoping can narrow `connect` on an inherited/selected AF_UNIX socket, but `connect` must still be explicitly granted by target seccomp.",
    "README scope/seccomp separation",
)
replace_one(
    "README.md",
    "- When `landlock.scope_signal = enabled`, the runtime requires Landlock ABI 6 or newer and sets only `LANDLOCK_SCOPE_SIGNAL` in the ruleset scope field. The target may signal only processes in the same or a nested Landlock domain; launcher-owned namespace PID 1 remains outside the target domain, so an otherwise permitted target signal operation toward PID 1 receives Landlock `EPERM`. Signal scoping is a narrowing layer and does not grant signalling syscalls through seccomp.\n- Landlock is an additional restriction layer, not revocation of explicit object capabilities: already-open descriptors intentionally exposed through stdio, selected handles, redirection, or the brokered socket keep their documented object authority.\n",
    "- When `landlock.scope_signal = enabled`, the runtime requires Landlock ABI 6 or newer and sets `LANDLOCK_SCOPE_SIGNAL` in the ruleset scope field. The target may signal only processes in the same or a nested Landlock domain; launcher-owned namespace PID 1 remains outside the target domain, so an otherwise permitted target signal operation toward PID 1 receives Landlock `EPERM`. Signal scoping is a narrowing layer and does not grant signalling syscalls through seccomp.\n- When `landlock.scope_abstract_unix_socket = enabled`, the runtime likewise requires ABI 6 or newer and adds `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` to the same scope bitmask. An AF_UNIX socket inherited through explicit selected-handle authority can no longer `connect` to an abstract socket created outside the target's Landlock domain; the denial is `EPERM` even though the socket object itself was opened before restriction.\n- Landlock pathname/TCP rules do not generally revoke already-open descriptors. The 13B abstract-UNIX scope is a deliberate kernel-defined exception for cross-domain abstract-socket `connect`; it does not revoke already-connected stream traffic or other selected-handle operations.\n",
    "README abstract scope invariant",
)
replace_one(
    "README.md",
    "`landlock.scope_signal = enabled|disabled` is independently optional and defaults to `disabled`. Enabling it requires Landlock ABI 6 or newer and places the direct target in a signal scope that permits signalling only processes in the same or a nested Landlock domain. It has no per-process exception list and does not grant a signalling syscall; the relevant `kill`/pidfd-style interface must still be explicitly present in target seccomp policy.\n",
    "`landlock.scope_abstract_unix_socket = enabled|disabled` is independently optional and defaults to `disabled`. Enabling it requires Landlock ABI 6 or newer and prevents the direct target from connecting to abstract UNIX sockets owned by processes outside the same or a nested Landlock domain, including when the unconnected AF_UNIX socket was explicitly selected before restriction. It is not a pathname-UNIX-socket policy or per-address allowlist, and it does not grant `connect`; target seccomp must still allow that syscall.\n\n`landlock.scope_signal = enabled|disabled` is separately optional and defaults to `disabled`. Enabling it requires Landlock ABI 6 or newer and places the direct target in a signal scope that permits signalling only processes in the same or a nested Landlock domain. It has no per-process exception list and does not grant a signalling syscall; the relevant `kill`/pidfd-style interface must still be explicitly present in target seccomp policy. The two ABI-6 scopes may be enabled independently or together.\n",
    "README scope policy format",
)
replace_one(
    "README.md",
    "- an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` opens a pidfd for namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with `landlock.scope_signal = enabled` must receive exact `EPERM`. Signal number 0 is a permission check, so the oracle proves outward signal-authority attenuation without changing PID 1 process state;\n",
    "- an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` opens a pidfd for namespace PID 1 and succeeds at `pidfd_send_signal(..., 0, ...)`; the otherwise-identical target with `landlock.scope_signal = enabled` must receive exact `EPERM`. Signal number 0 is a permission check, so the oracle proves outward signal-authority attenuation without changing PID 1 process state;\n- the host parent binds/listens on a real abstract AF_UNIX stream socket and explicitly selects an unconnected host-created AF_UNIX client into target fd 9. With identical target seccomp granting only `connect` plus launch/exit syscalls, the unscoped raw target connects successfully and the parent accepts the connection; with `landlock.scope_abstract_unix_socket = enabled`, the same connect path exits with exact `EPERM`, and a nonblocking parent `accept4` proves no connection was queued;\n",
    "README abstract scope evidence",
)
replace_one(
    "README.md",
    "Landlock TCP port enforcement requires ABI 4 or newer; and Landlock signal scoping requires ABI 6 or newer.",
    "Landlock TCP port enforcement requires ABI 4 or newer; and Landlock abstract-UNIX and signal scoping each require ABI 6 or newer.",
    "README platform ABI",
)
replace_one(
    "README.md",
    "- Landlock signal scope is one-way signal-authority attenuation with no per-process exception list. It is not a general signal broker, does not replace PID-namespace lifecycle ownership, and does not claim Landlock scoping for abstract Unix sockets or other IPC mechanisms;\n",
    "- Landlock signal scope is one-way signal-authority attenuation with no per-process exception list. Landlock abstract-UNIX scope independently attenuates cross-domain abstract-socket `connect`, including on an explicitly selected unconnected socket, but is not a pathname UNIX policy, per-address allowlist, general AF_UNIX broker, or revocation of an already-connected stream. Neither scope replaces PID/IPC namespace lifecycle or target seccomp;\n",
    "README scope limitations",
)
replace_one(
    "README.md",
    "- selected handles are launch-time mappings only. There is no post-launch `SCM_RIGHTS`/broker API, descriptor revocation, rights attenuation, arbitrary remapping language, or directory-handle support. A deliberately selected already-open object can bypass pathname visibility because that object capability already exists;\n",
    "- selected handles are launch-time mappings only. There is no post-launch `SCM_RIGHTS`/broker API, generic descriptor revocation/access-mode attenuation, arbitrary remapping language, or directory-handle support. A deliberately selected already-open object can bypass pathname visibility because that object capability already exists; 13B is limited to the kernel-defined Landlock abstract-UNIX cross-domain `connect` restriction on AF_UNIX sockets;\n",
    "README selected-handle limitation",
)

# Threat model: distinguish the scoped abstract-connect exception from general pre-opened authority.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–13A threat model",
    "# Milestones 1–13B threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 13A verified candidate adds optional Landlock signal scoping that attenuates the direct target's signal authority toward processes outside its Landlock domain.",
    "Milestone 13A added optional Landlock signal scoping that attenuates the direct target's signal authority toward processes outside its Landlock domain. The current Milestone 13B verified candidate adds independent abstract-UNIX-socket scoping that attenuates cross-domain `connect` on an explicitly selected AF_UNIX socket.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "independently optional Landlock TCP bind/connect port envelopes, and optional Landlock signal scope, stdio",
    "independently optional Landlock TCP bind/connect port envelopes, optional Landlock abstract-UNIX-socket and signal scopes, stdio",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock signal scope:** `landlock.scope_signal = enabled` requires Landlock ABI 6+ and places `LANDLOCK_SCOPE_SIGNAL` in the ruleset `scoped` field. The direct target can then signal only processes in the same or a nested Landlock domain. Launcher-owned namespace PID 1 is outside that target domain, so an otherwise permitted signal operation toward PID 1 receives `EPERM`. The scope narrows authority and does not grant a signal syscall through seccomp.\n- **Object-capability exception:** Landlock does not retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B/11A brokered sockets. Those remain separate explicit object capabilities.\n",
    "- **Optional Landlock signal scope:** `landlock.scope_signal = enabled` requires Landlock ABI 6+ and places `LANDLOCK_SCOPE_SIGNAL` in the ruleset `scoped` field. The direct target can then signal only processes in the same or a nested Landlock domain. Launcher-owned namespace PID 1 is outside that target domain, so an otherwise permitted signal operation toward PID 1 receives `EPERM`. The scope narrows authority and does not grant a signal syscall through seccomp.\n- **Optional Landlock abstract UNIX socket scope:** `landlock.scope_abstract_unix_socket = enabled` also requires ABI 6+ and adds `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` to the ruleset scope bitmask. A target using an explicitly selected, host-created unconnected AF_UNIX socket cannot connect to an abstract socket created outside the target's Landlock domain; the kernel returns `EPERM` even though the socket object predates restriction.\n- **Object-capability boundary:** pathname/TCP Landlock rules do not generally retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B/11A brokered sockets. Milestone 13B is the narrow kernel-defined exception for cross-domain abstract-UNIX `connect`; already-connected streams and unrelated object operations keep their documented authority.\n",
    "threat abstract scope property",
)
replace_one(
    "THREAT_MODEL.md",
    "Signal interfaces such as `kill`, `tgkill`, `pidfd_open`, and `pidfd_send_signal` likewise remain explicit target seccomp grants; enabling Landlock signal scope does not add them.",
    "Signal interfaces such as `kill`, `tgkill`, `pidfd_open`, and `pidfd_send_signal` likewise remain explicit target seccomp grants; enabling Landlock signal scope does not add them. Enabling abstract-UNIX scope likewise does not add `connect` or `socket`; 13B's executable oracle explicitly grants only `connect` on an already-selected socket.",
    "threat scope syscall separation",
)
replace_one(
    "THREAT_MODEL.md",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n\n## Landlock signal-scope semantics\n",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`. Milestone 13B adds one separate Landlock rule for cross-domain abstract-UNIX `connect`; it does not turn `CLONE_NEWIPC` into a general descriptor revocation boundary.\n\n## Landlock abstract-UNIX-scope semantics\n\n`landlock.scope_abstract_unix_socket` is independently optional and defaults to disabled. When enabled, parent preflight requires Landlock ABI 6 or newer and the direct target adds `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` to the ruleset `scoped` bitmask. It composes by bitwise union with `LANDLOCK_SCOPE_SIGNAL` when both are requested; policies using neither scope preserve the historical shorter ruleset structure size. The ruleset is activated after `no_new_privs` and before target seccomp/pinned exec.\n\nThe executable oracle deliberately uses an already-open object capability rather than target-created networking. The trusted host parent creates a real abstract AF_UNIX stream listener plus an unconnected AF_UNIX client socket, then exposes only that client through existing selected-handle mapping at target fd 9. An unscoped target with explicit `connect` permission reaches the listener and the parent accepts the connection. The otherwise-identical abstract-scoped target must return exact `EPERM`, after which nonblocking `accept4` must return `EAGAIN`; the positive baseline proves seccomp did not cause the denial. This is the kernel-defined cross-domain abstract-socket scope, not pathname mediation.\n\n13B does not provide per-address exceptions, pathname UNIX-socket filtering, a general AF_UNIX broker, socket creation grants, or revocation of already-connected stream traffic. It specifically attenuates the `connect` operation across Landlock domains, including when the unconnected socket was inherited/selected before restriction.\n\n## Landlock signal-scope semantics\n",
    "threat abstract scope semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "13A does not provide per-process exceptions, arbitrary signal forwarding, a signal broker, or Landlock scoping for abstract Unix sockets or another IPC object class. It narrows an already-explicit signalling interface and does not replace launcher-owned PID namespace lifecycle supervision.",
    "13A does not provide per-process exceptions, arbitrary signal forwarding, or a signal broker. It narrows an already-explicit signalling interface and does not replace launcher-owned PID namespace lifecycle supervision. Abstract-UNIX scoping is the separate 13B object boundary described above.",
    "threat signal boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "This is an explicit object-capability grant. It preserves the underlying open-file-description authority and state rather than mediating a new pathname lookup. Therefore a selected FD may intentionally expose an object outside the chroot/path namespace, and Milestone 6A does not claim rights attenuation, revocation, pathname confinement of that already-open object, post-launch descriptor transfer, or support for directory handles.",
    "This is an explicit object-capability grant. It preserves the underlying open-file-description access mode and state rather than mediating a new pathname lookup. Therefore a selected FD may intentionally expose an object outside the chroot/path namespace. The launcher provides no generic revocation or access-mode attenuation, post-launch descriptor transfer, pathname confinement of that object, or directory handles; 13B separately demonstrates the kernel's narrow Landlock ability to deny cross-domain abstract-UNIX `connect` on a selected AF_UNIX socket.",
    "threat selected-handle boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- a general policy that forbids all IPC object types or revokes descriptor-based IPC deliberately exposed to the target. Milestone 13A scopes only signal authority; it has no per-process exception list and does not claim abstract-Unix-socket or other Landlock IPC scoping;\n",
    "- a general policy that forbids all IPC object types or generically revokes descriptor-based IPC deliberately exposed to the target. Milestone 13A scopes signal authority and 13B scopes cross-domain abstract-UNIX `connect`; neither provides per-object exceptions, pathname UNIX mediation, eventfd/pipe/memfd policy, nor a general IPC broker;\n",
    "threat IPC non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "whether isolated loopback or Landlock signal scoping is activated",
    "whether isolated loopback, Landlock abstract-UNIX scoping, or Landlock signal scoping is activated",
    "threat trust scope choice",
)
replace_one(
    "THREAT_MODEL.md",
    "- a Landlock signal-scope oracle in which an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` succeeds at signal-number-0 permission checking against namespace PID 1, while the otherwise-identical scoped target requires exact `EPERM`;\n",
    "- a Landlock signal-scope oracle in which an unscoped raw target explicitly granted `pidfd_open` and `pidfd_send_signal` succeeds at signal-number-0 permission checking against namespace PID 1, while the otherwise-identical scoped target requires exact `EPERM`;\n- a Landlock abstract-UNIX-scope oracle in which the parent proves a selected host-created unconnected AF_UNIX socket can connect to its real abstract listener when unscoped, then requires exact `EPERM` for the otherwise-identical scoped target and exact `EAGAIN` from a nonblocking listener accept check proving no denied connection was queued;\n",
    "threat abstract evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 12A are complete on `main`; the bounded persistent-volume, pathname-envelope, brokered-loopback, and TCP-port-envelope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 13A verified candidate adds Landlock signal-scope attenuation with exact unscoped-success/scoped-`EPERM` evidence against launcher-owned namespace PID 1. After 13A integrates, do not farm signal numbers or equivalent signal syscalls around the same scope mechanism; promote only to a materially different IPC object boundary with executable evidence or to another subsystem frontier.",
    "Milestones through 13A are complete on `main`; the bounded persistent-volume, pathname-envelope, brokered-loopback, TCP-port-envelope, and signal-scope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 13B verified candidate adds the distinct Landlock abstract-UNIX object boundary with selected-socket unscoped-success/scoped-`EPERM` evidence. After 13B integrates, seal the ABI-6 Landlock scope surface at this bounded laboratory level; do not farm signal aliases or AF_UNIX socket-type variants that repeat the same scope mechanism, and promote to a materially different subsystem authority frontier.",
    "threat phase promotion",
)

# Roadmap: seal 13A and add 13B as a different IPC object boundary.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a process-to-process authority boundary rather than another pathname, port, or brokered-socket variant.",
    "**Status: complete on `main`.** Adds a process-to-process authority boundary rather than another pathname, port, or brokered-socket variant.",
    "roadmap 13A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 13 promotion rule\n\nAfter 13A integrates, seal this signal-scope mechanism. Do not farm signal numbers, `kill`/`tgkill` aliases, or pidfd variants that repeat the same permission boundary. Promote only to a materially different IPC object boundary with executable positive/negative evidence or to another subsystem frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n",
    "### Slice 13B — Landlock abstract UNIX socket scope\n\n**Current verified candidate.** Adds a distinct cross-domain socket-object boundary and deliberately composes with existing selected-handle authority rather than inventing another broker path.\n\nAcceptance evidence is executable:\n\n- policy accepts optional `landlock.scope_abstract_unix_socket = enabled|disabled`, defaults to disabled, rejects invalid/duplicate declarations, and can coexist with the independent signal scope;\n- enabling abstract-UNIX scope requires Landlock ABI 6 or newer. Older or unavailable kernels fail explicitly rather than dropping the request;\n- the direct target ORs `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` into the ABI-6 ruleset `scoped` bitmask and may combine it with `LANDLOCK_SCOPE_SIGNAL`; historical shorter ruleset structure sizes remain unchanged when neither scope is requested;\n- the scope does not grant socket authority: target seccomp must explicitly include `connect`, and the oracle uses an already-open AF_UNIX client delivered through existing selected-handle fd 9 rather than adding `socket`;\n- the host binds/listens on a real abstract AF_UNIX stream endpoint. The unscoped raw target connects through selected fd 9 and the parent successfully accepts that connection; the otherwise-identical scoped target must exit with exact `EPERM`, and a nonblocking parent `accept4` must then return `EAGAIN`, proving no connection was queued;\n- all Milestones 1–13A regressions plus deterministic CLI tests remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 13B is the kernel-defined cross-domain abstract-UNIX `connect` scope. It does not provide pathname UNIX-socket filtering, per-address/per-peer exceptions, a general AF_UNIX broker, implicit `socket`/`connect` grants, or revocation of already-connected stream traffic. Stream-vs-datagram variants are not separate roadmap milestones for this same scope bit.\n\n### Milestone 13 promotion rule\n\nAfter 13B integrates, seal the ABI-6 Landlock scope surface at this bounded laboratory scope. Do not farm signal syscall aliases, signal numbers, or AF_UNIX socket-type variants that repeat the same scoped-field mechanism. Promote only to a materially different executable authority frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n",
    "roadmap 13B section",
)
