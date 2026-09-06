from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 17A and document only the 18A behavior proven by the executable candidate.
replace_one(
    "README.md",
    "The current Milestone 17A verified candidate adds **launcher-owned process-tree resource telemetry**: namespace PID 1 reports cumulative waited-child user/system CPU time and Linux largest-child peak RSS after the sandbox process tree has converged.",
    "Milestone 17A added **launcher-owned process-tree resource telemetry**: namespace PID 1 reports cumulative waited-child user/system CPU time and Linux largest-child peak RSS after the sandbox process tree has converged. The current Milestone 18A verified candidate adds **one exact host-path AF_UNIX stream broker**: the trusted parent connects to one declared filesystem socket pathname before namespace entry and exposes only that connected stream object at one declared target fd.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "one exact numeric host-IPv4 UDP address/port/target-fd triple, one brokered host-loopback TCP listener port/target-fd pair,",
    "one exact numeric host-IPv4 UDP address/port/target-fd triple, one exact host-path AF_UNIX stream pathname/target-fd pair, one brokered host-loopback TCP listener port/target-fd pair,",
    "README policy summary",
)
replace_one(
    "README.md",
    "UDP `connect()` is not a handshake and does not prove that a service exists or that any later datagram is delivered. If a brokered listener is declared,",
    "UDP `connect()` is not a handshake and does not prove that a service exists or that any later datagram is delivered. If `ipc.host_unix_stream_path` is declared, the trusted parent separately creates `AF_UNIX|SOCK_STREAM|SOCK_CLOEXEC` state in the host filesystem namespace, connects to exactly that configured pathname, and moves only the connected socket onto the collision-safe selected-handle plane. The configured host pathname must be absolute, fit Linux `sockaddr_un.sun_path`, and be lexically disjoint from `filesystem.root`, so the broker does not deliberately re-expose a socket pathname through the chroot. If a brokered listener is declared,",
    "README parent UNIX broker pipeline",
)
replace_one(
    "README.md",
    "- A declared brokered host-loopback TCP listener",
    "- A declared exact host-path AF_UNIX stream endpoint is one already-connected host-local IPC object capability: the trusted parent performs the pathname `connect(2)` before fork, stores the resulting stream on the collision-safe launcher plane, and exposes it only at the declared target fd. The configured pathname is rejected if it overlaps `filesystem.root`; a target-created AF_UNIX socket with explicit `socket`/`connect` seccomp grants still receives `ENOENT` for that original host pathname after chroot. This is lexical configured-path separation, not filesystem-alias or inode-identity proof.\n- A declared brokered host-loopback TCP listener",
    "README UNIX broker invariant",
)
replace_one(
    "README.md",
    "Optional selected handles use `handle.<target_fd> = <source_fd>`",
    "An optional exact host-path AF_UNIX stream capability uses the all-or-nothing pair `ipc.host_unix_stream_path = <absolute-host-socket-path>` and `ipc.host_unix_stream_target_fd = <fd>`. The pathname must be at most 107 bytes on Linux, contain no NUL or `..`, and be lexically disjoint from `filesystem.root`; the fd must be 3–63, below `limit.open_files`, and distinct from every selected-handle or other broker destination. This slice supports one filesystem-path stream endpoint only—no abstract address, datagram/seqpacket mode, SCM_RIGHTS broker, or post-launch connection service.\n\nOptional selected handles use `handle.<target_fd> = <source_fd>`",
    "README UNIX broker policy format",
)
replace_one(
    "README.md",
    "Linux x86_64 integration tests prove that:\n\n",
    "Linux x86_64 integration tests prove that:\n\n- a real host `UnixListener` bound at one temporary filesystem pathname accepts the launcher-created broker connection; the raw target writes exact `brokered-host-unix-ok` bytes through target fd 10, reads exact `host-unix-reply` bytes back, then creates a fresh AF_UNIX stream socket itself and must receive exact `ENOENT` when connecting to the original host pathname, distinguishing path confinement from seccomp denial;\n",
    "README UNIX broker evidence",
)

# Threat model: record the new object authority without expanding it into a general UNIX policy.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–17A threat model",
    "# Milestones 1–18A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 17A verified candidate adds launcher-owned post-mortem process-tree resource telemetry from `RUSAGE_CHILDREN` after PID1 teardown convergence.",
    "Milestone 17A added launcher-owned post-mortem process-tree resource telemetry from `RUSAGE_CHILDREN` after PID1 teardown convergence. The current Milestone 18A verified candidate adds one exact filesystem-path AF_UNIX stream broker whose connection is created by the trusted host parent and delivered as an already-connected object capability.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional exact numeric host-IPv4 connected UDP socket capability, and one optional brokered host-loopback TCP listener capability,",
    "one optional exact numeric host-IPv4 connected UDP socket capability, one optional exact host-path AF_UNIX connected stream capability, and one optional brokered host-loopback TCP listener capability,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP ingress listener:**",
    "- **Exact host-path AF_UNIX stream capability:** the all-or-nothing pathname/fd pair names one trusted host filesystem socket pathname and one target descriptor. Policy validation requires an absolute pathname of at most 107 Linux pathname bytes, rejects `..`/NUL, requires lexical disjointness from `filesystem.root`, and rejects descriptor collisions. Before fork, the trusted parent creates `SOCK_STREAM|SOCK_CLOEXEC`, connects to exactly that pathname in the host filesystem namespace, moves the connected socket onto the existing collision-safe launcher plane, and later remaps only that object into the direct target. The target's own fresh AF_UNIX socket is still chroot-confined and executable evidence requires exact `ENOENT` for the original host pathname. This does not prove alias/canonical inode identity or create a general AF_UNIX policy.\n- **Brokered host-loopback TCP ingress listener:**",
    "threat UNIX broker property",
)
replace_one(
    "THREAT_MODEL.md",
    "the 9B/11A/15A/16A brokered sockets.",
    "the 9B/11A/15A/16A/18A brokered sockets.",
    "threat object capability broker list",
)
replace_one(
    "THREAT_MODEL.md",
    "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.\n\nEvidence includes:\n",
    "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.\n\nEvidence includes:\n\n- an exact host-path AF_UNIX broker oracle: a trusted host listener accepts the launcher-created stream, exchanges exact request/reply bytes with target fd 10, and the raw target then independently creates a fresh AF_UNIX stream socket and requires `ENOENT` when trying the same original host pathname from inside the chroot;\n",
    "threat UNIX broker evidence",
)

# Roadmap: seal 17A, make 18A the verified candidate, and explicitly prevent variant farming.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Converts resource data already owned by namespace PID 1 into an explicit post-mortem report without pretending to provide cgroup enforcement or benchmarking.",
    "**Status: complete on `main`.** Converts resource data already owned by namespace PID 1 into an explicit post-mortem report without pretending to provide cgroup enforcement or benchmarking.",
    "roadmap 17A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 17 promotion rule\n\nAfter 17A integrates, do not farm more `rusage` counters or output aliases. Promote only to a materially different enforceable resource boundary when prerequisites exist, or another independent authority/observability subsystem with executable evidence. Milestone 4A remains blocked until a real writable/delegated cgroup-v2 subtree is available to the unprivileged runtime user.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, broader-protocol or routed network authority beyond the bounded preconnected IPv4 TCP/UDP brokers and Landlock TCP port envelope, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "### Milestone 17 promotion rule\n\n17A is integrated; do not farm more `rusage` counters or output aliases. Promote only to a materially different enforceable resource boundary when prerequisites exist, or another independent authority/observability subsystem with executable evidence. Milestone 4A remains blocked until a real writable/delegated cgroup-v2 subtree is available to the unprivileged runtime user.\n\n## Milestone 18 — exact host-local IPC object authority\n\n### Slice 18A — one exact host-path AF_UNIX stream broker\n\n**Current verified candidate.** Adds a host-local IPC authority surface that is distinct from the sealed IPv4 TCP/UDP broker family and from Landlock's abstract-UNIX cross-domain scope.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `ipc.host_unix_stream_path` / `ipc.host_unix_stream_target_fd`; the pathname must be absolute, contain no NUL or `..`, fit Linux `sockaddr_un.sun_path` at no more than 107 pathname bytes, and be lexically disjoint from `filesystem.root`;\n- the target fd remains bounded to 3–63, below `limit.open_files`, and cannot collide with a selected handle or any existing TCP/UDP/listener broker destination;\n- before fork and before entering the target namespaces/chroot, the trusted parent creates `AF_UNIX` `SOCK_STREAM|SOCK_CLOEXEC`, connects to exactly the configured host pathname, and moves the connected stream onto the existing collision-safe selected-handle storage/remap plane; setup/connect failure is terminal rather than a fallback;\n- a real host `UnixListener` accepts that connection. The raw target writes exact `brokered-host-unix-ok` bytes through fd 10 and reads exact `host-unix-reply` bytes back;\n- the same raw target then creates a fresh AF_UNIX stream socket with explicit `socket` and `connect` seccomp grants and attempts the original absolute host pathname. Exact `ENOENT` is required, proving the host pathname was not made directly reachable through the sandbox chroot and that seccomp `EPERM` is not masquerading as path confinement;\n- all Milestones 1–17A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 18A is exactly one preconnected filesystem-path AF_UNIX stream capability. It does not support abstract addresses, datagram/seqpacket variants, SCM_RIGHTS descriptor brokering, pathname alias/canonical-inode proof, per-peer credential policy, a general AF_UNIX graph, or dynamic post-launch connection brokering.\n\n### Milestone 18 promotion rule\n\nAfter 18A integrates, seal this single exact-path stream object-capability slice. Do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants. Promote only to a materially different executable authority/enforcement frontier. Supplementary-group isolation and cgroup-backed aggregate accounting remain blocked on their documented kernel/environment prerequisites.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized AF_UNIX authority beyond the single exact-path 18A stream object, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    "roadmap 18A section",
)
