from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 18A and describe only the credential check that executable evidence proves.
replace_one(
    "README.md",
    "The current Milestone 18A verified candidate adds **one exact host-path AF_UNIX stream broker**: the trusted parent connects to one declared filesystem socket pathname before namespace entry and exposes only that connected stream object at one declared target fd.",
    "Milestone 18A added **one exact host-path AF_UNIX stream broker**: the trusted parent connects to one declared filesystem socket pathname before namespace entry and exposes only that connected stream object at one declared target fd. The current Milestone 19A verified candidate can additionally **bind that broker to one exact peer UID/GID pair** using Linux `SO_PEERCRED` before the socket is admitted to target authority.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "one exact host-path AF_UNIX stream pathname/target-fd pair, one brokered host-loopback TCP listener port/target-fd pair",
    "one exact host-path AF_UNIX stream pathname/target-fd pair optionally narrowed by an all-or-nothing peer UID/GID pair, one brokered host-loopback TCP listener port/target-fd pair",
    "README policy summary",
)
replace_one(
    "README.md",
    "If `ipc.host_unix_stream_path` is declared, the trusted parent separately creates `AF_UNIX|SOCK_STREAM|SOCK_CLOEXEC` state in the host filesystem namespace, connects to exactly that configured pathname, and moves only the connected socket onto the collision-safe selected-handle plane. The configured host pathname must be absolute, fit Linux `sockaddr_un.sun_path`, and be lexically disjoint from `filesystem.root`, so the broker does not deliberately re-expose a socket pathname through the chroot.",
    "If `ipc.host_unix_stream_path` is declared, the trusted parent separately creates `AF_UNIX|SOCK_STREAM|SOCK_CLOEXEC` state in the host filesystem namespace and connects to exactly that configured pathname. When `ipc.host_unix_stream_peer_uid` / `ipc.host_unix_stream_peer_gid` are present, the parent immediately queries Linux `SO_PEERCRED` on that connected socket and requires an exact UID/GID match before moving the object onto the collision-safe selected-handle plane; query failure or mismatch is a setup error. The configured host pathname must be absolute, fit Linux `sockaddr_un.sun_path`, and be lexically disjoint from `filesystem.root`, so the broker does not deliberately re-expose a socket pathname through the chroot.",
    "README parent broker pipeline",
)
replace_one(
    "README.md",
    "An optional exact host-path AF_UNIX stream capability uses the all-or-nothing pair `ipc.host_unix_stream_path = <absolute-host-socket-path>` and `ipc.host_unix_stream_target_fd = <fd>`. The pathname must be at most 107 bytes on Linux, contain no NUL or `..`, and be lexically disjoint from `filesystem.root`; the fd must be 3–63, below `limit.open_files`, and distinct from every selected-handle or other broker destination. This slice supports one filesystem-path stream endpoint only—no abstract address, datagram/seqpacket mode, SCM_RIGHTS broker, or post-launch connection service.",
    "An optional exact host-path AF_UNIX stream capability uses the all-or-nothing pair `ipc.host_unix_stream_path = <absolute-host-socket-path>` and `ipc.host_unix_stream_target_fd = <fd>`. The pathname must be at most 107 bytes on Linux, contain no NUL or `..`, and be lexically disjoint from `filesystem.root`; the fd must be 3–63, below `limit.open_files`, and distinct from every selected-handle or other broker destination. An optional credential pin uses the all-or-nothing pair `ipc.host_unix_stream_peer_uid = <u32>` and `ipc.host_unix_stream_peer_gid = <u32>` and is invalid without the brokered endpoint. When present, the launcher requires Linux `SO_PEERCRED` to return exactly that UID/GID before the connected socket can become target authority. This is a kernel-provided connection-time peer-credential snapshot, not cryptographic authentication, a service-unique identity, peer-PID enforcement, or pathname alias proof. The slice still supports one filesystem-path stream endpoint only—no abstract address, datagram/seqpacket mode, SCM_RIGHTS broker, or post-launch connection service.",
    "README policy format",
)
replace_one(
    "README.md",
    "- a real host `UnixListener` bound at one temporary filesystem pathname accepts the launcher-created broker connection; the raw target writes exact `brokered-host-unix-ok` bytes through target fd 10, reads exact `host-unix-reply` bytes back, then creates a fresh AF_UNIX stream socket itself and must receive exact `ENOENT` when connecting to the original host pathname, distinguishing path confinement from seccomp denial;",
    "- a real host `UnixListener` bound at one temporary filesystem pathname accepts the launcher-created broker connection while the policy pins the launcher's actual UID/GID; the launcher verifies exact Linux `SO_PEERCRED`, the raw target writes exact `brokered-host-unix-ok` bytes through target fd 10, reads exact `host-unix-reply` bytes back, then creates a fresh AF_UNIX stream socket itself and must receive exact `ENOENT` when connecting to the original host pathname. A separate real listener with an intentionally wrong expected UID makes `run()` fail with a peer-credential `SetupFailed` before target execution;",
    "README executable evidence",
)
replace_one(
    "README.md",
    "A brokered connected host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation; a brokered ingress listener additionally requires host-side IPv4 TCP `socket`/`bind`/`listen`.",
    "A brokered connected host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation; a brokered host-path AF_UNIX stream requires host-side AF_UNIX `socket`/`connect`, and a declared peer UID/GID pin additionally requires `getsockopt(SO_PEERCRED)`; a brokered ingress listener additionally requires host-side IPv4 TCP `socket`/`bind`/`listen`.",
    "README platform requirements",
)

# Threat model: separate exact object selection from optional kernel peer-credential narrowing.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–18A threat model",
    "# Milestones 1–19A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 18A verified candidate adds one exact filesystem-path AF_UNIX stream broker whose connection is created by the trusted host parent and delivered as an already-connected object capability.",
    "Milestone 18A added one exact filesystem-path AF_UNIX stream broker whose connection is created by the trusted host parent and delivered as an already-connected object capability. The current Milestone 19A verified candidate optionally narrows that authority by requiring the connected peer's Linux `SO_PEERCRED` UID/GID to match one declared pair before target launch.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Exact host-path AF_UNIX stream capability:** the all-or-nothing pathname/fd pair names one trusted host filesystem socket pathname and one target descriptor. Policy validation requires an absolute pathname of at most 107 Linux pathname bytes, rejects `..`/NUL, requires lexical disjointness from `filesystem.root`, and rejects descriptor collisions. Before fork, the trusted parent creates `SOCK_STREAM|SOCK_CLOEXEC`, connects to exactly that pathname in the host filesystem namespace, moves the connected socket onto the existing collision-safe launcher plane, and later remaps only that object into the direct target. The target's own fresh AF_UNIX socket is still chroot-confined and executable evidence requires exact `ENOENT` for the original host pathname. This does not prove alias/canonical inode identity or create a general AF_UNIX policy.\n",
    "- **Exact host-path AF_UNIX stream capability:** the all-or-nothing pathname/fd pair names one trusted host filesystem socket pathname and one target descriptor. Policy validation requires an absolute pathname of at most 107 Linux pathname bytes, rejects `..`/NUL, requires lexical disjointness from `filesystem.root`, and rejects descriptor collisions. Before fork, the trusted parent creates `SOCK_STREAM|SOCK_CLOEXEC`, connects to exactly that pathname in the host filesystem namespace, moves the connected socket onto the existing collision-safe launcher plane, and later remaps only that object into the direct target. The target's own fresh AF_UNIX socket is still chroot-confined and executable evidence requires exact `ENOENT` for the original host pathname. This does not prove alias/canonical inode identity or create a general AF_UNIX policy.\n- **Optional host-UNIX peer credential pin:** `ipc.host_unix_stream_peer_uid` and `ipc.host_unix_stream_peer_gid` are an all-or-nothing narrowing pair that requires the exact-path stream broker. After `connect(2)` and before the socket is admitted to the selected-handle plane, the trusted parent calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` and requires the returned UID/GID to exactly match policy. Query failure, unexpected credential structure size, or mismatch fails setup before target execution. This is kernel credential evidence for that connection, not cryptographic authentication, peer-PID policy, or a service-unique identity among processes sharing the same UID/GID.\n",
    "threat peer credential property",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional exact host-path AF_UNIX connected stream capability, and one optional brokered host-loopback TCP listener capability",
    "one optional exact host-path AF_UNIX connected stream capability optionally narrowed by one exact peer UID/GID pair, and one optional brokered host-loopback TCP listener capability",
    "threat protected boundary",
)

# Roadmap: seal 18A and promote credential binding as a distinct enforcement slice.
replace_one(
    "ROADMAP.md",
    """### Slice 18A — one exact host-path AF_UNIX stream broker\n\n**Current verified candidate.** Adds a host-local IPC authority surface that is distinct from the sealed IPv4 TCP/UDP broker family and from Landlock's abstract-UNIX cross-domain scope.\n""",
    """### Slice 18A — one exact host-path AF_UNIX stream broker\n\n**Status: complete on `main`.** Adds a host-local IPC authority surface that is distinct from the sealed IPv4 TCP/UDP broker family and from Landlock's abstract-UNIX cross-domain scope.\n""",
    "roadmap 18A status",
)
replace_one(
    "ROADMAP.md",
    """### Milestone 18 promotion rule\n\nAfter 18A integrates, seal this single exact-path stream object-capability slice. Do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants. Promote only to a materially different executable authority/enforcement frontier. Supplementary-group isolation and cgroup-backed aggregate accounting remain blocked on their documented kernel/environment prerequisites.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized AF_UNIX authority beyond the single exact-path 18A stream object, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n""",
    """### Milestone 18 promotion rule\n\n18A is integrated; seal the exact-path stream object-capability slice. Do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants. The next AF_UNIX work must add a materially different enforcement property rather than another transport spelling. Supplementary-group isolation and cgroup-backed aggregate accounting remain blocked on their documented kernel/environment prerequisites.\n\n## Milestone 19 — host-local IPC peer identity enforcement\n\n### Slice 19A — exact peer UID/GID for the host AF_UNIX broker\n\n**Current verified candidate.** Narrows the already-bounded 18A object capability with kernel-provided peer identity evidence before target authority exists.\n\nAcceptance evidence is executable:\n\n- policy accepts optional all-or-nothing `ipc.host_unix_stream_peer_uid` / `ipc.host_unix_stream_peer_gid` unsigned integers and rejects incomplete pairs or credentials declared without the exact-path host-UNIX broker;\n- the trusted parent performs the existing exact host-path `connect(2)`, then calls `getsockopt(SOL_SOCKET, SO_PEERCRED)` before the connected socket is moved onto the selected-handle storage plane; query failure, unexpected credential size, or UID/GID mismatch is a terminal setup failure;\n- target seccomp authority is unchanged because peer inspection occurs entirely in trusted parent preparation and does not add target `getsockopt`, `socket`, or `connect`;\n- a real `UnixListener` run pins the launcher's actual UID/GID, completes the exact 18A request/reply oracle, and retains the fresh-target-socket `ENOENT` host-path confinement proof;\n- a separate real listener run deliberately declares the wrong UID with the real GID and requires public `run()` to return peer-credential `SetupFailed` before target execution;\n- all Milestones 1–18A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: `SO_PEERCRED` is Linux kernel credential metadata captured for the connected peer. 19A matches UID/GID only; it does not provide cryptographic authentication, service-unique identity among processes sharing credentials, peer-PID enforcement, pathname alias/canonical-inode proof, SCM_RIGHTS mediation, or dynamic post-launch brokering.\n\n### Milestone 19 promotion rule\n\nAfter 19A integrates, seal peer UID/GID matching at this bounded scope. Do not farm PID/credential field variants around the same `SO_PEERCRED` query. Promote only to a materially different executable authority/enforcement frontier. Supplementary-group isolation and delegated cgroup accounting remain blocked on their documented prerequisites.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.\n""",
    "roadmap promotion",
)
