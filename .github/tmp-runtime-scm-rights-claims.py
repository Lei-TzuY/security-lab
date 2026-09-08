from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "README.md",
    "The current Milestone 34A verified candidate adds **expected-base identity binding for atomic COW replay**: the checked replay API recomputes the canonical base identity before destination/staging setup and fails closed on a digest mismatch. The project is",
    "The current Milestone 34A verified candidate adds **expected-base identity binding for atomic COW replay**: the checked replay API recomputes the canonical base identity before destination/staging setup and fails closed on a digest mismatch. An independent verified host-local IPC candidate adds **receive-only post-launch `SCM_RIGHTS` object handoff** over the existing exact-path AF_UNIX broker: the executed target must explicitly allow `recvmsg`, and the already-connected host peer remains optionally pinned by exact UID/GID. The project is",
    "README summary",
)
replace_one(
    "README.md",
    "- selected handles are launch-time mappings only. There is no post-launch `SCM_RIGHTS`/broker API, generic descriptor revocation/access-mode attenuation, arbitrary remapping language, or directory-handle support. A deliberately selected already-open object can bypass pathname visibility because that object capability already exists; 13B is limited to the kernel-defined Landlock abstract-UNIX cross-domain `connect` restriction on AF_UNIX sockets;",
    "- selected handles themselves remain launch-time mappings. The current host-local IPC candidate separately permits an explicitly seccomp-authorized target to call `recvmsg(MSG_CMSG_CLOEXEC)` on the already-brokered exact-path AF_UNIX stream and receive one `SCM_RIGHTS` descriptor from that connected peer after target-executed readiness. This is target-side receive over an existing brokered channel, not a general launcher post-launch broker API; there is no target `sendmsg` grant, generic descriptor revocation/access-mode attenuation, arbitrary remapping language, or directory-handle policy. A deliberately exposed object can bypass pathname visibility because that object capability exists independently of the chroot;",
    "README limitation",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 34A verified candidate binds one replay API to an explicitly expected base identity and rejects a digest mismatch before replay destination/staging setup; this remains identity/precondition evidence rather than authenticity, provenance, or attestation. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "The current Milestone 34A verified candidate binds one replay API to an explicitly expected base identity and rejects a digest mismatch before replay destination/staging setup; this remains identity/precondition evidence rather than authenticity, provenance, or attestation. An independent host-local IPC candidate permits receive-only post-launch `SCM_RIGHTS` transfer over the already-brokered exact-path AF_UNIX stream, with explicit target `recvmsg` authority and the existing optional peer UID/GID pin. Every claimed property must correspond to a kernel mechanism and executable evidence.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher provides no generic revocation or access-mode attenuation, post-launch descriptor transfer, pathname confinement of that object, or directory handles; 13B separately demonstrates the kernel's narrow Landlock ability to deny cross-domain abstract-UNIX `connect` on a selected AF_UNIX socket.",
    "The launcher provides no generic revocation or access-mode attenuation, pathname confinement of that object, or directory handles. The current host-local IPC candidate separately allows the target to receive one post-launch descriptor with `recvmsg(SCM_RIGHTS)` over an already-authorized exact-path AF_UNIX stream; that is peer-to-target object transfer, not launcher-side arbitrary FD installation. 13B separately demonstrates the kernel's narrow Landlock ability to deny cross-domain abstract-UNIX `connect` on a selected AF_UNIX socket.",
    "selected-object semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP ingress listener:**",
    "- **Receive-only post-launch SCM_RIGHTS handoff:** an explicitly granted `recvmsg` syscall can consume one descriptor sent over the already-connected exact-path AF_UNIX broker. The raw target first writes a readiness byte after `execveat`; only then does the trusted test peer call host-side `sendmsg(SCM_RIGHTS)`. The target receives with `MSG_CMSG_CLOEXEC`, rejects truncated or non-`SOL_SOCKET`/non-`SCM_RIGHTS` ancillary metadata, reads exact marker bytes through the received descriptor, and still requires `ENOENT` for that file's original host pathname. The existing optional `SO_PEERCRED` UID/GID pin narrows which connected peer may supply the capability. This does not add target `sendmsg`, a launcher-owned dynamic broker API, rights attenuation, revocation, or a general IPC object graph.\n- **Brokered host-loopback TCP ingress listener:**",
    "SCM_RIGHTS security property",
)
replace_one(
    "THREAT_MODEL.md",
    "- post-launch descriptor brokering/`SCM_RIGHTS`, selected-handle revocation or rights attenuation, a general arbitrary FD-remapping language, or selected directory handles;",
    "- a general launcher-owned post-launch descriptor broker, target-side `SCM_RIGHTS` send authority, selected-handle revocation or rights attenuation, a general arbitrary FD-remapping language, or selected directory handles. The current candidate only demonstrates receive-side transfer from the already-connected exact-path AF_UNIX peer under explicit `recvmsg` authority;",
    "threat limitation",
)

old_frontier = """## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
"""
new_frontier = """## Independent host-local IPC frontier — post-launch object transfer

### Receive-only SCM_RIGHTS over the exact-path AF_UNIX broker

**Current verified candidate.** This is a materially new runtime object-capability handoff, not another AF_UNIX address spelling and not a new configuration-only broker name.

Acceptance evidence is executable:

- target seccomp may now explicitly name Linux x86_64 `recvmsg`; `sendmsg` is intentionally not added to the target syscall-name surface;
- the capability channel reuses the existing exact host-path AF_UNIX stream broker and its optional exact `SO_PEERCRED` UID/GID narrowing rather than attaching a new host IPC namespace or exposing the host pathname inside chroot;
- a raw target publishes one readiness byte from executed target code on broker fd 10; only after the host peer reads that byte does it call real `sendmsg(SCM_RIGHTS)` with one regular-file descriptor, proving the object handoff occurs after target exec rather than being preloaded before launch;
- the raw target calls `recvmsg(..., MSG_CMSG_CLOEXEC)`, requires a non-truncated `SOL_SOCKET` / `SCM_RIGHTS` control message containing exactly one descriptor, reads exact `runtime-fd-handoff-ok\\n` bytes through that descriptor, and closes it;
- the same target then attempts the original absolute host file pathname and requires exact `ENOENT`, proving the descriptor grant does not make that host pathname reachable through the sandbox root;
- existing broker, namespace, Landlock, seccomp, lifecycle, COW, and authority regressions remain active; exact candidate stable format/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: this slice is receive-only target-side capability transfer over one already-authorized connected AF_UNIX stream. It does not add target `sendmsg`, a launcher-owned post-launch broker API, descriptor-rights attenuation/revocation, object-type policy for arbitrary received FDs, multiple broker channels, or a general bidirectional IPC/RPC graph. The peer UID/GID pin is kernel credential evidence, not cryptographic service identity.

Promotion rule: do not farm additional payload bytes, target descriptor numbers, or ancillary-message spelling variants. A stronger host-local IPC phase must add materially new mediation such as bounded object-type/rights policy, launcher-owned dynamic brokering, revocation/lifetime control, or a generalized endpoint/object graph with executable evidence.

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, broader host-local IPC mediation beyond the bounded receive-only SCM_RIGHTS handoff, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.
"""
replace_one("ROADMAP.md", old_frontier, new_frontier, "roadmap host-local IPC frontier")
