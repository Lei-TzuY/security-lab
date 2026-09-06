from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# The 17A telemetry paragraph extends the generic evidence preamble. Keep the
# main claims script exact-match based, but align its expected source string.
script = Path(".github/tmp-milestone-18a-host-unix-claims.py")
text = script.read_text()
old = "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74.\\n\\nEvidence includes:\\n"
new = "The integration probe is statically linked with `-nostdlib` and uses raw Linux x86_64 syscalls. The full suite runs on stable Rust and Rust 1.74. Milestone 17A adds a raw mode that `mmap`s 8 MiB anonymously and faults every 4 KiB page; the parent requires `max_child_rss_kib >= 4096`, while CLI integration validates the stable JSON structure plus unsigned-decimal telemetry fields without pretending live CPU/RSS values are deterministic.\\n\\nEvidence includes:\\n"
if text.count(old) != 1:
    raise SystemExit(f"claims evidence marker: expected exactly one match, got {text.count(old)}")
script.write_text(text.replace(old, new, 1))

# Close stale Threat Model bookkeeping that predates already-integrated phases.
replace_one(
    "THREAT_MODEL.md",
    "- a general policy that forbids all IPC object types or generically revokes descriptor-based IPC deliberately exposed to the target. Milestone 13A scopes signal authority and 13B scopes cross-domain abstract-UNIX `connect`; neither provides per-object exceptions, pathname UNIX mediation, eventfd/pipe/memfd policy, nor a general IPC broker;",
    "- a general policy that forbids all IPC object types or generically revokes descriptor-based IPC deliberately exposed to the target. Milestone 13A scopes signal authority, 13B scopes cross-domain abstract-UNIX `connect`, and 18A brokers exactly one configured filesystem-path AF_UNIX stream; these do not provide a general per-object IPC graph, pathname allowlist, eventfd/pipe/memfd policy, or dynamic broker;",
    "threat IPC non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose whether isolated loopback, Landlock abstract-UNIX scoping, or Landlock signal scoping is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose the exact host AF_UNIX stream pathname and destination fd, whether isolated loopback, Landlock abstract-UNIX scoping, or Landlock signal scoping is activated, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "threat UNIX broker trust",
)
replace_one(
    "THREAT_MODEL.md",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, selected-target remapping, deadline/cancellation supervision preflight, cancellation eventfd pinning/signalling, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/Landlock/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal.",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, selected-source pin/inspection, launcher-owned host broker socket creation/connect/bind/listen, selected-target remapping, deadline/cancellation supervision preflight, cancellation eventfd pinning/signalling, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/Landlock/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal.",
    "threat broker failure semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 13A are complete on `main`; the bounded persistent-volume, pathname-envelope, brokered-loopback, TCP-port-envelope, and signal-scope phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 13B verified candidate adds the distinct Landlock abstract-UNIX object boundary with selected-socket unscoped-success/scoped-`EPERM` evidence. After 13B integrates, seal the ABI-6 Landlock scope surface at this bounded laboratory level; do not farm signal aliases or AF_UNIX socket-type variants that repeat the same scope mechanism, and promote to a materially different subsystem authority frontier.",
    "Milestones through 17A are complete on `main`; the bounded persistent-volume, pathname/Landlock, isolated-loopback, IPv4 broker, IPC-scope, device-ioctl, and post-mortem resource-observability phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 18A verified candidate adds one exact filesystem-path AF_UNIX stream object capability with positive byte exchange plus direct-path `ENOENT` evidence. After 18A integrates, seal this single exact-path stream slice; do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants, and promote to a materially different executable authority/enforcement frontier.",
    "threat phase promotion",
)
