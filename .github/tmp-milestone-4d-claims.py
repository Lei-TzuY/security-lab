from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README claims and policy surface.
replace_one(
    "README.md",
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestone 4B added an isolated Linux network namespace baseline. The current Milestone 4C candidate adds an **isolated Linux IPC namespace baseline** with executable SysV IPC visibility evidence. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated Linux network and IPC namespace baselines. The current Milestone 4D candidate adds an **owned UTS identity boundary**: policy supplies a validated sandbox hostname, the trusted launcher installs it in a new UTS namespace, and the host hostname remains unchanged. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "README 4D status",
)
replace_one(
    "README.md",
    "1. **Policy validation** requires a host `filesystem.root`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. Optional scratch, stdout redirection, stdout capture, and `limit.wall_clock_milliseconds` are validated fail-closed. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).\n",
    "1. **Policy validation** requires a host `filesystem.root`, a validated `identity.hostname`, sandbox-internal executable/cwd paths, explicit stdio disposition, resource limits, environment entries, and a syscall allowlist. `identity.hostname` is 1–63 bytes, ASCII letters/digits/`-`/`.` only, and must begin/end with an alphanumeric byte. Optional scratch, stdout redirection, stdout capture, and `limit.wall_clock_milliseconds` are validated fail-closed. A declared wall-clock deadline must be 1–86,400,000 ms (24 hours).\n",
    "README hostname policy",
)
replace_one(
    "README.md",
    "3. **Owned namespace/filesystem setup** atomically creates user, mount, PID, network, and IPC namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. The launcher neither attaches the new network namespace to a host network topology nor shares the host SysV IPC/POSIX message-queue namespace with the target.\n",
    "3. **Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, installs the policy hostname in the new UTS namespace, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. The launcher neither attaches the new network namespace to a host network topology nor shares host IPC/UTS identity state with the target.\n",
    "README UTS pipeline",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- The launcher owns the target UTS nodename: `identity.hostname` is installed after namespace/UID/GID setup but before capability clearing and target seccomp, and the host nodename remains unchanged.\n",
    "README UTS invariant",
)
replace_one(
    "README.md",
    "`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.\n",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\n`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.\n",
    "README hostname format",
)
replace_one(
    "README.md",
    "filesystem.root = /\nfilesystem.scratch = /var/tmp\n",
    "filesystem.root = /\nidentity.hostname = security-lab\nfilesystem.scratch = /var/tmp\n",
    "README hostname example",
)
replace_one(
    "README.md",
    "- the host creates a real SysV message queue under an explicit key and proves host lookup returns that queue ID; a raw sandbox target explicitly granted `msgget` looks up the same key inside the new IPC namespace and must receive `ENOENT`. A visible host queue or seccomp `EPERM` fails the fixture;\n",
    "- the host creates a real SysV message queue under an explicit key and proves host lookup returns that queue ID; a raw sandbox target explicitly granted `msgget` looks up the same key inside the new IPC namespace and must receive `ENOENT`. A visible host queue or seccomp `EPERM` fails the fixture;\n- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;\n",
    "README UTS evidence",
)
replace_one(
    "README.md",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC namespaces, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`.",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC/UTS namespaces, `sethostname`, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`.",
    "README UTS platform",
)
replace_one(
    "README.md",
    "- UTS and cgroup namespaces are not yet created;\n",
    "- the UTS slice controls and proves only the sandbox nodename (`identity.hostname`); it does not expose a policy for NIS/domainname or claim a broader machine-identity service;\n- a cgroup namespace is not yet created, and aggregate cgroup controller enforcement remains blocked by missing unprivileged delegation on the current CI runner;\n",
    "README UTS limits",
)

# Threat model.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–4C threat model\n",
    "# Milestones 1–4D threat model\n",
    "threat title 4D",
)
replace_one(
    "THREAT_MODEL.md",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestone 4B added an isolated network namespace baseline. The current Milestone 4C candidate adds an isolated IPC namespace baseline. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestones 4B–4C added isolated network and IPC namespace baselines. The current Milestone 4D candidate adds launcher-owned UTS nodename identity. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "threat purpose 4D",
)
replace_one(
    "THREAT_MODEL.md",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, network- and IPC-namespace membership, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "threat protected UTS",
)
replace_one(
    "THREAT_MODEL.md",
    "- **User/mount/PID/network/IPC namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network and IPC namespaces rather than sharing those host namespaces.\n",
    "- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.\n- **Owned UTS nodename:** `identity.hostname` is required and fail-closed validated to 1–63 ASCII bytes. The trusted launcher installs it with `sethostname` inside the new UTS namespace before capability clearing and target seccomp.\n",
    "threat UTS property",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without any requested mandatory namespace boundary.\n",
    "The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without any mandatory namespace boundary.\n",
    "threat unshare UTS",
)
replace_one(
    "THREAT_MODEL.md",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n\n## Deadline and lifecycle orchestration\n",
    "This baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n\n## UTS identity semantics\n\n`identity.hostname` is a required launcher-owned nodename, not a target request to call `sethostname`. The policy parser accepts only 1–63 ASCII bytes containing letters, digits, `-`, or `.`, and rejects leading/trailing `-` or `.`. The parent prepares the bytes before fork. After the combined namespace transition and UID/GID map setup, the trusted launcher calls `sethostname` while it still has the user-namespace authority required for setup; target capabilities are cleared and target seccomp is installed later.\n\nExecutable evidence uses raw `uname` in the target to compare `utsname.nodename` with the policy value. The trusted parent independently reads `/proc/sys/kernel/hostname` before and after the run and requires it to remain exactly unchanged. This slice does **not** claim policy control of NIS/domainname or any broader host identity service.\n\n## Deadline and lifecycle orchestration\n",
    "threat UTS semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher creates user/mount/PID/network/IPC namespaces and filesystem state, then forks launcher-owned namespace PID 1.",
    "The launcher creates user/mount/PID/network/IPC/UTS namespaces, installs the policy UTS nodename, and constructs filesystem state before it forks launcher-owned namespace PID 1.",
    "threat UTS orchestration",
)
replace_one(
    "THREAT_MODEL.md",
    "- UTS or cgroup namespaces;\n",
    "- policy control of UTS domainname/NIS domain or a general machine-identity service;\n- a cgroup namespace or aggregate cgroup controller boundary on the current non-delegated runner;\n",
    "threat UTS non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- a host-created SysV message queue whose explicit key is first proven visible from the host; a raw target explicitly granted `msgget` must receive `ENOENT` for that same key inside the IPC namespace. Seeing the host queue or receiving seccomp `EPERM` fails the test;\n",
    "- a host-created SysV message queue whose explicit key is first proven visible from the host; a raw target explicitly granted `msgget` must receive `ENOENT` for that same key inside the IPC namespace. Seeing the host queue or receiving seccomp `EPERM` fails the test;\n- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n",
    "threat UTS evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Invalid policy is rejected before launch. Namespace creation, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed network/IPC namespace transition is part of the same mandatory namespace failure path and never falls back to the corresponding host namespace.\n",
    "Invalid policy is rejected before launch. Namespace creation, UTS hostname installation, deadline support preflight, pidfd creation, timer creation/arming, supervision poll, namespace/bootstrap/init forks, descriptor cleanup, capture reads, mount/capability/seccomp setup, process-tree kill/reap, lifecycle publication, and target exec failures are terminal. A failed network/IPC/UTS namespace transition or hostname installation never falls back to the corresponding host namespace/identity.\n",
    "threat UTS failure",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestone 4B is complete on `main` with host-network-namespace separation. The current 4C frontier adds independent IPC-namespace separation with a real SysV visibility oracle. After 4C integrates, do not farm additional IPC-key variants; either return to 4A when delegated cgroup-v2 evidence becomes available, or promote to another independently executable namespace/control-plane frontier such as an owned UTS identity boundary.\n",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestones 4B and 4C are complete on `main` with network- and IPC-namespace separation. The current 4D frontier owns the sandbox UTS nodename through required policy, trusted `sethostname`, raw `uname` evidence, and host-identity non-mutation evidence. After 4D integrates, do not farm hostname syntax aliases or domainname variants. The next promotion should target a materially different remaining boundary, with supplementary-group isolation and seccomp syscall-argument filtering both requiring architecture review before implementation.\n",
    "threat promotion 4D",
)

# Roadmap promotion/status.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Add `CLONE_NEWIPC` to the existing mandatory namespace transition and prove a real host SysV IPC object is invisible from the target namespace.\n",
    "**Status: complete on `main`.** Adds `CLONE_NEWIPC` to the mandatory namespace transition and proves a real host SysV IPC object is invisible from the target namespace.\n",
    "roadmap 4C complete",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 4 promotion rule\n\nAfter 4C integrates, do not farm additional SysV keys, queue variants, or duplicate namespace probes. Return to 4A when real unprivileged cgroup-v2 delegation becomes available; otherwise promote to the next independently executable isolation/control-plane frontier. A strong candidate is an owned UTS identity slice that sets a launcher-controlled hostname in `CLONE_NEWUTS` and proves the target observes that value while the host hostname remains unchanged.\n",
    "### Slice 4D — owned UTS identity\n\n**Current verified candidate.** Make sandbox nodename identity explicit and launcher-owned rather than inheriting the host hostname into an otherwise isolated environment.\n\nAcceptance evidence is executable:\n\n- policy requires `identity.hostname`; validation permits 1–63 ASCII bytes containing letters, digits, `-`, and `.`, with an alphanumeric first/last byte, and rejects missing/duplicate/empty/oversized/invalid values;\n- `CLONE_NEWUTS` joins the existing mandatory user/mount/PID/network/IPC namespace transition;\n- the trusted launcher owns pre-fork hostname bytes and calls `sethostname` after UID/GID mapping but before capability clearing and target seccomp;\n- a raw target explicitly granted `uname` observes exactly the configured nodename;\n- the trusted parent reads `/proc/sys/kernel/hostname` before and after sandbox execution and proves the host nodename remains unchanged;\n- the target is not granted a launcher-only hostname mutation path, and no domainname/NIS-domain policy is claimed;\n- all Milestones 1–4C regressions, stable quality checks, and the full Rust 1.74 suite remain green.\n\nBoundary: 4D owns the sandbox UTS **nodename** only. It is not a general machine-identity service and does not claim configurable domainname.\n\n### Milestone 4 promotion rule\n\nAfter 4D integrates, do not farm hostname aliases, punctuation variants, or domainname copies. Return to 4A only when real unprivileged cgroup-v2 delegation becomes available. Otherwise select a materially different executable boundary after architecture audit; high-value candidates include enforcing/observing an empty supplementary-group set or introducing narrowly-scoped seccomp syscall-argument filtering with deterministic allow/deny evidence.\n",
    "roadmap 4D section",
)
replace_one(
    "ROADMAP.md",
    "External asynchronous cancellation, selected-handle passing, syscall-argument filtering, UTS isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "External asynchronous cancellation, selected-handle passing, syscall-argument filtering, supplementary-group isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "roadmap remove UTS later",
)
