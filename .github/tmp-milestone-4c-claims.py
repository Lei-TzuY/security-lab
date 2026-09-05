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
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline. The current Milestone 4B candidate adds an **isolated Linux network namespace baseline**: the target no longer shares the host network stack, while target socket syscalls remain governed independently by the explicit seccomp allowlist. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "`security-lab` is a correctness-first systems-security laboratory. Milestone 1 established a bounded Linux process sandbox; Milestone 2 sealed ambient descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a launcher-owned monotonic wall-clock deadline; Milestone 4B added an isolated Linux network namespace baseline. The current Milestone 4C candidate adds an **isolated Linux IPC namespace baseline** with executable SysV IPC visibility evidence. The project is **not** a penetration-testing toolkit, malware framework, container runtime, or production multi-tenant isolation boundary.\n",
    "README status",
)
replace_one(
    "README.md",
    "3. **Owned namespace/filesystem setup** atomically creates user, mount, PID, and network namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. The launcher does not attach a veth, configure routes, or otherwise connect the new network namespace to the host network stack.\n",
    "3. **Owned namespace/filesystem setup** atomically creates user, mount, PID, network, and IPC namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, makes mount propagation private, revalidates the selected root by `(st_dev, st_ino)`, recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. The launcher neither attaches the new network namespace to a host network topology nor shares the host SysV IPC/POSIX message-queue namespace with the target.\n",
    "README pipeline namespace",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- SysV IPC identifiers/keys are resolved inside the target IPC namespace rather than the host IPC namespace; a host-created message queue is not discoverable by the same key from the target.\n",
    "README security IPC",
)
replace_one(
    "README.md",
    "- a host `127.0.0.1` TCP listener is first proven reachable from the host process, then a raw sandbox target is explicitly granted `socket`, `connect`, `close`, and `exit` and attempts the same host loopback port from the new network namespace; only network-stack unreachable/refused results are accepted, while seccomp `EPERM` or a successful cross-namespace connection fails the fixture;\n",
    "- a host `127.0.0.1` TCP listener is first proven reachable from the host process, then a raw sandbox target is explicitly granted `socket`, `connect`, `close`, and `exit` and attempts the same host loopback port from the new network namespace; only network-stack unreachable/refused results are accepted, while seccomp `EPERM` or a successful cross-namespace connection fails the fixture;\n- the host creates a real SysV message queue under an explicit key and proves host lookup returns that queue ID; a raw sandbox target explicitly granted `msgget` looks up the same key inside the new IPC namespace and must receive `ENOENT`. A visible host queue or seccomp `EPERM` fails the fixture;\n",
    "README IPC evidence",
)
replace_one(
    "README.md",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network namespaces, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`.",
    "Real enforcement is implemented only for **Linux x86_64**. Required mechanisms include `openat2`, `open_tree`, `mount_setattr`, `move_mount`, tmpfs, user/mount/PID/network/IPC namespaces, UID/GID maps, capability operations, `close_range`, `pipe2`, `dup2`, seccomp, `execveat`, shared anonymous mappings, `fork`, `kill`, `wait4`, and `waitpid`.",
    "README platform IPC",
)
replace_one(
    "README.md",
    "- IPC, UTS, and cgroup namespaces are not yet created;\n",
    "- the IPC namespace isolates SysV IPC and POSIX message-queue namespace membership, but it does not revoke IPC channels deliberately exposed through inherited file descriptors/sockets/pipes;\n- UTS and cgroup namespaces are not yet created;\n",
    "README IPC non-goal",
)

replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–4B threat model\n",
    "# Milestones 1–4C threat model\n",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline. The current Milestone 4B candidate adds an isolated Linux network namespace baseline. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "`security-lab` is an educational, correctness-first Linux sandbox. Milestone 1 established syscall/resource/environment controls; Milestone 2 sealed descriptor, launch, filesystem/identity, stdio, redirection, and bounded-capture authority; Milestone 3 sealed PID-tree lifecycle ownership plus a policy-owned monotonic wall-clock deadline; Milestone 4B added an isolated network namespace baseline. The current Milestone 4C candidate adds an isolated IPC namespace baseline. Every claimed property must correspond to a kernel mechanism and executable evidence.\n",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, network-namespace membership, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "The trusted host parent launches one direct target through launcher-owned bootstrap and namespace-init processes. On supported Linux x86_64, the launcher constrains initial filesystem visibility/mutability, namespace identity, network- and IPC-namespace membership, capabilities, target syscalls, selected resources, environment, cwd, inherited descriptors, stdio, bounded capture, process-tree lifecycle, and—when declared—a wall-clock execution deadline while preserving fail-closed launch/lifecycle reporting.\n",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **User/mount/PID/network namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in a distinct network namespace rather than the host network namespace.\n",
    "- **User/mount/PID/network/IPC namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network and IPC namespaces rather than sharing those host namespaces.\n- **SysV IPC visibility boundary:** message-queue keys/IDs are resolved in the target IPC namespace. Host SysV queues are not discoverable by the same key from the target after `CLONE_NEWIPC`.\n",
    "threat IPC property",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without `CLONE_NEWNET`.\n",
    "The launcher calls `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC)` in one fail-closed namespace transition. If that transition is denied or unsupported, launch fails rather than retrying without any requested mandatory namespace boundary.\n",
    "threat unshare",
)
replace_one(
    "THREAT_MODEL.md",
    "The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect remains independently controlled by seccomp. Explicitly inherited stdio objects remain an intentional exception: if the policy exposes an already-open socket via `stdio.* = inherit`, network namespace creation does not retroactively revoke that object capability.\n",
    "The target later drops effective/permitted/inheritable capabilities before exec. Target socket creation/connect and SysV IPC syscalls remain independently controlled by seccomp. Explicitly inherited stdio objects remain an intentional exception: namespace creation does not retroactively revoke an already-open socket, pipe, or other descriptor capability exposed through `stdio.* = inherit`.\n\n## IPC namespace semantics\n\n`CLONE_NEWIPC` separates SysV IPC objects and the POSIX message-queue namespace from the host. The executable regression uses a host-created SysV message queue because its key lookup gives a direct positive/negative visibility oracle: the host proves the key maps to a queue ID, while the target with an explicit `msgget` grant must receive `ENOENT` for the same key. `EPERM` is not accepted as evidence.\n\nThis baseline does not claim a general IPC policy. Pipes, Unix sockets, eventfds, memfds, or other objects deliberately exposed through inherited descriptors remain object capabilities governed by the descriptor/stdio policy rather than by `CLONE_NEWIPC`.\n",
    "threat IPC semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "The launcher creates user/mount/PID/network namespaces and filesystem state, then forks launcher-owned namespace PID 1.",
    "The launcher creates user/mount/PID/network/IPC namespaces and filesystem state, then forks launcher-owned namespace PID 1.",
    "threat orchestration IPC",
)
replace_one(
    "THREAT_MODEL.md",
    "- IPC, UTS, or cgroup namespaces;\n",
    "- a general policy that forbids all IPC object types or revokes descriptor-based IPC deliberately exposed to the target;\n- UTS or cgroup namespaces;\n",
    "threat IPC non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- a host `127.0.0.1` TCP listener that is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. The raw target accepts only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` and successful host-listener reachability both fail the test;\n",
    "- a host `127.0.0.1` TCP listener that is first proven reachable from the host process, followed by a raw sandbox target explicitly granted `socket`, `connect`, `close`, and `exit` attempting the same port. The raw target accepts only `ECONNREFUSED`, `ENETUNREACH`, or `EHOSTUNREACH`; seccomp `EPERM` and successful host-listener reachability both fail the test;\n- a host-created SysV message queue whose explicit key is first proven visible from the host; a raw target explicitly granted `msgget` must receive `ENOENT` for that same key inside the IPC namespace. Seeing the host queue or receiving seccomp `EPERM` fails the test;\n",
    "threat IPC evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "A failed network-namespace transition is part of the same mandatory namespace failure path and never falls back to the host network namespace.\n",
    "A failed network/IPC namespace transition is part of the same mandatory namespace failure path and never falls back to the corresponding host namespace.\n",
    "threat failure IPC",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestone 4A cgroup-v2 aggregate process accounting is blocked by missing unprivileged delegation on the current GitHub-hosted runner. The independently verifiable Milestone 4B frontier therefore establishes host-network-namespace separation first. After 4B integrates, do not farm additional unreachable errno variants. The next network step should be a coherent controlled-connectivity hypothesis (explicit topology/route/endpoint policy with real positive and negative connectivity evidence), or return to 4A once delegated cgroup-v2 evidence becomes available.\n",
    "Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner. Milestone 4B is complete on `main` with host-network-namespace separation. The current 4C frontier adds independent IPC-namespace separation with a real SysV visibility oracle. After 4C integrates, do not farm additional IPC-key variants; either return to 4A when delegated cgroup-v2 evidence becomes available, or promote to another independently executable namespace/control-plane frontier such as an owned UTS identity boundary.\n",
    "threat promotion IPC",
)

replace_one(
    "ROADMAP.md",
    "## Milestone 4 — aggregate accounting and network isolation\n",
    "## Milestone 4 — aggregate accounting and namespace isolation\n",
    "roadmap M4 title",
)
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Establish a real host-network-namespace boundary before designing controlled connectivity.\n",
    "**Status: complete on `main`.** Establishes a real host-network-namespace boundary before any controlled-connectivity policy is attempted.\n",
    "roadmap 4B status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 4 promotion rule\n\nAfter 4B integrates, do not farm additional unreachable errno variants or duplicate loopback tests. Choose one of two higher-value frontiers:\n\n1. return to 4A when real unprivileged cgroup-v2 delegation becomes available; or\n2. design a coherent controlled-connectivity slice that introduces explicit topology/route/endpoint policy and proves both an allowed connection and a denied connection through real networking.\n",
    "### Slice 4C — isolated IPC namespace baseline\n\n**Current verified candidate.** Add `CLONE_NEWIPC` to the existing mandatory namespace transition and prove a real host SysV IPC object is invisible from the target namespace.\n\nAcceptance evidence is executable:\n\n- the trusted host creates a SysV message queue under a collision-checked explicit key and proves `msgget(key, 0)` returns that queue ID before sandbox launch;\n- the raw target receives the same key and is explicitly granted `execveat`, `msgget`, and `exit`;\n- inside the new IPC namespace, `msgget(key, 0)` must return `ENOENT`; seeing the host queue or receiving seccomp `EPERM` fails the fixture;\n- the host removes the queue with `IPC_RMID` after the sandbox run, independent of whether the sandbox result succeeds;\n- `CLONE_NEWIPC` is part of the same fail-closed unshare as user/mount/PID/network namespaces, so failure never retries in the host IPC namespace;\n- all Milestones 1–4B regressions, stable quality checks, and Rust 1.74 full tests remain green.\n\nBoundary: 4C establishes SysV IPC/POSIX message-queue namespace separation. It does not revoke pipes, sockets, or other descriptor-based IPC deliberately exposed through the existing stdio/descriptor policy.\n\n### Milestone 4 promotion rule\n\nAfter 4C integrates, do not farm additional SysV keys, queue variants, or duplicate namespace probes. Return to 4A when real unprivileged cgroup-v2 delegation becomes available; otherwise promote to the next independently executable isolation/control-plane frontier. A strong candidate is an owned UTS identity slice that sets a launcher-controlled hostname in `CLONE_NEWUTS` and proves the target observes that value while the host hostname remains unchanged.\n",
    "roadmap 4C section",
)
replace_one(
    "ROADMAP.md",
    "External asynchronous cancellation, selected-handle passing, syscall-argument filtering, IPC/UTS isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "External asynchronous cancellation, selected-handle passing, syscall-argument filtering, UTS isolation, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "roadmap later IPC",
)
