from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 25A and describe the verified 26A boundary without claiming
# full PID1 secrecy.
replace_one(
    "README.md",
    "The current Milestone 25A verified candidate adds a **runtime enforcement receipt** to successful `RunReport`/`run-json` results, positively recording launcher-owned kernel setup stages that actually completed during that invocation.",
    "Milestone 25A added a **runtime enforcement receipt** to `RunReport`/`run-json`, positively recording launcher-owned kernel setup stages that actually completed during that invocation. The current Milestone 26A verified candidate adds an optional **private procfs for the sandbox PID namespace** while hardening launcher-owned PID 1 so the target cannot reopen PID1 control descriptors through `/proc/1/fd`.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only or writable volume source/target pairs, repeatable `landlock.read_execute`,",
    "Optional `filesystem.proc = enabled|disabled`, read-only or writable volume source/target pairs, repeatable `landlock.read_execute`,",
    "README proc policy summary",
)
replace_one(
    "README.md",
    "6. **PID-namespace lifecycle split** forks the first process in the new PID namespace as launcher-owned PID 1. That init forks the direct target as PID 2. PID 1 stays outside target stdio/rlimit/capability/seccomp setup.",
    "6. **PID-namespace lifecycle split / optional private procfs** forks the first process in the new PID namespace as launcher-owned PID 1. When `filesystem.proc = enabled`, PID 1 first mounts a fresh `nosuid,nodev,noexec` procfs at `/proc`, then sets itself non-dumpable with `PR_SET_DUMPABLE=0` before forking the direct target as PID 2. This keeps namespace PID metadata available while the kernel proc/ptrace credential gate denies target access to PID1's `/proc/1/fd` descriptor table. PID 1 stays outside target stdio/rlimit/capability/seccomp setup.",
    "README proc lifecycle",
)
replace_one(
    "README.md",
    "The receipt positively records completed base namespace, optional time-offset, hostname, private-mount, read-only-root, chroot, FD-sanitization, rlimit, capability-reduction, `no_new_privs`, optional Landlock, and seccomp stages.",
    "The receipt positively records completed base namespace, optional time-offset, hostname, private-mount, read-only-root, chroot, FD-sanitization, optional private-procfs boundary, rlimit, capability-reduction, `no_new_privs`, optional Landlock, and seccomp stages.",
    "README receipt proc field",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- When `filesystem.proc = enabled`, launcher-owned PID 1 mounts a fresh procfs only after entering the sandbox PID namespace and before the direct target exists. PID 1 then sets `PR_SET_DUMPABLE=0`; the `private_procfs` receipt bit is published only after both operations succeed. `/proc/1` and `/proc/2` remain visible and `/proc/1/status` may remain readable, but the target must receive `EACCES` opening `/proc/1/fd`, so PID1 cancellation/deadline/pidfd control descriptors are not reacquirable through procfs.\n",
    "README proc invariant",
)
replace_one(
    "README.md",
    "`limit.stdout_total_bytes` is optional and valid only with stdout capture.",
    "`filesystem.proc` is optional and accepts only `enabled` or `disabled` (default `disabled`). When enabled, `/proc` must be an existing directory beneath the selected root and may not hide the executable/working directory or overlap scratch or persistent-volume targets. The runtime mounts a fresh procfs for the sandbox PID namespace and hardens launcher-owned PID 1's proc descriptor visibility before target fork. This is PID-namespace observability plus a control-descriptor boundary, not full PID1 metadata secrecy.\n\n`limit.stdout_total_bytes` is optional and valid only with stdout capture.",
    "README proc policy format",
)
replace_one(
    "README.md",
    "Linux x86_64 integration tests prove that:\n\n",
    "Linux x86_64 integration tests prove that:\n\n- with `filesystem.proc = enabled`, a raw target sees namespace `/proc/1` and `/proc/2` while the trusted host PID is absent; a second raw target runs under an unsignalled cancellation token plus a five-second deadline, keeps `/proc/1/status` readable, and requires exact `EACCES` opening `/proc/1/fd`, while the report positively records `private_procfs`;\n",
    "README proc evidence",
)

# ROADMAP: 25A is already integrated on main; 26A is the current executable
# candidate and its integration gate now includes PID1 descriptor-access closure.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds structured positive evidence for launcher-owned setup stages that actually completed during a sandbox invocation.",
    "**Status: complete on `main`.** Adds structured positive evidence for launcher-owned setup stages that actually completed during a sandbox invocation.",
    "ROADMAP 25A status",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.",
    """## Milestone 26 — PID namespace observability surface

### Slice 26A — private procfs with PID1 control-descriptor closure

**Current verified candidate.** Adds an optional procfs view backed by the sandbox PID namespace while preserving launcher-owned PID 1 control authority.

Acceptance evidence is executable:

- policy accepts `filesystem.proc = enabled|disabled`, defaults to disabled, requires an existing `/proc` directory beneath the selected root, and rejects overlap with executable/working directory, private scratch, or persistent-volume targets;
- after the process becomes namespace PID 1 and before the direct target is forked, PID 1 mounts a fresh procfs at `/proc` with `MS_NOSUID|MS_NODEV|MS_NOEXEC`;
- PID 1 immediately sets `PR_SET_DUMPABLE=0`; failure is a distinct fail-closed launch phase, and the `private_procfs` enforcement-receipt bit is published only after both the procfs mount and PID1 descriptor-access hardening succeed;
- the original raw oracle proves `/proc/1` and `/proc/2` exist while a trusted host PID path is `ENOENT`, and the host-side mountpoint returns to its empty fixture state after the private mount namespace exits;
- a separate control-plane raw oracle runs with an unsignalled `CancellationToken` plus a five-second deadline, preserves `/proc/1/status` readability, and requires exact `EACCES` when opening `/proc/1/fd`; natural `Exited(0)` still wins, proving the hardening composes with real cancellation/deadline supervision instead of disabling that lifecycle path;
- all prior sandbox/tooling regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact candidate.

Boundary: 26A is PID-namespace proc observability with explicit closure of PID1's proc descriptor-table route. It does not claim that PID1 cmdline/status metadata is secret, hide the existence of PID1, implement arbitrary procfs mount options, provide a per-process visibility policy, or prevent a sufficiently privileged external host process from observing the sandbox.

### Milestone 26 promotion rule

After 26A integrates, seal the private-procfs/PID-visibility slice. Do not farm proc mount-option aliases or additional metadata files. Promote to a materially different executable authority/enforcement frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their prerequisites change.

## Later frontiers

Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, routed/broader network authority beyond the bounded IPv4 brokers, generalized host-local IPC authority beyond the exact-path/peer-credential broker, and delegated aggregate cgroup accounting remain separate evidence-backed frontiers. Do not add configuration-only names without executable kernel behavior and integration evidence.""",
    "ROADMAP 26A section",
)

# Threat model: keep the claim deliberately narrower than process secrecy.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–24B + Milestone 25A candidate threat model",
    "# Milestones 1–25A + Milestone 26A candidate threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 25A verified candidate adds a post-attempt runtime enforcement receipt whose positive fields are published only after the corresponding launcher-owned kernel setup operation succeeds.",
    "Milestone 25A added a post-attempt runtime enforcement receipt whose positive fields are published only after the corresponding launcher-owned kernel setup operation succeeds. The current Milestone 26A verified candidate adds an optional private procfs for the sandbox PID namespace and explicitly closes the target's `/proc/1/fd` route to launcher-owned PID1 control descriptors.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "network/IPC/UTS namespace membership plus an optional descendant time namespace, capabilities,",
    "network/IPC/UTS namespace membership plus optional descendant time and private-procfs views, capabilities,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.\n",
    "- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.\n- **Optional private procfs / PID1 control boundary:** when `filesystem.proc = enabled`, namespace PID 1 mounts a fresh `nosuid,nodev,noexec` procfs at `/proc` before direct-target fork and then sets `PR_SET_DUMPABLE=0`. The runtime publishes `private_procfs` only after both steps succeed. Namespace PID metadata such as `/proc/1/status` may remain readable, but opening `/proc/1/fd` from the target must fail with `EACCES`, preventing procfs from turning PID1's cancellation eventfd, timerfd, pidfd, or other launcher-owned descriptors into target capabilities.\n",
    "threat proc property",
)
replace_one(
    "THREAT_MODEL.md",
    "- persistent executable allowlisting, multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.",
    "- full secrecy of launcher-owned PID 1 metadata. Milestone 26A intentionally permits PID1 existence and ordinary status/cmdline-style observability while sealing the `/proc/1/fd` descriptor-table route;\n- persistent executable allowlisting, multi-architecture seccomp, side-channel resistance, or protection from sufficiently privileged external ptrace/signal interference.",
    "threat proc non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "Evidence includes:\n\n",
    "Evidence includes:\n\n- private-procfs policy/receipt regressions plus two raw target oracles: one proves namespace PID 1/2 visibility with the trusted host PID absent, and one runs under real unsignalled cancellation + deadline supervision, proves `/proc/1/status` remains observable, and requires exact `EACCES` for `/proc/1/fd`;\n\n",
    "threat proc evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 23A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, supplementary-group closure, resource observability, observed-output enforcement, and bounded descendant time-namespace phases are sealed. Milestone 24A static authority-manifest tooling is also complete on `main`. The current Milestone 24B verified candidate adds conservative partial runtime-capability preflight while explicitly refusing to claim full launch compatibility from unprobed mandatory mechanisms. After 24B integrates, seal this observability layer rather than farming command/output aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; future promotion must target a materially different executable authority/enforcement frontier or add genuinely safe positive evidence for a previously unprobed mandatory runtime prerequisite.",
    "Milestones through 25A are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, resource observability, observed-output enforcement, descendant time namespace, static/preflight observability, and runtime enforcement-receipt phases are sealed. The current Milestone 26A verified candidate adds private PID-namespace procfs observability while explicitly hardening launcher-owned PID1 descriptor-table access before target fork. After 26A integrates, seal this PID-visibility slice rather than farming proc mount aliases. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; supplementary-group isolation also remains blocked on a viable mapping architecture. Future promotion must target a materially different executable authority/enforcement frontier or add genuinely safe positive evidence for a previously unprobed mandatory runtime prerequisite.",
    "threat phase promotion",
)
