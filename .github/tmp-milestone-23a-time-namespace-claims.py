from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 22B and describe only the executable 23A behavior.
replace_one(
    "README.md",
    "The current Milestone 22B verified candidate adds an optional **host-observed stdout total-output budget** for captured stdout: once the launcher observes bytes beyond the declared threshold, it asks launcher-owned PID 1 to terminate and reap the sandbox process tree and reports a distinct output-limit outcome.",
    "Milestone 22B added an optional **host-observed stdout total-output budget** for captured stdout: once the launcher observes bytes beyond the declared threshold, it asks launcher-owned PID 1 to terminate and reap the sandbox process tree and reports a distinct output-limit outcome. The current Milestone 23A verified candidate adds **policy-owned descendant time offsets**: when an explicit monotonic/boottime pair is declared, launcher setup creates a Linux time namespace for children and installs bounded offsets before namespace PID 1 is born.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "optional `limit.stdout_total_bytes`, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "optional `limit.stdout_total_bytes`, an all-or-nothing `time.monotonic_offset_seconds` / `time.boottime_offset_seconds` pair, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "README policy summary",
)
replace_one(
    "README.md",
    "**Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, installs the policy hostname in the new UTS namespace, makes mount propagation private,",
    "**Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces and, only when time offsets are declared, a child time namespace. It maps namespace UID/GID 0 to the launching effective UID/GID, then writes the prepared `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets to `/proc/self/timens_offsets` before the first namespace child exists. The bootstrap itself remains in the parent time namespace while launcher-owned PID 1 and the direct target inherit the configured child time namespace. Setup then installs the policy hostname in the new UTS namespace, makes mount propagation private,",
    "README namespace pipeline",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- When both time offsets are declared, only descendants enter the added Linux time namespace. Policy bounds each nonnegative offset to at most 31,536,000 seconds and rejects an all-zero pair; launcher setup writes both offsets after user/group mapping and before namespace PID 1 is forked. The host/bootstrap clock domain is not modified.\n",
    "README time invariant",
)
replace_one(
    "README.md",
    "`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.",
    "`time.monotonic_offset_seconds` and `time.boottime_offset_seconds` are an optional all-or-nothing pair. Each is a nonnegative integer no larger than 31,536,000 seconds (365 days), and they may not both be zero. When present, they request Linux descendant time-namespace offsets; they do not change host time or `CLOCK_REALTIME`.\n\n`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement. This remains a relative launcher supervision duration rather than a target-visible wall-clock timestamp policy.",
    "README time policy format",
)
replace_one(
    "README.md",
    "- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;\n",
    "- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;\n- a time-namespace policy declaring +3600 seconds for `CLOCK_MONOTONIC` and +7200 seconds for `CLOCK_BOOTTIME` causes a raw target granted only `clock_gettime`, `write`, `execveat`, and `exit` to emit both binary timespecs inside the corresponding host-before/host-after plus-offset windows, while the trusted parent proves its own monotonic clock did not jump;\n",
    "README time evidence",
)

# Threat model: explicit descendant clock-domain boundary, without realtime/virtual-time claims.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–21A + 22B threat model",
    "# Milestones 1–23A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 22B verified candidate adds a launcher-owned response to a host-observed captured-stdout threshold without claiming an exact kernel emission cap.",
    "Milestone 22B added a launcher-owned response to a host-observed captured-stdout threshold without claiming an exact kernel emission cap. The current Milestone 23A verified candidate optionally gives launcher descendants a separate Linux time namespace with bounded `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets while leaving the host/bootstrap clock domain unchanged.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, capabilities,",
    "namespace identity including a policy-owned UTS nodename, network/IPC/UTS namespace membership, optional descendant monotonic/boottime time-namespace offsets, capabilities,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Owned UTS nodename:** `identity.hostname` is required and fail-closed validated to 1–63 ASCII bytes. The trusted launcher installs it with `sethostname` inside the new UTS namespace before capability clearing and target seccomp.\n",
    "- **Owned UTS nodename:** `identity.hostname` is required and fail-closed validated to 1–63 ASCII bytes. The trusted launcher installs it with `sethostname` inside the new UTS namespace before capability clearing and target seccomp.\n- **Optional descendant time namespace:** `time.monotonic_offset_seconds` and `time.boottime_offset_seconds` are an all-or-nothing pair of nonnegative offsets bounded to one year each, with an all-zero pair rejected. Only when configured does launcher setup add `CLONE_NEWTIME`; after UID/GID mapping and before the first namespace child, it writes both prepared offsets to `/proc/self/timens_offsets`. The bootstrap remains in the parent time namespace while PID 1 and its target descendants inherit the child time namespace.\n",
    "threat time property",
)
replace_one(
    "THREAT_MODEL.md",
    "## Deadline, cancellation, and lifecycle orchestration\n",
    "## Time namespace semantics\n\nMilestone 23A uses Linux `CLONE_NEWTIME` only when both time-offset policy fields are declared. The calling bootstrap remains in the parent time namespace; `/proc/self/timens_offsets` configures the namespace that its subsequent children join. Offset records are formatted before the initial host `fork`, then written after the launcher owns its user-namespace UID/GID mapping but before namespace PID 1 exists. Consequently PID 1 and the direct target observe shifted `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`, while host-parent timing and bootstrap setup stay in the unshifted domain.\n\nThe executable oracle captures raw target timespecs for +3600-second monotonic and +7200-second boottime policy and requires each value to land between trusted host measurements plus the declared offset, allowing only a small scheduling tolerance. The parent also proves its own monotonic interval remains ordinary. This slice does not virtualize `CLOCK_REALTIME`, provide arbitrary clock rates/freezing/stepping, or create a deterministic virtual-time scheduler.\n\n## Deadline, cancellation, and lifecycle orchestration\n",
    "threat time semantics",
)
replace_one(
    "THREAT_MODEL.md",
    "- policy control of UTS domainname/NIS domain or a general machine-identity service;\n",
    "- policy control of UTS domainname/NIS domain or a general machine-identity service;\n- `CLOCK_REALTIME` virtualization, negative time offsets, clock-rate scaling/freezing, deterministic virtual time, or a general clock namespace policy. Milestone 23A offsets only descendant `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`;\n",
    "threat time non-goals",
)
replace_one(
    "THREAT_MODEL.md",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n- paired time-offset parser/validator regressions plus a raw `clock_gettime` oracle that observes the declared +3600-second monotonic and +7200-second boottime offsets inside trusted host measurement windows while the host monotonic clock remains unshifted;\n",
    "threat time evidence",
)

# Roadmap: seal 22B and promote the independently executable time-namespace slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.",
    "**Status: complete on `main`.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.",
    "roadmap 22B status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 22B promotion rule\n\nAfter 22B integrates, do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. Re-evaluate the reserved supplementary-group/user-namespace frontier separately, or promote to another independent subsystem frontier with executable evidence.\n\n## Later frontiers\n",
    "### Milestone 22B promotion rule\n\n22B is sealed on `main`. Do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. The supplementary-group frontier remains blocked by the current unprivileged user-namespace mapping semantics, so promotion moves to an independently executable kernel boundary.\n\n## Milestone 23 — policy-owned time domain\n\n### Slice 23A — descendant monotonic/boottime offsets\n\n**Current verified candidate.** Adds an optional Linux child time namespace rather than another resource/output variant.\n\nAcceptance evidence is executable:\n\n- policy accepts only the all-or-nothing pair `time.monotonic_offset_seconds` / `time.boottime_offset_seconds`; each value is nonnegative and bounded to 31,536,000 seconds, and an all-zero pair is rejected;\n- without the pair, the existing namespace flags and all prior execution behavior remain unchanged; with the pair, launcher setup adds `CLONE_NEWTIME`;\n- offset records are fully prepared before the initial fork, then written to `/proc/self/timens_offsets` after UID/GID mapping and before namespace PID 1 is created, so no policy formatting/allocation is introduced into the post-fork setup path;\n- Linux time-namespace child semantics keep the bootstrap in the parent clock domain while namespace PID 1 and the direct target inherit the configured child time namespace;\n- a raw target explicitly granted `clock_gettime`, `write`, `execveat`, and `exit` emits binary `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` timespecs. With +3600/+7200 second policy, each value must land inside the trusted host-before/host-after window plus its declared offset; the host monotonic interval itself must remain unshifted;\n- a five-second launcher-owned deadline is active in the same run, while all Milestones 1–22B regressions remain green; stable format/Clippy/full tests and the full Rust 1.74 suite pass on the exact implementation head.\n\nBoundary: 23A does not alter `CLOCK_REALTIME`, support negative offsets, rate scaling/freezing, clock stepping, deterministic virtual time, or a general scheduler/time API. The launcher wall-clock deadline remains a relative supervision control rather than a target-visible absolute time claim.\n\n### Milestone 23 promotion rule\n\nAfter 23A integrates, seal basic Linux time-offset ownership. Do not farm more offset values or clock-read fixture variants. Promote to a materially different executable subsystem; revisit supplementary groups, routed host networking, or cgroup accounting only when their documented environment prerequisites change.\n\n## Later frontiers\n",
    "roadmap 23A section",
)
