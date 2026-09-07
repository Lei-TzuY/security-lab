from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: reflect already-integrated 22B/24A and describe only verified 23A behavior.
replace_one(
    "README.md",
    "The current Milestone 22B verified candidate adds an optional **host-observed stdout total-output budget** for captured stdout: once the launcher observes bytes beyond the declared threshold, it asks launcher-owned PID 1 to terminate and reap the sandbox process tree and reports a distinct output-limit outcome.",
    "Milestone 22B added an optional **host-observed stdout total-output budget** for captured stdout: once the launcher observes bytes beyond the declared threshold, it asks launcher-owned PID 1 to terminate and reap the sandbox process tree and reports a distinct output-limit outcome. Milestone 24A added deterministic human and JSON **static policy-authority manifests** that validate policy without launching or probing runtime support. The current Milestone 23A verified candidate adds an optional **policy-owned Linux time namespace for descendants**, with bounded `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` offsets installed before namespace PID 1 and the target are created.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "optional `limit.stdout_total_bytes`, selected non-stdio handles, and `limit.wall_clock_milliseconds`",
    "optional `limit.stdout_total_bytes`, the paired `time.monotonic_offset_seconds` / `time.boottime_offset_seconds` controls, selected non-stdio handles, and `limit.wall_clock_milliseconds`",
    "README policy summary",
)
replace_one(
    "README.md",
    "3. **Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces, maps namespace UID/GID 0 to the launching effective UID/GID, installs the policy hostname in the new UTS namespace, makes mount propagation private,",
    "3. **Owned namespace/filesystem/identity setup** atomically creates user, mount, PID, network, IPC, and UTS namespaces and, when the paired time offsets are declared, also requests `CLONE_NEWTIME` for a child time namespace. It maps namespace UID/GID 0 to the launching effective UID/GID; before namespace PID 1 or the target exists, it writes the declared `monotonic` and `boottime` offsets to `/proc/self/timens_offsets`. It installs the policy hostname in the new UTS namespace, makes mount propagation private,",
    "README namespace pipeline",
)
replace_one(
    "README.md",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n",
    "- The target receives user/mount/PID/network/IPC/UTS namespace isolation, private mount propagation, a recursively read-only root, chroot/cwd selection, capability clearing, `no_new_privs`, rlimits, and default-deny seccomp.\n- When both time offsets are declared, launcher bootstrap remains on the host clock view while its subsequently created PID 1/target descendants enter the prepared time namespace. `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` observe the configured nonnegative offsets; `CLOCK_REALTIME` is not virtualized or claimed.\n",
    "README time invariant",
)
replace_one(
    "README.md",
    "`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.\n",
    "The time namespace is optional and uses the all-or-nothing pair `time.monotonic_offset_seconds` / `time.boottime_offset_seconds`. Each offset must be 0 through 31,536,000 seconds (365 days), and they may not both be zero. These values change only descendant `CLOCK_MONOTONIC` / `CLOCK_BOOTTIME` readings; they are separate from the launcher's wall-clock deadline and do not change host clocks or `CLOCK_REALTIME`.\n\n`limit.wall_clock_milliseconds` is optional. When present it must be an integer from 1 through 86,400,000 and enables launcher-owned monotonic deadline enforcement.\n",
    "README time policy",
)
replace_one(
    "README.md",
    "- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;\n",
    "- required hostname parsing rejects missing, duplicate, empty, oversized, underscore-containing, and leading/trailing punctuation values; a raw target explicitly granted `uname` observes the exact policy hostname while the trusted parent proves `/proc/sys/kernel/hostname` is byte-for-byte unchanged before and after sandbox execution;\n- paired time-offset policy rejects incomplete, all-zero, and oversized declarations; a raw target explicitly granted `clock_gettime` emits `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` timespecs, and the trusted parent requires them to fall within bounded tolerance of host samples plus exact 3,600-second and 7,200-second configured offsets;\n",
    "README time evidence",
)
replace_one(
    "README.md",
    "user/mount/PID/network/IPC/UTS namespaces, `sethostname`, UID/GID maps,",
    "user/mount/PID/network/IPC/UTS namespaces, optional `CLONE_NEWTIME` plus `/proc/self/timens_offsets` when time offsets are declared, `sethostname`, UID/GID maps,",
    "README platform support",
)

# Threat model: precise descendant-clock property, no wall-clock/RTC overclaim.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–21A + 22B threat model",
    "# Milestones 1–22B + 23A candidate threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 22B verified candidate adds a launcher-owned response to a host-observed captured-stdout threshold without claiming an exact kernel emission cap.",
    "Milestone 22B added a launcher-owned response to a host-observed captured-stdout threshold without claiming an exact kernel emission cap. The current Milestone 23A verified candidate adds a policy-owned child time namespace with bounded monotonic/boottime offsets while leaving the trusted bootstrap and host clocks unchanged.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "network/IPC/UTS namespace membership, capabilities,",
    "network/IPC/UTS namespace membership plus an optional descendant time namespace, capabilities,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.\n",
    "- **User/mount/PID/network/IPC/UTS namespace isolation:** namespace UID/GID 0 map only to the launching effective UID/GID; mount propagation is private; launcher-owned PID 1 parents the direct target as PID 2; the target executes in distinct network, IPC, and UTS namespaces rather than sharing those host namespaces.\n- **Optional policy-owned descendant time namespace:** when the paired offsets are declared, the bootstrap adds `CLONE_NEWTIME`, writes `monotonic` and `boottime` offsets to `/proc/self/timens_offsets` after user-namespace mapping and before the first descendant is created, then forks PID 1/target into that prepared child time namespace. Policy bounds each nonnegative offset to 365 days and rejects an all-zero pair.\n",
    "threat time property",
)
replace_one(
    "THREAT_MODEL.md",
    "- policy control of UTS domainname/NIS domain or a general machine-identity service;\n",
    "- policy control of UTS domainname/NIS domain or a general machine-identity service;\n- `CLOCK_REALTIME`/RTC wall-clock virtualization, negative time offsets, arbitrary clock-rate changes, or a general virtual-time scheduler. Milestone 23A offsets only descendant `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`;\n",
    "threat time non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "and any wall-clock deadline. Enabling loopback authorizes",
    "any wall-clock deadline, and any declared monotonic/boottime time-namespace offsets. Enabling loopback authorizes",
    "threat time trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n",
    "- required `identity.hostname` parser regressions plus a raw target explicitly granted `uname` observing the exact configured nodename while the trusted parent verifies the host hostname is unchanged before/after execution;\n- paired time-offset parser/validator regressions plus a raw target explicitly granted `clock_gettime` whose captured `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME` values must track host samples plus exact 3,600-second and 7,200-second offsets within a bounded two-second scheduling tolerance;\n",
    "threat time evidence",
)
replace_one(
    "THREAT_MODEL.md",
    "Namespace creation, UTS hostname installation, selected-source pin/inspection,",
    "Namespace creation, requested time-offset installation, UTS hostname installation, selected-source pin/inspection,",
    "threat time failure",
)
replace_one(
    "THREAT_MODEL.md",
    "Milestones through 17A are complete on `main`; the bounded persistent-volume, pathname/Landlock, isolated-loopback, IPv4 broker, IPC-scope, device-ioctl, and post-mortem resource-observability phases are sealed. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation on the current GitHub-hosted runner, and supplementary-group clearing remains blocked by the current unprivileged `setgroups=deny`/`gid_map` mapping architecture. The current Milestone 18A verified candidate adds one exact filesystem-path AF_UNIX stream object capability with positive byte exchange plus direct-path `ENOENT` evidence. After 18A integrates, seal this single exact-path stream slice; do not farm socket paths, target-fd aliases, or AF_UNIX socket-type variants, and promote to a materially different executable authority/enforcement frontier.",
    "Milestones through 22B are complete on `main`; the bounded persistent-volume, namespace/network brokers, Landlock pathname/network/IPC/device envelopes, richer seccomp predicates, supplementary-group closure, resource observability, and observed-output enforcement phases are sealed. Milestone 24A static authority-manifest tooling is also complete on `main` and remains explicitly distinct from runtime preflight. The current Milestone 23A verified candidate adds one bounded descendant time-namespace model. After 23A integrates, seal this clock-offset slice rather than farming more clock IDs or offset spellings. Milestone 4A cgroup-v2 aggregate process accounting remains blocked by missing unprivileged delegation; future promotion must target a materially different executable authority, enforcement, runtime-preflight, or observability frontier.",
    "threat phase promotion",
)

# Roadmap: seal already-merged 22B, add 23A candidate and record already-merged 24A tooling.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.",
    "**Status: complete on `main`.** Converts captured-stdout overrun from unbounded drain work into an explicit launcher-owned termination result without changing target seccomp authority.",
    "roadmap 22B status",
)
replace_one(
    "ROADMAP.md",
    "After 22B integrates, do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. Re-evaluate the reserved supplementary-group/user-namespace frontier separately, or promote to another independent subsystem frontier with executable evidence.",
    "22B is sealed on `main`. Do not farm alternate byte units, stderr copies, or extra output-result spellings without a materially new output-control architecture. Promote to another independent subsystem frontier with executable evidence.",
    "roadmap 22B promotion",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n",
    "## Milestone 23 — descendant time virtualization\n\n### Slice 23A — policy-owned MONOTONIC/BOOTTIME offsets\n\n**Current verified candidate.** Adds one optional Linux time namespace for subsequently created sandbox descendants without changing host clocks or the launcher's own clock view.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `time.monotonic_offset_seconds` / `time.boottime_offset_seconds`, bounds each nonnegative value to 365 days, and rejects an all-zero pair;\n- only when requested, launcher namespace setup adds `CLONE_NEWTIME`; after UID/GID mapping and before namespace PID 1 exists, bootstrap writes the declared `monotonic` and `boottime` offsets to `/proc/self/timens_offsets`;\n- launcher-owned PID 1 and the direct target are created after offset installation and therefore enter the prepared child time namespace, while bootstrap and trusted host samples remain on the original clock view;\n- a raw target explicitly granted `clock_gettime` emits `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`; the parent requires values within two seconds of host samples plus exact 3,600-second and 7,200-second configured offsets;\n- static `manifest` / `manifest-json` output exposes the declared time-namespace authority without changing `runtime_preflight=false`;\n- all prior sandbox/tooling regressions, stable rustfmt/Clippy/full tests, and the full Rust 1.74 suite are green on the exact integrated candidate.\n\nBoundary: 23A does not virtualize `CLOCK_REALTIME`, set RTC/wall-clock time, support negative offsets or clock-rate scaling, or claim deterministic virtual scheduling.\n\n### Milestone 23 promotion rule\n\nAfter 23A integrates, seal this bounded clock-offset model. Do not farm more clock IDs, unit aliases, or offset spellings; promote only to a materially different executable frontier.\n\n## Milestone 24 — policy observability tooling\n\n### Slice 24A — static policy authority manifest\n\n**Status: complete on `main`.** `manifest` and `manifest-json` validate policy fail-closed and emit deterministic declared-authority summaries without launching the sandbox or probing kernel support. Argument contents and environment values remain redacted, while authority-bearing filesystem, broker, Landlock, resource, output, seccomp, and time-namespace fields are reviewable.\n\nBoundary: this is static observability, not runtime capability preflight or proof of effective kernel state.\n\n## Later frontiers\n",
    "roadmap 23/24 sections",
)
