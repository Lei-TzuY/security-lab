from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 13B and document only the verified ABI-5 device-ioctl boundary.
replace_one(
    "README.md",
    "The current Milestone 13B verified candidate adds an independent **Landlock abstract UNIX socket scope** that can attenuate `connect` authority on an explicitly selected, already-open AF_UNIX socket when the remote abstract socket belongs to an outside Landlock domain.",
    "Milestone 13B added an independent **Landlock abstract UNIX socket scope** that can attenuate `connect` authority on an explicitly selected, already-open AF_UNIX socket when the remote abstract socket belongs to an outside Landlock domain. The current Milestone 14A verified candidate adds an optional **Landlock device-ioctl envelope** that narrows ioctl authority for character/block devices opened after the target enters its Landlock domain.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "repeatable `landlock.read_execute` and `landlock.file_mutate` paths, repeatable `landlock.tcp_bind_port`",
    "repeatable `landlock.read_execute`, `landlock.file_mutate`, and `landlock.device_ioctl` paths, repeatable `landlock.tcp_bind_port`",
    "README validation surface",
)
replace_one(
    "README.md",
    "Each Landlock pathname list is limited to 32 absolute sandbox paths and rejects `/` and duplicates.",
    "Each Landlock pathname list is limited to 32 absolute sandbox paths and rejects `/` and duplicates. A `landlock.device_ioctl` entry is additionally type-checked against the final mounted tree and must resolve to a character or block device.",
    "README device validation",
)
replace_one(
    "README.md",
    "builds a Landlock ruleset for the requested pathname/TCP-port access classes and IPC scopes",
    "builds a Landlock ruleset for the requested pathname/device-ioctl/TCP-port access classes and IPC scopes",
    "README target enforcement",
)
replace_one(
    "README.md",
    "- When `landlock.file_mutate` is non-empty, the runtime requires Landlock ABI 3 or newer and handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. Mutation paths are policy-bounded to existing writable authority: exactly the private scratch root or directories at/beneath `volume.writable_target`. Final mutation directories are pinned after scratch/volume mount construction, so the rule governs the actual mounted object rather than the pre-mount placeholder.\n",
    "- When `landlock.file_mutate` is non-empty, the runtime requires Landlock ABI 3 or newer and handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. Mutation paths are policy-bounded to existing writable authority: exactly the private scratch root or directories at/beneath `volume.writable_target`. Final mutation directories are pinned after scratch/volume mount construction, so the rule governs the actual mounted object rather than the pre-mount placeholder.\n- When `landlock.device_ioctl` is non-empty, the runtime requires Landlock ABI 5 or newer and handles `LANDLOCK_ACCESS_FS_IOCTL_DEV`. Each declared path is reopened against the final mounted tree after namespace/mount construction, must resolve without symlink/magic-link traversal to a character or block device, and receives one path-beneath ioctl rule. Landlock binds this device-ioctl right when a device is opened after restriction: undeclared newly opened devices may remain visible/openable but covered ioctls receive `EACCES`. Target `ioctl` still requires an explicit seccomp grant.\n",
    "README device invariant",
)
replace_one(
    "README.md",
    "- Landlock pathname/TCP rules do not generally revoke already-open descriptors. The 13B abstract-UNIX scope is a deliberate kernel-defined exception for cross-domain abstract-socket `connect`; it does not revoke already-connected stream traffic or other selected-handle operations.",
    "- Landlock pathname/TCP rules do not generally revoke already-open descriptors. Device-ioctl authority is likewise bound at device-open time, so `landlock.device_ioctl` does not retroactively attenuate a device fd opened before restriction. The 13B abstract-UNIX scope remains a separate kernel-defined exception for cross-domain abstract-socket `connect`; it does not revoke already-connected stream traffic or other selected-handle operations.",
    "README object capability boundary",
)
replace_one(
    "README.md",
    "`landlock.tcp_bind_port = <port>` and `landlock.tcp_connect_port = <port>` are independently optional and repeatable up to 32 entries each.",
    "`landlock.device_ioctl = <absolute-sandbox-device>` is independently optional and repeatable up to 32 entries. `/`, relative paths, and duplicates are rejected. Requested enforcement requires Landlock ABI 5 or newer. Against the final mounted sandbox tree, each configured path must resolve to a character or block device; declaring the path grants `LANDLOCK_ACCESS_FS_IOCTL_DEV` to device file descriptions opened after restriction. This is a coarse device-ioctl right, not a per-command ioctl allowlist, and it does not revoke ioctl authority already attached to a device fd opened before Landlock restriction. Target seccomp must still explicitly allow `ioctl`.\n\n`landlock.tcp_bind_port = <port>` and `landlock.tcp_connect_port = <port>` are independently optional and repeatable up to 32 entries each.",
    "README device policy format",
)
replace_one(
    "README.md",
    "- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;",
    "- with host-side baselines proving `RNDGETENTCNT` succeeds on both `/dev/urandom` and `/dev/random`, the sandbox mounts host `/dev` read-only at `/devices`, opens both devices after Landlock restriction, requires the same ioctl to succeed on declared `/devices/urandom`, and requires exact `EACCES` on undeclared `/devices/random`; target seccomp explicitly allows `ioctl`, so seccomp `EPERM` cannot masquerade as Landlock evidence;\n- exact allowed/denied syscall profiles behave as declared and malformed policies fail closed;",
    "README device executable evidence",
)

# Threat model: name the open-time device-FD authority precisely and preserve pre-opened-FD exceptions.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–13B threat model",
    "# Milestones 1–14A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 13B verified candidate adds independent abstract-UNIX-socket scoping that attenuates cross-domain `connect` on an explicitly selected AF_UNIX socket.",
    "Milestone 13B added independent abstract-UNIX-socket scoping that attenuates cross-domain `connect` on an explicitly selected AF_UNIX socket. The current Milestone 14A verified candidate adds ABI-5 device-ioctl mediation for character/block devices opened after Landlock restriction.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "optional Landlock read/execute and regular-file mutation pathname envelopes, independently optional Landlock TCP bind/connect port envelopes",
    "optional Landlock read/execute and regular-file mutation pathname envelopes, an optional Landlock device-ioctl envelope, independently optional Landlock TCP bind/connect port envelopes",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock regular-file mutation envelope:** `landlock.file_mutate` may name only the scratch root or a directory equal to/beneath the writable persistent-volume target, so it only narrows pre-existing write authority. The direct target pins those directories after final mount construction and, on Landlock ABI 3+, handles `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; undeclared sibling directories on the same writable mount receive `EACCES` for covered create/write/truncate/remove operations.\n",
    "- **Optional Landlock regular-file mutation envelope:** `landlock.file_mutate` may name only the scratch root or a directory equal to/beneath the writable persistent-volume target, so it only narrows pre-existing write authority. The direct target pins those directories after final mount construction and, on Landlock ABI 3+, handles `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; undeclared sibling directories on the same writable mount receive `EACCES` for covered create/write/truncate/remove operations.\n- **Optional Landlock device-ioctl envelope:** non-empty `landlock.device_ioctl` requires Landlock ABI 5+. After final mount construction the direct target resolves each declared path without symlink/magic-link traversal, requires a character or block device, and grants `LANDLOCK_ACCESS_FS_IOCTL_DEV` through a path-beneath rule. The kernel binds this right when the device is opened after restriction, so an undeclared newly opened device receives `EACCES` for covered ioctls even when pathname visibility and target seccomp permit the open/ioctl syscalls.\n",
    "threat device property",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Object-capability boundary:** pathname/TCP Landlock rules do not generally retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B/11A brokered sockets. Milestone 13B is the narrow kernel-defined exception for cross-domain abstract-UNIX `connect`; already-connected streams and unrelated object operations keep their documented authority.",
    "- **Object-capability boundary:** pathname/TCP Landlock rules do not generally retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B/11A brokered sockets. Device-ioctl permission is also attached at device-open time, so a device fd opened before restriction keeps its existing ioctl authority. Milestone 13B is the narrow kernel-defined exception for cross-domain abstract-UNIX `connect`; already-connected streams and unrelated object operations keep their documented authority.",
    "threat object capability boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "Enabling abstract-UNIX scope likewise does not add `connect` or `socket`; 13B's executable oracle explicitly grants only `connect` on an already-selected socket.",
    "Enabling abstract-UNIX scope likewise does not add `connect` or `socket`; 13B's executable oracle explicitly grants only `connect` on an already-selected socket. Enabling device-ioctl mediation does not add `ioctl`; 14A's executable oracle explicitly grants that syscall and distinguishes Landlock `EACCES` from seccomp `EPERM`.",
    "threat no widening",
)
replace_one(
    "THREAT_MODEL.md",
    "## Network namespace semantics",
    "## Landlock device-ioctl semantics\n\nMilestone 14A is independently optional. A non-empty `landlock.device_ioctl` list is bounded to 32 unique absolute sandbox paths, forbids `/`, and requires Landlock ABI 5 or newer. The direct target resolves each path only after persistent-volume/scratch mount construction, verifies with `fstat` that the final object is a character or block device, and adds one `LANDLOCK_RULE_PATH_BENEATH` rule granting `LANDLOCK_ACCESS_FS_IOCTL_DEV`. Unsupported older ABIs or invalid final object types fail closed.\n\nDevice-ioctl authority is an open-time Landlock property rather than a retroactive descriptor revocation mechanism. The executable oracle therefore opens both `/devices/urandom` and `/devices/random` after restriction: `RNDGETENTCNT` succeeds on the declared first device and returns exact `EACCES` on the undeclared sibling, while host-side baselines prove the ioctl itself works on both underlying devices. This slice does not provide a per-ioctl-command allowlist, attenuate a device fd opened before restriction, create a device namespace, or authorize target `ioctl` through seccomp.\n\n## Network namespace semantics",
    "threat device semantics section",
)

# Roadmap: seal 13B and promote the already-green device-ioctl implementation as 14A.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a distinct cross-domain socket-object boundary and deliberately composes with existing selected-handle authority rather than inventing another broker path.",
    "**Status: complete on `main`.** Adds a distinct cross-domain socket-object boundary and deliberately composes with existing selected-handle authority rather than inventing another broker path.",
    "roadmap 13B status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 13 promotion rule\n\nAfter 13B integrates, seal the ABI-6 Landlock scope surface at this bounded laboratory scope. Do not farm signal syscall aliases, signal numbers, or AF_UNIX socket-type variants that repeat the same scoped-field mechanism. Promote only to a materially different executable authority frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n\n## Later frontiers",
    "### Milestone 13 promotion rule\n\n13B is integrated; seal the ABI-6 Landlock scope surface at this bounded laboratory scope. Do not farm signal syscall aliases, signal numbers, or AF_UNIX socket-type variants that repeat the same scoped-field mechanism. Promote only to a materially different executable authority frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n\n## Milestone 14 — device operation authority\n\n### Slice 14A — Landlock device-ioctl envelope\n\n**Current verified candidate.** Adds a distinct device-driver operation boundary rather than another pathname, network-port, or IPC-scope variant.\n\nAcceptance evidence is executable:\n\n- policy accepts repeatable `landlock.device_ioctl = <absolute-sandbox-device>` entries, bounded to 32 unique paths; `/`, relative paths, duplicates, and oversized lists are rejected fail-closed;\n- requested enforcement requires Landlock ABI 5 or newer. Older or unavailable kernels fail explicitly rather than silently dropping `LANDLOCK_ACCESS_FS_IOCTL_DEV`;\n- after final namespace/mount construction, the direct target resolves each declared path with `openat2` beneath the sandbox root while rejecting symlink/magic-link traversal, verifies with `fstat` that it is a character or block device, and adds a `LANDLOCK_RULE_PATH_BENEATH` rule carrying only `IOCTL_DEV`;\n- host-side baselines first prove `RNDGETENTCNT` succeeds on both `/dev/urandom` and `/dev/random`; the sandbox then exposes host `/dev` read-only at `/devices`, so both device nodes are real and visible without creating a device namespace;\n- the raw target opens `/devices/urandom` after Landlock restriction and the same ioctl succeeds, proving positive declared authority; it separately opens undeclared `/devices/random` after restriction and requires exact `EACCES` for the same ioctl, proving Landlock denial rather than pathname invisibility;\n- target seccomp explicitly grants `openat`, `ioctl`, `close`, and `exit`, so seccomp `EPERM` cannot masquerade as device-ioctl evidence; all earlier sandbox/CLI regressions remain active, and the exact synced candidate passes stable format/Clippy/full tests plus the full Rust 1.74 suite.\n\nBoundary: Landlock ABI-5 `IOCTL_DEV` is a coarse right bound when a character/block device is opened after restriction. 14A does not provide a per-ioctl-command allowlist, revoke ioctl authority already attached to a pre-restriction fd, create/filter device nodes, provide a device namespace, or widen target seccomp.\n\n### Milestone 14 promotion rule\n\nAfter 14A integrates, seal this coarse device-ioctl layer. Do not farm extra device names or ioctl request codes through the same rule. Promote only to a materially different executable frontier with kernel/runtime evidence.\n\n## Later frontiers",
    "roadmap 14A section",
)
