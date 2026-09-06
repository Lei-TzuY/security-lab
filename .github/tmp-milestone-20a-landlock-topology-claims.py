from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))

# README: seal already-integrated 19A and document only the verified 20A authority.
replace_one(
    "README.md",
    "The current Milestone 19A verified candidate can additionally **bind that broker to one exact peer UID/GID pair**",
    "Milestone 19A additionally **binds that broker to one exact peer UID/GID pair**",
    "README 19A seal",
)
replace_one(
    "README.md",
    "repeatable `landlock.read_execute`, `landlock.file_mutate`, and `landlock.device_ioctl` paths",
    "repeatable `landlock.read_execute`, `landlock.file_mutate`, `landlock.path_topology_mutate`, and `landlock.device_ioctl` paths",
    "README policy list",
)
replace_one(
    "README.md",
    "A non-empty read/execute list must cover the initial executable; each file-mutation path must name the scratch root itself or lie beneath the declared writable persistent-volume target.",
    "A non-empty read/execute list must cover the initial executable; each file-mutation path must name the scratch root itself or lie beneath the declared writable persistent-volume target. Every `landlock.path_topology_mutate` entry must exactly match one declared `landlock.file_mutate` directory, so topology authority cannot introduce a new writable pathname surface.",
    "README topology validation",
)
replace_one(
    "README.md",
    "- When `landlock.file_mutate` is non-empty, the runtime requires Landlock ABI 3 or newer and handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. Mutation paths are policy-bounded to existing writable authority: exactly the private scratch root or directories at/beneath `volume.writable_target`. Final mutation directories are pinned after scratch/volume mount construction, so the rule governs the actual mounted object rather than the pre-mount placeholder.\n",
    "- When `landlock.file_mutate` is non-empty, the runtime requires Landlock ABI 3 or newer and handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. Mutation paths are policy-bounded to existing writable authority: exactly the private scratch root or directories at/beneath `volume.writable_target`. Final mutation directories are pinned after scratch/volume mount construction, so the rule governs the actual mounted object rather than the pre-mount placeholder.\n- `landlock.path_topology_mutate` is an explicit augmentation of an exactly matching `landlock.file_mutate` directory. For those paths the same final-tree Landlock rule additionally grants only `MAKE_DIR`, `REMOVE_DIR`, `MAKE_SYM`, and `REFER`, enabling bounded directory/symlink creation and cross-directory rename/reparent while leaving socket/FIFO/device creation ungranted. Target `mkdir`, `rmdir`, `symlink`, and `rename` still require explicit seccomp grants.\n",
    "README topology invariant",
)
replace_one(
    "README.md",
    "The handled mutation rights are `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; directory creation/removal, symlink/device/socket/FIFO creation, rename/link `REFER`, and broader metadata mutation remain outside this slice.",
    "The base handled mutation rights are `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. An optional matching `landlock.path_topology_mutate` entry adds only `MAKE_DIR`, `REMOVE_DIR`, `MAKE_SYM`, and `REFER` to that same directory rule; device/socket/FIFO creation and broader metadata mutation remain outside the model.",
    "README topology policy semantics",
)

# Threat model: candidate claim is executable, but remains a narrow augmentation.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–19A threat model",
    "# Milestones 1–20A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 19A verified candidate optionally narrows that authority by requiring the connected peer's Linux `SO_PEERCRED` UID/GID to match one declared pair before target launch.",
    "Milestone 19A optionally narrows that authority by requiring the connected peer's Linux `SO_PEERCRED` UID/GID to match one declared pair before target launch. The current Milestone 20A verified candidate adds an explicit Landlock pathname-topology mutation augmentation for directories that already have the regular-file mutation envelope.",
    "threat purpose promotion",
)
replace_one(
    "THREAT_MODEL.md",
    "optional Landlock read/execute and regular-file mutation pathname envelopes, an optional Landlock device-ioctl envelope",
    "optional Landlock read/execute, regular-file mutation, and matching pathname-topology mutation envelopes, an optional Landlock device-ioctl envelope",
    "threat protected topology",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock regular-file mutation envelope:** `landlock.file_mutate` may name only the scratch root or a directory equal to/beneath the writable persistent-volume target, so it only narrows pre-existing write authority. The direct target pins those directories after final mount construction and, on Landlock ABI 3+, handles `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; undeclared sibling directories on the same writable mount receive `EACCES` for covered create/write/truncate/remove operations.\n",
    "- **Optional Landlock regular-file mutation envelope:** `landlock.file_mutate` may name only the scratch root or a directory equal to/beneath the writable persistent-volume target, so it only narrows pre-existing write authority. The direct target pins those directories after final mount construction and, on Landlock ABI 3+, handles `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; undeclared sibling directories on the same writable mount receive `EACCES` for covered create/write/truncate/remove operations.\n- **Optional Landlock pathname-topology mutation augmentation:** every `landlock.path_topology_mutate` path must exactly match an existing `landlock.file_mutate` directory. The matching final-tree rule additionally receives only `MAKE_DIR`, `REMOVE_DIR`, `MAKE_SYM`, and `REFER`. The raw target proves mkdir/symlink/rename/rmdir succeed inside `/persist/allowed`, equivalent sibling operations receive exact `EACCES`, and a rename from the allowed subtree into the denied sibling is rejected before host topology changes.\n",
    "threat topology property",
)

# Roadmap: close 19A, promote 20A as a materially different filesystem authority slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Narrows the already-bounded 18A object capability with kernel-provided peer identity evidence before target authority exists.",
    "**Status: complete on `main`.** Narrows the already-bounded 18A object capability with kernel-provided peer identity evidence before target authority exists.",
    "roadmap 19A seal",
)
replace_one(
    "ROADMAP.md",
    "After 19A integrates, seal peer UID/GID matching at this bounded scope. Do not farm PID/credential field variants around the same `SO_PEERCRED` query. Promote only to a materially different executable authority/enforcement frontier. Supplementary-group isolation and delegated cgroup accounting remain blocked on their documented prerequisites.\n\n## Later frontiers",
    "19A is integrated; peer UID/GID matching is sealed at this bounded scope. Do not farm PID/credential field variants around the same `SO_PEERCRED` query. Promotion moves to a materially different executable authority/enforcement frontier. Supplementary-group isolation and delegated cgroup accounting remain blocked on their documented prerequisites.\n\n## Milestone 20 — Landlock pathname topology authority\n\n### Slice 20A — bounded directory/symlink/reparent mutation\n\n**Current verified candidate.** Extends the existing 10B regular-file mutation envelope with an explicit topology authority bitset rather than implicitly widening every writable directory.\n\nAcceptance evidence is executable:\n\n- repeatable `landlock.path_topology_mutate = <absolute-sandbox-directory>` entries are bounded to 32 unique non-root paths and each must exactly match a declared `landlock.file_mutate` directory; topology policy therefore cannot introduce a writable path that did not already pass the regular-file mutation surface checks;\n- the direct target reuses the same post-mount pinned Landlock path rule and adds only `LANDLOCK_ACCESS_FS_MAKE_DIR`, `REMOVE_DIR`, `MAKE_SYM`, and `REFER`; regular-file rights remain the 10B set and socket/FIFO/device creation rights are not granted;\n- target syscall authority remains independently explicit: `mkdir`, `rmdir`, `symlink`, and `rename` are recognized by the x86_64 seccomp compiler but are not auto-added to any allowlist;\n- a raw target creates and removes `/persist/allowed/newdir`, creates `/persist/allowed/newlink`, and renames `/persist/allowed/from/item` to `/persist/allowed/to/item`; host-side assertions prove exact renamed bytes and symlink target;\n- equivalent mkdir/symlink operations beneath `/persist/denied` and a rename from the allowed subtree into that denied sibling must return exact Landlock `EACCES`, while the trusted parent proves no denied-side objects were created;\n- the existing 10B file-mutation oracle and all Milestones 1–19A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 20A is a narrow augmentation of an existing `landlock.file_mutate` directory. It does not grant socket/FIFO/device creation, general metadata mutation, filesystem alias/canonicalization proof, rights revocation for pre-opened descriptors, or a general mount/filesystem transaction model.\n\n### Milestone 20 promotion rule\n\nAfter 20A integrates, seal this bounded pathname-topology slice. Do not farm additional topology syscall spellings that map to the same Landlock rights. Promote to a materially different capability such as a broader routed network model only with explicit topology/endpoint evidence, or revisit blocked cgroup/supplementary-group work only when its environment/namespace prerequisites become real.\n\n## Later frontiers",
    "roadmap 20A section",
)
