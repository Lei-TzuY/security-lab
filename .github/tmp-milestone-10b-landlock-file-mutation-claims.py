from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def replace_section(path: str, start: str, end: str, replacement: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    start_index = text.find(start)
    if start_index < 0 or text.find(start, start_index + 1) >= 0:
        raise SystemExit(f"{label}: start marker missing or non-unique")
    end_index = text.find(end, start_index)
    if end_index < 0:
        raise SystemExit(f"{label}: end marker missing")
    p.write_text(text[:start_index] + replacement + text[end_index:])


# README: seal 10A and document only verified 10B mutation authority.
replace_one(
    "README.md",
    "The current Milestone 10A verified candidate adds an optional **Landlock read/execute pathname envelope** that further narrows which already-visible sandbox paths may be read or executed after trusted setup.",
    "Milestone 10A added an optional **Landlock read/execute pathname envelope** that narrows which already-visible sandbox paths may be read or executed after trusted setup. The current Milestone 10B verified candidate adds an independent **Landlock regular-file mutation envelope** that can only narrow already-writable scratch or persistent-volume surfaces.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only or writable volume source/target pairs, repeatable `landlock.read_execute` paths, `network.loopback`, one brokered host-loopback TCP port/target-fd pair, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. A non-empty Landlock list is limited to 32 absolute sandbox paths, rejects `/` and duplicates, and must cover the initial executable.",
    "Optional read-only or writable volume source/target pairs, repeatable `landlock.read_execute` and `landlock.file_mutate` paths, `network.loopback`, one brokered host-loopback TCP port/target-fd pair, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed. Each Landlock list is limited to 32 absolute sandbox paths and rejects `/` and duplicates. A non-empty read/execute list must cover the initial executable; each file-mutation path must name the scratch root itself or lie beneath the declared writable persistent-volume target.",
    "README policy summary",
)
replace_one(
    "README.md",
    "- When `landlock.read_execute` is non-empty, the launcher preflights Landlock support and the direct target installs a Landlock ruleset handling only `EXECUTE`, `READ_FILE`, and `READ_DIR`. Declared regular files receive read/execute access; declared directories grant those handled rights beneath them. Undeclared visible paths remain in the chroot but pathname reads/executes are denied by Landlock.\n- Landlock is an additional pathname restriction, not revocation of explicit object capabilities: already-open descriptors intentionally exposed through stdio, selected handles, or the brokered socket keep their documented object authority.",
    "- When `landlock.read_execute` is non-empty, the launcher preflights Landlock support and the direct target installs a Landlock ruleset handling only `EXECUTE`, `READ_FILE`, and `READ_DIR`. Declared regular files receive read/execute access; declared directories grant those handled rights beneath them. Undeclared visible paths remain in the chroot but pathname reads/executes are denied by Landlock.\n- When `landlock.file_mutate` is non-empty, the runtime requires Landlock ABI 3 or newer and handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`. Mutation paths are policy-bounded to existing writable authority: exactly the private scratch root or directories at/beneath `volume.writable_target`. Final mutation directories are pinned after scratch/volume mount construction, so the rule governs the actual mounted object rather than the pre-mount placeholder.\n- Landlock is an additional pathname restriction, not revocation of explicit object capabilities: already-open descriptors intentionally exposed through stdio, selected handles, redirection, or the brokered socket keep their documented object authority.",
    "README Landlock invariants",
)
replace_one(
    "README.md",
    "`landlock.read_execute = <absolute-sandbox-path>` is optional and repeatable up to 32 entries. An empty list disables Landlock and preserves legacy behavior. When enabled, `/` is forbidden, duplicate paths are rejected, and at least one declared path must cover the initial executable. The launcher requires every declared path to exist beneath the selected root as a regular file or directory, then reopens the final mounted object after namespace/mount construction before installing the Landlock rules. This slice handles read/execute rights only; it is not a general write-policy language.\n",
    "`landlock.read_execute = <absolute-sandbox-path>` is optional and repeatable up to 32 entries. An empty read/execute list leaves those rights unhandled. When enabled, `/` is forbidden, duplicate paths are rejected, and at least one declared path must cover the initial executable. The launcher requires every declared path to exist beneath the selected root as a regular file or directory, then reopens the final mounted object after namespace/mount construction before installing the Landlock rules.\n\n`landlock.file_mutate = <absolute-sandbox-directory>` is independently optional and repeatable up to 32 entries. It narrows regular-file mutation only: each path must be exactly `filesystem.scratch` or be equal to/beneath `volume.writable_target`; it cannot create writability on the recursively read-only root. Mutation paths are opened as directories against the final mounted tree. Requested mutation enforcement requires Landlock ABI 3 so `WRITE_FILE` and `TRUNCATE` can be controlled together; unsupported older ABIs fail explicitly rather than silently omitting truncation control. The handled mutation rights are `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; directory creation/removal, symlink/device/socket/FIFO creation, rename/link `REFER`, and broader mutation classes are outside this slice.\n",
    "README Landlock policy format",
)
replace_one(
    "README.md",
    "- with `/probe` and `/landlock-allowed` declared in `landlock.read_execute`, the raw target reads exact `landlock-allowed\\n` bytes from `/landlock-allowed/marker`, while a separately existing `/landlock-denied/secret` under the same chroot returns exact `EACCES`; this distinguishes Landlock denial from chroot invisibility or seccomp `EPERM`;\n",
    "- with `/probe` and `/landlock-allowed` declared in `landlock.read_execute`, the raw target reads exact `landlock-allowed\\n` bytes from `/landlock-allowed/marker`, while a separately existing `/landlock-denied/secret` under the same chroot returns exact `EACCES`; this distinguishes Landlock denial from chroot invisibility or seccomp `EPERM`;\n- with `/scratch` and `/persist/allowed` declared in `landlock.file_mutate`, a raw target creates a private-scratch file, truncates and rewrites `/persist/allowed/existing` to exact `landlock-persistent-write\\n`, and unlinks `/persist/allowed/remove-me`; sibling `/persist/denied` is on the same writable host mount but create and unlink attempts there must return exact `EACCES`. The parent proves the allowed host mutations persisted while the denied sentinel remains unchanged and no denied file was created;\n",
    "README Landlock mutation evidence",
)
replace_one(
    "README.md",
    "A brokered host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation.\n\nIf mandatory kernel primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the requested boundary.",
    "A brokered host-loopback endpoint additionally requires host-side IPv4 TCP `socket`/`connect` during parent preparation. Landlock read/execute enforcement requires ABI 1 or newer; requested regular-file mutation enforcement requires ABI 3 or newer because truncation was not restrictable before ABI 3.\n\nIf mandatory kernel primitives are unavailable or denied, launch returns an explicit unsupported/setup failure rather than dropping the requested boundary.",
    "README platform Landlock ABI",
)

# THREAT MODEL: exact 10B boundary, no broader filesystem claims.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–10A threat model",
    "# Milestones 1–10B threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 10A verified candidate adds an optional Landlock layer that narrows read/execute pathname authority within the already-constructed sandbox filesystem.",
    "Milestone 10A added an optional Landlock layer that narrows read/execute pathname authority within the already-constructed sandbox filesystem. The current Milestone 10B verified candidate adds an independent regular-file mutation envelope constrained to already-writable scratch or persistent-volume authority.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional brokered host-loopback TCP socket capability, an optional Landlock read/execute pathname envelope, stdio, bounded capture",
    "one optional brokered host-loopback TCP socket capability, optional Landlock read/execute and regular-file mutation pathname envelopes, stdio, bounded capture",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock read/execute envelope:** when at least one `landlock.read_execute` path is declared, the launcher requires kernel Landlock support, prevalidates each path beneath the selected root, then the direct target constructs rules against the final mounted tree. After capability reduction and `no_new_privs`, `landlock_restrict_self` activates handling for only `EXECUTE`, `READ_FILE`, and `READ_DIR` before seccomp and pinned exec. Undeclared visible paths therefore fail pathname read/execute access rather than becoming invisible.\n- **Object-capability exception:** Landlock does not retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, or the 9B broker. Those remain separate explicit object capabilities.",
    "- **Optional Landlock read/execute envelope:** when at least one `landlock.read_execute` path is declared, the launcher requires kernel Landlock support, prevalidates each path beneath the selected root, then the direct target constructs rules against the final mounted tree. After capability reduction and `no_new_privs`, `landlock_restrict_self` activates handling for only `EXECUTE`, `READ_FILE`, and `READ_DIR` before seccomp and pinned exec. Undeclared visible paths therefore fail pathname read/execute access rather than becoming invisible.\n- **Optional Landlock regular-file mutation envelope:** `landlock.file_mutate` may name only the scratch root or a directory equal to/beneath the writable persistent-volume target, so it only narrows pre-existing write authority. The direct target pins those directories after final mount construction and, on Landlock ABI 3+, handles `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE`; undeclared sibling directories on the same writable mount receive `EACCES` for covered create/write/truncate/remove operations.\n- **Object-capability exception:** Landlock does not retroactively attenuate already-open file descriptions or sockets deliberately exposed through stdio, selected handles, launcher-opened redirection, or the 9B broker. Those remain separate explicit object capabilities.",
    "threat Landlock properties",
)
replace_section(
    "THREAT_MODEL.md",
    "## Landlock pathname-envelope semantics\n",
    "## Network namespace semantics\n",
    '''## Landlock pathname-envelope semantics\n\nMilestones 10A–10B are optional and independently configured. An empty pair of Landlock lists performs no Landlock syscalls and preserves the prior filesystem behavior. `landlock.read_execute` is bounded to 32 unique absolute sandbox paths, forbids `/`, and must cover the initial executable when non-empty. `landlock.file_mutate` is separately bounded to 32 unique absolute sandbox directories, forbids `/`, and may only select the private scratch root itself or a directory equal to/beneath `volume.writable_target`. This makes 10B a narrowing layer rather than a way to invent write authority on the recursively read-only root.\n\nRead/execute paths are parent-prevalidated beneath the pinned root as regular files or directories. Mutation paths are deliberately pinned later by the direct target against the final mounted root because a writable persistent-volume subtree does not necessarily exist in the pre-mount root placeholder. Mutation paths must resolve as real directories with symlink/magic-link traversal forbidden. Exact paths present in both policy lists receive the union of their configured rights in one rule.\n\nThe ruleset handles only the rights actually requested. 10A uses `LANDLOCK_ACCESS_FS_EXECUTE`, `LANDLOCK_ACCESS_FS_READ_FILE`, and `LANDLOCK_ACCESS_FS_READ_DIR`. 10B uses `LANDLOCK_ACCESS_FS_WRITE_FILE`, `LANDLOCK_ACCESS_FS_MAKE_REG`, `LANDLOCK_ACCESS_FS_REMOVE_FILE`, and `LANDLOCK_ACCESS_FS_TRUNCATE`. Requested 10B enforcement requires Landlock ABI 3 or newer because older ABIs cannot restrict truncation; the runtime fails explicitly rather than weakening that claim. `PR_SET_NO_NEW_PRIVS` is set before `landlock_restrict_self`; setup failure is reported through the owned launch-error channel and never falls back to unrestricted execution.\n\nThe executable 10B oracle composes both writable surface types: it creates a file in private scratch, truncates and rewrites an existing file in `/persist/allowed`, removes another allowed regular file, and then requires exact `EACCES` for both create and unlink in sibling `/persist/denied` on the same writable mount. Parent-side checks prove exact persistent bytes, removal of only the allowed sentinel, preservation of the denied sentinel, and absence of the denied created file. Target seccomp explicitly grants `openat`, `write`, `close`, and `unlink`, so seccomp `EPERM` cannot masquerade as Landlock evidence.\n\nLandlock remains complementary to chroot/mount/seccomp/object-capability controls. It does not retroactively govern file descriptions opened before restriction. Milestone 10B intentionally does not handle directory creation/removal, symlink/device/socket/FIFO creation, `REFER` rename/link authority, filesystem aliases/canonicalization, or subtree-integrity proof.\n\n''',
    "threat Landlock semantics section",
)
replace_one(
    "THREAT_MODEL.md",
    "- a general Landlock filesystem policy: Milestone 10A handles only read/execute pathname rights, does not revoke pre-opened object capabilities, does not mediate write/create/remove rights, and does not prove filesystem aliases or subtree immutability;",
    "- a general Landlock filesystem policy: Milestones 10A/10B cover read/execute plus a bounded regular-file write/create/truncate/remove envelope only; they do not revoke pre-opened object capabilities, handle directory/symlink/device/socket/FIFO mutation or `REFER` rename/link authority, or prove filesystem aliases/subtree immutability;",
    "threat Landlock non-goal",
)

# ROADMAP: seal 10A and promote the verified 10B vertical slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a kernel-enforced pathname access layer inside the already-constructed sandbox filesystem rather than another mount or networking variant.",
    "**Status: complete on `main`.** Adds a kernel-enforced pathname access layer inside the already-constructed sandbox filesystem rather than another mount or networking variant.",
    "roadmap 10A status",
)
replace_one(
    "ROADMAP.md",
    '''### Milestone 10 promotion rule\n\nAfter 10A integrates, do not farm extra path-count limits or equivalent read/execute aliases. Further Landlock work must add a materially different executable authority dimension, such as an intentionally designed mutation envelope with interactions against scratch/persistent volumes, or the project should promote to another independent frontier.\n''',
    '''### Slice 10B — Landlock regular-file mutation envelope\n\n**Current verified candidate.** Adds a separate pathname-mutation authority dimension that composes with the two existing writable surfaces rather than broadening them.\n\nAcceptance evidence is executable:\n\n- repeatable `landlock.file_mutate = <absolute-sandbox-directory>` entries are bounded to 32, reject `/`, duplicates, relative paths, and any path that is not exactly the private scratch root or equal to/beneath `volume.writable_target`;\n- requested mutation enforcement requires Landlock ABI 3 or newer so `WRITE_FILE` and `TRUNCATE` are both controlled; older ABIs fail explicitly rather than degrading the security claim;\n- mutation paths are pinned against the final mounted tree after scratch/persistent-volume construction, with symlink/magic-link traversal forbidden, because writable-volume subdirectories may not exist in the pre-mount root placeholder;\n- the ruleset handles only regular-file `WRITE_FILE`, `MAKE_REG`, `REMOVE_FILE`, and `TRUNCATE` for this slice, while 10A read/execute rights remain independently optional and exact duplicate paths combine both requested authority sets;\n- a raw target creates inside `/scratch`, truncates+rewrites `/persist/allowed/existing` to exact `landlock-persistent-write\\n`, and removes `/persist/allowed/remove-me`; create and unlink in sibling `/persist/denied` on the same writable host mount each require exact `EACCES`;\n- parent-side evidence proves the exact allowed bytes persisted, the allowed removal occurred, the denied sentinel remained byte-for-byte unchanged, and no denied file was created; target seccomp explicitly grants every syscall used by the oracle;\n- all Milestones 1–10A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 10B is a regular-file pathname mutation envelope only. It does not handle directory creation/removal, symlink/device/socket/FIFO creation, rename/link `REFER`, rights revocation for pre-opened descriptors, filesystem alias/canonicalization proof, or subtree immutability.\n\n### Milestone 10 promotion rule\n\nAfter 10B integrates, seal this bounded pathname-envelope phase. Do not farm more regular-file mutation aliases or path-count variants. Promote to a materially different authority or resource frontier; delegated cgroup accounting and supplementary-group isolation remain blocked until their external/kernel mapping prerequisites change.\n''',
    "roadmap 10B promotion",
)
