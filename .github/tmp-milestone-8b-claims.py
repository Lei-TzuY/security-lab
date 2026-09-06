from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 8A and describe only the verified writable-volume authority.
replace_one(
    "README.md",
    "The current Milestone 8A verified candidate adds **one explicit read-only persistent host-directory volume**: the launcher pins and revalidates the named host directory, recursively clones it read-only, and attaches it only at the declared sandbox mountpoint.",
    "Milestone 8A added **one explicit read-only persistent host-directory volume** with pinned/revalidated source identity and recursive read-only attachment. The current Milestone 8B verified candidate adds **one explicit writable persistent host-directory volume**: the trusted policy author deliberately grants host-mutation authority to exactly one declared directory while the sandbox root outside that mount remains recursively read-only.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional read-only volume source/target, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "Optional read-only or writable volume source/target pairs, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "README policy summary",
)
replace_one(
    "README.md",
    "every declared selected-handle source, and any declared read-only volume source/target before `fork`.",
    "every declared selected-handle source, and any declared read-only or writable volume source/target before `fork`.",
    "README parent preparation",
)
replace_one(
    "README.md",
    "If a read-only volume is declared, the launcher reopens its trusted absolute host source after namespace creation, revalidates `(st_dev, st_ino)` against the pre-fork pin, recursively clones that mount tree read-only, and attaches it only to the prevalidated target inside the cloned sandbox root.",
    "For each declared persistent volume, the launcher reopens its trusted absolute host source after namespace creation, revalidates `(st_dev, st_ino)` against the pre-fork pin, recursively clones that mount tree, and attaches it only to the prevalidated target inside the cloned sandbox root. Read-only volumes additionally receive recursive `MOUNT_ATTR_RDONLY`; writable volumes deliberately retain source mount writability.",
    "README shared volume pipeline",
)
replace_one(
    "README.md",
    "- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY`, visible only at its declared sandbox target, and its launcher source/temporary mount descriptors do not survive as target capabilities.\n",
    "- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY`, visible only at its declared sandbox target, and its launcher source/temporary mount descriptors do not survive as target capabilities.\n- A declared writable volume is an explicit trusted-policy grant of host mutation authority: its source is pinned/revalidated through the same launcher-owned path, attached only at its declared target, and does not make the surrounding sandbox root writable. Read-only and writable source/target declarations are rejected when their configured paths overlap.\n",
    "README writable invariant",
)
replace_one(
    "README.md",
    "An optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`. This slice exposes one existing host directory read-only; it does not create a writable persistent store.\n",
    "An optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`.\n\nAn optional writable persistent volume is declared separately with `volume.writable_source = <absolute-host-directory>` and `volume.writable_target = <absolute-sandbox-directory>`. This pair is also all-or-nothing; the source itself may not be host `/`, the target may not be sandbox `/`, the target may not contain the executable/working directory or overlap scratch, and configured read-only/writable source or target paths may not overlap. Choosing this policy intentionally authorizes the target to mutate that host directory; the checks are lexical policy disjointness plus pinned inode identity, not proof against every possible filesystem alias.\n",
    "README writable policy format",
)
replace_one(
    "README.md",
    "- a trusted host directory containing `volume-marker\\n` is mounted only at `/data`; the raw target reads the exact marker there, receives `EROFS` when it tries to create `/data/write-must-fail`, and receives `ENOENT` when it tries the original absolute host source path. The parent then proves the marker is unchanged and no host write escaped;\n",
    "- a trusted host directory containing `volume-marker\\n` is mounted only at `/data`; the raw target reads the exact marker there, receives `EROFS` when it tries to create `/data/write-must-fail`, and receives `ENOENT` when it tries the original absolute host source path. The parent then proves the marker is unchanged and no host write escaped;\n- a separate declared writable host directory is mounted only at `/persist`; the raw target creates `/persist/persisted` with exact `persistent-write\\n` bytes, still receives `EROFS` when it tries to create `/root-write-must-fail`, and receives `ENOENT` for the original host source pathname. The parent then reads the exact persisted bytes from the declared host source and proves the root-side forbidden file was not created;\n",
    "README writable evidence",
)
replace_one(
    "README.md",
    "there is no device namespace, writable persistent-volume policy, multi-volume graph, or configured network endpoint policy; Milestone 8A exposes only one declared host directory read-only",
    "there is no device namespace, general multi-volume graph, volume snapshot/copy-on-write policy, or configured network endpoint policy; Milestones 8A/8B expose at most one declared read-only and one declared writable host directory",
    "README writable limitation",
)

# Threat model: explicit trusted host-mutation authority, with no stronger durability claims.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–8A threat model",
    "# Milestones 1–8B threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 8A verified candidate adds one explicit read-only persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and recursive read-only mount attachment.",
    "Milestone 8A added one explicit read-only persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and recursive read-only mount attachment. The current Milestone 8B verified candidate adds one separate writable host-directory exposure that intentionally grants host-mutation authority while reusing the same source identity and target attachment controls.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "one optional read-only persistent host-directory volume, stdio, bounded capture",
    "up to one optional read-only and one optional writable persistent host-directory volume, stdio, bounded capture",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Explicit read-only persistent volume:** when declared, the trusted host source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.\n",
    "- **Explicit read-only persistent volume:** when declared, the trusted host source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.\n- **Explicit writable persistent volume:** when separately declared, the trusted host source follows the same pre-fork pin, post-namespace `(st_dev, st_ino)` revalidation, detached recursive clone, target pin, and launcher-owned attachment path, but intentionally does not receive `MOUNT_ATTR_RDONLY`. This is a trusted-policy authorization for target writes to persist into that source; the surrounding cloned sandbox root remains read-only.\n",
    "threat writable property",
)
replace_one(
    "THREAT_MODEL.md",
    "a device namespace, writable persistent-volume policy, multi-volume graph, copy-on-write/snapshot semantics, or immutable/cryptographic root-subtree snapshot; Milestone 8A is one read-only host-directory exposure only",
    "a device namespace, general multi-volume graph, copy-on-write/snapshot semantics, durability/transaction/atomicity guarantees, or immutable/cryptographic root-subtree snapshot; Milestones 8A/8B cover only one read-only and one writable host-directory exposure",
    "threat writable non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "The policy author is trusted to choose filesystem exposure, including any declared read-only host-volume source/target, stdio exposure",
    "The policy author is trusted to choose filesystem exposure, including any declared read-only or writable host-volume source/target; declaring a writable source intentionally authorizes target mutation of that host directory. The policy author is also trusted to choose stdio exposure",
    "threat writable trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- read-only-volume parser/validator regressions plus a raw mount oracle that reads the exact marker only from the declared `/data` target, requires `EROFS` for a create attempt there, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the source content was unchanged;\n",
    "- read-only-volume parser/validator regressions plus a raw mount oracle that reads the exact marker only from the declared `/data` target, requires `EROFS` for a create attempt there, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the source content was unchanged;\n- writable-volume parser/validator regressions plus a raw mount oracle that writes exact `persistent-write\\n` bytes at `/persist/persisted`, still requires `EROFS` outside the writable mount, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the exact bytes persisted only in the declared source;\n",
    "threat writable evidence",
)

# Roadmap: seal 8A and promote 8B as the verified candidate.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds one explicit host-directory exposure without weakening the recursively read-only sandbox-root invariant.",
    "**Status: complete on `main`.** Adds one explicit read-only host-directory exposure without weakening the recursively read-only sandbox-root invariant.",
    "roadmap 8A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 8 promotion rule\n\nAfter 8A integrates, do not farm extra target paths that repeat the same read-only mount mechanism. Promote only to a materially different data-plane capability such as a carefully bounded writable persistent volume or controlled networking with positive connectivity evidence.\n",
    "### Slice 8B — one writable persistent host volume\n\n**Current verified candidate.** Adds one explicit host-mutation capability rather than another read-only path variant.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `volume.writable_source` / `volume.writable_target`; host `/` and sandbox `/` are forbidden, the target cannot contain the executable/working directory or overlap private scratch, and configured read-only/writable source or target paths may not overlap;\n- read-only and writable volumes share one launcher-owned prepared-volume path: pre-fork source pin, target validation beneath the pinned root, post-namespace source reopen and `(st_dev, st_ino)` revalidation, detached recursive mount clone, target pin, and `move_mount` attachment;\n- only read-only volumes receive recursive `MOUNT_ATTR_RDONLY`; a writable volume deliberately preserves source writability as explicit policy-authorized host mutation authority;\n- the raw target creates `/persist/persisted` with exact `persistent-write\\n` bytes, still requires `EROFS` for `/root-write-must-fail`, and requires `ENOENT` for the original absolute host source pathname;\n- the trusted parent proves the exact bytes persisted in the declared host source and that no forbidden root-side file was created;\n- 8A read-only evidence and all Milestones 1–7A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.\n\nBoundary: 8B is at most one explicitly writable existing host directory. It does not claim durability/transaction/atomicity semantics, snapshots/copy-on-write, a general mount graph, alias-proof source disjointness, special network-filesystem behavior, or automatic `nodev`/`nosuid`/`noexec` hardening for that host mount.\n\n### Milestone 8 promotion rule\n\nAfter 8B integrates, the persistent-volume authority model is sealed at this bounded laboratory scope. Do not farm extra mountpoints or access-mode aliases. Promote to a materially different executable frontier such as controlled networking with positive connectivity evidence, or revisit aggregate cgroup accounting only when real unprivileged delegation becomes available.\n",
    "roadmap 8B section",
)
replace_one(
    "ROADMAP.md",
    "Supplementary-group isolation with a viable mapping architecture, writable/broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "Supplementary-group isolation with a viable mapping architecture, broader/generalized persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "roadmap later frontiers",
)
