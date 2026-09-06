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
    "- Initial target, cwd, scratch, read-only volume target, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root; a declared read-only volume source is a separate trusted host path pinned before fork and identity-revalidated before attachment.",
    "- Initial target, cwd, scratch, persistent-volume targets, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root; every declared persistent-volume source must be a separate trusted host path whose configured path is disjoint from `filesystem.root`, then is pinned before fork and identity-revalidated before attachment.",
    "README root/source invariant",
)
replace_one(
    "README.md",
    "- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY`, visible only at its declared sandbox target, and its launcher source/temporary mount descriptors do not survive as target capabilities.",
    "- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY` and attached only at its declared sandbox target. Its configured source path must be disjoint from `filesystem.root`, and launcher source/temporary mount descriptors do not survive as target capabilities.",
    "README readonly invariant",
)
replace_one(
    "README.md",
    "- A declared writable volume is an explicit trusted-policy grant of host mutation authority: its source is pinned/revalidated through the same launcher-owned path, attached only at its declared target, and does not make the surrounding sandbox root writable. Read-only and writable source/target declarations are rejected when their configured paths overlap.",
    "- A declared writable volume is an explicit trusted-policy grant of host mutation authority: its source is path-disjoint from `filesystem.root`, pinned/revalidated through the same launcher-owned path, attached only at its declared target, and therefore cannot reopen the configured sandbox-root tree for writes through that source path. Read-only and writable source/target declarations are also rejected when their configured paths overlap.",
    "README writable invariant",
)
replace_one(
    "README.md",
    "An optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`.",
    "An optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The source's configured path must not be `filesystem.root`, an ancestor of it, or a descendant within it. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`.",
    "README readonly policy",
)
replace_one(
    "README.md",
    "An optional writable persistent volume is declared separately with `volume.writable_source = <absolute-host-directory>` and `volume.writable_target = <absolute-sandbox-directory>`. This pair is also all-or-nothing; the source itself may not be host `/`, the target may not be sandbox `/`, the target may not contain the executable/working directory or overlap scratch, and configured read-only/writable source or target paths may not overlap. Choosing this policy intentionally authorizes the target to mutate that host directory; the checks are lexical policy disjointness plus pinned inode identity, not proof against every possible filesystem alias.",
    "An optional writable persistent volume is declared separately with `volume.writable_source = <absolute-host-directory>` and `volume.writable_target = <absolute-sandbox-directory>`. This pair is also all-or-nothing; the source's configured path must not be `filesystem.root`, an ancestor of it, or a descendant within it; the target may not be sandbox `/`, may not contain the executable/working directory or overlap scratch, and configured read-only/writable source or target paths may not overlap. Choosing this policy intentionally authorizes the target to mutate that host directory; the checks are lexical policy disjointness plus pinned inode identity, not proof against every possible filesystem alias.",
    "README writable policy",
)

replace_one(
    "ROADMAP.md",
    "- policy accepts the all-or-nothing pair `volume.readonly_source` / `volume.readonly_target`; the source is an absolute trusted host directory, while the target is an absolute sandbox path that cannot be `/`, contain the executable/working directory, or overlap private scratch;",
    "- policy accepts the all-or-nothing pair `volume.readonly_source` / `volume.readonly_target`; the source is an absolute trusted host directory whose configured path must be disjoint from `filesystem.root`, while the target is an absolute sandbox path that cannot be `/`, contain the executable/working directory, or overlap private scratch;",
    "roadmap 8A root/source invariant",
)
replace_one(
    "ROADMAP.md",
    "- policy accepts the all-or-nothing pair `volume.writable_source` / `volume.writable_target`; host `/` and sandbox `/` are forbidden, the target cannot contain the executable/working directory or overlap private scratch, and configured read-only/writable source or target paths may not overlap;",
    "- policy accepts the all-or-nothing pair `volume.writable_source` / `volume.writable_target`; the source's configured path must be disjoint from `filesystem.root`, sandbox `/` is forbidden as the target, the target cannot contain the executable/working directory or overlap private scratch, and configured read-only/writable source or target paths may not overlap;",
    "roadmap 8B root/source invariant",
)
replace_one(
    "ROADMAP.md",
    "- 8A read-only evidence and all Milestones 1–7A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.",
    "- a dedicated public `run()` regression rejects both a writable source nested inside `filesystem.root` and a read-only source that contains the root, before any namespace/mount setup begins;\n- 8A read-only evidence and all Milestones 1–7A regressions remain active; stable format/Clippy/full tests and the full Rust 1.74 suite are green.",
    "roadmap 8B root/source evidence",
)

replace_one(
    "THREAT_MODEL.md",
    "- **Explicit read-only persistent volume:** when declared, the trusted host source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.",
    "- **Explicit read-only persistent volume:** when declared, the trusted host source's configured path must be disjoint from `filesystem.root`; the source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.",
    "threat readonly root/source invariant",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Explicit writable persistent volume:** when separately declared, the trusted host source follows the same pre-fork pin, post-namespace `(st_dev, st_ino)` revalidation, detached recursive clone, target pin, and launcher-owned attachment path, but intentionally does not receive `MOUNT_ATTR_RDONLY`. This is a trusted-policy authorization for target writes to persist into that source; the surrounding cloned sandbox root remains read-only.",
    "- **Explicit writable persistent volume:** when separately declared, the trusted host source's configured path must be disjoint from `filesystem.root`, then follows the same pre-fork pin, post-namespace `(st_dev, st_ino)` revalidation, detached recursive clone, target pin, and launcher-owned attachment path, but intentionally does not receive `MOUNT_ATTR_RDONLY`. This is a trusted-policy authorization for target writes to persist into that source without reopening the configured sandbox-root tree through the source path; the surrounding cloned sandbox root remains read-only.",
    "threat writable root/source invariant",
)
replace_one(
    "THREAT_MODEL.md",
    "- a device namespace, general multi-volume graph, copy-on-write/snapshot semantics, durability/transaction/atomicity guarantees, or immutable/cryptographic root-subtree snapshot; Milestones 8A/8B cover only one read-only and one writable host-directory exposure;",
    "- a device namespace, general multi-volume graph, copy-on-write/snapshot semantics, durability/transaction/atomicity guarantees, filesystem-alias-proof volume/root disjointness, or immutable/cryptographic root-subtree snapshot; Milestones 8A/8B cover only one read-only and one writable host-directory exposure;",
    "threat alias non-goal",
)
