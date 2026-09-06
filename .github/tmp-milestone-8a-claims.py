from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: close 7A, describe only the verified 8A read-only host-directory slice.
replace_one(
    "README.md",
    "The current Milestone 7A candidate adds **caller-owned external cancellation**: a cloneable one-way token can ask launcher-owned PID 1 to terminate and reap the sandbox process tree while the token itself remains outside target authority.",
    "Milestone 7A added **caller-owned external cancellation**: a cloneable one-way token can ask launcher-owned PID 1 to terminate and reap the sandbox process tree while the token itself remains outside target authority. The current Milestone 8A verified candidate adds **one explicit read-only persistent host-directory volume**: the launcher pins and revalidates the named host directory, recursively clones it read-only, and attaches it only at the declared sandbox mountpoint.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "Optional scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "Optional read-only volume source/target, scratch, stdout redirection, stdout capture, selected non-stdio handles, and `limit.wall_clock_milliseconds` are validated fail-closed.",
    "README policy pipeline",
)
replace_one(
    "README.md",
    "Parent preparation** pins the root, cwd, initial executable, and every declared selected-handle source before `fork`.",
    "Parent preparation** pins the root, cwd, initial executable, every declared selected-handle source, and any declared read-only volume source/target before `fork`.",
    "README parent preparation",
)
replace_one(
    "README.md",
    "recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace.",
    "recursively clones it, applies recursive `MOUNT_ATTR_RDONLY`, and attaches it only inside the private mount namespace. If a read-only volume is declared, the launcher reopens its trusted absolute host source after namespace creation, revalidates `(st_dev, st_ino)` against the pre-fork pin, recursively clones that mount tree read-only, and attaches it only to the prevalidated target inside the cloned sandbox root.",
    "README volume mount pipeline",
)
replace_one(
    "README.md",
    "- Initial target, cwd, scratch, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root.\n",
    "- Initial target, cwd, scratch, read-only volume target, and stdout-redirection paths are fail-closed and bounded by the selected filesystem root; a declared read-only volume source is a separate trusted host path pinned before fork and identity-revalidated before attachment.\n- A declared read-only volume is recursively `MOUNT_ATTR_RDONLY`, visible only at its declared sandbox target, and its launcher source/temporary mount descriptors do not survive as target capabilities.\n",
    "README volume invariants",
)
replace_one(
    "README.md",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n",
    "`identity.hostname` is required. It must contain 1–63 ASCII bytes using letters, digits, `-`, or `.`, with an alphanumeric first and last byte. The launcher installs this value as the sandbox UTS nodename before the untrusted target starts.\n\nAn optional read-only persistent volume is declared with `volume.readonly_source = <absolute-host-directory>` and `volume.readonly_target = <absolute-sandbox-directory>`. The pair is all-or-nothing. The target may not be `/`, may not contain the executable or working directory, and may not overlap `filesystem.scratch`. This slice exposes one existing host directory read-only; it does not create a writable persistent store.\n",
    "README volume policy format",
)
replace_one(
    "README.md",
    "- a host-created pipe read end is duplicated to a high source descriptor, explicitly mapped to target fd 9, and the raw target reads the exact `selected-handle-ok` marker only from fd 9. The original high source descriptor and a separate undeclared high descriptor both return `EBADF` after exec; a directory source is independently rejected before launch;\n",
    "- a host-created pipe read end is duplicated to a high source descriptor, explicitly mapped to target fd 9, and the raw target reads the exact `selected-handle-ok` marker only from fd 9. The original high source descriptor and a separate undeclared high descriptor both return `EBADF` after exec; a directory source is independently rejected before launch;\n- a trusted host directory containing `volume-marker\\n` is mounted only at `/data`; the raw target reads the exact marker there, receives `EROFS` when it tries to create `/data/write-must-fail`, and receives `ENOENT` when it tries the original absolute host source path. The parent then proves the marker is unchanged and no host write escaped;\n",
    "README volume test evidence",
)
replace_one(
    "README.md",
    "- there is no device namespace, persistent data-volume policy, or configured network endpoint policy;\n",
    "- there is no device namespace, writable persistent-volume policy, multi-volume graph, or configured network endpoint policy; Milestone 8A exposes only one declared host directory read-only;\n",
    "README volume limitation",
)

# Threat model: make the new authority explicit without claiming writable persistence.
replace_one(
    "THREAT_MODEL.md",
    "# Milestones 1–7A threat model",
    "# Milestones 1–8A threat model",
    "threat title",
)
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 7A candidate adds a caller-owned external cancellation control plane whose launcher-owned PID 1 supervision terminates and reaps the sandbox process tree.",
    "Milestone 7A added a caller-owned external cancellation control plane whose launcher-owned PID 1 supervision terminates and reaps the sandbox process tree. The current Milestone 8A verified candidate adds one explicit read-only persistent host-directory exposure with pre-fork pinning, post-namespace inode identity revalidation, and recursive read-only mount attachment.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "selected resources, environment, cwd, ambient inherited descriptors, explicit selected non-stdio object handles, stdio, bounded capture, process-tree lifecycle, a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used,",
    "selected resources, environment, cwd, ambient inherited descriptors, explicit selected non-stdio object handles, one optional read-only persistent host-directory volume, stdio, bounded capture, process-tree lifecycle, a wall-clock execution deadline when declared, and caller-requested external cancellation when the cancellable API is used,",
    "threat protected boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.\n",
    "- **Filesystem mutability/path boundary:** the revalidated root is recursively cloned/read-only, optional scratch is private `nosuid,nodev,noexec` tmpfs, and the target is chrooted into the constructed root.\n- **Explicit read-only persistent volume:** when declared, the trusted host source directory is pinned before fork, reopened after namespace creation with symlink/magic-link traversal forbidden, identity-checked by `(st_dev, st_ino)`, recursively cloned with `MOUNT_ATTR_RDONLY`, and attached only to the validated target in the cloned root. Temporary source/tree/target descriptors are launcher setup state, not target capabilities.\n",
    "threat volume property",
)
replace_one(
    "THREAT_MODEL.md",
    "- a device namespace, persistent data-volume policy, or immutable/cryptographic root-subtree snapshot;\n",
    "- a device namespace, writable persistent-volume policy, multi-volume graph, copy-on-write/snapshot semantics, or immutable/cryptographic root-subtree snapshot; Milestone 8A is one read-only host-directory exposure only;\n",
    "threat volume non-goal",
)
replace_one(
    "THREAT_MODEL.md",
    "- The policy author is trusted to choose filesystem exposure, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "- The policy author is trusted to choose filesystem exposure, including any declared read-only host-volume source/target, stdio exposure, selected already-open object handles, target data/syscall grants, resource ceilings, capture ceilings, and any wall-clock deadline.",
    "threat volume trust",
)
replace_one(
    "THREAT_MODEL.md",
    "- selected-handle policy regressions plus a raw pipe oracle in which target fd 9 reads the exact marker while the original selected source descriptor and an unrelated undeclared high descriptor both return `EBADF`; a directory descriptor source is separately rejected before launch;\n",
    "- selected-handle policy regressions plus a raw pipe oracle in which target fd 9 reads the exact marker while the original selected source descriptor and an unrelated undeclared high descriptor both return `EBADF`; a directory descriptor source is separately rejected before launch;\n- read-only-volume parser/validator regressions plus a raw mount oracle that reads the exact marker only from the declared `/data` target, requires `EROFS` for a create attempt there, requires `ENOENT` for the original host source pathname after chroot, and is followed by host-side proof that the source content was unchanged;\n",
    "threat volume evidence",
)

# Roadmap: seal 7A and promote 8A as the verified candidate.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Add a caller-owned one-way cancellation primitive that integrates with launcher-owned PID 1 process-tree supervision without exposing the control descriptor to the target.",
    "**Status: complete on `main`.** Adds a caller-owned one-way cancellation primitive that integrates with launcher-owned PID 1 process-tree supervision without exposing the control descriptor to the target.",
    "roadmap 7A status",
)
replace_one(
    "ROADMAP.md",
    "After 7A integrates, do not farm cancellation aliases, signal numbers, or alternate wake primitives that repeat the same ownership path. Promote to a materially different executable boundary such as evidence-backed persistent-volume policy or controlled networking.",
    "7A is sealed on `main`; do not farm cancellation aliases, signal numbers, or alternate wake primitives that repeat the same ownership path. Promotion is now a materially different executable data-plane boundary.",
    "roadmap 7 promotion",
)
replace_one(
    "ROADMAP.md",
    "## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "## Milestone 8 — explicit persistent data exposure\n\n### Slice 8A — one read-only persistent host volume\n\n**Current verified candidate.** Adds one explicit host-directory exposure without weakening the recursively read-only sandbox-root invariant.\n\nAcceptance evidence is executable:\n\n- policy accepts the all-or-nothing pair `volume.readonly_source` / `volume.readonly_target`; the source is an absolute trusted host directory, while the target is an absolute sandbox path that cannot be `/`, contain the executable/working directory, or overlap private scratch;\n- before fork, the launcher pins the source with `openat2(O_PATH|O_DIRECTORY|O_CLOEXEC)` while forbidding symlink/magic-link traversal, and independently verifies the target beneath the pinned sandbox root;\n- after the private user/mount namespace exists, the launcher reopens the trusted source pathname and requires its `(st_dev, st_ino)` to match the pre-fork pin before using it;\n- the source mount tree is recursively cloned with `open_tree`, recursively marked `MOUNT_ATTR_RDONLY`, and attached with `move_mount` only to the prevalidated target inside the cloned sandbox root;\n- the raw target reads exact `volume-marker\\n` bytes from `/data/marker`, requires `EROFS` when creating `/data/write-must-fail`, and requires `ENOENT` when opening the original absolute host source pathname;\n- the trusted parent proves the host marker is byte-for-byte unchanged and the forbidden host file was never created;\n- all Milestones 1–7A regressions, stable format/Clippy/full tests, and the full Rust 1.74 suite remain green.\n\nBoundary: 8A is exactly one read-only existing host-directory mount. It does not provide writable persistence, multiple-volume composition, snapshots/copy-on-write, durability/atomicity guarantees, or special network-filesystem semantics.\n\n### Milestone 8 promotion rule\n\nAfter 8A integrates, do not farm extra target paths that repeat the same read-only mount mechanism. Promote only to a materially different data-plane capability such as a carefully bounded writable persistent volume or controlled networking with positive connectivity evidence.\n\n## Later frontiers\n\nSupplementary-group isolation with a viable mapping architecture, writable/broader persistent-volume policy, and controlled networking remain separate evidence-backed frontiers.",
    "roadmap 8A section",
)
