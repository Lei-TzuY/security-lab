from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal 32A and describe only the executable 33A identity contract.
replace_one(
    "README.md",
    "The current Milestone 32A verified candidate adds **bounded host-side atomic COW diff replay**: a trusted base directory is copied into a private sibling staging tree, the canonical diff is replayed without following symlink parents, and a completed new snapshot is published only with `renameat2(RENAME_NOREPLACE)`.",
    "Milestone 32A added **bounded host-side atomic COW diff replay**: a trusted base directory is copied into a private sibling staging tree, the canonical diff is replayed without following symlink parents, and a completed new snapshot is published only with `renameat2(RENAME_NOREPLACE)`. The current Milestone 33A verified candidate adds **bounded canonical SHA-256 snapshot identity** for the supported regular-file/directory/symlink tree model, committing to sorted raw path bytes, object type, Unix permission modes, file bytes, and symlink targets under explicit byte/node work ceilings.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "\n## Policy observability commands\n",
    """
## Canonical snapshot identity

Milestone 33A adds `snapshot_sha256(root, limits)` as a separate trusted-host evidence path for the supported snapshot object model. `SnapshotIdentityLimits` fail-closed bounds both canonical bytes hashed and filesystem nodes visited. On Linux, traversal is deterministic over sorted raw directory-entry bytes, does not follow symlinks while walking the tree, and domain-separates directories, regular files, and symlinks. The canonical stream commits to absolute snapshot-relative path bytes, regular-file/directory Unix permission bits, exact regular-file length/content, and exact symlink target bytes before SHA-256 is finalized.

The implementation rejects unsupported special-node kinds instead of silently omitting them, rejects an over-budget scan instead of returning a partial digest, and checks opened regular files/directories against the expected object type. Executable evidence includes one fixed canonical SHA-256 vector reproduced by two independently materialized equivalent trees; independent content, mode, symlink-target, and topology mutations each change the digest; and a Milestone 32A replay whose resulting identity exactly matches a separately materialized expected tree while the trusted base identity remains unchanged.

This digest is **identity evidence, not authenticity or provenance**. It does not sign or key the hash, does not bind 32A replay to an expected base automatically, does not preserve or commit to UID/GID, timestamps, xattrs/ACLs, hard-link identity, or unsupported special nodes, and is not a point-in-time snapshot against hostile concurrent host writers. Durability/crash semantics remain outside this API.

## Policy observability commands
""",
    "README snapshot identity section",
)

# Roadmap: seal 32A and promote 33A with executable acceptance evidence.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a bounded host-side apply path for the canonical 31A diff without mutating the trusted base directory in place.",
    "**Status: complete on `main`.** Adds a bounded host-side apply path for the canonical 31A diff without mutating the trusted base directory in place.",
    "roadmap 32A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 32 promotion rule\n\nAfter 32A integrates, seal basic replay/apply semantics rather than farming path aliases, extra failure codes, or duplicate record variants. Promote to stronger snapshot identity/integrity evidence or another independent executable authority/enforcement frontier; any durability or overwrite-transaction phase requires its own fsync/crash semantics and deterministic evidence.\n\n## Later frontiers\n",
    """### Milestone 32 promotion rule

32A is sealed on `main`; do not farm replay path aliases, extra failure codes, or duplicate record variants. Promotion is now stronger snapshot identity/integrity evidence or another independent executable authority/enforcement frontier; any durability or overwrite-transaction phase requires its own fsync/crash semantics and deterministic evidence.

## Milestone 33 — canonical snapshot identity

### Slice 33A — bounded SHA-256 identity for supported snapshot trees

**Current verified candidate.** Adds deterministic cryptographic content identity for the exact regular-file/directory/symlink tree model already preserved by the 31A/32A lifecycle, without claiming authenticity or a broader metadata snapshot.

Acceptance evidence is executable:

- `snapshot_sha256(root, limits)` requires an absolute trusted host root and exposes `SnapshotIdentityLimits` with fail-closed byte and node ceilings;
- one versioned/domain-separated canonical stream hashes sorted raw path bytes plus node type; directories commit to Unix permission bits, regular files commit to permission bits plus exact length/content, and symlinks commit to exact target bytes;
- traversal opens child directories and regular files without following symlinks, verifies opened object type, detects regular-file shrink/growth across the committed size/read boundary, and rejects unsupported special-node kinds instead of omitting them;
- two independently materialized equivalent fixture trees produce the exact fixed SHA-256 `b3ff412811f2f9298015ab9320339ab3d35bd53a531b6b4e645ae8656d3c1c85`, with 5 accounted nodes and 140 canonical bytes;
- independent mutations to regular-file content, permission mode, symlink target, and topology each produce a different identity;
- a 32A diff replay leaves the trusted base identity unchanged and produces a destination identity exactly equal to an independently materialized expected tree;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation candidate.

Boundary: 33A is canonical SHA-256 identity evidence for the supported tree model. It is not a signature, MAC, trusted provenance statement, or automatic replay precondition; it omits UID/GID ownership, timestamps, xattrs/ACLs, hard-link identity, and special nodes, and it does not establish a point-in-time snapshot against hostile concurrent host writers or any durability/crash guarantee.

### Milestone 33 promotion rule

After 33A integrates, seal hash-algorithm/vector variants. A materially stronger next COW-lifecycle slice is to bind replay to an explicitly expected base identity and fail before publication on mismatch, or to add independently evidenced authenticity/provenance; neither should be inferred from a bare digest.

## Later frontiers
""",
    "roadmap 33A section",
)

# Threat model: keep replay and identity claims distinct.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 32A verified candidate adds a separate trusted-host replay lifecycle that materializes a new snapshot under explicit byte/node budgets and publishes it only after complete staging-tree construction.",
    "Milestone 32A added a separate trusted-host replay lifecycle that materializes a new snapshot under explicit byte/node budgets and publishes it only after complete staging-tree construction. The current Milestone 33A verified candidate adds a separate bounded canonical SHA-256 identity calculation for supported snapshot trees; it is deterministic content/topology/mode identity evidence, not authenticity or provenance.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "protection from hostile concurrent host mutation, cryptographic diff/base identity, omitted metadata preservation, or confinement guarantees for a later consumer that follows symlink objects preserved in the snapshot.",
    "protection from hostile concurrent host mutation, automatic binding to an expected cryptographic base/destination identity, omitted metadata preservation, or confinement guarantees for a later consumer that follows symlink objects preserved in the snapshot.",
    "threat replay boundary",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Optional Landlock read/execute envelope:**",
    """- **Canonical SHA-256 snapshot identity:** `snapshot_sha256` is a trusted-host, fail-closed bounded traversal of one absolute snapshot root. A versioned/domain-separated canonical stream commits to sorted raw path bytes and node type; supported directories additionally commit to Unix permission bits, regular files to permission bits plus exact length/content, and symlinks to exact target bytes. Traversal does not follow symlink entries as directories/files, rejects unsupported node kinds, and enforces byte/node ceilings. Deterministic evidence fixes one exact digest vector, proves content/mode/symlink/topology sensitivity, and proves a 32A replay matches an independently materialized expected tree while leaving the base identity unchanged. This is not a signature, MAC, trusted provenance statement, point-in-time atomic snapshot against hostile host writers, replay precondition, or commitment to omitted ownership/timestamp/xattr/ACL/hard-link metadata.\n- **Optional Landlock read/execute envelope:**""",
    "threat identity property",
)
