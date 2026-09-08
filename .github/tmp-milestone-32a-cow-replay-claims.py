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
    "The current Milestone 31A verified candidate adds a **bounded post-run COW diff export**: launcher-owned PID 1 walks the private upper tree after target/descendant convergence and reports supported content/topology changes plus regular-file/directory Unix permission bits without persisting the upper layer.",
    "Milestone 31A added a **bounded post-run COW diff export**: launcher-owned PID 1 walks the private upper tree after target/descendant convergence and reports supported content/topology changes plus regular-file/directory Unix permission bits without persisting the upper layer. The current Milestone 32A verified candidate adds **bounded host-side atomic COW diff replay**: a trusted base directory is copied into a private sibling staging tree, the canonical diff is replayed without following symlink parents, and a completed new snapshot is published only with `renameat2(RENAME_NOREPLACE)`.",
    "README milestone summary",
)

readme_section = r'''## COW diff replay

Milestone 32A adds a host-side replay lifecycle for the bounded `CowDiff` emitted by Milestone 31A. `apply_cow_diff_atomic(base, destination, diff, limits)` requires absolute host paths, validates the canonical diff ordering/encoding and supported file/directory/symlink/remove/opaque-directory records, copies the trusted base into a private sibling staging directory, and resolves every diff parent component fd-by-fd with `O_NOFOLLOW`. The base is never modified in place.

`CowDiffApplyLimits` explicitly bounds replay work by canonical diff plus copied regular-file/symlink bytes and by accounted base/diff nodes. Budget overflow, unsupported base node kinds, malformed diff paths, symlink-parent traversal, destination races, or any other pre-publication failure return an error rather than a partial successful snapshot. Failed staging cleanup is reported separately instead of being hidden.

A successful replay restores supported Unix permission modes and publishes the completed staging tree with one Linux `renameat2(RENAME_NOREPLACE)`. The destination must not already exist; there is no overwrite fallback. This gives failure atomicity for **new-snapshot publication before the rename boundary**, not durability or crash consistency. The API does not `fsync` the tree, does not preserve UID/GID, timestamps, xattrs/ACLs, hard-link identity, or special nodes, does not protect against a hostile concurrent writer mutating the trusted base/destination parent during replay, and does not claim that symlink objects intentionally preserved in the resulting snapshot are confinement-safe if a later consumer follows them.

'''
replace_one(
    "README.md",
    "## Policy observability commands\n",
    readme_section + "## Policy observability commands\n",
    "README replay section",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 31A verified candidate optionally exports that private upper as a bounded post-run content/topology/permission-mode change-set after PID-tree convergence.",
    "Milestone 31A optionally exports that private upper as a bounded post-run content/topology/permission-mode change-set after PID-tree convergence. The current Milestone 32A verified candidate adds a separate trusted-host replay lifecycle that materializes a new snapshot under explicit byte/node budgets and publishes it only after complete staging-tree construction.",
    "threat purpose",
)
replace_one(
    "THREAT_MODEL.md",
    "This is not ownership/timestamp/other-xattr/ACL/hard-link identity preservation, a replay engine, atomic commit, or cryptographic snapshot integrity.",
    "The export mechanism itself does not preserve ownership/timestamps/other xattrs/ACLs/hard-link identity and is not cryptographic snapshot integrity; replay is a separate host-side lifecycle rather than an implication of export success.\n- **Atomic host-side COW replay:** `apply_cow_diff_atomic` validates canonical diff structure and exact encoded-byte accounting before mutation, copies a trusted base directory into a private sibling staging tree, refuses unsupported base node kinds, and resolves replay parents fd-by-fd with `O_NOFOLLOW`. Explicit byte/node ceilings fail closed. Supported file/directory/symlink/remove/opaque-directory records are applied only inside staging; directory modes are restored after topology changes. Success publishes a previously absent destination with one `renameat2(RENAME_NOREPLACE)` and no non-atomic fallback. Any pre-publication replay failure leaves the base unchanged and the destination absent; staging cleanup failure is surfaced explicitly. This is new-snapshot publication atomicity only: it does not provide fsync-backed durability/crash recovery, overwrite transactions, protection from hostile concurrent host mutation, cryptographic diff/base identity, omitted metadata preservation, or confinement guarantees for a later consumer that follows symlink objects preserved in the snapshot.",
    "threat replay property",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a launcher-owned, bounded change-export capability for the existing ephemeral COW root without turning the private upper layer into persistent host state.",
    "**Status: complete on `main`.** Adds a launcher-owned, bounded change-export capability for the existing ephemeral COW root without turning the private upper layer into persistent host state.",
    "roadmap 31A status",
)

old_promotion = """### Milestone 31 promotion rule

After 31A integrates, do not farm more record tags or metadata fields unless they close a demonstrated replay/integrity boundary. Promote to a materially different capability such as a verified replay/apply lifecycle with confinement and failure atomicity, stronger snapshot identity/integrity evidence, or another independent authority/enforcement frontier.

## Later frontiers
"""
new_promotion = """### Milestone 31 promotion rule

31A is sealed on `main`; do not farm more record tags or metadata fields unless they close a demonstrated replay/integrity boundary. Promotion is now a materially different COW lifecycle capability.

## Milestone 32 — COW diff replay lifecycle

### Slice 32A — atomic new-snapshot replay

**Current verified candidate.** Adds a bounded host-side apply path for the canonical 31A diff without mutating the trusted base directory in place.

Acceptance evidence is executable:

- `apply_cow_diff_atomic(base, destination, diff, limits)` accepts only absolute trusted host paths, requires a previously absent destination, validates canonical diff path/order/record shape plus exact `encoded_bytes`, and rejects malformed/root-replacement inputs before staging mutation;
- replay work is fail-closed bounded by explicit `CowDiffApplyLimits`: canonical diff plus copied regular-file/symlink bytes consume the byte budget, while base nodes plus diff records consume the node budget;
- the launcher-side helper copies supported base regular files/directories/symlinks into a private sibling staging directory and rejects unsupported node kinds instead of silently dropping them;
- every diff parent is resolved fd-by-fd with `O_DIRECTORY|O_NOFOLLOW`; a copied symlink used as a parent therefore fails rather than redirecting a replay write outside staging;
- replay implements regular-file upsert with bytes/mode, directory ensure/mode, symlink replacement, recursive removal, and opaque-directory clearing; supported directory modes are restored after topology mutation;
- success publishes the completed tree with one Linux `renameat2(RENAME_NOREPLACE)` and no fallback to a non-atomic overwrite path;
- deterministic tests prove a mixed replay preserves the base while producing exact replacement/new-file bytes, modes, removals, opaque-directory semantics and symlink target; a symlink-parent escape attempt fails with no outside mutation or destination publication; and a byte-budget failure leaves the base unchanged, destination absent, and staging cleaned;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation candidate.

Boundary: 32A provides failure-atomic publication of a **new** snapshot up to the final rename boundary. It does not overwrite an existing destination, fsync data/metadata, provide crash-recovery or durability guarantees, preserve UID/GID/timestamps/xattrs/ACLs/hard links/special nodes, prove cryptographic identity of the base/diff, defend against hostile concurrent host writers, or claim that preserved symlink objects are confinement-safe for later consumers that choose to follow them.

### Milestone 32 promotion rule

After 32A integrates, seal basic replay/apply semantics rather than farming path aliases, extra failure codes, or duplicate record variants. Promote to stronger snapshot identity/integrity evidence or another independent executable authority/enforcement frontier; any durability or overwrite-transaction phase requires its own fsync/crash semantics and deterministic evidence.

## Later frontiers
"""
replace_one("ROADMAP.md", old_promotion, new_promotion, "roadmap 32A section")
