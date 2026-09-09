from pathlib import Path


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, insertion: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(marker)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one marker, got {count}")
    p.write_text(text.replace(marker, insertion + marker, 1))


def append_to_section(path: str, header: str, paragraph: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    start = text.find(header)
    if start < 0:
        raise SystemExit(f"{label}: section header missing")
    next_header = text.find("\n## ", start + len(header))
    if next_header < 0:
        raise SystemExit(f"{label}: following section header missing")
    p.write_text(text[:next_header] + "\n\n" + paragraph.rstrip() + "\n" + text[next_header:])


# README: seal 42A and describe the new cross-run comparable identity without
# turning an unkeyed digest into an authentication or rollback claim.
replace_once(
    "README.md",
    "The current Milestone 42A verified candidate adds `audit_snapshot_store(store_root, limits)`,",
    "Milestone 42A adds `audit_snapshot_store(store_root, limits)`,",
    "README 42A status",
)
insert_before(
    "README.md",
    "## Test evidence\n",
    "### Canonical snapshot-store inventory identity\n\n"
    "The current Milestone 43A verified candidate adds `snapshot_store_inventory_identity` and `verify_snapshot_store_inventory_identity`. The identity is derived only after every observed object crosses the exact 42A integrity gate. Audited `(SnapshotIdentity, archive_bytes)` records are sorted by the complete canonical identity tuple, then a versioned SHA-256 domain covers exact object count, aggregate archive bytes, and every fixed-width record. This makes the fingerprint independent of filesystem enumeration/insertion order while changing when store membership or an audited object's identity/length changes.\n\n"
    "The SHA-256 value is an unkeyed integrity fingerprint, not signer authentication or rollback resistance. `verify_snapshot_store_inventory_identity` treats its expected identity as trusted caller input; cross-run change detection therefore requires retaining that expected value in an independently trusted location or state channel rather than inside the same rollbackable store. Unsafe, tampered, or over-budget stores fail through the existing 42A audit path before a new inventory identity is accepted.\n\n",
    "README 43A insertion",
)

# Threat model: 42A is integrated and 43A adds an externally retainable integrity
# fingerprint, still without authenticity or independently anchored monotonicity.
replace_once(
    "THREAT_MODEL.md",
    "Milestones through 41B are integrated on `main`",
    "Milestones through 42A are integrated on `main`",
    "threat integrated milestone summary",
)
append_to_section(
    "THREAT_MODEL.md",
    "## Content-addressed snapshot-store semantics\n",
    "Milestone 43A composes the 42A whole-store audit into a deterministic inventory identity. Only objects that passed canonical-name, regular/read-only/single-link, bounded complete-read, canonical archive parse, and filename/archive identity equality checks contribute records. Those records are sorted by complete snapshot identity and SHA-256 hashes a versioned domain, exact object count, aggregate archive bytes, and each `(sha256, encoded_bytes, nodes, archive_bytes)` record. Repeated audits of the same object set are therefore independent of directory enumeration/insertion order, while membership changes alter the identity. The expected identity accepted by the verification API is trusted caller input: the digest is unkeyed and does not authenticate signer provenance, trust-policy membership, or freshness. Keeping expected state in the same rollbackable store does not improve the 41B rollback boundary.",
    "threat 43A semantics",
)

# Roadmap: seal 42A and promote the independently useful inventory identity.
replace_once(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.",
    "**Status: complete on `main`.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.",
    "roadmap 42A status",
)
insert_before(
    "ROADMAP.md",
    "## Independent host-local IPC frontier — post-launch object transfer\n",
    "## Milestone 43 — canonical snapshot-store inventory identity\n\n"
    "### Slice 43A — externally retainable whole-store fingerprint\n\n"
    "**Current verified candidate.** Promotes 42A's one-time integrity pass into a deterministic state identity that a caller can retain independently and compare across later audits.\n\n"
    "Acceptance evidence is executable:\n\n"
    "- `snapshot_store_inventory_identity(store_root, limits)` reuses the exact 42A audited-object traversal rather than maintaining a second filesystem walker; unsafe, tampered, or over-budget objects therefore fail before they can contribute to a new inventory identity;\n"
    "- each successful object contributes the complete canonical `(sha256, encoded_bytes, nodes)` snapshot identity plus exact archive byte length; records are sorted by the complete tuple so `readdir` and insertion order cannot change the result;\n"
    "- a versioned SHA-256 domain additionally covers exact object count and aggregate archive bytes, and the public identity exposes those counts beside the digest;\n"
    "- two stores containing the same objects inserted in opposite orders produce exactly the same identity, and repeated computation over one unchanged store is stable;\n"
    "- adding an object changes the identity, a caller-retained two-object expected identity rejects the store after one object is deleted, and content tamper is surfaced as the underlying 42A identity-mismatch error rather than being summarized into a fresh valid fingerprint;\n"
    "- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.\n\n"
    "Boundary: 43A is an unkeyed deterministic integrity fingerprint. The expected identity is trusted caller input; storing it beside the audited objects does not prevent rollback. This slice does not authenticate signer provenance/trust-policy membership, provide an independently anchored monotonic counter, serialize a signed inventory artifact, lock out independent concurrent publishers, repair/GC objects, or provide remote replication guarantees.\n\n"
    "### Milestone 43 promotion rule\n\n"
    "After 43A integrates, do not farm alternative digest encodings, object-order permutations, or more add/delete aliases. A stronger inventory phase must add a materially new trust or lifecycle boundary such as authenticated/independently retained inventory state, safe store mutation, or remote comparison with executable evidence.\n\n",
    "roadmap 43A insertion",
)
