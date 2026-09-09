from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: seal integrated 42A and describe only the verified 43A commitment surface.
replace_one(
    "README.md",
    "The current Milestone 41B verified candidate adds **authenticated persisted trust-policy identity state** so state-backed snapshot operations reject a stale caller-supplied policy before store or destination access while the trusted state directory and host-held authentication key remain intact.",
    "Milestone 41B added **authenticated persisted trust-policy identity state** so state-backed snapshot operations reject a stale caller-supplied policy before store or destination access while the trusted state directory and host-held authentication key remain intact. Milestone 42A added a **bounded read-only whole-store integrity audit** over the content-addressed object store. The current Milestone 43A verified candidate adds a **deterministic audited snapshot-store inventory identity** for externally retained cross-run membership comparison.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "The current Milestone 42A verified candidate adds `audit_snapshot_store(store_root, limits)`",
    "Milestone 42A added `audit_snapshot_store(store_root, limits)`",
    "README 42A status",
)
readme = Path("README.md")
text = readme.read_text()
heading = "### Bounded snapshot-store integrity audit"
addition_heading = "### Canonical snapshot-store inventory identity"
if addition_heading in text:
    raise SystemExit("README 43A section already exists")
start = text.index(heading)
end = text.find("\n## ", start)
if end == -1:
    raise SystemExit("README next top-level section not found")
addition = """

### Canonical snapshot-store inventory identity

The current Milestone 43A verified candidate adds `snapshot_store_inventory_identity(store_root, limits)` and `verify_snapshot_store_inventory_identity(store_root, expected, limits)` as a cross-run identity layer above the complete Milestone 42A audit. Only objects that already pass 42A filename, regular-file, single-link, read-only-mode, byte-budget, canonical-archive, and archive-derived identity checks contribute to the inventory commitment.

The inventory format is deterministic and versioned. Successfully audited object records are sorted by the complete canonical snapshot identity tuple `(sha256, encoded_bytes, nodes)` and exact archive byte length before hashing. SHA-256 covers the domain `security-lab-snapshot-store-inventory-v1\\0`, exact object count, aggregate archive bytes, and every sorted record. The fixed two-object regression locks the current encoding at `objects=2`, `archive_bytes=198`, and `sha256=74ac767d1be69f143d68b88a8202214af6cf464aa2307b4397f84eb9baef0af1`; equivalent stores built in opposite insertion order reproduce that exact identity.

An independently retained expected identity can detect observed store membership additions or deletions, while underlying 42A integrity failures remain their original fail-closed audit errors. This value is an **unkeyed integrity/membership commitment**, not authentication or rollback protection. Persisting the expected value inside the same rollbackable store does not create an independent trust anchor, and the scan still assumes a quiescent or cooperatively serialized store rather than a point-in-time snapshot under hostile concurrent mutation.
"""
text = text[:end] + addition + text[end:]
readme.write_text(text)

# Threat model: close stale high-level status and state the 43A claim/non-claim boundary.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 40A verified candidate adds authenticated host-local content-addressed storage keyed by the complete canonical identity tuple, with no-replace publication, exact-byte deduplication, and identity/signature re-verification before materialization.",
    "Milestones 40A–40B added authenticated host-local content-addressed storage plus success-return Linux `fsync` durability. Milestones 41A–41B added explicit signer trust policy and authenticated persisted policy-identity state, and Milestone 42A added bounded whole-store integrity audit. The current Milestone 43A verified candidate adds a deterministic unkeyed commitment to the complete successfully audited store membership for externally retained comparison.",
    "threat purpose status",
)
threat = Path("THREAT_MODEL.md")
text = threat.read_text()
needle = "Milestone 42A adds a separate read-only whole-store integrity audit."
start = text.index(needle)
end = text.find("\n\n", start)
if end == -1:
    raise SystemExit("threat 42A paragraph terminator not found")
paragraph = """

Milestone 43A adds a separate deterministic whole-store membership commitment above that audit. `snapshot_store_inventory_identity` collects only fully validated 42A object identities, sorts records by the complete `(sha256, encoded_bytes, nodes, archive_bytes)` tuple, and hashes a versioned domain plus exact object/aggregate-byte counts and every record. `verify_snapshot_store_inventory_identity` compares a recomputed value with caller-retained expected state and therefore detects observed object-set additions/deletions when that expected state is independently trusted. The fixed two-object golden vector locks the current encoding. The inventory hash is unkeyed: it is not signer provenance, trust-policy authentication, rollback resistance, or an independently anchored monotonic state. The scan retains 42A's quiescent/cooperative-serialization assumption and does not claim a point-in-time view against an independent concurrent store writer.
"""
text = text[:end] + paragraph + text[end:]
threat.write_text(text)

# Roadmap: seal 42A and promote the existing verified 43A implementation.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.",
    "**Status: complete on `main`.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.",
    "roadmap 42A status",
)
roadmap = Path("ROADMAP.md")
text = roadmap.read_text()
marker = "## Independent host-local IPC frontier — post-launch object transfer"
if "## Milestone 43 — canonical audited store inventory commitment" in text:
    raise SystemExit("roadmap 43 already exists")
if marker not in text:
    raise SystemExit("roadmap insertion marker not found")
section = """
## Milestone 43 — canonical audited store inventory commitment

### Slice 43A — deterministic whole-store membership identity

**Current verified candidate.** Adds a cross-run store-membership commitment above the complete 42A integrity audit rather than another malformed-object variant.

Acceptance evidence is executable:

- `snapshot_store_inventory_identity(store_root, limits)` reuses the exact bounded 42A scan and receives a record only after that object passes canonical filename, object-type/link/mode, archive-byte, canonical-parser, and archive-derived identity checks;
- every accepted record commits to the complete snapshot identity tuple `(sha256, encoded_bytes, nodes)` plus exact archive byte length; records are sorted before hashing so filesystem enumeration and insertion order do not affect the result;
- the versioned SHA-256 stream commits to `security-lab-snapshot-store-inventory-v1\\0`, exact object count, aggregate archive bytes, and all sorted records;
- two equivalent two-object stores populated in opposite orders produce the fixed golden identity `74ac767d1be69f143d68b88a8202214af6cf464aa2307b4397f84eb9baef0af1` with exactly 2 objects and 198 archive bytes;
- `verify_snapshot_store_inventory_identity` accepts an unchanged independently expected inventory, while deterministic addition/deletion evidence changes the identity and returns `IdentityMismatch` with the newly observed counts;
- existing 42A content-tamper failure propagates as the original audit error rather than being hidden behind an inventory mismatch;
- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.

Boundary: 43A is an unkeyed commitment to one successfully audited observed store inventory. It does not authenticate signer/trust-policy provenance, persist or independently protect the expected identity, prevent rollback when expected state is restored with the store, serialize independent publishers, provide a point-in-time concurrent snapshot, or repair/quarantine/delete/garbage-collect objects.

### Milestone 43 promotion rule

After 43A integrates, seal this inventory-commitment encoding. Do not farm digest renderings, record-order aliases, or more add/delete variants. A stronger store-lifecycle phase must introduce materially new safe concurrency/mutation semantics or an independently anchored authentication/rollback boundary with executable evidence; otherwise promote to another independent authority frontier.

"""
text = text.replace(marker, section + marker, 1)
roadmap.write_text(text)
