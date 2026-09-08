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
    "The current Milestone 37A verified candidate adds **Ed25519 public-key signatures over canonical snapshot identity** with strict verification under an exact caller-supplied public key.",
    "Milestone 37A added **Ed25519 public-key signatures over canonical snapshot identity** with strict verification under an exact caller-supplied public key. The current Milestone 38A verified candidate adds a **bounded deterministic snapshot archive** whose completed serialized records reproduce the existing canonical identity and can be failure-atomically materialized as a new host snapshot.",
    "README milestone summary",
)

archive_section = """## Bounded snapshot archive

The current Milestone 38A verified candidate adds `serialize_snapshot_archive(root, limits)`, `snapshot_archive_identity(bytes, limits)`, and `materialize_snapshot_archive_atomic(bytes, destination, limits)`. The archive is a versioned deterministic binary representation of the existing supported regular-file/directory/symlink snapshot model. Serialization walks Linux directories fd-relatively without following symlinks, sorts raw entry bytes, rejects unsupported node kinds, enforces explicit archive-byte/identity-byte/node ceilings, and reparses the completed archive before returning its canonical Milestone 33A identity.

Archive parsing is fail-closed: the root directory must be first, paths must be absolute/NUL-free and strictly increasing in raw-byte order, every non-root parent must already be an earlier directory record, dot/dot-dot/empty components and trailing bytes are rejected, and regular-file contents plus Unix permission modes and exact symlink target bytes feed the same canonical identity stream as the live-tree scanner. Executable round-trip evidence proves two captures of an unchanged tree produce identical bytes, the archive identity equals the independently computed live-tree identity, later source mutation does not change the captured archive, and a materialized tree reproduces the captured identity.

Materialization validates the complete archive before creating staging state, builds a private sibling tree with fd-relative `O_NOFOLLOW` parent resolution, restores supported modes, and publishes only with Linux `renameat2(RENAME_NOREPLACE)`. Malformed or over-budget input, an existing/racing destination, symlink-parent archive topology, or any other pre-publication failure must leave no published destination; failed staging cleanup is reported separately. This is **failure-atomic new-snapshot publication**, not fsync-backed crash durability. Successful serialization freezes the returned archive bytes against later source mutation, but it does not claim a hostile-writer atomic point-in-time view while the live source is being captured. Preserved symlink objects are identity data, not a guarantee that later consumers may safely follow them outside the materialized tree.

"""
replace_one(
    "README.md",
    "## Policy observability commands\n",
    archive_section + "## Policy observability commands\n",
    "README archive section",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds independently verifiable public-key signature semantics to the existing bounded canonical snapshot identity rather than another symmetric tag encoding.",
    "**Status: complete on `main`.** Adds independently verifiable public-key signature semantics to the existing bounded canonical snapshot identity rather than another symmetric tag encoding.",
    "ROADMAP 37A status",
)

old_promotion = """### Milestone 37 promotion rule

After 37A integrates, do not farm key encodings, signature text formats, algorithm aliases, or extra verify wrappers. A stronger provenance phase requires an independently specified trust/key lifecycle or attestation model. Otherwise promote to a real frozen/serialized source snapshot, durability/versioned publication, or a materially new launcher-owned mediation boundary.

## Independent host-local IPC frontier — post-launch object transfer
"""
new_promotion = """### Milestone 37 promotion rule

37A is sealed on `main`; do not farm key encodings, signature text formats, algorithm aliases, or extra verify wrappers. A stronger provenance phase requires an independently specified trust/key lifecycle or attestation model. The active promotion is instead a serialized snapshot artifact with executable round-trip/publication evidence.

## Milestone 38 — bounded serialized snapshot artifact

### Slice 38A — deterministic canonical snapshot archive

**Current verified candidate.** Freezes the supported snapshot object model into bounded deterministic bytes and can materialize those bytes into a new failure-atomically published host tree.

Acceptance evidence is executable:

- `serialize_snapshot_archive` walks the supported Linux tree fd-relatively, preserves directory/regular-file permission bits and exact symlink target bytes, rejects unsupported node kinds, and enforces explicit archive-byte, canonical-identity-byte, and node ceilings;
- the completed archive is reparsed before success, and `snapshot_archive_identity` derives the existing Milestone 33A canonical identity from archive records alone without consulting the live tree;
- parser canonicality requires root-first records, strictly increasing raw path order, directory-before-child topology, safe absolute snapshot-relative paths, bounded symlink targets, exact declared node count, and no trailing bytes;
- two captures of one unchanged tree produce byte-identical archives, archive identity equals an independent live-tree `snapshot_sha256`, later source mutation diverges from but cannot alter the captured bytes, and materialization reproduces the captured contents, modes, symlink target, and canonical identity;
- `materialize_snapshot_archive_atomic` validates the entire artifact before mutation, builds a private sibling staging tree through fd-relative non-symlink parent resolution, restores supported modes, and publishes only with `renameat2(RENAME_NOREPLACE)`; malformed/budget failures, an existing destination, and a symlink-parent archive leave no published destination or staging residue;
- exact candidate stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green.

Boundary: 38A freezes the bytes returned after a successful capture, not an atomic point-in-time view against a hostile concurrent source writer. Publication is failure-atomic at the rename boundary but not `fsync` durability/crash consistency. The archive intentionally omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes, and preserved symlink objects are not a confinement guarantee for later consumers that follow them.

### Milestone 38 promotion rule

After 38A integrates, do not farm archive encodings, filename suffixes, compression wrappers, or duplicate identity helpers. Promote only to materially new durability/versioned publication, independently authenticated archive transport/key lifecycle, or another executable authority boundary.

## Independent host-local IPC frontier — post-launch object transfer
"""
replace_one("ROADMAP.md", old_promotion, new_promotion, "ROADMAP 38A section")

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 37A verified candidate adds Ed25519 public-key signature verification over that same bounded canonical identity tuple.",
    "Milestone 37A added Ed25519 public-key signature verification over that same bounded canonical identity tuple. The current Milestone 38A verified candidate adds a deterministic bounded serialized snapshot artifact plus failure-atomic new-tree materialization for the same supported object/identity model.",
    "threat purpose",
)

ed25519_property = """- **Ed25519 canonical snapshot signature:** `sign_snapshot_ed25519` signs a versioned domain plus the bounded 33A identity digest/byte/node accounting under an exact caller-supplied 32-byte signing seed and returns its corresponding public key. `verify_snapshot_ed25519` independently recomputes the identity, parses the supplied public key, and uses `ed25519-dalek` strict verification. Content mutation, a different public key, corrupted signature bytes, and the decoded Edwards-identity weak key with the `R=B, S=1` universal-forgery shape all fail closed. This establishes signature validity under the supplied public key for the modeled identity; it does not establish certificate/trust-chain provenance, public-key ownership, hardware attestation, key generation/storage/rotation/revocation, point-in-time source consistency, or durability.
"""
archive_property = ed25519_property + """- **Bounded canonical snapshot archive:** `serialize_snapshot_archive` deterministically records the supported directory/regular-file/symlink model under explicit archive-byte/identity-byte/node limits and derives the 33A identity by reparsing the completed artifact. `snapshot_archive_identity` validates canonical record ordering/topology and derives that identity without touching a live tree. `materialize_snapshot_archive_atomic` validates the whole artifact before staging, resolves archive parents fd-relatively without following symlinks, restores supported modes, and publishes a new destination only with `renameat2(RENAME_NOREPLACE)`. Round-trip evidence reproduces exact captured contents, modes, symlink target, and canonical identity; malformed/budget/symlink-parent/existing-destination failures publish nothing and leave no staging residue. This freezes successful capture bytes against later source mutation, but does not claim an atomic live-source view against a hostile writer, fsync-backed durability/crash consistency, preservation of metadata outside the 33A model, or follow-safe semantics for preserved symlink objects.
"""
replace_one("THREAT_MODEL.md", ed25519_property, archive_property, "threat archive property")
