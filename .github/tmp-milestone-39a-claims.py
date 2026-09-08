from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_after_bullet(path: str, bullet_prefix: str, new_bullet: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    if text.count(bullet_prefix) != 1:
        raise SystemExit(f"{label}: expected exactly one bullet prefix")
    start = text.index(bullet_prefix)
    end = text.find("\n- **", start + len(bullet_prefix))
    if end == -1:
        raise SystemExit(f"{label}: could not locate following bullet")
    if new_bullet in text:
        raise SystemExit(f"{label}: new bullet already present")
    p.write_text(text[:end] + "\n" + new_bullet + text[end:])


# README: seal 38A and describe only the verified 39A publication gate.
replace_one(
    "README.md",
    "The current Milestone 38A verified candidate adds a **bounded deterministic snapshot archive** whose completed serialized records reproduce the existing canonical identity and can be failure-atomically materialized as a new host snapshot.",
    "Milestone 38A added a **bounded deterministic snapshot archive** whose completed serialized records reproduce the existing canonical identity and can be failure-atomically materialized as a new host snapshot. The current Milestone 39A verified candidate adds **Ed25519-verified archive publication**: a frozen canonical archive must strictly verify under the exact caller-supplied public key and signature before destination inspection, staging, or publication can begin.",
    "README milestone summary",
)
replace_one(
    "README.md",
    "The current Milestone 38A verified candidate adds `serialize_snapshot_archive(root, limits)`, `snapshot_archive_identity(bytes, limits)`, and `materialize_snapshot_archive_atomic(bytes, destination, limits)`.",
    "Milestone 38A added `serialize_snapshot_archive(root, limits)`, `snapshot_archive_identity(bytes, limits)`, and `materialize_snapshot_archive_atomic(bytes, destination, limits)`.",
    "README archive status",
)
replace_one(
    "README.md",
    "\n## Development\n",
    "\n## Ed25519-verified archive publication\n\nThe current Milestone 39A verified candidate adds `materialize_snapshot_archive_ed25519_atomic(archive, destination, public_key, signature, limits)`. The function first validates the complete canonical archive under the existing archive byte/identity byte/node ceilings, derives the Milestone 33A identity directly from those frozen records, and then reuses the Milestone 37A `ed25519-dalek` strict verifier over the exact supplied public key and 64-byte signature. Only a successfully verified artifact may enter the existing 38A fd-relative staging and `renameat2(RENAME_NOREPLACE)` publication path.\n\nExecutable evidence signs the canonical identity corresponding to a captured archive, mutates the live source afterward, and still publishes the original frozen bytes with the original identity. A wrong public key must return signature verification failure before even a deliberately missing destination parent is inspected; a parse-valid content-byte tamper must also fail verification, publish no destination, and leave no staging residue. Existing 37A strict-verification regressions, including weak-key/universal-forgery rejection, remain active through the shared verifier.\n\nThis is authenticated publication **under the exact caller-supplied public key**. It does not establish who owns or trusts that key, a certificate/trust store, key generation/storage/rotation/revocation, remote or hardware attestation, authenticated transport, `fsync` crash durability, or a richer snapshot metadata model.\n\n## Development\n",
    "README 39A section",
)

# Threat model: make the verification-before-side-effects invariant explicit.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 38A verified candidate adds a deterministic bounded serialized snapshot artifact plus failure-atomic new-tree materialization for the same supported object/identity model.",
    "Milestone 38A added a deterministic bounded serialized snapshot artifact plus failure-atomic new-tree materialization for the same supported object/identity model. The current Milestone 39A verified candidate requires that artifact's canonical identity to pass the existing strict Ed25519 verification path under the exact caller-supplied public key/signature before destination inspection, staging, or publication.",
    "threat purpose 39A",
)
insert_after_bullet(
    "THREAT_MODEL.md",
    "- **Bounded canonical snapshot archive:**",
    "- **Ed25519-verified archive publication:** `materialize_snapshot_archive_ed25519_atomic` fully parses and bounds the frozen archive, derives its canonical identity from the artifact records, and applies the Milestone 37A `verify_strict` Ed25519 check before destination-parent inspection or staging creation. Wrong-key and parse-valid content-tamper evidence fail with signature verification errors and leave no publication/staging state; a later mutation of the original live source cannot alter the already-captured authenticated archive. This proves signature validity under the exact supplied public key for the frozen supported archive semantics, not public-key provenance, certificate/trust-store policy, key lifecycle, attestation, authenticated transport, or crash durability.",
    "threat 39A property",
)

# Roadmap: seal 38A and promote one materially new authenticated-publication slice.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Freezes the supported snapshot object model into bounded deterministic bytes and can materialize those bytes into a new failure-atomically published host tree.",
    "**Status: complete on `main`.** Freezes the supported snapshot object model into bounded deterministic bytes and can materialize those bytes into a new failure-atomically published host tree.",
    "roadmap 38A status",
)
replace_one(
    "ROADMAP.md",
    "### Milestone 38 promotion rule\n\nAfter 38A integrates, do not farm archive encodings, filename suffixes, compression wrappers, or duplicate identity helpers. Promote only to materially new durability/versioned publication, independently authenticated archive transport/key lifecycle, or another executable authority boundary.\n",
    "### Milestone 38 promotion rule\n\n38A is sealed on `main`; do not farm archive encodings, filename suffixes, compression wrappers, or duplicate identity helpers. The active promotion is authenticated use of the frozen artifact rather than another serialization variant.\n\n## Milestone 39 — authenticated snapshot archive publication\n\n### Slice 39A — Ed25519 verification before atomic publication\n\n**Current verified candidate.** Composes the existing 37A strict public-key signature verifier with the 38A frozen archive/materialization path so unauthenticated archive bytes cannot reach destination inspection or staging.\n\nAcceptance evidence is executable:\n\n- `materialize_snapshot_archive_ed25519_atomic` validates the complete bounded/canonical archive and derives its 33A identity directly from artifact records before signature verification;\n- the exact caller-supplied 32-byte public key and 64-byte signature are checked by the existing `ed25519-dalek` strict verifier over the same versioned 37A identity message;\n- only successful verification may enter 38A fd-relative staging and `renameat2(RENAME_NOREPLACE)` publication;\n- an archive signed before later live-source mutation still publishes the original captured bytes and reproduces the captured canonical identity;\n- a wrong public key fails before a deliberately missing destination parent is inspected, while a parse-valid archive content tamper fails verification with no destination or staging residue;\n- existing 37A strict-verification security regressions and all 38A malformed/budget/publication regressions remain active; stable rustfmt/Clippy/full tests and the full Rust 1.74 suite remain green.\n\nBoundary: 39A proves signature validity under the exact supplied public key for the frozen supported archive semantics. It does not establish public-key ownership/provenance, certificate or trust-store policy, key generation/storage/rotation/revocation, remote/hardware attestation, authenticated transport, `fsync` crash durability, overwrite/version-retention semantics, or a broader metadata/object model.\n\n### Milestone 39 promotion rule\n\nAfter 39A integrates, do not farm signature encodings, duplicate verify wrappers, key-file spelling, or extra tamper vectors that exercise the same gate. Promote only to a real trust/key lifecycle, crash-durable/versioned publication, or another independent executable authority boundary.\n",
    "roadmap 39A section",
)
