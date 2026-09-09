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


# README: describe only the executable 42A audit and its explicit non-goals.
insert_before(
    "README.md",
    "## Test evidence\n",
    "### Bounded snapshot-store integrity audit\n\n"
    "The current Milestone 42A verified candidate adds `audit_snapshot_store(store_root, limits)`, a read-only bounded integrity pass over the existing content-addressed snapshot object format. On Linux it opens the trusted store root and `objects/` directory without following symlinks, enumerates through the already-open directory, opens each observed object fd-relatively with `O_NOFOLLOW`, requires a single-link regular file with no write permission bits, enforces explicit entry/per-object/aggregate byte and archive identity/node ceilings, parses the complete canonical identity tuple from the object filename, validates the complete archive, and requires the archive-derived identity to match the filename exactly.\n\n"
    "This audit assumes a quiescent or cooperatively serialized host-local store. It is integrity inventory, not signer/trust-policy authentication: the store does not persist signature evidence beside each object, and authenticated publication/materialization remain the responsibility of the existing Ed25519/trust-state APIs. The audit does not lock out independent publishers and does not repair, quarantine, delete, garbage-collect, snapshot, or provide rollback/replication guarantees.\n\n",
    "README 42A insertion",
)

# Threat model: seal the integrated 41B wording and add bounded 42A semantics without
# claiming authenticity, repair, concurrency consistency, or rollback resistance.
replace_once(
    "THREAT_MODEL.md",
    "Milestones through 41A are integrated on `main`",
    "Milestones through 41B are integrated on `main`",
    "threat integrated milestone summary",
)
replace_once(
    "THREAT_MODEL.md",
    "The current Milestone 41B verified candidate persists and authenticates the exact policy identity",
    "Milestone 41B persists and authenticates the exact policy identity",
    "threat 41B candidate status",
)
append_to_section(
    "THREAT_MODEL.md",
    "## Content-addressed snapshot-store semantics\n",
    "Milestone 42A adds a separate read-only whole-store integrity audit. It bounds non-dot object-directory entries, aggregate archive bytes, per-object archive bytes, identity bytes, and archive nodes; opens the store root, `objects/`, and each observed object without following symlinks; rejects non-canonical names, non-regular objects, objects with more than one hard link, and objects retaining write permission bits; reparses every complete archive; and requires the archive-derived canonical identity tuple to equal the filename tuple. Executable evidence covers a healthy multi-object inventory plus content tamper, filename mismatch, symlink, writable-object, hard-link, entry-budget, and aggregate-byte failures.\n\n"
    "The audit assumes a quiescent or cooperatively serialized trusted host-local store. It does not authenticate signer provenance or trust-policy membership because object files do not persist per-object signature/trust evidence, does not lock out an independent publisher or promise a point-in-time inventory under concurrent mutation, and does not repair, quarantine, delete, garbage-collect, snapshot, replicate, or strengthen the 41B rollback boundary.",
    "threat 42A semantics",
)

# Roadmap: 41B is integrated; 42A is the active verified candidate.
replace_once(
    "ROADMAP.md",
    "**Current verified candidate.** Adds host-owned authenticated state for the exact trust-policy identity so cooperating state-backed operations cannot silently reuse an older caller-supplied policy while that state and its authentication key remain intact.",
    "**Status: complete on `main`.** Adds host-owned authenticated state for the exact trust-policy identity so cooperating state-backed operations cannot silently reuse an older caller-supplied policy while that state and its authentication key remain intact.",
    "roadmap 41B status",
)
insert_before(
    "ROADMAP.md",
    "## Independent host-local IPC frontier — post-launch object transfer\n",
    "## Milestone 42 — bounded content-addressed store integrity audit\n\n"
    "### Slice 42A — read-only bounded inventory validation\n\n"
    "**Current verified candidate.** Adds a whole-store read-only integrity pass over the existing Milestones 40A/40B object format rather than another publication or materialization wrapper.\n\n"
    "Acceptance evidence is executable:\n\n"
    "- `audit_snapshot_store(store_root, limits)` requires a trusted absolute non-root store path and explicit non-zero entry, aggregate archive-byte, per-object archive-byte, canonical identity-byte, and archive-node ceilings;\n"
    "- Linux opens the store root and `objects/` with `O_NOFOLLOW`, enumerates through the already-open directory, opens every observed object fd-relatively with `O_NOFOLLOW`, and rejects non-canonical names, symlink/special entries, non-regular files, multi-link objects, or files retaining write bits;\n"
    "- every canonical filename is parsed as the complete `(sha256, encoded_bytes, nodes)` identity tuple; the complete bounded archive is read, required not to change length during that read, validated by the existing canonical archive parser, and its derived identity must exactly match the filename identity;\n"
    "- a healthy two-object store reports exact object and aggregate-byte counts; deterministic regressions reject content tamper, canonical filename/identity mismatch, a symlink entry, a writable object, an external hard-link alias, entry-budget overflow, and aggregate-byte overflow;\n"
    "- exact candidate rustfmt, Clippy with `-D warnings`, complete stable tests, and the complete Rust 1.74 suite are green.\n\n"
    "Boundary: 42A is a read-only integrity inventory for a quiescent or cooperatively serialized trusted host-local store. It does not verify signer provenance/trust-policy membership or persisted signatures, lock out independent concurrent publishers, repair/quarantine/delete/garbage-collect objects, provide a point-in-time concurrent snapshot, or strengthen rollback/remote-replica guarantees.\n\n"
    "### Milestone 42 promotion rule\n\n"
    "After 42A integrates, do not farm more malformed filenames, tamper bytes, link counts, or budget aliases that repeat the same audit path. Promote only to a materially different executable store-lifecycle or authority boundary with safe mutation/concurrency semantics and deterministic evidence, or to another independent frontier if that evidence is not yet available.\n\n",
    "roadmap 42A insertion",
)
