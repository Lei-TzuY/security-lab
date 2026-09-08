from pathlib import Path
import re


def replace_exact(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def replace_regex(path: str, pattern: str, repl: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    new, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(new)


# README: seal 40A and add only the durability semantics proven by the 40B tests.
replace_exact(
    "README.md",
    "The current Milestone 40A verified candidate adds a trusted host-local content-addressed store",
    "Milestone 40A added a trusted host-local content-addressed store",
    "README 40A status",
)
replace_regex(
    "README.md",
    r"(Milestone 40A added a trusted host-local content-addressed store.*?\n\n)",
    r'''\1The current Milestone 40B verified candidate adds success-return durability for authenticated content-addressed publication with `store_snapshot_archive_ed25519_durable`. It first reuses the Milestone 40A verify-before-store, no-replace exact-object path, then reopens the committed identity-addressed regular read-only object and crosses real Linux `fsync` barriers in order for the object, its `objects/` directory, and the pre-existing store root before returning success. A deterministic subprocess installs a narrow seccomp filter that returns `EPERM` only for `fsync`; the durable API must report that real barrier failure instead of acknowledging success. Retrying the same authenticated archive after that ambiguous rename-without-durable-ack state converges through exact-object deduplication (`inserted = false`) and reruns the barriers before success. This guarantee is exactly the local kernel/filesystem `fsync` contract; it is not a journal, a physical power-loss simulator, stale-temp recovery/GC, replication, or hostile-store-writer protection.\n\n''',
    "README 40B durable paragraph",
)

# Threat model: distinguish 40A atomic publication from 40B success-return durability.
replace_exact(
    "THREAT_MODEL.md",
    "No `fsync` crash durability, key provenance/trust lifecycle, garbage collection, distributed-store, replication, or hostile concurrent-writer property is claimed.",
    "Milestone 40A itself did not claim `fsync` crash durability, key provenance/trust lifecycle, garbage collection, distributed-store, replication, or hostile concurrent-writer properties.",
    "threat 40A historical durability boundary",
)
replace_regex(
    "THREAT_MODEL.md",
    r"(Milestone 40A treats the store root as trusted host-local state\..*?Milestone 40A itself did not claim `fsync` crash durability, key provenance/trust lifecycle, garbage collection, distributed-store, replication, or hostile concurrent-writer properties\.\n)",
    r'''\1\nMilestone 40B adds a narrower lifecycle guarantee: `store_snapshot_archive_ed25519_durable` acknowledges success only after the authenticated/no-replace 40A result has been reopened and checked as the expected regular read-only object and `fsync` has succeeded on that object, the containing `objects/` directory, and the store root. The denial regression uses a real seccomp `EPERM` response for `fsync` to prove the barrier is attempted and failure is surfaced. If publication reached the final 40A rename but no durable acknowledgement was returned, an exact retry is safe: 40A byte-for-byte deduplication identifies the same object and 40B reruns all durability barriers. The claim is limited to the Linux/local-filesystem `fsync` contract and does not imply a journal, transactional multi-object commit, stale temporary-object scavenging, storage-device power-loss testing, remote replication, or resistance to a privileged hostile store writer.\n''',
    "threat 40B durable semantics",
)

# Roadmap: close 40A, add 40B as the verified candidate, and promote beyond fsync variants.
replace_regex(
    "ROADMAP.md",
    r"(## Milestone 40 — authenticated content-addressed snapshot storage\n\n### Slice 40A — immutable identity-addressed frozen archive objects\n\n)\*\*Current verified candidate\.\*\*",
    r"\1**Status: complete on `main`.**",
    "roadmap 40A status",
)
replace_exact(
    "ROADMAP.md",
    "Boundary: 40A is a trusted host-local bounded object store. Mode `0444` is an API immutability convention, not protection from a privileged writer controlling the store root. It does not provide `fsync` crash durability/recovery, trust-store or key provenance/rotation/revocation, garbage collection/indexing, version retention, remote/distributed CAS, replication, or hostile concurrent store-writer protection.\n\n### Milestone 40 promotion rule\n\nAfter 40A integrates, do not farm object filename encodings, extra dedup aliases, or repeated tamper vectors. Promote to a materially stronger lifecycle boundary such as crash-durable publication/recovery or independently specified trust/key lifecycle semantics.",
    """Boundary: 40A is a trusted host-local bounded object store. Mode `0444` is an API immutability convention, not protection from a privileged writer controlling the store root. 40A by itself does not provide success-return `fsync` durability, trust-store or key provenance/rotation/revocation, garbage collection/indexing, version retention, remote/distributed CAS, replication, or hostile concurrent store-writer protection.\n\n### Slice 40B — success-return durable content-addressed publication\n\n**Current verified candidate.** Adds a real durability barrier to the authenticated 40A object lifecycle rather than another content-address or tamper variant.\n\nAcceptance evidence is executable:\n\n- `store_snapshot_archive_ed25519_durable` first executes the existing bounded archive validation, strict Ed25519 verification, no-replace publication, and exact-object dedup path; no unauthenticated archive gains a durability shortcut;\n- after the 40A result, Linux code reopens the exact identity-addressed object beneath the store, checks that it is a regular read-only file with the expected archive length, then requires `fsync` success in order on the object, the `objects/` directory, and the store root before returning success;\n- a normal new insertion crosses those barriers and remains materializable through the existing identity re-derivation plus Ed25519 verification path;\n- a child test process installs a narrow seccomp filter that returns `EPERM` only for `fsync`; the durable API observes that real syscall failure at the object barrier and fails rather than silently acknowledging durability;\n- after that deliberately ambiguous state, where the 40A rename may already have published the exact object but 40B returned no durable acknowledgement, retrying the same authenticated archive converges through byte-for-byte deduplication with `inserted = false`, reruns all durability barriers, and remains materializable;\n- rustfmt, Clippy with `-D warnings`, the complete stable suite, and the complete Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 40B claims only success-return durability under the local Linux kernel/filesystem `fsync` contract. It does not claim a physical power-loss experiment, storage-device cache behavior beyond that contract, a write-ahead journal, transactional multi-object commit, stale temporary-object recovery/scavenging, garbage collection, remote replication, trust/key lifecycle, or protection from a privileged hostile writer controlling the store root.\n\n### Milestone 40 promotion rule\n\nAfter 40B integrates, the bounded host-local publication/durability path is sealed at this scope. Do not farm extra `fsync` orderings, filenames, or repeated failure aliases. Promote to an independently specified trust/key lifecycle boundary (key identity/provenance plus rotation or revocation semantics) or another materially different storage lifecycle capability with executable evidence.""",
    "roadmap 40B section",
)
