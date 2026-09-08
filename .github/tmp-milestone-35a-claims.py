from pathlib import Path
import re


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# README: describe the verified replay-input binding without claiming a frozen source snapshot.
replace_one(
    "README.md",
    "This digest is **identity evidence, not authenticity or provenance**. Milestone 34A can consume an explicitly supplied expected identity as an optimistic replay precondition, but neither the bare digest nor the checked replay signs, keys, authenticates, or attests that value. The identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes. The checked replay does not freeze or serialize the trusted base between the identity scan and replay, so hostile concurrent host mutation can still race that interval; durability/crash semantics also remain outside these APIs.",
    "Milestone 34A added an early expected-base replay gate before destination/staging setup. The current Milestone 35A verified candidate preserves that fail-fast gate and additionally derives the same 33A canonical identity from the opened directory/file modes, exact symlink targets, and exact regular-file bytes actually copied into the private staging tree; diff replay begins only if that completed materialized identity matches the caller-supplied expectation. This remains **identity evidence, not authenticity or provenance**: neither the digest nor checked replay signs, keys, authenticates, or attests the value, and the identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes. 35A binds replay to the actual materialized input, but it does not freeze or serialize the live source tree as a point-in-time filesystem snapshot while copying; authenticity/provenance and durability/crash semantics remain outside these APIs.",
    "README 35A identity semantics",
)

# Threat model: historical 34A, current 35A, and already-integrated SCM_RIGHTS state.
replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 34A verified candidate binds one replay API to an explicitly expected base identity and rejects a digest mismatch before replay destination/staging setup; this remains identity/precondition evidence rather than authenticity, provenance, or attestation. An independent host-local IPC candidate permits receive-only post-launch `SCM_RIGHTS` transfer over the already-brokered exact-path AF_UNIX stream, with explicit target `recvmsg` authority and the existing optional peer UID/GID pin.",
    "Milestone 34A added an early expected-base identity gate before replay destination/staging setup. The current Milestone 35A verified candidate preserves that fail-fast gate and derives the same canonical identity from the exact supported metadata and bytes copied into the private replay staging tree, requiring the completed materialized input to match before diff replay. This remains identity/precondition evidence rather than authenticity, provenance, or attestation. The receive-only post-launch `SCM_RIGHTS` handoff over the exact-path AF_UNIX broker is integrated on `main`, with explicit target `recvmsg` authority and the existing optional peer UID/GID pin.",
    "threat purpose 35A and SCM_RIGHTS status",
)
replace_one(
    "THREAT_MODEL.md",
    "- **Expected-base replay gate:** `apply_cow_diff_atomic_with_expected_base` computes the existing 33A canonical identity before destination-parent inspection or staging creation and requires the digest to match one caller-supplied `SnapshotIdentity`. Identity-scan failure is explicit; mismatch returns `BaseIdentityMismatch { expected, actual }` without entering replay setup. A match returns the identity actually checked plus the unchanged 32A replay report. The legacy unbound replay API remains intentionally available.",
    "- **Expected-base replay binding:** `apply_cow_diff_atomic_with_expected_base` preserves the 34A fail-fast canonical identity check before destination-parent inspection or staging creation. After that gate passes, 35A threads the same 33A canonical hasher through base materialization: sorted entries consume the independent identity node budget, opened directories/regular files contribute their supported Unix mode bits, symlinks contribute the exact target bytes copied, and regular files commit to the opened size plus the exact bytes written into staging; shrink/growth across that committed copy fails closed. The completed materialized identity must match the caller-supplied `SnapshotIdentity` before any diff entry is applied. A mismatch removes staging and publishes no destination; a match returns that materialized identity plus the unchanged replay accounting. The legacy unbound replay API remains intentionally available.",
    "threat expected-base binding property",
)
replace_one(
    "THREAT_MODEL.md",
    "- A caller using expected-base replay is trusted to obtain and retain the expected digest from independently trusted state. The digest itself is not provenance/authentication, and the base is not frozen between the identity scan and replay; hostile concurrent host mutation can still race that interval.",
    "- A caller using expected-base replay is trusted to obtain and retain the expected digest from independently trusted state. The digest itself is not provenance/authentication. The live source tree is not frozen or serialized while materialization runs, but replay proceeds only when the completed private staging input itself reproduces the expected canonical identity.",
    "threat expected-base trust assumption",
)

p = Path("THREAT_MODEL.md")
text = p.read_text()
pattern = re.compile(r"^- expected-base replay regressions prove .*?$", re.M)
replacement = "- expected-base replay regressions preserve the 34A fail-fast mismatch ordering and matching replay path, while the 35A post-first-gate regression mutates the source after the simulated early gate, requires the copy-derived materialized identity to return `BaseIdentityMismatch`, and proves no destination or staging residue is published; the existing 33A fixed canonical digest vector remains unchanged;"
text, count = pattern.subn(replacement, text, count=1)
if count != 1:
    raise SystemExit(f"threat expected-base evidence: expected one line, got {count}")
p.write_text(text)

# Roadmap: seal 34A, introduce 35A, and mark already-merged SCM_RIGHTS complete.
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Binds the 32A new-snapshot replay path to one explicitly supplied 33A canonical base identity without changing the legacy unbound replay API.",
    "**Status: complete on `main`.** Binds the 32A new-snapshot replay path to one explicitly supplied 33A canonical base identity without changing the legacy unbound replay API.",
    "roadmap 34A status",
)
replace_one(
    "ROADMAP.md",
    "After 34A integrates, seal expected-digest API aliases and mismatch variants. A materially stronger COW-lifecycle slice must close the identity-check-to-replay race with an executable frozen/immutable snapshot mechanism, add independently evidenced authenticity/provenance, or introduce separately specified durability/versioned-publication semantics; none may be inferred from 34A.",
    "34A is sealed on `main`; do not farm expected-digest aliases or mismatch variants. The current promotion is 35A, which closes the check-to-replay mis-binding for the actual private replay input by requiring the completed materialized canonical identity to match before diff application. Stronger later work must add independently evidenced authenticity/provenance, a true frozen/serialized source snapshot, or separately specified durability/versioned-publication semantics.",
    "roadmap 34 promotion",
)
insert_after = "34A is sealed on `main`; do not farm expected-digest aliases or mismatch variants. The current promotion is 35A, which closes the check-to-replay mis-binding for the actual private replay input by requiring the completed materialized canonical identity to match before diff application. Stronger later work must add independently evidenced authenticity/provenance, a true frozen/serialized source snapshot, or separately specified durability/versioned-publication semantics.\n"
section = r'''

## Milestone 35 — materialized replay-input binding

### Slice 35A — verified materialized base

**Current verified candidate.** Binds expected-base replay to the exact supported metadata and bytes materialized into the private staging tree before diff application, rather than trusting only the earlier live-source scan.

Acceptance evidence is executable:

- the existing 34A early gate remains first: replay limits validate, then `snapshot_sha256(base, identity_limits)` must match before destination-parent inspection or staging creation, preserving fail-fast stale-base behavior;
- after that gate, the 32A base-copy walk derives the same 33A canonical stream in sorted traversal order while it materializes staging, using opened directory/regular-file permission modes, exact symlink targets, and the exact regular-file bytes written to staging;
- independent 33A identity byte/node ceilings remain fail-closed during materialization; opened regular files commit to one observed size and fail closed if they shrink or grow across the copy boundary;
- the completed materialized `SnapshotIdentity` must match the caller-supplied expectation before any diff entry is applied. Mismatch returns `BaseIdentityMismatch`, removes the private staging tree, and publishes no destination;
- successful checked replay returns the materialized replay-input identity plus the existing bounded replay accounting; the unbound `apply_cow_diff_atomic` API remains available with unchanged semantics;
- a deterministic private regression models a source mutation after the first gate, requires materialized mismatch and zero staging residue, while the public 34A matching/early-mismatch regressions and the 33A fixed canonical SHA-256 vector remain active;
- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.

Boundary: 35A closes the 34A identity-check-to-replay **mis-binding for the input that is actually replayed**: diff application cannot begin unless the completed private materialization reproduces the expected supported-tree identity. It does not freeze, lock, or serialize the live source tree as a point-in-time filesystem snapshot while copying, does not add authenticity/provenance/attestation, and does not add durability/crash recovery or versioned publication. The identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes.

### Milestone 35 promotion rule

After 35A integrates, do not farm second-hash placements or identity API aliases. A stronger COW-lifecycle phase must add independently evidenced authenticity/provenance, a real frozen/serialized source snapshot, or separately specified durability/versioned publication. A separate architectural promotion may instead move to launcher-owned dynamic host-local IPC mediation; target-side self-inspection must not be relabeled as broker enforcement.
'''
roadmap = Path("ROADMAP.md")
text = roadmap.read_text()
if text.count(insert_after) != 1:
    raise SystemExit(f"roadmap 35A insertion anchor count={text.count(insert_after)}")
text = text.replace(insert_after, insert_after + section, 1)
roadmap.write_text(text)
replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** This is a materially new runtime object-capability handoff, not another AF_UNIX address spelling and not a new configuration-only broker name.",
    "**Status: complete on `main`.** This is a materially new runtime object-capability handoff, not another AF_UNIX address spelling and not a new configuration-only broker name.",
    "roadmap SCM_RIGHTS merged status",
)
