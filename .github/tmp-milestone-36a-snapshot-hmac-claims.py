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
    "Milestone 33A added **bounded canonical SHA-256 snapshot identity** for the supported regular-file/directory/symlink tree model. The current Milestone 34A verified candidate adds **expected-base identity binding for atomic COW replay**: the checked replay API recomputes the canonical base identity before destination/staging setup and fails closed on a digest mismatch. An independent verified host-local IPC candidate adds **receive-only post-launch `SCM_RIGHTS` object handoff** over the existing exact-path AF_UNIX broker: the executed target must explicitly allow `recvmsg`, and the already-connected host peer remains optionally pinned by exact UID/GID.",
    "Milestone 33A added **bounded canonical SHA-256 snapshot identity** for the supported regular-file/directory/symlink tree model. Milestone 34A added **expected-base identity binding for atomic COW replay**, and Milestone 35A additionally binds replay to the exact supported metadata and bytes materialized into private staging before diff application. The current Milestone 36A verified candidate adds **keyed HMAC-SHA256 authentication evidence for canonical snapshot identity** with a caller-supplied fixed-size secret key and constant-time tag verification. The receive-only post-launch `SCM_RIGHTS` object handoff over the existing exact-path AF_UNIX broker is integrated on `main`: the executed target must explicitly allow `recvmsg`, and the already-connected host peer remains optionally pinned by exact UID/GID.",
    "README milestone summary",
)

replace_one(
    "README.md",
    "Milestone 34A added an early expected-base replay gate before destination/staging setup. The current Milestone 35A verified candidate preserves that fail-fast gate and additionally derives the same 33A canonical identity from the opened directory/file modes, exact symlink targets, and exact regular-file bytes actually copied into the private staging tree; diff replay begins only if that completed materialized identity matches the caller-supplied expectation. This remains **identity evidence, not authenticity or provenance**: neither the digest nor checked replay signs, keys, authenticates, or attests the value, and the identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes. 35A binds replay to the actual materialized input, but it does not freeze or serialize the live source tree as a point-in-time filesystem snapshot while copying; authenticity/provenance and durability/crash semantics remain outside these APIs.\n\n## Policy observability commands",
    "Milestone 34A added an early expected-base replay gate before destination/staging setup. Milestone 35A preserves that fail-fast gate and additionally derives the same 33A canonical identity from the opened directory/file modes, exact symlink targets, and exact regular-file bytes actually copied into the private staging tree; diff replay begins only if that completed materialized identity matches the caller-supplied expectation. The identity model still omits UID/GID, timestamps, xattrs/ACLs, hard-link identity, and unsupported special nodes, and 35A does not freeze or serialize the live source tree as a point-in-time filesystem snapshot while copying.\n\n## Keyed snapshot authentication\n\nThe current Milestone 36A verified candidate adds `snapshot_hmac_sha256(root, key, limits)` and `verify_snapshot_hmac_sha256(root, key, expected_tag, limits)`. Both reuse the bounded Milestone 33A canonical identity. The key contract is exactly 32 caller-supplied bytes. The tag uses HMAC-SHA256 from the pinned `hmac` 0.12.1 / `sha2` 0.10.9 crates over the versioned domain `security-lab-snapshot-hmac-sha256-v1\\0`, followed by the canonical SHA-256 digest, `encoded_bytes` as little-endian `u64`, and `nodes` as little-endian `u64`. Verification uses the HMAC implementation's constant-time tag comparison path.\n\nExecutable evidence reuses the fixed 33A reference tree (`sha256=b3ff412811f2f9298015ab9320339ab3d35bd53a531b6b4e645ae8656d3c1c85`, 140 canonical bytes, 5 nodes). With key bytes `00..1f`, the fixed HMAC is `70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743`; an unchanged tree verifies, while content mutation or a different key returns `AuthenticationFailed`. Identity byte/node budget failures remain identity failures and are not converted into authentication mismatches.\n\nThis is symmetric **key-possession authentication evidence**, not a digital signature, public provenance statement, attestation, or proof that the caller supplied a high-entropy key. The library does not generate, persist, rotate, distribute, or protect keys; it does not make the live source a point-in-time snapshot and adds no durability/crash semantics.\n\n## Policy observability commands",
    "README keyed authentication section",
)

replace_one(
    "ROADMAP.md",
    "### Slice 35A — verified materialized base\n\n**Current verified candidate.**",
    "### Slice 35A — verified materialized base\n\n**Status: complete on `main`.**",
    "ROADMAP 35A status",
)

replace_one(
    "ROADMAP.md",
    "## Independent host-local IPC frontier — post-launch object transfer",
    "## Milestone 36 — keyed canonical snapshot authentication\n\n### Slice 36A — HMAC-SHA256 snapshot authentication\n\n**Current verified candidate.** Adds a symmetric authentication property over the existing bounded canonical snapshot identity rather than another digest placement or replay gate.\n\nAcceptance evidence is executable:\n\n- `snapshot_hmac_sha256(root, key, limits)` and `verify_snapshot_hmac_sha256(root, key, expected_tag, limits)` require an exact 32-byte caller-supplied key and reuse the bounded 33A canonical snapshot scan;\n- the tag is HMAC-SHA256 using pinned `hmac` 0.12.1 and `sha2` 0.10.9, over the versioned domain `security-lab-snapshot-hmac-sha256-v1\\0` plus canonical SHA-256, `encoded_bytes` little-endian `u64`, and `nodes` little-endian `u64`;\n- verification uses the HMAC implementation's constant-time tag comparison path and reports `AuthenticationFailed` without exposing a computed replacement tag;\n- the existing 33A reference tree with key bytes `00..1f` produces fixed tag `70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743`; the unchanged tree verifies, while content mutation and a distinct 32-byte key fail authentication;\n- identity byte/node budget exhaustion remains a distinct fail-closed `SnapshotIdentityError` path before tag comparison;\n- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head.\n\nBoundary: 36A is symmetric key-possession authentication for the existing canonical identity model. It is not a digital signature, public-key provenance, attestation, certificate/key-distribution system, key-generation/storage/rotation mechanism, or guarantee of caller key entropy. It does not freeze the live source tree, extend the identity metadata model, or add durability/crash recovery.\n\n### Milestone 36 promotion rule\n\nAfter 36A integrates, do not farm tag encodings, key-length aliases, MAC algorithm names, or extra verification wrappers. A stronger authentication/provenance phase must add independently evidenced public-key identity/signature semantics or a real trusted key lifecycle; otherwise promote to a frozen/serialized source snapshot, durability/versioned publication, or launcher-owned dynamic host-local IPC mediation.\n\n## Independent host-local IPC frontier — post-launch object transfer",
    "ROADMAP 36A section",
)

replace_one(
    "THREAT_MODEL.md",
    "Milestone 33A added a separate bounded canonical SHA-256 identity calculation for supported snapshot trees. Milestone 34A added an early expected-base identity gate before replay destination/staging setup. The current Milestone 35A verified candidate preserves that fail-fast gate and derives the same canonical identity from the exact supported metadata and bytes copied into the private replay staging tree, requiring the completed materialized input to match before diff replay. This remains identity/precondition evidence rather than authenticity, provenance, or attestation. The receive-only post-launch `SCM_RIGHTS` handoff over the exact-path AF_UNIX broker is integrated on `main`, with explicit target `recvmsg` authority and the existing optional peer UID/GID pin.",
    "Milestone 33A added a separate bounded canonical SHA-256 identity calculation for supported snapshot trees. Milestone 34A added an early expected-base identity gate before replay destination/staging setup, and Milestone 35A additionally requires the exact supported metadata and bytes materialized into private replay staging to reproduce that expected identity before diff application. The current Milestone 36A verified candidate adds symmetric HMAC-SHA256 key-possession authentication evidence over the canonical identity, with a fixed-size caller key and constant-time tag verification. The receive-only post-launch `SCM_RIGHTS` handoff over the exact-path AF_UNIX broker is integrated on `main`, with explicit target `recvmsg` authority and the existing optional peer UID/GID pin.",
    "THREAT purpose 36A",
)

replace_one(
    "THREAT_MODEL.md",
    "- **Brokered host-loopback TCP ingress listener:**",
    "- **Keyed canonical snapshot authentication:** `snapshot_hmac_sha256` first obtains the bounded 33A canonical identity, then authenticates a versioned domain plus the identity digest/byte/node accounting with HMAC-SHA256 under exactly 32 caller-supplied key bytes. `verify_snapshot_hmac_sha256` recomputes the identity and uses the HMAC implementation's constant-time tag verification; content mutation or a different key fails with `AuthenticationFailed`, while identity scan/budget errors remain separate failures. The fixed 33A tree and key `00..1f` produce tag `70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743`. This authenticates possession of the same secret key for the modeled identity; it does not establish a public signer identity, key entropy, certificate/provenance chain, secret storage/rotation, point-in-time source consistency, or durability.\n- **Brokered host-loopback TCP ingress listener:**",
    "THREAT HMAC property",
)
