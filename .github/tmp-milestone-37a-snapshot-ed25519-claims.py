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
    "The current Milestone 36A verified candidate adds **keyed HMAC-SHA256 authentication evidence for canonical snapshot identity** with a caller-supplied fixed-size secret key and constant-time tag verification.",
    "Milestone 36A added **keyed HMAC-SHA256 authentication evidence for canonical snapshot identity** with a caller-supplied fixed-size secret key and constant-time tag verification. The current Milestone 37A verified candidate adds **Ed25519 public-key signatures over canonical snapshot identity** with exact fixed-width key/signature material and strict signature verification.",
    "README milestone summary",
)

replace_one(
    "README.md",
    "This is symmetric **key-possession authentication evidence**, not a digital signature, public provenance statement, attestation, or proof that the caller supplied a high-entropy key. The library does not generate, persist, rotate, distribute, or protect keys; it does not make the live source a point-in-time snapshot and adds no durability/crash semantics.\n",
    "This is symmetric **key-possession authentication evidence**, not a digital signature, public provenance statement, attestation, or proof that the caller supplied a high-entropy key. The library does not generate, persist, rotate, distribute, or protect keys; it does not make the live source a point-in-time snapshot and adds no durability/crash semantics.\n\n## Public-key snapshot signatures\n\nThe current Milestone 37A verified candidate adds `sign_snapshot_ed25519(root, signing_key, limits)` and `verify_snapshot_ed25519(root, public_key, expected_signature, limits)`. Both reuse the bounded Milestone 33A canonical snapshot identity rather than defining a second filesystem model. The signing input is a versioned domain `security-lab-snapshot-ed25519-v1\\0`, followed by the canonical SHA-256 digest, `encoded_bytes` as little-endian `u64`, and `nodes` as little-endian `u64`. The signing API accepts an exact 32-byte Ed25519 signing seed, returns the corresponding 32-byte public key plus a 64-byte signature, and verification uses strict Ed25519 verification under the exact caller-supplied public key.\n\nExecutable evidence proves an unchanged supported tree verifies, while content mutation, a different public key, or one-bit signature corruption fails with `VerificationFailed`. A separate RFC 8032 test-vector oracle signs the empty message with the published test-vector seed, requires the exact published public key/signature bytes, and strictly verifies that signature. The exact implementation head passes stable rustfmt/Clippy/full tests and the full Rust 1.74 suite; the lockfile pins transitive `base64ct`/`zeroize` versions compatible with that declared MSRV.\n\nThis is bounded **public-key signature evidence for the canonical snapshot identity**, not key generation/storage/rotation, certificate or trust-store validation, signer authorization, remote attestation, hardware-backed key provenance, a signature chain, a frozen/serialized source snapshot, or durability/versioned publication. The API deliberately accepts caller-supplied key material and does not claim how that key became trusted.\n",
    "README Ed25519 section",
)

replace_one(
    "THREAT_MODEL.md",
    "The current Milestone 36A verified candidate adds symmetric HMAC-SHA256 key-possession authentication evidence over the canonical identity, with a fixed-size caller key and constant-time tag verification.",
    "Milestone 36A added symmetric HMAC-SHA256 key-possession authentication evidence over the canonical identity, with a fixed-size caller key and constant-time tag verification. The current Milestone 37A verified candidate adds Ed25519 public-key signature evidence over that same bounded canonical identity with exact fixed-width key/signature material and strict verification.",
    "threat model milestone summary",
)

hmac_property = "- **Keyed canonical snapshot authentication:** `snapshot_hmac_sha256` first obtains the bounded 33A canonical identity, then authenticates a versioned domain plus the identity digest/byte/node accounting with HMAC-SHA256 under exactly 32 caller-supplied key bytes. `verify_snapshot_hmac_sha256` recomputes the identity and uses the HMAC implementation's constant-time tag verification; content mutation or a different key fails with `AuthenticationFailed`, while identity scan/budget errors remain separate failures. The fixed 33A tree and key `00..1f` produce tag `70dfbe6a9ccdc1cc21b278c0ee249bbf651bd3db802d759ea2902698c4d64743`. This authenticates possession of the same secret key for the modeled identity; it does not establish a public signer identity, key entropy, certificate/provenance chain, secret storage/rotation, point-in-time source consistency, or durability.\n"
replace_one(
    "THREAT_MODEL.md",
    hmac_property,
    hmac_property + "- **Ed25519 canonical snapshot signature:** `sign_snapshot_ed25519` first obtains the same bounded 33A canonical identity, signs the versioned `security-lab-snapshot-ed25519-v1\\0` message containing digest/byte/node accounting with an exact 32-byte caller-supplied signing seed, and returns the corresponding 32-byte public key plus 64-byte signature. `verify_snapshot_ed25519` recomputes the identity and uses strict Ed25519 verification under the exact supplied public key. Unchanged-tree verification succeeds; content mutation, a different public key, or signature-bit corruption fails closed, and the backend is independently checked against RFC 8032 test vector 1. This is public-key signature evidence for the modeled canonical identity only: it does not establish signer authorization, certificate/trust-store semantics, key generation/storage/rotation, hardware provenance, remote attestation, source freezing, or durability.\n",
    "threat Ed25519 property",
)

replace_one(
    "ROADMAP.md",
    "**Current verified candidate.** Adds a symmetric authentication property over the existing bounded canonical snapshot identity rather than another digest placement or replay gate.",
    "**Status: complete on `main`.** Adds a symmetric authentication property over the existing bounded canonical snapshot identity rather than another digest placement or replay gate.",
    "roadmap 36A status",
)

promotion = "### Milestone 36 promotion rule\n\nAfter 36A integrates, do not farm tag encodings, key-length aliases, MAC algorithm names, or extra verification wrappers. A stronger authentication/provenance phase must add independently evidenced public-key identity/signature semantics or a real trusted key lifecycle; otherwise promote to a frozen/serialized source snapshot, durability/versioned publication, or launcher-owned dynamic host-local IPC mediation.\n"
replace_one(
    "ROADMAP.md",
    promotion,
    promotion + "\n## Milestone 37 — public-key canonical snapshot signatures\n\n### Slice 37A — Ed25519 snapshot signature evidence\n\n**Current verified candidate.** Adds a materially different public-key authenticity primitive over the existing bounded canonical snapshot identity rather than another shared-secret MAC wrapper.\n\nAcceptance evidence is executable:\n\n- `sign_snapshot_ed25519` accepts an exact 32-byte caller-supplied Ed25519 signing seed, computes the existing bounded canonical snapshot identity, signs a versioned/domain-separated message containing the identity digest plus encoded-byte/node accounting, and returns the identity, exact 32-byte public key, and exact 64-byte signature;\n- `verify_snapshot_ed25519` recomputes the bounded identity and performs strict Ed25519 verification under the exact caller-supplied public key; malformed public-key decoding, identity-scan failure, and signature verification failure remain distinct fail-closed results;\n- an unchanged tree verifies, while content mutation, a different public key, and one-bit signature corruption each fail;\n- an independent RFC 8032 test-vector oracle requires the published test-vector public key/signature bytes for the empty message and strictly verifies them, so the cryptographic backend is not validated only against self-generated outputs;\n- stable rustfmt/Clippy/full tests and the full Rust 1.74 suite are green on the exact implementation head, with MSRV-compatible transitive versions pinned in `Cargo.lock`.\n\nBoundary: 37A is public-key signature evidence for the existing canonical identity. It does not generate, store, rotate, distribute, authorize, or attest keys; it does not provide certificates, a trust store, signature chains, remote/hardware attestation, a frozen/serialized live-source snapshot, or durability/versioned publication.\n\n### Milestone 37 promotion rule\n\nAfter 37A integrates, do not farm signature encodings, Ed25519 wrapper aliases, alternate fixed test seeds, or additional self-sign/verify vectors. A stronger provenance phase must add real trusted key lifecycle or signer-authorization semantics; otherwise promote to the still-open frozen/serialized source-snapshot or durability/versioned-publication frontier.\n",
    "roadmap 37A section",
)
