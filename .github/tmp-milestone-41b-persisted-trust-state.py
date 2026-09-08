from pathlib import Path

module = Path("src/snapshot_trust_state.rs")
text = module.read_text()
old_import = "use crate::snapshot_archive::{SnapshotArchiveLimits, SnapshotArchiveMaterializeReport};"
if text.count(old_import) != 1:
    raise SystemExit("expected exactly one unused snapshot archive import")
text = text.replace(old_import, "use crate::snapshot_archive::SnapshotArchiveLimits;", 1)

start_marker = "/// Require the supplied policy to equal authenticated host-owned state before\n"
end_marker = "fn encode_state("
start = text.find(start_marker)
end = text.find(end_marker, start)
if start < 0 or end < 0:
    raise SystemExit("could not locate persisted trust operation wrappers")
replacement = '''/// A capability-like binding between one authenticated host-owned trust state\n/// and the exact caller-supplied policy snapshot expected to match it.\n///\n/// Constructing this value performs no I/O. Each operation acquires a shared\n/// state lock, authenticates the persisted identity, requires it to equal\n/// `policy.identity()`, and holds that lock until the underlying store or\n/// materialization operation returns. This makes the state/policy association\n/// explicit at the API boundary and prevents cooperating rotations from\n/// overtaking an accepted operation.\npub struct PersistedSnapshotTrust<'a> {\n    state_root: &'a Path,\n    state_key: &'a SnapshotTrustStateKey,\n    policy: &'a SnapshotTrustPolicy,\n}\n\nimpl<'a> PersistedSnapshotTrust<'a> {\n    pub fn new(\n        state_root: &'a Path,\n        state_key: &'a SnapshotTrustStateKey,\n        policy: &'a SnapshotTrustPolicy,\n    ) -> Self {\n        Self {\n            state_root,\n            state_key,\n            policy,\n        }\n    }\n\n    pub fn policy_identity(&self) -> SnapshotTrustPolicyIdentity {\n        self.policy.identity()\n    }\n\n    /// Require persisted trust-state equality before any snapshot-store access.\n    pub fn store_archive_ed25519_durable(\n        &self,\n        store_root: &Path,\n        archive: &[u8],\n        signer: SnapshotTrustKeyId,\n        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],\n        limits: SnapshotArchiveLimits,\n    ) -> Result<SnapshotTrustedStorePutReport, SnapshotTrustStateError> {\n        #[cfg(target_os = "linux")]\n        {\n            let _guard = linux::lock_shared_and_validate(\n                self.state_root,\n                self.state_key,\n                self.policy.identity(),\n            )?;\n            Ok(store_snapshot_archive_trusted_ed25519_durable(\n                store_root,\n                archive,\n                self.policy,\n                signer,\n                expected_signature,\n                limits,\n            )?)\n        }\n        #[cfg(not(target_os = "linux"))]\n        {\n            let _ = (store_root, archive, signer, expected_signature, limits);\n            Err(SnapshotTrustStateError::UnsupportedPlatform(\n                "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"\n                    .to_owned(),\n            ))\n        }\n    }\n\n    /// State-backed counterpart to trusted atomic materialization. The persisted\n    /// policy gate runs before store-object inspection and remains locked until\n    /// the materializer returns.\n    pub fn materialize_store_object_ed25519_atomic(\n        &self,\n        store_root: &Path,\n        identity: SnapshotIdentity,\n        destination: &Path,\n        signer: SnapshotTrustKeyId,\n        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],\n        limits: SnapshotArchiveLimits,\n    ) -> Result<SnapshotTrustedMaterializeReport, SnapshotTrustStateError> {\n        #[cfg(target_os = "linux")]\n        {\n            let _guard = linux::lock_shared_and_validate(\n                self.state_root,\n                self.state_key,\n                self.policy.identity(),\n            )?;\n            Ok(materialize_snapshot_store_object_trusted_ed25519_atomic(\n                store_root,\n                identity,\n                destination,\n                self.policy,\n                signer,\n                expected_signature,\n                limits,\n            )?)\n        }\n        #[cfg(not(target_os = "linux"))]\n        {\n            let _ = (\n                store_root,\n                identity,\n                destination,\n                signer,\n                expected_signature,\n                limits,\n            );\n            Err(SnapshotTrustStateError::UnsupportedPlatform(\n                "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"\n                    .to_owned(),\n            ))\n        }\n    }\n}\n\n'''
text = text[:start] + replacement + text[end:]
module.write_text(text)

lib = Path("src/lib.rs")
lib_text = lib.read_text()
for name in (
    "    materialize_snapshot_store_object_persisted_trust_ed25519_atomic,\n",
    "    store_snapshot_archive_persisted_trust_ed25519_durable,\n",
):
    if lib_text.count(name) != 1:
        raise SystemExit(f"expected exactly one export line: {name.strip()}")
    lib_text = lib_text.replace(name, "", 1)
needle = "pub use snapshot_trust_state::{\n"
if lib_text.count(needle) != 1:
    raise SystemExit("expected exactly one snapshot trust state export block")
lib_text = lib_text.replace(needle, needle + "    PersistedSnapshotTrust,\n", 1)
lib.write_text(lib_text)
