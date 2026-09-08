from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/snapshot_trust_state.rs",
    "use crate::snapshot_archive::{SnapshotArchiveLimits, SnapshotArchiveMaterializeReport};",
    "use crate::snapshot_archive::SnapshotArchiveLimits;",
    "remove unused archive report import",
)

replace_one(
    "src/snapshot_trust_state.rs",
    '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustStateReceipt {
    pub policy: SnapshotTrustPolicyIdentity,
}
''',
    '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotTrustStateReceipt {
    pub policy: SnapshotTrustPolicyIdentity,
}

/// One persisted trust-state authority reused by state-backed snapshot operations.
///
/// The context binds the host-owned authenticated state location/key to the exact
/// caller-supplied trust-policy snapshot. Each operation still reopens, locks,
/// authenticates, and compares persisted state before touching snapshot storage.
pub struct SnapshotTrustStateContext<'a> {
    state_root: &'a Path,
    state_key: &'a SnapshotTrustStateKey,
    policy: &'a SnapshotTrustPolicy,
}

impl<'a> SnapshotTrustStateContext<'a> {
    pub fn new(
        state_root: &'a Path,
        state_key: &'a SnapshotTrustStateKey,
        policy: &'a SnapshotTrustPolicy,
    ) -> Self {
        Self {
            state_root,
            state_key,
            policy,
        }
    }
}
''',
    "insert persisted trust context",
)

replace_one(
    "src/snapshot_trust_state.rs",
    '''pub fn store_snapshot_archive_persisted_trust_ed25519_durable(
    state_root: &Path,
    state_key: &SnapshotTrustStateKey,
    store_root: &Path,
    archive: &[u8],
    policy: &SnapshotTrustPolicy,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedStorePutReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(state_root, state_key, policy.identity())?;
        Ok(store_snapshot_archive_trusted_ed25519_durable(
            store_root,
            archive,
            policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            state_root,
            state_key,
            store_root,
            archive,
            policy,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}
''',
    '''pub fn store_snapshot_archive_persisted_trust_ed25519_durable(
    context: &SnapshotTrustStateContext<'_>,
    store_root: &Path,
    archive: &[u8],
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedStorePutReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(
            context.state_root,
            context.state_key,
            context.policy.identity(),
        )?;
        Ok(store_snapshot_archive_trusted_ed25519_durable(
            store_root,
            archive,
            context.policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            context,
            store_root,
            archive,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}
''',
    "refactor persisted store API",
)

replace_one(
    "src/snapshot_trust_state.rs",
    '''pub fn materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
    state_root: &Path,
    state_key: &SnapshotTrustStateKey,
    store_root: &Path,
    identity: SnapshotIdentity,
    destination: &Path,
    policy: &SnapshotTrustPolicy,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedMaterializeReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(state_root, state_key, policy.identity())?;
        Ok(materialize_snapshot_store_object_trusted_ed25519_atomic(
            store_root,
            identity,
            destination,
            policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            state_root,
            state_key,
            store_root,
            identity,
            destination,
            policy,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}
''',
    '''pub fn materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
    context: &SnapshotTrustStateContext<'_>,
    store_root: &Path,
    identity: SnapshotIdentity,
    destination: &Path,
    signer: SnapshotTrustKeyId,
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotTrustedMaterializeReport, SnapshotTrustStateError> {
    #[cfg(target_os = "linux")]
    {
        let _guard = linux::lock_shared_and_validate(
            context.state_root,
            context.state_key,
            context.policy.identity(),
        )?;
        Ok(materialize_snapshot_store_object_trusted_ed25519_atomic(
            store_root,
            identity,
            destination,
            context.policy,
            signer,
            expected_signature,
            limits,
        )?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            context,
            store_root,
            identity,
            destination,
            signer,
            expected_signature,
            limits,
        );
        Err(SnapshotTrustStateError::UnsupportedPlatform(
            "persisted snapshot trust operations currently require Linux flock and authenticated fd-relative state access"
                .to_owned(),
        ))
    }
}
''',
    "refactor persisted materialize API",
)

replace_one(
    "src/lib.rs",
    '''    store_snapshot_archive_persisted_trust_ed25519_durable, SnapshotTrustStateError,
    SnapshotTrustStateKey, SnapshotTrustStateReceipt, SNAPSHOT_TRUST_STATE_KEY_BYTES,
''',
    '''    store_snapshot_archive_persisted_trust_ed25519_durable, SnapshotTrustStateContext,
    SnapshotTrustStateError, SnapshotTrustStateKey, SnapshotTrustStateReceipt,
    SNAPSHOT_TRUST_STATE_KEY_BYTES,
''',
    "export persisted trust context",
)

Path("tests/snapshot_trust_state.rs").write_text(r'''#![cfg(target_os = "linux")]

use security_lab::{
    initialize_snapshot_trust_state, load_snapshot_trust_state_identity,
    materialize_snapshot_store_object_persisted_trust_ed25519_atomic,
    rotate_snapshot_trust_state, serialize_snapshot_archive, sign_snapshot_ed25519,
    snapshot_trust_state_path, store_snapshot_archive_persisted_trust_ed25519_durable,
    SnapshotArchiveLimits, SnapshotIdentityLimits, SnapshotTrustKey, SnapshotTrustKeyId,
    SnapshotTrustKeyState, SnapshotTrustPolicy, SnapshotTrustStateContext, SnapshotTrustStateError,
    SnapshotTrustStateKey,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "security-lab-snapshot-trust-state-{label}-{}-{id}",
            process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir(&path).expect("create snapshot trust-state workspace");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn archive_limits() -> SnapshotArchiveLimits {
    SnapshotArchiveLimits {
        max_archive_bytes: 1024 * 1024,
        max_identity_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn identity_limits() -> SnapshotIdentityLimits {
    SnapshotIdentityLimits {
        max_bytes: 1024 * 1024,
        max_nodes: 64,
    }
}

fn create_source(workspace: &Path) -> PathBuf {
    let source = workspace.join("source");
    fs::create_dir(&source).expect("create source root");
    fs::write(source.join("payload"), b"persisted-trust-payload\n")
        .expect("write source payload");
    source
}

#[test]
fn persisted_rotation_rejects_stale_policy_before_store_access_and_accepts_successor() {
    let workspace = TempDir::new("rotation");
    let source = create_source(workspace.path());
    let state_root = workspace.path().join("trust-state");
    let store = workspace.path().join("store");
    fs::create_dir(&state_root).expect("create trust-state root");
    fs::create_dir(&store).expect("create store root");

    let archive = serialize_snapshot_archive(&source, archive_limits()).expect("serialize archive");
    let old =
        sign_snapshot_ed25519(&source, &[0x71; 32], identity_limits()).expect("sign old key");
    let new =
        sign_snapshot_ed25519(&source, &[0x72; 32], identity_limits()).expect("sign new key");
    assert_eq!(old.snapshot, archive.identity);
    assert_eq!(new.snapshot, archive.identity);

    let old_id = SnapshotTrustKeyId::from_public_key(&old.public_key);
    let new_id = SnapshotTrustKeyId::from_public_key(&new.public_key);
    let generation_one =
        SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(old.public_key)])
            .expect("build generation-one policy");
    let state_key = SnapshotTrustStateKey::new([0xA5; 32]);

    let initialized = initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("initialize persisted trust state");
    assert_eq!(initialized.policy, generation_one.identity());
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("load initialized trust state"),
        generation_one.identity()
    );
    assert_eq!(
        initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
            .expect("exact initialization retry converges")
            .policy,
        generation_one.identity()
    );

    let first_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_one);
    let first = store_snapshot_archive_persisted_trust_ed25519_durable(
        &first_context,
        &store,
        &archive.bytes,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect("state-backed generation-one publication");
    assert!(first.store.inserted);
    assert_eq!(first.trust.policy, generation_one.identity());

    let generation_two = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("persist rotation");
    assert_eq!(
        generation_two.key_state(old_id),
        Some(SnapshotTrustKeyState::Revoked)
    );
    assert_eq!(
        generation_two.key_state(new_id),
        Some(SnapshotTrustKeyState::Active)
    );
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("load rotated trust state"),
        generation_two.identity()
    );

    let converged = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![new.public_key],
        &[old_id],
    )
    .expect("ambiguous rotation retry converges to persisted successor");
    assert_eq!(converged.identity(), generation_two.identity());

    let stale_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_one);
    let missing_store = workspace.path().join("missing-store");
    match store_snapshot_archive_persisted_trust_ed25519_durable(
        &stale_context,
        &missing_store,
        &archive.bytes,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("stale policy must fail before store access")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale store result: {other}"),
    }
    assert!(
        !missing_store.exists(),
        "stale state-backed publication must not touch missing store root"
    );

    let missing_parent = workspace.path().join("missing-destination-parent");
    let missing_destination = missing_parent.join("restored");
    match materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
        &stale_context,
        &store,
        archive.identity,
        &missing_destination,
        old_id,
        &old.signature,
        archive_limits(),
    )
    .expect_err("stale policy must fail before destination access")
    {
        SnapshotTrustStateError::StalePolicy { .. } => {}
        other => panic!("unexpected stale materialize result: {other}"),
    }
    assert!(
        !missing_parent.exists(),
        "stale state-backed materialization must not inspect destination parent"
    );

    let current_context = SnapshotTrustStateContext::new(&state_root, &state_key, &generation_two);
    let current = store_snapshot_archive_persisted_trust_ed25519_durable(
        &current_context,
        &store,
        &archive.bytes,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("rotated active signer deduplicates state-backed object");
    assert!(!current.store.inserted);
    assert_eq!(current.trust.policy, generation_two.identity());
    assert_eq!(current.trust.signer, new_id);

    let destination = workspace.path().join("restored");
    let restored = materialize_snapshot_store_object_persisted_trust_ed25519_atomic(
        &current_context,
        &store,
        archive.identity,
        &destination,
        new_id,
        &new.signature,
        archive_limits(),
    )
    .expect("materialize under persisted rotated trust state");
    assert_eq!(restored.materialization.identity, archive.identity);
    assert_eq!(restored.trust.policy, generation_two.identity());
    assert_eq!(restored.trust.signer, new_id);
    assert_eq!(
        fs::read(destination.join("payload")).expect("read restored payload"),
        b"persisted-trust-payload\n"
    );
}

#[test]
fn persisted_state_authentication_rejects_wrong_key_and_same_size_tamper() {
    let workspace = TempDir::new("authentication");
    let state_root = workspace.path().join("trust-state");
    fs::create_dir(&state_root).expect("create trust-state root");

    let source = create_source(workspace.path());
    let evidence =
        sign_snapshot_ed25519(&source, &[0x81; 32], identity_limits()).expect("derive trust key");
    let policy = SnapshotTrustPolicy::new(7, vec![SnapshotTrustKey::active(evidence.public_key)])
        .expect("build trust policy");
    let correct_key = SnapshotTrustStateKey::new([0xB4; 32]);
    initialize_snapshot_trust_state(&state_root, &correct_key, &policy)
        .expect("initialize authenticated state");

    let wrong_key = SnapshotTrustStateKey::new([0xB5; 32]);
    assert!(matches!(
        load_snapshot_trust_state_identity(&state_root, &wrong_key),
        Err(SnapshotTrustStateError::AuthenticationFailed)
    ));

    let state_path = snapshot_trust_state_path(&state_root);
    let mut bytes = fs::read(&state_path).expect("read persisted state bytes");
    assert!(bytes.len() > 20, "trust-state fixture must contain authenticated header");
    bytes[20] ^= 0x40;
    fs::write(&state_path, &bytes).expect("tamper persisted state without changing length");
    assert!(matches!(
        load_snapshot_trust_state_identity(&state_root, &correct_key),
        Err(SnapshotTrustStateError::AuthenticationFailed)
    ));
}

#[test]
fn stale_rotation_cannot_overwrite_newer_persisted_generation() {
    let workspace = TempDir::new("stale-rotation");
    let state_root = workspace.path().join("trust-state");
    fs::create_dir(&state_root).expect("create trust-state root");

    let source = create_source(workspace.path());
    let a = sign_snapshot_ed25519(&source, &[0x91; 32], identity_limits()).expect("derive key A");
    let b = sign_snapshot_ed25519(&source, &[0x92; 32], identity_limits()).expect("derive key B");
    let c = sign_snapshot_ed25519(&source, &[0x93; 32], identity_limits()).expect("derive key C");
    let a_id = SnapshotTrustKeyId::from_public_key(&a.public_key);
    let generation_one = SnapshotTrustPolicy::new(1, vec![SnapshotTrustKey::active(a.public_key)])
        .expect("build generation one");
    let state_key = SnapshotTrustStateKey::new([0xC6; 32]);
    initialize_snapshot_trust_state(&state_root, &state_key, &generation_one)
        .expect("initialize trust state");

    let generation_two = rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        2,
        vec![b.public_key],
        &[a_id],
    )
    .expect("advance persisted generation");

    match rotate_snapshot_trust_state(
        &state_root,
        &state_key,
        &generation_one,
        3,
        vec![c.public_key],
        &[],
    )
    .expect_err("stale writer must not replace newer persisted generation")
    {
        SnapshotTrustStateError::StalePolicy {
            persisted,
            supplied,
        } => {
            assert_eq!(persisted, generation_two.identity());
            assert_eq!(supplied, generation_one.identity());
        }
        other => panic!("unexpected stale rotation result: {other}"),
    }
    assert_eq!(
        load_snapshot_trust_state_identity(&state_root, &state_key)
            .expect("newer generation remains persisted"),
        generation_two.identity()
    );
}
''')
