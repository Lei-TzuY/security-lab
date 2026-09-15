from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


source = "src/snapshot_store_head_state.rs"

replace_one(
    source,
    """#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadPutReport {
    pub put: SnapshotStorePutReport,
    pub previous: SnapshotStoreHeadStateIdentity,
    pub successor: SnapshotStoreHeadStateIdentity,
}

#[derive(Debug)]
""",
    """#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotStoreHeadPutReport {
    pub put: SnapshotStorePutReport,
    pub previous: SnapshotStoreHeadStateIdentity,
    pub successor: SnapshotStoreHeadStateIdentity,
}

/// Inputs for one authenticated durable publication guarded by the persisted
/// whole-store head.
pub struct SnapshotStoreHeadPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

#[derive(Debug)]
""",
    "publish request struct",
)

replace_one(
    source,
    "    Transaction(SnapshotStoreTransactionError),\n",
    "    Transaction(Box<SnapshotStoreTransactionError>),\n",
    "boxed transaction error variant",
)
replace_one(
    source,
    "            Self::Transaction(source) => Some(source),\n",
    "            Self::Transaction(source) => Some(source.as_ref()),\n",
    "boxed transaction source",
)
replace_one(
    source,
    "        Self::Transaction(value)\n",
    "        Self::Transaction(Box::new(value))\n",
    "boxed transaction conversion",
)

old_public = """pub fn store_snapshot_archive_ed25519_durable_with_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    inventory_limits: SnapshotStoreAuditLimits,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    archive_limits: SnapshotArchiveLimits,
) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = \"linux\")]
    {
        linux::store(
            state_root,
            state_key,
            store_root,
            inventory_limits,
            archive,
            public_key,
            expected_signature,
            archive_limits,
        )
    }
    #[cfg(not(target_os = \"linux\"))]
    {
        let _ = (
            state_root,
            state_key,
            store_root,
            inventory_limits,
            archive,
            public_key,
            expected_signature,
            archive_limits,
        );
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            \"authenticated durable store-head publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions\"
                .to_owned(),
        ))
    }
}
"""
new_public = """pub fn store_snapshot_archive_ed25519_durable_with_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    request: SnapshotStoreHeadPublishRequest<'_>,
) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    #[cfg(target_os = \"linux\")]
    {
        linux::store(state_root, state_key, store_root, request)
    }
    #[cfg(not(target_os = \"linux\"))]
    {
        let _ = (state_root, state_key, store_root, request);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            \"authenticated durable store-head publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions\"
                .to_owned(),
        ))
    }
}
"""
replace_one(source, old_public, new_public, "public publication API")

replace_one(
    source,
    """        SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity,
        SnapshotStoreHeadStateKey, SnapshotStoreInventoryIdentity, SnapshotStoreReadTransaction,
        SnapshotStoreWriteTransaction, HEAD_STATE_BYTES, HEAD_STATE_FILE, HEAD_STATE_LOCK,
        SNAPSHOT_ED25519_PUBLIC_KEY_BYTES, SNAPSHOT_ED25519_SIGNATURE_BYTES,
""",
    """        SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError,
        SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey, SnapshotStoreInventoryIdentity,
        SnapshotStoreReadTransaction, SnapshotStoreWriteTransaction, HEAD_STATE_BYTES,
        HEAD_STATE_FILE, HEAD_STATE_LOCK,
""",
    "linux imports",
)
replace_one(
    source,
    "decode_state, encode_state, SnapshotArchiveLimits, SnapshotStoreAuditLimits,",
    "decode_state, encode_state, SnapshotStoreAuditLimits,",
    "remove stale linux archive-limit import",
)

old_internal = """    #[allow(clippy::too_many_arguments)]
    pub(super) fn store(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        inventory_limits: SnapshotStoreAuditLimits,
        archive: &[u8],
        public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
        archive_limits: SnapshotArchiveLimits,
    ) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
"""
new_internal = """    pub(super) fn store(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        request: SnapshotStoreHeadPublishRequest<'_>,
    ) -> Result<SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError> {
"""
replace_one(source, old_internal, new_internal, "internal publication API")

p = Path(source)
text = p.read_text()
for old, new, expected, label in [
    ("writer.inventory_identity(inventory_limits)?", "writer.inventory_identity(request.inventory_limits)?", 2, "inventory request uses"),
    ("""        let put = writer.store_ed25519_durable(
            archive,
            public_key,
            expected_signature,
            archive_limits,
        )?;
""", """        let put = writer.store_ed25519_durable(
            request.archive,
            request.public_key,
            request.expected_signature,
            request.archive_limits,
        )?;
""", 1, "publication request fields"),
]:
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{label}: expected {expected} matches, got {count}")
    text = text.replace(old, new)
p.write_text(text)

replace_one(
    "src/lib.rs",
    """    verify_snapshot_store_head_state, SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError,
    SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey,
    SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES,
""",
    """    verify_snapshot_store_head_state, SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport,
    SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey,
    SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES,
""",
    "lib export",
)

tests = "tests/snapshot_store_head_state.rs"
replace_one(
    tests,
    """    verify_snapshot_store_head_state, SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits,
    SnapshotStoreAuditLimits, SnapshotStoreHeadStateError, SnapshotStoreHeadStateKey,
""",
    """    verify_snapshot_store_head_state, SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits,
    SnapshotStoreAuditLimits, SnapshotStoreHeadPublishRequest, SnapshotStoreHeadStateError,
    SnapshotStoreHeadStateKey,
""",
    "test import",
)
replace_one(
    tests,
    """fn roots(workspace: &Path) -> (PathBuf, PathBuf) {
    let store = workspace.join(\"store\");
    let state = workspace.join(\"head-state\");
    fs::create_dir(&store).expect(\"create snapshot store\");
    fs::create_dir(&state).expect(\"create head-state root\");
    (store, state)
}
""",
    """fn roots(workspace: &Path) -> (PathBuf, PathBuf) {
    let store = workspace.join(\"store\");
    let state = workspace.join(\"head-state\");
    fs::create_dir(&store).expect(\"create snapshot store\");
    fs::create_dir(&state).expect(\"create head-state root\");
    (store, state)
}

fn publish_request(fixture: &Fixture) -> SnapshotStoreHeadPublishRequest<'_> {
    SnapshotStoreHeadPublishRequest {
        inventory_limits: audit_limits(),
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}
""",
    "test request helper",
)

p = Path(tests)
text = p.read_text()
for fixture, expected in [("first", 3), ("second", 1)]:
    old = f"""        audit_limits(),
        &{fixture}.archive,
        &{fixture}.public_key,
        &{fixture}.signature,
        archive_limits(),
"""
    new = f"        publish_request(&{fixture}),\n"
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"test calls for {fixture}: expected {expected}, got {count}")
    text = text.replace(old, new)
p.write_text(text)
