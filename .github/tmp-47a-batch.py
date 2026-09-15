from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Reuse one non-mutating archive/signature validation path for normal store and batch preflight.
replace_one(
    "src/snapshot_store.rs",
    """pub fn store_snapshot_archive_ed25519_atomic(
    store_root: &Path,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotStorePutReport, SnapshotStoreError> {
    validate_store_root(store_root)?;
    let identity = snapshot_archive_identity(archive, limits)?;
    verify_snapshot_identity_ed25519(identity, public_key, expected_signature)?;

""",
    """pub(crate) fn validate_snapshot_archive_ed25519(
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotIdentity, SnapshotStoreError> {
    let identity = snapshot_archive_identity(archive, limits)?;
    verify_snapshot_identity_ed25519(identity, public_key, expected_signature)?;
    Ok(identity)
}

pub fn store_snapshot_archive_ed25519_atomic(
    store_root: &Path,
    archive: &[u8],
    public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    limits: SnapshotArchiveLimits,
) -> Result<SnapshotStorePutReport, SnapshotStoreError> {
    validate_store_root(store_root)?;
    let identity = validate_snapshot_archive_ed25519(
        archive,
        public_key,
        expected_signature,
        limits,
    )?;

""",
    "snapshot store validation helper",
)

# Head-state batch types, bounded preflight, and publication path.
replace_one(
    "src/snapshot_store_head_state.rs",
    "use crate::snapshot_store::SnapshotStorePutReport;\n",
    "use crate::snapshot_store::{\n    validate_snapshot_archive_ed25519, SnapshotStoreError, SnapshotStorePutReport,\n};\n",
    "head-state store imports",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    "pub const SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES: usize = 32;\n",
    "pub const SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES: usize = 32;\npub const SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS: usize = 16;\n",
    "batch maximum constant",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    """pub struct SnapshotStoreHeadPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

#[derive(Debug)]
""",
    """pub struct SnapshotStoreHeadPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

pub struct SnapshotStoreHeadBatchItem<'a> {
    pub archive: &'a [u8],
    pub public_key: &'a [u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],
    pub expected_signature: &'a [u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],
    pub archive_limits: SnapshotArchiveLimits,
}

pub struct SnapshotStoreHeadBatchPublishRequest<'a> {
    pub inventory_limits: SnapshotStoreAuditLimits,
    pub items: &'a [SnapshotStoreHeadBatchItem<'a>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotStoreHeadBatchPutReport {
    pub puts: Vec<SnapshotStorePutReport>,
    pub previous: SnapshotStoreHeadStateIdentity,
    pub successor: SnapshotStoreHeadStateIdentity,
}

#[derive(Debug)]
""",
    "batch public types",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    """    StoreDiverged {
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
    Io {
""",
    """    StoreDiverged {
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
    },
    BatchItemInvalid {
        index: usize,
        source: Box<SnapshotStoreError>,
    },
    Io {
""",
    "batch item error variant",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    """            Self::StoreDiverged { anchored, actual } => write!(
                f,
                "snapshot store diverged from authenticated head generation {}: anchored {} objects={} bytes={} actual {} objects={} bytes={}",
                anchored.generation,
                anchored.inventory.sha256_hex(),
                anchored.inventory.objects,
                anchored.inventory.archive_bytes,
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
            Self::Io { phase, source } => {
""",
    """            Self::StoreDiverged { anchored, actual } => write!(
                f,
                "snapshot store diverged from authenticated head generation {}: anchored {} objects={} bytes={} actual {} objects={} bytes={}",
                anchored.generation,
                anchored.inventory.sha256_hex(),
                anchored.inventory.objects,
                anchored.inventory.archive_bytes,
                actual.sha256_hex(),
                actual.objects,
                actual.archive_bytes,
            ),
            Self::BatchItemInvalid { index, source } => write!(
                f,
                "snapshot store head-state batch item {index} failed prevalidation: {source}"
            ),
            Self::Io { phase, source } => {
""",
    "batch item display",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    """        match self {
            Self::Io { source, .. } => Some(source),
            Self::Transaction(source) => Some(source.as_ref()),
            _ => None,
        }
""",
    """        match self {
            Self::BatchItemInvalid { source, .. } => Some(source.as_ref()),
            Self::Io { source, .. } => Some(source),
            Self::Transaction(source) => Some(source.as_ref()),
            _ => None,
        }
""",
    "batch item error source",
)

replace_one(
    "src/snapshot_store_head_state.rs",
    """fn validate_roots(state_root: &Path, store_root: &Path) -> Result<(), SnapshotStoreHeadStateError> {
""",
    """/// Bounded multi-object publication under one authenticated store-head generation.
///
/// Every archive/signature pair is completely validated before either state or
/// store filesystem mutation is attempted. The head-state lock and exclusive
/// store transaction remain held across the whole publication loop, so
/// cooperating readers observe the inventory before or after a successful
/// batch, not an intermediate member. A successful batch advances the head at
/// most once; an all-deduplicated batch leaves it unchanged.
///
/// This is not a crash-atomic all-or-nothing filesystem transaction. If a later
/// object/durability operation fails after an earlier member was published, the
/// call returns an error and the unchanged authenticated head makes that
/// partial store advancement detectable as divergence.
pub fn store_snapshot_archives_ed25519_durable_with_head_state(
    state_root: &Path,
    state_key: &SnapshotStoreHeadStateKey,
    store_root: &Path,
    request: SnapshotStoreHeadBatchPublishRequest<'_>,
) -> Result<SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadStateError> {
    validate_roots(state_root, store_root)?;
    validate_batch_request(&request)?;
    #[cfg(target_os = "linux")]
    {
        linux::store_batch(state_root, state_key, store_root, request)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (state_root, state_key, store_root, request);
        Err(SnapshotStoreHeadStateError::UnsupportedPlatform(
            "authenticated durable store-head batch publication currently requires Linux flock, fsync, and cooperative snapshot-store transactions"
                .to_owned(),
        ))
    }
}

fn validate_batch_request(
    request: &SnapshotStoreHeadBatchPublishRequest<'_>,
) -> Result<(), SnapshotStoreHeadStateError> {
    if request.items.is_empty() {
        return Err(SnapshotStoreHeadStateError::InvalidInput(
            "batch publication requires at least one item".to_owned(),
        ));
    }
    if request.items.len() > SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS {
        return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
            "batch publication accepts at most {SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS} items"
        )));
    }

    let mut identities = Vec::with_capacity(request.items.len());
    for (index, item) in request.items.iter().enumerate() {
        let identity = validate_snapshot_archive_ed25519(
            item.archive,
            item.public_key,
            item.expected_signature,
            item.archive_limits,
        )
        .map_err(|source| SnapshotStoreHeadStateError::BatchItemInvalid {
            index,
            source: Box::new(source),
        })?;
        if let Some(first_index) = identities.iter().position(|existing| *existing == identity) {
            return Err(SnapshotStoreHeadStateError::InvalidInput(format!(
                "batch item {index} duplicates canonical identity from item {first_index}"
            )));
        }
        identities.push(identity);
    }
    Ok(())
}

fn validate_roots(state_root: &Path, store_root: &Path) -> Result<(), SnapshotStoreHeadStateError> {
""",
    "batch public API and prevalidation",
)

replace_one(
    "src/snapshot_store_head_state.rs",
    """        decode_state, encode_state, SnapshotStoreAuditLimits, SnapshotStoreHeadPublishRequest,
        SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity,
        SnapshotStoreHeadStateKey, SnapshotStoreInventoryIdentity, SnapshotStoreReadTransaction,
        SnapshotStoreWriteTransaction, HEAD_STATE_BYTES, HEAD_STATE_FILE, HEAD_STATE_LOCK,
""",
    """        decode_state, encode_state, SnapshotStoreAuditLimits,
        SnapshotStoreHeadBatchPublishRequest, SnapshotStoreHeadBatchPutReport,
        SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport, SnapshotStoreHeadStateError,
        SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey, SnapshotStoreInventoryIdentity,
        SnapshotStoreReadTransaction, SnapshotStoreWriteTransaction, HEAD_STATE_BYTES,
        HEAD_STATE_FILE, HEAD_STATE_LOCK,
""",
    "linux batch imports",
)
replace_one(
    "src/snapshot_store_head_state.rs",
    """    fn require_inventory(
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
""",
    """    pub(super) fn store_batch(
        state_root: &Path,
        state_key: &SnapshotStoreHeadStateKey,
        store_root: &Path,
        request: SnapshotStoreHeadBatchPublishRequest<'_>,
    ) -> Result<SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadStateError> {
        let guard = lock_state(state_root, libc::LOCK_EX)?;
        let previous = read_state_optional(guard.root.raw(), state_key)?
            .ok_or(SnapshotStoreHeadStateError::NotInitialized)?;
        if previous.generation == u64::MAX {
            return Err(SnapshotStoreHeadStateError::InvalidState(
                "store-head generation is exhausted".to_owned(),
            ));
        }

        let writer = SnapshotStoreWriteTransaction::begin(store_root)?;
        let actual = writer.inventory_identity(request.inventory_limits)?;
        require_inventory(previous, actual)?;

        let mut puts = Vec::with_capacity(request.items.len());
        let mut inserted_any = false;
        for item in request.items {
            let put = writer.store_ed25519_durable(
                item.archive,
                item.public_key,
                item.expected_signature,
                item.archive_limits,
            )?;
            inserted_any |= put.inserted;
            puts.push(put);
        }

        let successor = if inserted_any {
            let inventory = writer.inventory_identity(request.inventory_limits)?;
            let successor = SnapshotStoreHeadStateIdentity {
                generation: previous.generation + 1,
                inventory,
            };
            write_state(guard.root.raw(), state_key, successor, true)?;
            successor
        } else {
            previous
        };

        Ok(SnapshotStoreHeadBatchPutReport {
            puts,
            previous,
            successor,
        })
    }

    fn require_inventory(
        anchored: SnapshotStoreHeadStateIdentity,
        actual: SnapshotStoreInventoryIdentity,
""",
    "linux batch implementation",
)

# Public exports.
replace_one(
    "src/lib.rs",
    """    snapshot_store_head_state_path, store_snapshot_archive_ed25519_durable_with_head_state,
    verify_snapshot_store_head_state, SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport,
    SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey,
    SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES,
""",
    """    snapshot_store_head_state_path, store_snapshot_archive_ed25519_durable_with_head_state,
    store_snapshot_archives_ed25519_durable_with_head_state, verify_snapshot_store_head_state,
    SnapshotStoreHeadBatchItem, SnapshotStoreHeadBatchPublishRequest,
    SnapshotStoreHeadBatchPutReport, SnapshotStoreHeadPublishRequest, SnapshotStoreHeadPutReport,
    SnapshotStoreHeadStateError, SnapshotStoreHeadStateIdentity, SnapshotStoreHeadStateKey,
    SNAPSHOT_STORE_HEAD_MAX_BATCH_ITEMS, SNAPSHOT_STORE_HEAD_STATE_KEY_BYTES,
""",
    "lib batch exports",
)

# Integration tests.
replace_one(
    "tests/snapshot_store_head_state.rs",
    """    snapshot_store_object_path, store_snapshot_archive_ed25519_durable_with_head_state,
    verify_snapshot_store_head_state, SnapshotArchiveLimits, SnapshotIdentity,
    SnapshotIdentityLimits, SnapshotStoreAuditLimits, SnapshotStoreHeadPublishRequest,
    SnapshotStoreHeadStateError, SnapshotStoreHeadStateKey,
""",
    """    snapshot_store_object_path, store_snapshot_archive_ed25519_durable_with_head_state,
    store_snapshot_archives_ed25519_durable_with_head_state, verify_snapshot_store_head_state,
    SnapshotArchiveLimits, SnapshotIdentity, SnapshotIdentityLimits, SnapshotStoreAuditLimits,
    SnapshotStoreHeadBatchItem, SnapshotStoreHeadBatchPublishRequest, SnapshotStoreHeadPublishRequest,
    SnapshotStoreHeadStateError, SnapshotStoreHeadStateKey,
""",
    "test batch imports",
)
replace_one(
    "tests/snapshot_store_head_state.rs",
    """fn publish_request(fixture: &Fixture) -> SnapshotStoreHeadPublishRequest<'_> {
    SnapshotStoreHeadPublishRequest {
        inventory_limits: audit_limits(),
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}

""",
    """fn publish_request(fixture: &Fixture) -> SnapshotStoreHeadPublishRequest<'_> {
    SnapshotStoreHeadPublishRequest {
        inventory_limits: audit_limits(),
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}

fn batch_item(fixture: &Fixture) -> SnapshotStoreHeadBatchItem<'_> {
    SnapshotStoreHeadBatchItem {
        archive: &fixture.archive,
        public_key: &fixture.public_key,
        expected_signature: &fixture.signature,
        archive_limits: archive_limits(),
    }
}

""",
    "test batch helper",
)

p = Path("tests/snapshot_store_head_state.rs")
text = p.read_text()
text += r'''

#[test]
fn batch_publication_advances_one_generation_for_two_objects_and_dedups_as_a_unit() {
    let workspace = TempDir::new("batch-success");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x7A; 32]);
    let first = fixture(workspace.path(), "batch-first", b"batch-first\n", 0x31);
    let second = fixture(workspace.path(), "batch-second", b"batch-second\n", 0x32);

    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize batch head");
    assert_eq!(initial.generation, 1);
    assert_eq!(initial.inventory.objects, 0);

    let items = [batch_item(&first), batch_item(&second)];
    let committed = store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &items,
        },
    )
    .expect("publish two-object batch");
    assert_eq!(committed.previous, initial);
    assert_eq!(committed.puts.len(), 2);
    assert!(committed.puts.iter().all(|put| put.inserted));
    assert_eq!(committed.successor.generation, 2);
    assert_eq!(committed.successor.inventory.objects, 2);
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify batch successor"),
        committed.successor
    );

    let dedup_items = [batch_item(&first), batch_item(&second)];
    let dedup = store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &dedup_items,
        },
    )
    .expect("deduplicate full batch");
    assert_eq!(dedup.previous, committed.successor);
    assert_eq!(dedup.successor, committed.successor);
    assert_eq!(dedup.puts.len(), 2);
    assert!(dedup.puts.iter().all(|put| !put.inserted));
}

#[test]
fn batch_prevalidates_every_item_before_first_object_publication() {
    let workspace = TempDir::new("batch-preflight");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x8B; 32]);
    let first = fixture(workspace.path(), "preflight-first", b"preflight-first\n", 0x41);
    let second = fixture(workspace.path(), "preflight-second", b"preflight-second\n", 0x42);
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize preflight head");

    let mut bad_signature = second.signature;
    bad_signature[0] ^= 0x80;
    let items = [
        batch_item(&first),
        SnapshotStoreHeadBatchItem {
            archive: &second.archive,
            public_key: &second.public_key,
            expected_signature: &bad_signature,
            archive_limits: archive_limits(),
        },
    ];
    match store_snapshot_archives_ed25519_durable_with_head_state(
        &state,
        &key,
        &store,
        SnapshotStoreHeadBatchPublishRequest {
            inventory_limits: audit_limits(),
            items: &items,
        },
    ) {
        Err(SnapshotStoreHeadStateError::BatchItemInvalid { index: 1, .. }) => {}
        Err(other) => panic!("unexpected batch prevalidation result: {other}"),
        Ok(_) => panic!("invalid second batch member unexpectedly published"),
    }

    assert!(
        !snapshot_store_object_path(&store, first.identity).exists(),
        "first object was published before later batch prevalidation failed"
    );
    assert!(
        !snapshot_store_object_path(&store, second.identity).exists(),
        "invalid second object was published"
    );
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify unchanged head after batch prevalidation failure"),
        initial
    );
}

#[test]
fn batch_rejects_duplicate_identity_before_store_mutation() {
    let workspace = TempDir::new("batch-duplicate");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0x9C; 32]);
    let first = fixture(workspace.path(), "duplicate", b"duplicate-batch\n", 0x52);
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize duplicate head");
    let items = [batch_item(&first), batch_item(&first)];

    assert!(matches!(
        store_snapshot_archives_ed25519_durable_with_head_state(
            &state,
            &key,
            &store,
            SnapshotStoreHeadBatchPublishRequest {
                inventory_limits: audit_limits(),
                items: &items,
            },
        ),
        Err(SnapshotStoreHeadStateError::InvalidInput(_))
    ));
    assert!(!snapshot_store_object_path(&store, first.identity).exists());
    assert_eq!(
        verify_snapshot_store_head_state(&state, &key, &store, audit_limits())
            .expect("verify unchanged head after duplicate batch"),
        initial
    );
}
'''
p.write_text(text)
