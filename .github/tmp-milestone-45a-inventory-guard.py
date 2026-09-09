from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    file = Path(path)
    text = file.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    file.write_text(text.replace(old, new, 1))


replace_one(
    "src/snapshot_store_transaction.rs",
    """    LockContended {\n        requested: SnapshotStoreTransactionMode,\n    },\n    UnsupportedPlatform(String),\n""",
    """    LockContended {\n        requested: SnapshotStoreTransactionMode,\n    },\n    InventoryConflict {\n        expected: SnapshotStoreInventoryIdentity,\n        actual: SnapshotStoreInventoryIdentity,\n    },\n    UnsupportedPlatform(String),\n""",
    "transaction inventory conflict variant",
)

replace_one(
    "src/snapshot_store_transaction.rs",
    """            Self::LockContended { requested } => write!(\n                f,\n                \"snapshot store {requested} transaction lock is contended\"\n            ),\n            Self::UnsupportedPlatform(message) => {\n""",
    """            Self::LockContended { requested } => write!(\n                f,\n                \"snapshot store {requested} transaction lock is contended\"\n            ),\n            Self::InventoryConflict { expected, actual } => write!(\n                f,\n                \"snapshot store inventory changed before guarded write: expected {} objects={} bytes={} actual {} objects={} bytes={}\",\n                expected.sha256_hex(),\n                expected.objects,\n                expected.archive_bytes,\n                actual.sha256_hex(),\n                actual.objects,\n                actual.archive_bytes,\n            ),\n            Self::UnsupportedPlatform(message) => {\n""",
    "transaction inventory conflict display",
)

replace_one(
    "src/snapshot_store_transaction.rs",
    """    /// Authenticated durable publication while the exclusive store transaction\n    /// lock is held.\n    pub fn store_ed25519_durable(\n""",
    """    /// Recompute the complete audited inventory while the exclusive store\n    /// transaction lock is held. This is useful for obtaining a successor token\n    /// before releasing the write transaction.\n    pub fn inventory_identity(\n        &self,\n        limits: SnapshotStoreAuditLimits,\n    ) -> Result<SnapshotStoreInventoryIdentity, SnapshotStoreTransactionError> {\n        Ok(snapshot_store_inventory_identity(&self.store_root, limits)?)\n    }\n\n    /// Authenticated durable publication while the exclusive store transaction\n    /// lock is held.\n    pub fn store_ed25519_durable(\n""",
    "write transaction inventory observation",
)

replace_one(
    "src/snapshot_store_transaction.rs",
    """        Ok(store_snapshot_archive_ed25519_durable(\n            &self.store_root,\n            archive,\n            public_key,\n            expected_signature,\n            limits,\n        )?)\n    }\n\n    fn acquire(\n        store_root: &Path,\n""",
    """        Ok(store_snapshot_archive_ed25519_durable(\n            &self.store_root,\n            archive,\n            public_key,\n            expected_signature,\n            limits,\n        )?)\n    }\n\n    /// Optimistic guarded durable publication. The complete audited store\n    /// inventory is compared with a caller-retained expected identity while the\n    /// exclusive transaction lock is held. A mismatch is a typed conflict and\n    /// returns before the supplied archive reaches the publication path.\n    ///\n    /// Participating writers can therefore use a previously observed inventory\n    /// identity as a compare-and-swap style precondition without weakening the\n    /// existing authenticated, no-replace, fsync-backed object publication.\n    pub fn store_ed25519_durable_if_inventory(\n        &self,\n        expected_inventory: SnapshotStoreInventoryIdentity,\n        inventory_limits: SnapshotStoreAuditLimits,\n        archive: &[u8],\n        public_key: &[u8; SNAPSHOT_ED25519_PUBLIC_KEY_BYTES],\n        expected_signature: &[u8; SNAPSHOT_ED25519_SIGNATURE_BYTES],\n        limits: SnapshotArchiveLimits,\n    ) -> Result<SnapshotStorePutReport, SnapshotStoreTransactionError> {\n        let actual_inventory =\n            snapshot_store_inventory_identity(&self.store_root, inventory_limits)?;\n        if actual_inventory != expected_inventory {\n            return Err(SnapshotStoreTransactionError::InventoryConflict {\n                expected: expected_inventory,\n                actual: actual_inventory,\n            });\n        }\n        self.store_ed25519_durable(archive, public_key, expected_signature, limits)\n    }\n\n    fn acquire(\n        store_root: &Path,\n""",
    "guarded durable publication",
)

replace_one(
    "tests/snapshot_store_transaction.rs",
    """use security_lab::{\n    serialize_snapshot_archive, sign_snapshot_ed25519, SnapshotArchiveLimits, SnapshotIdentity,\n""",
    """use security_lab::{\n    serialize_snapshot_archive, sign_snapshot_ed25519, snapshot_store_object_path,\n    SnapshotArchiveLimits, SnapshotIdentity,\n""",
    "transaction test object path import",
)

path = Path("tests/snapshot_store_transaction.rs")
text = path.read_text()
addition = r'''

#[test]
fn inventory_guarded_write_rejects_stale_base_then_publishes_matching_successor() {
    let workspace = TempDir::new("guarded-inventory");
    let store = workspace.path().join("store");
    fs::create_dir(&store).expect("create guarded inventory store");
    let first = fixture(workspace.path(), "guard-first", b"guard-first\n", 0x71);
    let second = fixture(workspace.path(), "guard-second", b"guard-second\n", 0x72);
    let third = fixture(workspace.path(), "guard-third", b"guard-third\n", 0x73);

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin first writer");
        writer
            .store_ed25519_durable(
                &first.archive,
                &first.public_key,
                &first.signature,
                archive_limits(),
            )
            .expect("publish first guarded fixture");
    }

    let one_object = {
        let reader = SnapshotStoreReadTransaction::begin(&store).expect("capture base inventory");
        reader
            .inventory_identity(audit_limits())
            .expect("read one-object base inventory")
    };
    assert_eq!(one_object.objects, 1);

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin intervening writer");
        writer
            .store_ed25519_durable(
                &second.archive,
                &second.public_key,
                &second.signature,
                archive_limits(),
            )
            .expect("publish intervening object");
    }

    let two_objects = {
        let reader = SnapshotStoreReadTransaction::begin(&store).expect("read advanced inventory");
        reader
            .inventory_identity(audit_limits())
            .expect("read two-object inventory")
    };
    assert_eq!(two_objects.objects, 2);
    assert_ne!(two_objects, one_object);

    {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin stale guarded writer");
        match writer.store_ed25519_durable_if_inventory(
            one_object,
            audit_limits(),
            &third.archive,
            &third.public_key,
            &third.signature,
            archive_limits(),
        ) {
            Err(SnapshotStoreTransactionError::InventoryConflict { expected, actual }) => {
                assert_eq!(expected, one_object);
                assert_eq!(actual, two_objects);
            }
            Err(other) => panic!("unexpected stale guarded write result: {other}"),
            Ok(_) => panic!("stale guarded write unexpectedly published"),
        }
        assert!(
            !snapshot_store_object_path(&store, third.identity).exists(),
            "stale guarded write published the candidate object"
        );
        assert_eq!(
            writer
                .inventory_identity(audit_limits())
                .expect("re-read inventory under stale writer lock"),
            two_objects
        );
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
    }

    let three_objects = {
        let writer = SnapshotStoreWriteTransaction::begin(&store).expect("begin matching guarded writer");
        let report = writer
            .store_ed25519_durable_if_inventory(
                two_objects,
                audit_limits(),
                &third.archive,
                &third.public_key,
                &third.signature,
                archive_limits(),
            )
            .expect("publish with matching inventory precondition");
        assert!(report.inserted);
        assert_eq!(report.identity, third.identity);
        assert_contended(
            SnapshotStoreReadTransaction::try_begin(&store),
            SnapshotStoreTransactionMode::Read,
        );
        writer
            .inventory_identity(audit_limits())
            .expect("read successor inventory under same write lock")
    };

    assert_eq!(three_objects.objects, 3);
    assert_ne!(three_objects, two_objects);
    let reader = SnapshotStoreReadTransaction::begin(&store).expect("begin final inventory reader");
    assert_eq!(
        reader
            .inventory_identity(audit_limits())
            .expect("read final guarded inventory"),
        three_objects
    );
}
'''
if "fn inventory_guarded_write_rejects_stale_base_then_publishes_matching_successor" in text:
    raise SystemExit("guarded inventory regression already exists")
path.write_text(text + addition)
