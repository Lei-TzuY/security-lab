from pathlib import Path

path = Path("tests/snapshot_store_head_state.rs")
text = path.read_text()
name = "batch_post_store_failure_leaves_detectable_head_divergence"
if name in text:
    raise SystemExit(f"{name} already exists")

text += r'''

#[test]
fn batch_post_store_failure_leaves_detectable_head_divergence() {
    let workspace = TempDir::new("batch-post-store-failure");
    let (store, state) = roots(workspace.path());
    let key = SnapshotStoreHeadStateKey::new([0xAD; 32]);
    let first = fixture(
        workspace.path(),
        "post-store-first",
        b"post-store-first\n",
        0x71,
    );
    let second = fixture(
        workspace.path(),
        "post-store-second",
        b"post-store-second\n",
        0x72,
    );
    let initial = initialize_snapshot_store_head_state(&state, &key, &store, audit_limits())
        .expect("initialize post-store failure head");

    let mut successor_limits = audit_limits();
    successor_limits.max_total_archive_bytes = first.archive.len() as u64;
    let items = [batch_item(&first), batch_item(&second)];
    assert!(
        store_snapshot_archives_ed25519_durable_with_head_state(
            &state,
            &key,
            &store,
            SnapshotStoreHeadBatchPublishRequest {
                inventory_limits: successor_limits,
                items: &items,
            },
        )
        .is_err(),
        "successor inventory budget should fail after durable object publication"
    );

    assert!(
        snapshot_store_object_path(&store, first.identity).exists(),
        "first object should remain durably published after later failure"
    );
    assert!(
        snapshot_store_object_path(&store, second.identity).exists(),
        "second object should remain durably published before successor audit failure"
    );
    assert_eq!(
        load_snapshot_store_head_state(&state, &key).expect("load unchanged head after failure"),
        initial,
        "failed batch must not advance authenticated head"
    );

    match verify_snapshot_store_head_state(&state, &key, &store, audit_limits()) {
        Err(SnapshotStoreHeadStateError::StoreDiverged { anchored, actual }) => {
            assert_eq!(anchored, initial);
            assert_eq!(actual.objects, 2);
        }
        Err(other) => panic!("unexpected post-store divergence result: {other}"),
        Ok(_) => panic!("unanchored durable batch advancement was not detected"),
    }
}
'''
path.write_text(text)
