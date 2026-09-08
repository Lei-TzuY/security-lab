from pathlib import Path

path = Path("tests/snapshot_archive.rs")
text = path.read_text()
marker = "fn symlink_parent_archive_is_rejected_before_materialization()"
if marker in text:
    raise SystemExit("symlink-parent regression already exists")
text += r'''

fn push_path_record_prefix(bytes: &mut Vec<u8>, tag: u8, path: &[u8]) {
    bytes.push(tag);
    bytes.extend_from_slice(&(path.len() as u32).to_le_bytes());
    bytes.extend_from_slice(path);
}

#[test]
fn symlink_parent_archive_is_rejected_before_materialization() {
    let temp = TempTree::new();
    let destination = temp.path().join("must-not-publish");

    let mut archive = b"security-lab-snapshot-archive-v1\0".to_vec();
    archive.extend_from_slice(&3u64.to_le_bytes());

    push_path_record_prefix(&mut archive, b'D', b"/");
    archive.extend_from_slice(&0o755u32.to_le_bytes());

    push_path_record_prefix(&mut archive, b'L', b"/pivot");
    archive.extend_from_slice(&2u32.to_le_bytes());
    archive.extend_from_slice(b"..");

    push_path_record_prefix(&mut archive, b'F', b"/pivot/escape");
    archive.extend_from_slice(&0o600u32.to_le_bytes());
    archive.extend_from_slice(&1u64.to_le_bytes());
    archive.push(b'x');

    let identity_error = snapshot_archive_identity(&archive, archive_limits())
        .expect_err("a symlink may not become an archive parent");
    assert!(matches!(identity_error, SnapshotArchiveError::InvalidInput(_)));

    let materialize_error = materialize_snapshot_archive_atomic(
        &archive,
        &destination,
        archive_limits(),
    )
    .expect_err("symlink-parent archive must fail before materialization");
    assert!(matches!(materialize_error, SnapshotArchiveError::InvalidInput(_)));
    assert!(!destination.exists());
    assert!(!has_staging_residue(temp.path()));
}
'''
path.write_text(text)
