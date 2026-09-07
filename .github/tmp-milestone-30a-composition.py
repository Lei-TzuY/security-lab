from pathlib import Path

p = Path("tests/sandbox.rs")
text = p.read_text()
anchor = '''#[test]
fn readonly_persistent_volume_is_visible_only_at_declared_readonly_mount() {
'''
if text.count(anchor) != 1:
    raise SystemExit(
        f"readonly volume composition anchor: expected exactly one match, got {text.count(anchor)}"
    )
addition = '''#[test]
fn copy_on_write_root_preserves_readonly_persistent_volume_semantics() {
    let source = readonly_volume_source().to_path_buf();
    let forbidden_write = source.join("write-must-fail");
    let _ = std::fs::remove_file(&forbidden_write);
    let marker_before = std::fs::read(source.join("marker")).expect("read host volume marker");
    let source_argument = source.to_string_lossy().into_owned();

    let mut mounted = policy(
        "v",
        &[source_argument.as_str()],
        &["execveat", "openat", "read", "close", "exit"],
    );
    mounted.cow_root_bytes = Some(COW_ROOT_BYTES);
    mounted.readonly_volume_source = Some(source.clone());
    mounted.readonly_volume_target = Some(PathBuf::from("/data"));

    let report = run_report(&mounted).expect("COW root plus read-only volume run failed");
    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    assert!(report.enforcement.copy_on_write_root);
    assert!(!report.enforcement.readonly_root);
    assert_eq!(
        std::fs::read(source.join("marker")).expect("read host volume marker after COW run"),
        marker_before,
        "COW root changed a declared read-only persistent-volume marker"
    );
    assert!(
        !forbidden_write.exists(),
        "COW root widened a declared read-only persistent volume"
    );
}

'''
p.write_text(text.replace(anchor, addition + anchor, 1))
