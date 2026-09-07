from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/authority_delta.rs",
    "use security_lab::{SandboxPolicy, StdioMode};",
    "use security_lab::{PersistentVolumeAccess, PersistentVolumePolicy, SandboxPolicy, StdioMode};",
    "authority delta imports",
)

replace_one(
    "src/authority_delta.rs",
    '''    push_change(
        "filesystem.persistent_volumes",
        subset_relation(
            map_is_subset(&baseline.persistent_volumes, &candidate.persistent_volumes),
            map_is_subset(&candidate.persistent_volumes, &baseline.persistent_volumes),
            true,
        ),
        &mut changes,
    );
''',
    '''    compare_persistent_volumes(
        &baseline.persistent_volumes,
        &candidate.persistent_volumes,
        &mut changes,
    );
''',
    "persistent volume comparison call",
)

replace_one(
    "src/authority_delta.rs",
    '''fn compare_selected_handles(
''',
    '''fn compare_persistent_volumes(
    baseline: &BTreeMap<String, PersistentVolumePolicy>,
    candidate: &BTreeMap<String, PersistentVolumePolicy>,
    changes: &mut Vec<Change>,
) {
    let mut class = DeltaClass::Unchanged;

    for (name, baseline_volume) in baseline {
        let relation = match candidate.get(name) {
            None => DeltaClass::Reduced,
            Some(candidate_volume) => compare_persistent_volume(baseline_volume, candidate_volume),
        };
        class = combine_classes(class, relation);
    }

    for name in candidate.keys() {
        if !baseline.contains_key(name) {
            class = combine_classes(class, DeltaClass::Widened);
        }
    }

    push_change("filesystem.persistent_volumes", class, changes);
}

fn compare_persistent_volume(
    baseline: &PersistentVolumePolicy,
    candidate: &PersistentVolumePolicy,
) -> DeltaClass {
    if baseline.source != candidate.source || baseline.target != candidate.target {
        return DeltaClass::Incomparable;
    }

    match (baseline.access, candidate.access) {
        (PersistentVolumeAccess::Writable, PersistentVolumeAccess::ReadOnly) => DeltaClass::Reduced,
        (PersistentVolumeAccess::ReadOnly, PersistentVolumeAccess::Writable) => DeltaClass::Widened,
        _ => DeltaClass::Unchanged,
    }
}

fn compare_selected_handles(
''',
    "persistent volume comparator",
)

new_tests = r'''
#[test]
fn removed_named_persistent_volume_is_detected_as_authority_reduction() {
    let root = unique_absent_root("named-volume-removed");
    let candidate_text = base_policy(&root);
    let baseline_text = format!(
        "{candidate_text}volume.mount.assets.source = /srv/assets\nvolume.mount.assets.target = /assets\nvolume.mount.assets.access = read-only\n"
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"reduced\""));
    assert!(stdout.contains("\"field\":\"filesystem.persistent_volumes\",\"class\":\"reduced\""));
    assert!(stdout.contains("\"static_non_widening\":true"));
}

#[test]
fn named_persistent_volume_writable_to_readonly_is_reduction() {
    let root = unique_absent_root("named-volume-narrow");
    let base = base_policy(&root);
    let baseline_text = format!(
        "{base}volume.mount.state.source = /srv/state\nvolume.mount.state.target = /state\nvolume.mount.state.access = writable\n"
    );
    let candidate_text = baseline_text.replace(
        "volume.mount.state.access = writable",
        "volume.mount.state.access = read-only",
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"reduced\""));
    assert!(stdout.contains("\"field\":\"filesystem.persistent_volumes\",\"class\":\"reduced\""));
    assert!(stdout.contains("\"widening_detected\":false"));
}

#[test]
fn named_persistent_volume_readonly_to_writable_is_widening() {
    let root = unique_absent_root("named-volume-widen");
    let base = base_policy(&root);
    let baseline_text = format!(
        "{base}volume.mount.state.source = /srv/state\nvolume.mount.state.target = /state\nvolume.mount.state.access = read-only\n"
    );
    let candidate_text = baseline_text.replace(
        "volume.mount.state.access = read-only",
        "volume.mount.state.access = writable",
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(5));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"widened\""));
    assert!(stdout.contains("\"field\":\"filesystem.persistent_volumes\",\"class\":\"widened\""));
    assert!(stdout.contains("\"widening_detected\":true"));
}

#[test]
fn named_persistent_volume_path_change_is_incomparable() {
    let root = unique_absent_root("named-volume-path-change");
    let base = base_policy(&root);
    let baseline_text = format!(
        "{base}volume.mount.assets.source = /srv/assets-a\nvolume.mount.assets.target = /assets\nvolume.mount.assets.access = read-only\n"
    );
    let candidate_text = baseline_text.replace(
        "volume.mount.assets.source = /srv/assets-a",
        "volume.mount.assets.source = /srv/assets-b",
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(6));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"incomparable\""));
    assert!(stdout.contains("\"field\":\"filesystem.persistent_volumes\",\"class\":\"incomparable\""));
}

'''
replace_one(
    "tests/authority_delta_cli.rs",
    '''#[test]
fn invalid_candidate_fails_closed_before_comparison() {
''',
    new_tests + '''#[test]
fn invalid_candidate_fails_closed_before_comparison() {
''',
    "authority delta regression insertion",
)
