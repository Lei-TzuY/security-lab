from pathlib import Path

path = Path('.github/tmp-28a-multi-volume.py')
text = path.read_text()
marker = '# Add authority-delta evidence: exact added named mount is a widening.\n'
if text.count(marker) != 1:
    raise SystemExit('expected exactly one authority-delta generator section')
prefix = text.split(marker, 1)[0]
replacement = r'''# Add authority-delta evidence: exact added named mount is a widening.
marker = "#[test]\nfn invalid_candidate_fails_closed_before_comparison() {\n"
delta_test = '''#[test]
fn added_named_persistent_volume_is_detected_as_authority_widening() {
    let root = unique_absent_root("named-volume");
    let baseline_text = base_policy(&root);
    let candidate_text = format!(
        "{baseline_text}volume.mount.assets.source = /srv/assets\\nvolume.mount.assets.target = /assets\\nvolume.mount.assets.access = read-only\\n"
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let candidate = TempPolicy::new("candidate", &candidate_text);

    let output = run_json(&baseline, &candidate);
    assert_eq!(output.status.code(), Some(5));
    let stdout = String::from_utf8(output.stdout).expect("utf8 output");
    assert!(stdout.contains("\\\"status\\\":\\\"widened\\\""));
    assert!(stdout.contains(
        "\\\"field\\\":\\\"filesystem.persistent_volumes\\\",\\\"class\\\":\\\"widened\\\""
    ));
}

'''
replace_one("tests/authority_delta_cli.rs", marker, delta_test + marker, "authority delta named volume test")
'''
path.write_text(prefix + replacement)
