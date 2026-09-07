from pathlib import Path

path = Path('.github/tmp-28a-multi-volume.py')
text = path.read_text()
section = '# Add authority-delta evidence: exact added named mount is a widening.\n'
if text.count(section) != 1:
    raise SystemExit('expected exactly one authority-delta generator section')
prefix = text.split(section, 1)[0]
replacement = (
    '# Add authority-delta evidence: exact added named mount is a widening.\n'
    'marker = "#[test]\\nfn invalid_candidate_fails_closed_before_comparison() {\\n"\n'
    'delta_test = """#[test]\n'
    'fn added_named_persistent_volume_is_detected_as_authority_widening() {\n'
    '    let root = unique_absent_root("named-volume");\n'
    '    let baseline_text = base_policy(&root);\n'
    '    let candidate_text = format!(\n'
    '        "{baseline_text}volume.mount.assets.source = /srv/assets\\\\nvolume.mount.assets.target = /assets\\\\nvolume.mount.assets.access = read-only\\\\n"\n'
    '    );\n'
    '    let baseline = TempPolicy::new("baseline", &baseline_text);\n'
    '    let candidate = TempPolicy::new("candidate", &candidate_text);\n\n'
    '    let output = run_json(&baseline, &candidate);\n'
    '    assert_eq!(output.status.code(), Some(5));\n'
    '    let stdout = String::from_utf8(output.stdout).expect("utf8 output");\n'
    '    assert!(stdout.contains("\\\\\\\"status\\\\\\\":\\\\\\\"widened\\\\\\\""));\n'
    '    assert!(stdout.contains(\n'
    '        "\\\\\\\"field\\\\\\\":\\\\\\\"filesystem.persistent_volumes\\\\\\\",\\\\\\\"class\\\\\\\":\\\\\\\"widened\\\\\\\""\n'
    '    ));\n'
    '}\n\n'
    '"""\n'
    'replace_one("tests/authority_delta_cli.rs", marker, delta_test + marker, "authority delta named volume test")\n'
)
path.write_text(prefix + replacement)
