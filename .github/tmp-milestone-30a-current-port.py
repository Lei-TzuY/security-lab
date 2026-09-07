from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Current policy-preflight JSON grew after the original COW prototype. Keep COW
# explicitly unprobed unless a real launch owns the user+mount namespace.
replace_one(
    "src/policy_preflight.rs",
    '''        output.push_str(",\\\"private_procfs\\\":{\\\"status\\\":\\\"");
        output.push_str(self.private_procfs_status().as_str());
        output.push_str("\\\",\\\"reason\\\":");
        if self.requirements.private_procfs {
            output.push_str("\\\"pid_namespace_procfs_mount_requires_real_launch\\\"");
        } else {
            output.push_str("null");
        }
        output.push_str("}}}");
''',
    '''        output.push_str(",\\\"private_procfs\\\":{\\\"status\\\":\\\"");
        output.push_str(self.private_procfs_status().as_str());
        output.push_str("\\\",\\\"reason\\\":");
        if self.requirements.private_procfs {
            output.push_str("\\\"pid_namespace_procfs_mount_requires_real_launch\\\"");
        } else {
            output.push_str("null");
        }
        output.push_str("},\\\"copy_on_write_root\\\":{\\\"status\\\":\\\"");
        output.push_str(self.copy_on_write_root_status().as_str());
        output.push_str("\\\",\\\"reason\\\":");
        if self.requirements.copy_on_write_root {
            output.push_str("\\\"overlayfs_mount_requires_real_user_mount_namespace\\\"");
        } else {
            output.push_str("null");
        }
        output.push_str("}}}");
''',
    "current preflight COW JSON",
)

# Runtime receipt completeness now understands the two mutually exclusive final
# root modes rather than requiring readonly_root unconditionally.
replace_one(
    "src/runtime_receipt_gate_main.rs",
    '''    require(
        &mut required,
        &mut missing,
        "readonly_root",
        receipt.readonly_root,
    );
''',
    '''    if policy.cow_root_bytes.is_some() {
        require(
            &mut required,
            &mut missing,
            "copy_on_write_root",
            receipt.copy_on_write_root,
        );
        if receipt.readonly_root {
            unexpected.push("readonly_root");
        }
    } else {
        require(
            &mut required,
            &mut missing,
            "readonly_root",
            receipt.readonly_root,
        );
        if receipt.copy_on_write_root {
            unexpected.push("copy_on_write_root");
        }
    }
''',
    "runtime receipt final-root mode",
)
replace_one(
    "src/runtime_receipt_gate_main.rs",
    '''            private_mount_propagation: true,
            readonly_root: true,
            chroot: true,
''',
    '''            private_mount_propagation: true,
            readonly_root: true,
            copy_on_write_root: false,
            chroot: true,
''',
    "runtime receipt fixture field",
)
replace_one(
    "src/runtime_receipt_gate_main.rs",
    '''    #[test]
    fn requested_optional_stage_becomes_required() {
''',
    '''    #[test]
    fn requested_copy_on_write_root_replaces_readonly_root_requirement() {
        let mut receipt = complete_base_receipt();
        receipt.readonly_root = false;
        receipt.copy_on_write_root = true;
        let assessment = assess(
            &policy("filesystem.cow_root_bytes = 16777216"),
            &receipt,
        );
        assert!(assessment.complete());
        assert!(assessment.required.contains(&"copy_on_write_root"));
        assert!(!assessment.required.contains(&"readonly_root"));

        receipt.readonly_root = true;
        let assessment = assess(
            &policy("filesystem.cow_root_bytes = 16777216"),
            &receipt,
        );
        assert_eq!(assessment.unexpected, vec!["readonly_root"]);
        assert_eq!(assessment.exit_code(), EXIT_RECEIPT_UNEXPECTED);
    }

    #[test]
    fn requested_optional_stage_becomes_required() {
''',
    "runtime receipt COW gate regression",
)

# Keep the public run-json contract deterministic when the receipt grows.
replace_one(
    "tests/cli.rs",
    '\\"private_mount_propagation\\":true,\\"readonly_root\\":true,\\"chroot\\":true,',
    '\\"private_mount_propagation\\":true,\\"readonly_root\\":true,\\"copy_on_write_root\\":false,\\"chroot\\":true,',
    "CLI runtime receipt golden",
)

# Authority delta was introduced after the old prototype. COW-root presence is
# real write authority; a larger private upper budget is also a widening.
replace_one(
    "src/authority_delta.rs",
    '''    compare_exact_incomparable(
        "filesystem.private_procfs",
        &baseline.procfs_enabled,
        &candidate.procfs_enabled,
        &mut changes,
    );
    compare_scratch(baseline, candidate, &mut changes);
''',
    '''    compare_exact_incomparable(
        "filesystem.private_procfs",
        &baseline.procfs_enabled,
        &candidate.procfs_enabled,
        &mut changes,
    );
    compare_copy_on_write_root(baseline, candidate, &mut changes);
    compare_scratch(baseline, candidate, &mut changes);
''',
    "authority delta COW call",
)
replace_one(
    "src/authority_delta.rs",
    '''fn compare_scratch(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {
''',
    '''fn compare_copy_on_write_root(
    baseline: &SandboxPolicy,
    candidate: &SandboxPolicy,
    changes: &mut Vec<Change>,
) {
    match (baseline.cow_root_bytes, candidate.cow_root_bytes) {
        (None, None) => {}
        (None, Some(_)) => push_change(
            "filesystem.copy_on_write_root",
            DeltaClass::Widened,
            changes,
        ),
        (Some(_), None) => push_change(
            "filesystem.copy_on_write_root",
            DeltaClass::Reduced,
            changes,
        ),
        (Some(base), Some(new)) => push_change(
            "filesystem.copy_on_write_root_bytes",
            classify_allowance(base, new),
            changes,
        ),
    }
}

fn compare_scratch(baseline: &SandboxPolicy, candidate: &SandboxPolicy, changes: &mut Vec<Change>) {
''',
    "authority delta COW semantics",
)
replace_one(
    "tests/authority_delta_cli.rs",
    '''#[test]
fn lower_resource_ceiling_is_detected_as_reduction() {
''',
    '''#[test]
fn copy_on_write_root_is_modeled_as_ephemeral_write_authority() {
    let root = unique_absent_root("cow-root");
    let baseline_text = base_policy(&root);
    let cow_text = format!("{baseline_text}filesystem.cow_root_bytes = 16777216\\n");
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let cow = TempPolicy::new("cow", &cow_text);

    let widened = run_json(&baseline, &cow);
    assert_eq!(widened.status.code(), Some(5));
    let stdout = String::from_utf8(widened.stdout).expect("utf8 output");
    assert!(stdout.contains("\\\"status\\\":\\\"widened\\\""));
    assert!(stdout.contains(
        "\\\"field\\\":\\\"filesystem.copy_on_write_root\\\",\\\"class\\\":\\\"widened\\\""
    ));

    let reduced = run_json(&cow, &baseline);
    assert_eq!(reduced.status.code(), Some(0));
    let stdout = String::from_utf8(reduced.stdout).expect("utf8 output");
    assert!(stdout.contains("\\\"status\\\":\\\"reduced\\\""));
    assert!(stdout.contains(
        "\\\"field\\\":\\\"filesystem.copy_on_write_root\\\",\\\"class\\\":\\\"reduced\\\""
    ));

    let larger_text = format!("{baseline_text}filesystem.cow_root_bytes = 33554432\\n");
    let larger = TempPolicy::new("larger", &larger_text);
    let enlarged = run_json(&cow, &larger);
    assert_eq!(enlarged.status.code(), Some(5));
    let stdout = String::from_utf8(enlarged.stdout).expect("utf8 output");
    assert!(stdout.contains(
        "\\\"field\\\":\\\"filesystem.copy_on_write_root_bytes\\\",\\\"class\\\":\\\"widened\\\""
    ));
}

#[test]
fn lower_resource_ceiling_is_detected_as_reduction() {
''',
    "authority delta COW regression",
)
