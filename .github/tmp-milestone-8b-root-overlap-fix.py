from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Close a real authority bypass: a persistent-volume source may not be the
# sandbox root, an ancestor of it, or a descendant within it. Otherwise a
# writable volume could reopen mutation of the host tree that the cloned root
# deliberately exposes read-only, and either access mode could leave the source
# reachable through the root outside the declared target.
replace_one(
    "src/policy.rs",
    '''                validate_absolute_path("volume.readonly_source", source)?;
                validate_absolute_path("volume.readonly_target", target)?;
                if target == Path::new("/") {''',
    '''                validate_absolute_path("volume.readonly_source", source)?;
                validate_absolute_path("volume.readonly_target", target)?;
                if source.starts_with(&self.root_dir) || self.root_dir.starts_with(source) {
                    return Err(PolicyError::new(
                        "volume.readonly_source must not overlap filesystem.root",
                    ));
                }
                if target == Path::new("/") {''',
    "read-only source/root disjointness",
)
replace_one(
    "src/policy.rs",
    '''                validate_absolute_path("volume.writable_source", source)?;
                validate_absolute_path("volume.writable_target", target)?;
                if source == Path::new("/") {
                    return Err(PolicyError::new(
                        "volume.writable_source must not grant the host root",
                    ));
                }
                if target == Path::new("/") {''',
    '''                validate_absolute_path("volume.writable_source", source)?;
                validate_absolute_path("volume.writable_target", target)?;
                if source.starts_with(&self.root_dir) || self.root_dir.starts_with(source) {
                    return Err(PolicyError::new(
                        "volume.writable_source must not overlap filesystem.root",
                    ));
                }
                if target == Path::new("/") {''',
    "writable source/root disjointness",
)

policy_path = Path("src/policy.rs")
policy = policy_path.read_text()
anchor = '''    "#;

    #[test]
    fn parses_complete_policy() {'''
if policy.count(anchor) != 1:
    raise SystemExit(f"volume test helper anchor: expected exactly one match, got {policy.count(anchor)}")
policy = policy.replace(
    anchor,
    '''    "#;

    fn volume_valid() -> String {
        VALID.replace("filesystem.root = /", "filesystem.root = /sandbox/root")
    }

    #[test]
    fn parses_complete_policy() {''',
    1,
)

# Existing positive/negative volume parser tests used filesystem.root=/, which
# necessarily overlaps every absolute host source once the invariant is made
# explicit. Give only those tests a realistic separate sandbox root.
for name in [
    "parses_readonly_volume_pair",
    "rejects_incomplete_or_unsafe_readonly_volume",
    "parses_writable_volume_pair",
    "rejects_incomplete_or_unsafe_writable_volume",
]:
    marker = f"    #[test]\n    fn {name}() {{\n"
    start = policy.find(marker)
    if start == -1:
        raise SystemExit(f"missing volume test {name}")
    end = policy.find("\n    #[test]", start + len(marker))
    if end == -1:
        raise SystemExit(f"cannot find end of volume test {name}")
    block = policy[start:end]
    if "{VALID}" not in block:
        raise SystemExit(f"volume test {name} has no VALID references")
    block = block.replace(marker, marker + "        let base = volume_valid();\n", 1)
    block = block.replace("{VALID}", "{base}")
    policy = policy[:start] + block + policy[end:]

readonly_tail = '''        let overlaps_scratch = format!(
            "{base}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /scratch/data"
        );
        assert!(overlaps_scratch.parse::<SandboxPolicy>().is_err());
    }'''
readonly_new = '''        let overlaps_scratch = format!(
            "{base}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /scratch/data"
        );
        assert!(overlaps_scratch.parse::<SandboxPolicy>().is_err());

        let source_inside_root = format!(
            "{base}\\nvolume.readonly_source = /sandbox/root/source\\nvolume.readonly_target = /data"
        );
        let err = source_inside_root.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("must not overlap filesystem.root"));

        let source_contains_root = format!(
            "{base}\\nvolume.readonly_source = /sandbox\\nvolume.readonly_target = /data"
        );
        let err = source_contains_root.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("must not overlap filesystem.root"));
    }'''
if policy.count(readonly_tail) != 1:
    raise SystemExit(f"readonly regression anchor: expected exactly one match, got {policy.count(readonly_tail)}")
policy = policy.replace(readonly_tail, readonly_new, 1)

writable_tail = '''        let overlaps_readonly_source = format!(
            "{base}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /data\\nvolume.writable_source = /srv/data/state\\nvolume.writable_target = /persist"
        );
        assert!(overlaps_readonly_source.parse::<SandboxPolicy>().is_err());
    }'''
writable_new = '''        let overlaps_readonly_source = format!(
            "{base}\\nvolume.readonly_source = /srv/data\\nvolume.readonly_target = /data\\nvolume.writable_source = /srv/data/state\\nvolume.writable_target = /persist"
        );
        assert!(overlaps_readonly_source.parse::<SandboxPolicy>().is_err());

        let source_inside_root = format!(
            "{base}\\nvolume.writable_source = /sandbox/root/state\\nvolume.writable_target = /persist"
        );
        let err = source_inside_root.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("must not overlap filesystem.root"));

        let source_contains_root = format!(
            "{base}\\nvolume.writable_source = /sandbox\\nvolume.writable_target = /persist"
        );
        let err = source_contains_root.parse::<SandboxPolicy>().unwrap_err();
        assert!(err.to_string().contains("must not overlap filesystem.root"));
    }'''
if policy.count(writable_tail) != 1:
    raise SystemExit(f"writable regression anchor: expected exactly one match, got {policy.count(writable_tail)}")
policy = policy.replace(writable_tail, writable_new, 1)
policy_path.write_text(policy)

# Public run-path regression for the concrete writable-root bypass and the
# inverse ancestor case. These must fail as InvalidPolicy before any namespace
# or mount setup starts.
replace_one(
    "tests/sandbox.rs",
    '''}

#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {''',
    '''}

#[test]
fn persistent_volume_source_cannot_overlap_sandbox_root() {
    let mut writable = policy("X", &[], &["execveat", "exit"]);
    writable.writable_volume_source = Some(fixture_root().join("persist"));
    writable.writable_volume_target = Some(PathBuf::from("/persist"));
    match run(&writable).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error.to_string().contains("must not overlap filesystem.root"));
        }
        other => panic!("unexpected writable root-overlap result: {other}"),
    }

    let mut readonly = policy("X", &[], &["execveat", "exit"]);
    readonly.readonly_volume_source = Some(
        fixture_root()
            .parent()
            .expect("fixture root has a parent")
            .to_path_buf(),
    );
    readonly.readonly_volume_target = Some(PathBuf::from("/data"));
    match run(&readonly).unwrap_err() {
        SandboxError::InvalidPolicy(error) => {
            assert!(error.to_string().contains("must not overlap filesystem.root"));
        }
        other => panic!("unexpected read-only root-overlap result: {other}"),
    }
}

#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {''',
    "public root-overlap regression",
)
