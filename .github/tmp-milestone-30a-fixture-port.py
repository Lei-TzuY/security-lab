from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# The old prototype used lowercase k before Milestone 29A claimed it for the
# forbidden-mask oracle. Give COW-root its own still-unused z dispatch instead.
replace_one(
    "tests/fixtures/probe.S",
    "#   k mutate an ephemeral copy-on-write root and verify merged-state behavior\n",
    "#   z mutate an ephemeral copy-on-write root and verify merged-state behavior\n",
    "COW fixture mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $107, %al
    je .copy_on_write_root
''',
    '''    cmp $122, %al
    je .copy_on_write_root
''',
    "COW fixture mode dispatch",
)
replace_one(
    "tests/sandbox.rs",
    '''        let mut cow = policy(
            "k",
            &[],
            &["execveat", "openat", "read", "write", "close", "unlink", "exit"],
        );
''',
    '''        let mut cow = policy(
            "z",
            &[],
            &["execveat", "openat", "read", "write", "close", "unlink", "exit"],
        );
''',
    "COW integration fixture mode",
)

# Prevent future milestone probes from silently reusing an existing one-byte
# dispatch value. This checks the actual assembly dispatch table, not a duplicate
# hand-maintained list.
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn copy_on_write_root_is_ephemeral_and_preserves_host_lower() {
''',
    '''#[test]
fn raw_fixture_dispatch_modes_are_unique() {
    let source = include_str!("fixtures/probe.S");
    let dispatch = source
        .split_once("_start:\\n")
        .expect("raw fixture has _start")
        .1
        .split_once("\\n.allowed:")
        .expect("raw fixture dispatch precedes .allowed")
        .0;
    let mut modes = BTreeSet::new();
    for line in dispatch.lines() {
        let line = line.trim();
        let Some(value) = line
            .strip_prefix("cmp $")
            .and_then(|rest| rest.strip_suffix(", %al"))
        else {
            continue;
        };
        let value: u16 = value.parse().expect("fixture dispatch uses decimal byte values");
        assert!(
            modes.insert(value),
            "duplicate raw fixture dispatch mode byte {value}"
        );
    }
    assert!(modes.len() >= 40, "unexpectedly small raw fixture dispatch table");
}

#[test]
fn copy_on_write_root_is_ephemeral_and_preserves_host_lower() {
''',
    "fixture dispatch uniqueness regression",
)
