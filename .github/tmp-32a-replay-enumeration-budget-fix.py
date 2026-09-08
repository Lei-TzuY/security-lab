from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


source = "src/cow_diff_apply.rs"
replace_one(
    source,
    """        for name in read_directory_names(source_fd)? {\n            budget.consume_base_node()?;\n""",
    """        for name in read_directory_names_bounded(source_fd, Some(budget))? {\n""",
    "base enumeration consumes budget before retention",
)
replace_one(
    source,
    """    fn clear_directory(directory_fd: RawFd) -> Result<(), CowDiffApplyError> {\n        for name in read_directory_names(directory_fd)? {\n""",
    """    fn clear_directory(directory_fd: RawFd) -> Result<(), CowDiffApplyError> {\n        for name in read_directory_names_bounded(directory_fd, None)? {\n""",
    "unbudgeted staging enumeration uses shared helper",
)
replace_one(
    source,
    """    fn read_directory_names(directory_fd: RawFd) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {\n""",
    """    fn read_directory_names_bounded(\n        directory_fd: RawFd,\n        mut base_budget: Option<&mut Budget>,\n    ) -> Result<Vec<Vec<u8>>, CowDiffApplyError> {\n""",
    "directory enumeration signature",
)
replace_one(
    source,
    """                if name != b\".\" && name != b\"..\" {\n                    names.push(name.to_vec());\n                }\n""",
    """                if name != b\".\" && name != b\"..\" {\n                    if let Some(budget) = &mut base_budget {\n                        // Reserve the base-tree node before retaining its name.\n                        // This makes max_nodes bound directory-enumeration\n                        // buffering instead of applying only after collection.\n                        budget.consume_base_node()?;\n                    }\n                    names.push(name.to_vec());\n                }\n""",
    "reserve node before buffering name",
)


tests = "tests/cow_diff_apply.rs"
replace_one(
    tests,
    """use std::fs;\nuse std::os::unix::ffi::OsStrExt;\n""",
    """use std::ffi::CString;\nuse std::fs;\nuse std::os::unix::ffi::OsStrExt;\n""",
    "test imports",
)
replace_one(
    tests,
    """#[test]\nfn byte_budget_failure_is_atomic_and_cleans_staging() {\n""",
    """#[test]\nfn node_budget_is_enforced_during_base_directory_enumeration() {\n    let tree = TempTree::new();\n    let base = tree.path().join(\"base\");\n    let destination = tree.path().join(\"snapshot\");\n    fs::create_dir(&base).expect(\"create base\");\n    fs::write(base.join(\"regular\"), b\"x\").expect(\"write regular base child\");\n\n    let fifo = base.join(\"fifo\");\n    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect(\"fifo path has no NUL\");\n    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);\n\n    let changes = diff(Vec::new());\n    let tight = CowDiffApplyLimits {\n        max_bytes: 1024 * 1024,\n        max_nodes: 2,\n    };\n    let error = apply_cow_diff_atomic(&base, &destination, &changes, tight)\n        .expect_err(\"base enumeration must stop at the global node budget\");\n\n    assert!(matches!(\n        error,\n        CowDiffApplyError::BudgetExceeded {\n            resource: \"node\",\n            limit: 2,\n            attempted: 3,\n        }\n    ));\n    assert!(!destination.exists());\n    assert!(staging_entries(tree.path()).is_empty());\n}\n\n#[test]\nfn byte_budget_failure_is_atomic_and_cleans_staging() {\n""",
    "enumeration budget regression",
)
