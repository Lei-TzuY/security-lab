from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


source = "src/snapshot_identity.rs"
replace_one(
    source,
    """        fn record_directory(\n            &mut self,\n            path: &[u8],\n            mode: u32,\n        ) -> Result<(), SnapshotIdentityError> {\n            self.consume_node()?;\n            self.record_prefix(b'D', path)?;\n            self.update(&mode.to_le_bytes())\n        }\n""",
    """        fn record_directory(\n            &mut self,\n            path: &[u8],\n            mode: u32,\n        ) -> Result<(), SnapshotIdentityError> {\n            self.record_prefix(b'D', path)?;\n            self.update(&mode.to_le_bytes())\n        }\n""",
    "directory record node accounting",
)
replace_one(
    source,
    """        fn begin_file(\n            &mut self,\n            path: &[u8],\n            mode: u32,\n            length: u64,\n        ) -> Result<(), SnapshotIdentityError> {\n            self.consume_node()?;\n            self.record_prefix(b'F', path)?;\n            self.update(&mode.to_le_bytes())?;\n            self.update(&length.to_le_bytes())\n        }\n""",
    """        fn begin_file(\n            &mut self,\n            path: &[u8],\n            mode: u32,\n            length: u64,\n        ) -> Result<(), SnapshotIdentityError> {\n            self.record_prefix(b'F', path)?;\n            self.update(&mode.to_le_bytes())?;\n            self.update(&length.to_le_bytes())\n        }\n""",
    "file record node accounting",
)
replace_one(
    source,
    """            self.consume_node()?;\n            self.record_prefix(b'L', path)?;\n            self.update(&target_len.to_le_bytes())?;\n""",
    """            self.record_prefix(b'L', path)?;\n            self.update(&target_len.to_le_bytes())?;\n""",
    "symlink record node accounting",
)
replace_one(
    source,
    """        let mut identity = CanonicalHasher::new(limits)?;\n        identity.record_directory(b\"/\", root_stat.st_mode & 0o7777)?;\n        hash_directory(root_fd.raw(), &[], 0, &mut identity)?;\n""",
    """        let mut identity = CanonicalHasher::new(limits)?;\n        identity.consume_node()?;\n        identity.record_directory(b\"/\", root_stat.st_mode & 0o7777)?;\n        hash_directory(root_fd.raw(), &[], 0, &mut identity)?;\n""",
    "root node accounting",
)
replace_one(
    source,
    """        for name in read_directory_names(directory_fd)? {\n""",
    """        for name in read_directory_names(directory_fd, identity)? {\n""",
    "budgeted directory enumeration call",
)
replace_one(
    source,
    """    fn read_directory_names(directory_fd: RawFd) -> Result<Vec<Vec<u8>>, SnapshotIdentityError> {\n""",
    """    fn read_directory_names(\n        directory_fd: RawFd,\n        identity: &mut CanonicalHasher,\n    ) -> Result<Vec<Vec<u8>>, SnapshotIdentityError> {\n""",
    "budgeted directory enumeration signature",
)
replace_one(
    source,
    """                if name != b\".\" && name != b\"..\" {\n                    names.push(name.to_vec());\n                }\n""",
    """                if name != b\".\" && name != b\"..\" {\n                    // Reserve the node budget before retaining the entry name.\n                    // This bounds directory-enumeration memory/work globally,\n                    // including ancestor name vectors that remain live while\n                    // recursion processes a child directory.\n                    identity.consume_node()?;\n                    names.push(name.to_vec());\n                }\n""",
    "directory enumeration node reservation",
)


tests = "tests/snapshot_identity.rs"
replace_one(
    tests,
    """fn encoded_bytes(entries: &[CowDiffEntry]) -> u64 {\n""",
    """#[test]\nfn node_budget_is_enforced_during_directory_enumeration() {\n    let tree = TempTree::new();\n    let root = tree.path().join(\"snapshot\");\n    fs::create_dir(&root).expect(\"create snapshot\");\n    fs::write(root.join(\"regular\"), b\"x\").expect(\"write regular child\");\n\n    let fifo = root.join(\"fifo\");\n    let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect(\"fifo path has no NUL\");\n    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);\n\n    let error = snapshot_sha256(\n        &root,\n        SnapshotIdentityLimits {\n            max_bytes: 1024 * 1024,\n            max_nodes: 2,\n        },\n    )\n    .expect_err(\"directory enumeration must stop at the global node budget\");\n\n    assert!(matches!(\n        error,\n        SnapshotIdentityError::BudgetExceeded {\n            resource: \"node\",\n            limit: 2,\n            attempted: 3,\n        }\n    ));\n}\n\nfn encoded_bytes(entries: &[CowDiffEntry]) -> u64 {\n""",
    "enumeration budget regression",
)
