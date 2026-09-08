from pathlib import Path

path = Path("src/snapshot_archive.rs")
text = path.read_text()
text = text.replace("    use std::cmp::Ordering as CmpOrdering;\n", "", 1)
old = '''        names.sort_by(|left, right| {
            let primary = left.cmp(right);
            if primary == CmpOrdering::Equal {
                CmpOrdering::Equal
            } else {
                primary
            }
        });
'''
if old not in text:
    raise SystemExit("cleanup sort block not found")
text = text.replace(old, "        names.sort();\n", 1)
old_result = "        let materialize_result = (|| {\n"
if old_result not in text:
    raise SystemExit("materialize result binding not found")
text = text.replace(
    old_result,
    "        let materialize_result: Result<(), SnapshotArchiveError> = (|| {\n",
    1,
)
for old_mode, new_mode in [
    ("(root_stat.st_mode & 0o7777) as u32", "root_stat.st_mode & 0o7777"),
    ("(current.st_mode & 0o7777) as u32", "current.st_mode & 0o7777"),
    ("(stat.st_mode & 0o7777) as u32", "stat.st_mode & 0o7777"),
]:
    if old_mode not in text:
        raise SystemExit(f"mode cast not found: {old_mode}")
    text = text.replace(old_mode, new_mode, 1)
path.write_text(text)
