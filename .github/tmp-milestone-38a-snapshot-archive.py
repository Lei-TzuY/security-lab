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
path.write_text(text)
