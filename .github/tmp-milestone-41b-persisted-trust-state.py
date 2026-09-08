from pathlib import Path

path = Path("src/snapshot_trust_state.rs")
text = path.read_text()
old = "use crate::snapshot_archive::{SnapshotArchiveLimits, SnapshotArchiveMaterializeReport};"
new = "use crate::snapshot_archive::SnapshotArchiveLimits;"
if text.count(old) != 1:
    raise SystemExit("expected exactly one unused snapshot archive import")
path.write_text(text.replace(old, new, 1))
