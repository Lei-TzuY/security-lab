from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "README.md",
    "- with `/scratch` and `/persist/allowed` declared in `landlock.file_mutate`, a raw target creates a private-scratch file, truncates and rewrites `/persist/allowed/existing` to exact `landlock-persistent-write\\n`, and unlinks `/persist/allowed/remove-me`; sibling `/persist/denied` is on the same writable host mount but create and unlink attempts there must return exact `EACCES`. The parent proves the allowed host mutations persisted while the denied sentinel remains unchanged and no denied file was created;",
    "- with `/scratch` and `/persist/allowed` declared in `landlock.file_mutate`, a raw target creates a private-scratch file, calls `truncate(2)` on `/persist/allowed/existing`, reopens it `O_WRONLY`, writes exact `landlock-persistent-write\\n`, and unlinks `/persist/allowed/remove-me`; sibling `/persist/denied` is on the same writable host mount but create, unlink, `O_WRONLY` open, and `truncate(2)` each return exact `EACCES`. The parent proves the allowed host mutations persisted while the denied sentinel remains byte-for-byte unchanged and no denied file was created;",
    "README independent mutation evidence",
)

replace_one(
    "ROADMAP.md",
    "- a raw target creates inside `/scratch`, truncates+rewrites `/persist/allowed/existing` to exact `landlock-persistent-write\\n`, and removes `/persist/allowed/remove-me`; create and unlink in sibling `/persist/denied` on the same writable host mount each require exact `EACCES`;",
    "- a raw target creates inside `/scratch`, independently calls `truncate(2)` then opens `/persist/allowed/existing` `O_WRONLY` before writing exact `landlock-persistent-write\\n`, and removes `/persist/allowed/remove-me`; create, unlink, `O_WRONLY` open, and `truncate(2)` in sibling `/persist/denied` on the same writable host mount each require exact `EACCES`;",
    "ROADMAP independent mutation evidence",
)

replace_one(
    "THREAT_MODEL.md",
    "The executable 10B oracle composes both writable surface types: it creates a file in private scratch, truncates and rewrites an existing file in `/persist/allowed`, removes another allowed regular file, and then requires exact `EACCES` for both create and unlink in sibling `/persist/denied` on the same writable mount. Parent-side checks prove exact persistent bytes, removal of only the allowed sentinel, preservation of the denied sentinel, and absence of the denied created file. Target seccomp explicitly grants `openat`, `write`, `close`, and `unlink`, so seccomp `EPERM` cannot masquerade as Landlock evidence.",
    "The executable 10B oracle composes both writable surface types: it creates a file in private scratch, independently calls `truncate(2)` on an existing file in `/persist/allowed`, reopens it `O_WRONLY` and writes the exact replacement bytes, removes another allowed regular file, and then requires exact `EACCES` for create, unlink, `O_WRONLY` open, and `truncate(2)` in sibling `/persist/denied` on the same writable mount. Parent-side checks prove exact persistent bytes, removal of only the allowed sentinel, byte-for-byte preservation of the denied sentinel, and absence of the denied created file. Target seccomp explicitly grants `openat`, `truncate`, `write`, `close`, and `unlink`, so seccomp `EPERM` cannot masquerade as Landlock evidence.",
    "threat-model independent mutation evidence",
)
