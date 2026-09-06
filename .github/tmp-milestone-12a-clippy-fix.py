from pathlib import Path

path = Path("src/platform/linux.rs")
text = path.read_text()


def replace_one(old: str, new: str, label: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    text = text.replace(old, new, 1)


replace_one(
    "    struct PreparedLaunch {\n",
    "    struct PreparedLandlock {\n        read_execute: Vec<CString>,\n        file_mutate: Vec<CString>,\n        tcp_bind_ports: Vec<u16>,\n        tcp_connect_ports: Vec<u16>,\n    }\n\n    struct PreparedLaunch {\n",
    "prepared Landlock struct",
)
replace_one(
    "        landlock_read_execute: Vec<CString>,\n        landlock_file_mutate: Vec<CString>,\n        landlock_tcp_bind_ports: Vec<u16>,\n        landlock_tcp_connect_ports: Vec<u16>,\n",
    "        landlock: PreparedLandlock,\n",
    "prepared launch Landlock field",
)
replace_one(
    "                landlock_read_execute,\n                landlock_file_mutate,\n                landlock_tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),\n                landlock_tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),\n",
    "                landlock: PreparedLandlock {\n                    read_execute: landlock_read_execute,\n                    file_mutate: landlock_file_mutate,\n                    tcp_bind_ports: policy.landlock_tcp_bind_ports.clone(),\n                    tcp_connect_ports: policy.landlock_tcp_connect_ports.clone(),\n                },\n",
    "prepared launch Landlock value",
)
replace_one(
    "    unsafe fn prepare_landlock_ruleset_or_fail(\n        read_execute_paths: &[CString],\n        file_mutate_paths: &[CString],\n        tcp_bind_ports: &[u16],\n        tcp_connect_ports: &[u16],\n        root_tree_fd: RawFd,\n",
    "    unsafe fn prepare_landlock_ruleset_or_fail(\n        landlock: &PreparedLandlock,\n        root_tree_fd: RawFd,\n",
    "Landlock prepare grouped signature",
)
replace_one(
    "            &prepared.landlock_read_execute,\n            &prepared.landlock_file_mutate,\n            &prepared.landlock_tcp_bind_ports,\n            &prepared.landlock_tcp_connect_ports,\n            root_tree_fd,\n",
    "            &prepared.landlock,\n            root_tree_fd,\n",
    "Landlock grouped call",
)

start = text.index("    unsafe fn prepare_landlock_ruleset_or_fail(")
end = text.index("    unsafe fn restrict_landlock_or_fail(", start)
segment = text[start:end]
for old, new in [
    ("read_execute_paths", "landlock.read_execute"),
    ("file_mutate_paths", "landlock.file_mutate"),
    ("tcp_bind_ports", "landlock.tcp_bind_ports"),
    ("tcp_connect_ports", "landlock.tcp_connect_ports"),
]:
    segment = segment.replace(old, new)
text = text[:start] + segment + text[end:]

path.write_text(text)
