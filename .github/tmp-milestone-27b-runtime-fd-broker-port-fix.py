from pathlib import Path

path = Path("tests/sandbox.rs")
text = path.read_text()
old = '''    let null_file = std::fs::File::open("/dev/null").expect("open runtime broker source");
    let mut brokered = policy(
        "0",
        &[null_file.as_raw_fd().to_string().as_str()],
        &["execveat", "write", "close", "fcntl", "exit"],
    );
'''
new = '''    let null_file = std::fs::File::open("/dev/null").expect("open runtime broker source");
    let source_text = null_file.as_raw_fd().to_string();
    let mut brokered = policy(
        "0",
        &[source_text.as_str()],
        &["execveat", "write", "close", "fcntl", "exit"],
    );
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"runtime broker seccomp regression binding: expected one match, got {count}")
path.write_text(text.replace(old, new, 1))
