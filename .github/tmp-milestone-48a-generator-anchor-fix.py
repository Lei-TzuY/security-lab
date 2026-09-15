from pathlib import Path

path = Path('.github/tmp-milestone-48a-sealed-executable.py')
text = path.read_text()
old = 'fn parse_u64(value: &str, line_no: usize, key: &str) -> Result<u64, PolicyError>'
new = 'fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError>'
count = text.count(old)
if count != 2:
    raise SystemExit(f'expected two stale parse_u64 anchors, got {count}')
path.write_text(text.replace(old, new))
