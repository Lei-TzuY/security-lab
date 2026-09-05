from pathlib import Path

path = Path('.github/tmp-milestone-7a-cancellation.py')
text = path.read_text()
old = '    let mut marker = [0u8; 25];\n'
new = '    let mut marker = [0u8; 26];\n'
count = text.count(old)
if count != 1:
    raise SystemExit(f'marker-length fix expected one match, got {count}')
path.write_text(text.replace(old, new, 1))
