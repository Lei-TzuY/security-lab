from pathlib import Path

path = Path('.github/tmp-milestone-7a-cancellation.py')
text = path.read_text()

old = '    let mut marker = [0u8; 25];\n'
new = '    let mut marker = [0u8; 26];\n'
count = text.count(old)
if count != 1:
    raise SystemExit(f'marker-length fix expected one match, got {count}')
text = text.replace(old, new, 1)

old = "'''    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n'''"
new = "'''    ret\n\n.forbidden:\n'''"
count = text.count(old)
if count != 1:
    raise SystemExit(f'cancellation-oracle anchor fix expected one match, got {count}')
text = text.replace(old, new, 1)

old = "'''    xor %edi, %edi\n    jmp .exit\n\n.cancellation_tree:\n"
new = "'''    ret\n\n.cancellation_tree:\n"
count = text.count(old)
if count != 1:
    raise SystemExit(f'cancellation-oracle replacement fix expected one match, got {count}')
text = text.replace(old, new, 1)

path.write_text(text)
