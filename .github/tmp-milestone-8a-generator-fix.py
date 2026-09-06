from pathlib import Path

path = Path('.github/tmp-milestone-8a-readonly-volume.py')
text = path.read_text()
old = '#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\\n'
new = '#   c fork a descendant, publish cancellation readiness on fd 9, then pause\\n'
count = text.count(old)
if count != 1:
    raise SystemExit(f'volume comment-anchor fix expected one match, got {count}')
text = text.replace(old, new, 1)
path.write_text(text)
