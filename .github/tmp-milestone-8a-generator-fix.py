from pathlib import Path

path = Path(".github/tmp-milestone-8a-readonly-volume.py")
text = path.read_text()
old = '''replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\\n",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\\n#   v read a declared persistent volume, prove it is read-only, and hide its host source path\\n",
    "probe mode comment",
)
'''
new = '''replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\\n",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\\n#   v read a declared persistent volume, prove it is read-only, and hide its host source path\\n",
    "probe mode comment",
)
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"volume comment-block fix expected one match, got {count}")
path.write_text(text.replace(old, new, 1))
