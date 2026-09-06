from pathlib import Path

path = Path(".github/tmp-milestone-12a.py")
text = path.read_text()
needle = "\\\\" + "\n" + "landlock.tcp_"
replacement = "\\\\nlandlock.tcp_"
count = text.count(needle)
if count != 7:
    raise SystemExit(f"expected 7 malformed Landlock TCP test separators, got {count}")
path.write_text(text.replace(needle, replacement))
