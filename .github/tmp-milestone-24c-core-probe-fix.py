from pathlib import Path

p = Path('.github/tmp-milestone-24c-core-probe.py')
text = p.read_text()
needle = "    '''        output.push('\\n');"
count = text.count(needle)
if count != 2:
    raise SystemExit(f'expected two human-output triple strings, got {count}')
p.write_text(text.replace(needle, "    r'''        output.push('\\n');"))
