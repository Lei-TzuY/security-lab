from pathlib import Path

p = Path("tests/authority_delta_cli.rs")
text = p.read_text()
replacements = {
    'assert!(stdout.contains(""status":"reduced""));': 'assert!(stdout.contains(r#""status":"reduced""#));',
    '        ""field":"seccomp.forbidden_masks","class":"reduced""': '        r#""field":"seccomp.forbidden_masks","class":"reduced""#',
    'assert!(stdout.contains(""status":"widened""));': 'assert!(stdout.contains(r#""status":"widened""#));',
    '        ""field":"seccomp.forbidden_masks","class":"widened""': '        r#""field":"seccomp.forbidden_masks","class":"widened""#',
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"escape repair expected one match for {old!r}, got {count}")
    text = text.replace(old, new, 1)
p.write_text(text)
