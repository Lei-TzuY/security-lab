from pathlib import Path

p = Path("src/policy.rs")
text = p.read_text()
old = "octets == [0, 0, 0, 0] || octets[0] >= 224"
count = text.count(old)
if count != 2:
    raise SystemExit(f"IPv4 class guard: expected 2 matches, got {count}")
text = text.replace(old, "octets[0] == 0 || octets[0] >= 224")
old_test = 'for address in ["example.com", "0.0.0.0", "224.0.0.1", "255.255.255.255"] {'
if text.count(old_test) != 1:
    raise SystemExit("IPv4 invalid-address test list did not match exactly once")
text = text.replace(
    old_test,
    'for address in ["example.com", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255"] {',
    1,
)
p.write_text(text)
