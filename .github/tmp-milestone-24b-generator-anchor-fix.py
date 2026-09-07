from pathlib import Path


path = Path(".github/tmp-milestone-24b-policy-preflight.py")
text = path.read_text()
old = '''replace_one(
    "src/host_capabilities.rs",
    "    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {",
    "    CapabilityProbe,\\n    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {",
    "linux platform tuple signature",
)
# The same signature text occurs again for the non-Linux implementation after
# the first replacement, so replace it once more.
replace_one(
    "src/host_capabilities.rs",
    "    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {",
    "    CapabilityProbe,\\n    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {",
    "non-linux platform tuple signature",
)
'''
new = '''p = Path("src/host_capabilities.rs")
text = p.read_text()
old_signature = "    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {"
new_signature = "    CapabilityProbe,\\n    CapabilityProbe,\\n    CapabilityProbe,\\n    bool,\\n) {"
count = text.count(old_signature)
if count != 2:
    raise SystemExit(
        f"platform tuple signatures: expected exactly 2 matches, got {count}"
    )
p.write_text(text.replace(old_signature, new_signature, 2))
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"generator platform tuple block: expected exactly 1 match, got {count}")
path.write_text(text.replace(old, new, 1))
