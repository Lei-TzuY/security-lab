from pathlib import Path

p = Path("src/policy_preflight.rs")
text = p.read_text()
old = """                stdout_output_limit: true,
                time_namespace: false,
            }
"""
new = """                stdout_output_limit: true,
                time_namespace: false,
                private_procfs: false,
            }
"""
if text.count(old) != 1:
    raise SystemExit("preflight requirement fixture: expected one match")
text = text.replace(old, new, 1)
old_json = r'''\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null}}}'''
new_json = r'''\"time_namespace\":{\"status\":\"not_requested\",\"reason\":null},\"private_procfs\":{\"status\":\"not_requested\",\"reason\":null}}}'''
if text.count(old_json) != 1:
    raise SystemExit("preflight exact JSON fixture: expected one match")
p.write_text(text.replace(old_json, new_json, 1))

probe = Path("tests/fixtures/probe.S")
probe_text = probe.read_text()
old_probe = '''landlock_buffer:
    .skip 32
proc_pid1_path:
    .asciz "/proc/1"
proc_pid2_path:
    .asciz "/proc/2"

.section .note.GNU-stack,"",@progbits
'''
new_probe = '''landlock_buffer:
    .skip 32

.section .rodata
proc_pid1_path:
    .asciz "/proc/1"
proc_pid2_path:
    .asciz "/proc/2"

.section .note.GNU-stack,"",@progbits
'''
if probe_text.count(old_probe) != 1:
    raise SystemExit("procfs fixture string section: expected one match")
probe.write_text(probe_text.replace(old_probe, new_probe, 1))
