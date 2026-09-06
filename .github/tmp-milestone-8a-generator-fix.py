from pathlib import Path

path = Path(".github/tmp-milestone-8a-readonly-volume.py")
text = path.read_text()

comment_old = '''replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\\n",
    "#   c fork a live descendant, publish a readiness marker on fd 9, then await cancellation\\n#   v read a declared persistent volume, prove it is read-only, and hide its host source path\\n",
    "probe mode comment",
)
'''
comment_new = '''replace_one(
    "tests/fixtures/probe.S",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\\n",
    "#   c fork a descendant, publish cancellation readiness on fd 9, then pause\\n#   v read a declared persistent volume, prove it is read-only, and hide its host source path\\n",
    "probe mode comment",
)
'''
if text.count(comment_old) != 1:
    raise SystemExit(
        f"volume comment-block fix expected one match, got {text.count(comment_old)}"
    )
text = text.replace(comment_old, comment_new, 1)

dispatch_old = '''replace_one(
    "tests/fixtures/probe.S",
    "    cmp $99, %al\\n    je .cancellation_tree\\n    jmp .fail2\\n",
    "    cmp $99, %al\\n    je .cancellation_tree\\n    cmp $118, %al\\n    je .readonly_volume\\n    jmp .fail2\\n",
    "probe mode dispatch",
)
'''
dispatch_new = '''replace_one(
    "tests/fixtures/probe.S",
    "    cmp $99, %al\\n    je .cancellation_tree\\n    cmp $70, %al\\n    je .forbidden\\n",
    "    cmp $99, %al\\n    je .cancellation_tree\\n    cmp $118, %al\\n    je .readonly_volume\\n    cmp $70, %al\\n    je .forbidden\\n",
    "probe mode dispatch",
)
'''
if text.count(dispatch_old) != 1:
    raise SystemExit(
        f"volume dispatch-block fix expected one match, got {text.count(dispatch_old)}"
    )
text = text.replace(dispatch_old, dispatch_new, 1)

oracle_prefix_old = '''    "    ret\\n\\n.forbidden:\\n",
    "    ret\\n\\n.readonly_volume:\\n'''
oracle_prefix_new = '''    ".cancellation_descendant_pause:\\n    mov $34, %eax\\n    syscall\\n    jmp .cancellation_descendant_pause\\n\\n.forbidden:\\n",
    ".cancellation_descendant_pause:\\n    mov $34, %eax\\n    syscall\\n    jmp .cancellation_descendant_pause\\n\\n.readonly_volume:\\n'''
if text.count(oracle_prefix_old) != 1:
    raise SystemExit(
        f"volume oracle-prefix fix expected one match, got {text.count(oracle_prefix_old)}"
    )
text = text.replace(oracle_prefix_old, oracle_prefix_new, 1)

# The 6A selected-handle oracle already owns .fail30 and 7A cancellation owns
# .fail31. Rewrite only the 8A raw-oracle replacement block to use .fail32.
oracle_marker = '    "volume raw oracle",\n)\n'
oracle_end = text.find(oracle_marker)
if oracle_end == -1:
    raise SystemExit("volume raw-oracle block marker not found")
oracle_start = text.rfind('replace_one(\n', 0, oracle_end)
if oracle_start == -1:
    raise SystemExit("volume raw-oracle block start not found")
oracle_end += len(oracle_marker)
oracle_block = text[oracle_start:oracle_end]
if oracle_block.count('.fail30') == 0:
    raise SystemExit("volume raw-oracle block contains no stale .fail30 references")
if '.fail31' in oracle_block or '.fail32' in oracle_block:
    raise SystemExit("volume raw-oracle block unexpectedly references reserved/new failure labels")
oracle_block = oracle_block.replace('.fail30', '.fail32')
text = text[:oracle_start] + oracle_block + text[oracle_end:]

fail_block_old = '''replace_one(
    "tests/fixtures/probe.S",
    ".fail29:\\n    mov $29, %edi\\n\\n.exit:\\n",
    ".fail29:\\n    mov $29, %edi\\n    jmp .exit\\n.fail30:\\n    mov $30, %edi\\n\\n.exit:\\n",
    "volume fail label",
)
'''
fail_block_new = '''replace_one(
    "tests/fixtures/probe.S",
    ".fail31:\\n    mov $31, %edi\\n\\n.exit:\\n",
    ".fail31:\\n    mov $31, %edi\\n    jmp .exit\\n.fail32:\\n    mov $32, %edi\\n\\n.exit:\\n",
    "volume fail label",
)
'''
if text.count(fail_block_old) != 1:
    raise SystemExit(
        f"volume fail-block fix expected one match, got {text.count(fail_block_old)}"
    )
text = text.replace(fail_block_old, fail_block_new, 1)

path.write_text(text)
