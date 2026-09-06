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

path.write_text(text)
