from pathlib import Path

path = Path("tests/fixtures/probe.S")
text = path.read_text()
needle = "    mov 96(%rsp), %r12d\n"
if text.count(needle) != 1:
    raise SystemExit(f"expected exactly one received-FD load, got {text.count(needle)}")
insert = needle + "\n" + """    # The handed-off capability must be read-only in the actual sandbox target.\n    # write(2) is explicitly allowed by this fixture for the readiness byte, so\n    # exact EBADF here proves the received open-file-description lacks write access.\n    mov $1, %eax\n    mov %r12d, %edi\n    lea runtime_fd_handoff_marker(%rip), %rsi\n    mov $1, %edx\n    syscall\n    cmp $-9, %rax\n    jne .brokered_host_unix_scm_rights_fail\n\n"""
path.write_text(text.replace(needle, insert, 1))
