from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/platform/linux.rs",
    '            "unlink" => libc::SYS_unlink,\n            "newfstatat" => libc::SYS_newfstatat,',
    '            "unlink" => libc::SYS_unlink,\n            "truncate" => libc::SYS_truncate,\n            "newfstatat" => libc::SYS_newfstatat,',
    "truncate syscall mapping",
)

replace_one(
    "tests/fixtures/probe.S",
    '''    # Existing file in the allowed persistent subtree must be writable+truncatable.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_existing(%rip), %rsi\n    mov $513, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail38\n    mov %rax, %r12\n''',
    '''    # Exercise TRUNCATE independently from WRITE_FILE on the allowed file.\n    mov $76, %eax\n    lea landlock_mutation_existing(%rip), %rdi\n    xor %esi, %esi\n    syscall\n    test %rax, %rax\n    js .fail38\n\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_existing(%rip), %rsi\n    mov $1, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail38\n    mov %rax, %r12\n''',
    "independent allowed truncate/write evidence",
)

replace_one(
    "tests/fixtures/probe.S",
    '''    mov $87, %eax\n    lea landlock_mutation_denied_remove(%rip), %rdi\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    xor %edi, %edi\n    jmp .exit\n''',
    '''    mov $87, %eax\n    lea landlock_mutation_denied_remove(%rip), %rdi\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    # WRITE_FILE must be independently denied on an existing sibling file.\n    mov $257, %eax\n    mov $-100, %edi\n    lea landlock_mutation_denied_remove(%rip), %rsi\n    mov $1, %edx\n    xor %r10d, %r10d\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    # TRUNCATE must also be independently denied, proving the ABI-3 right is active.\n    mov $76, %eax\n    lea landlock_mutation_denied_remove(%rip), %rdi\n    xor %esi, %esi\n    syscall\n    cmp $-13, %rax\n    jne .fail38\n\n    xor %edi, %edi\n    jmp .exit\n''',
    "independent denied write/truncate evidence",
)

replace_one(
    "tests/sandbox.rs",
    '        &["execveat", "openat", "write", "close", "unlink", "exit"],',
    '        &[\n            "execveat", "openat", "truncate", "write", "close", "unlink", "exit",\n        ],',
    "Landlock mutation seccomp grant",
)
