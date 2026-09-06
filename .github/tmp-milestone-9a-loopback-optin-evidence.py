from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "tests/fixtures/probe.S",
    "#   n prove policy-owned loopback supports positive intra-sandbox TCP\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM",
    "#   n prove policy-owned loopback supports positive intra-sandbox TCP\n#   o prove loopback remains down unless policy explicitly enables it\n#   F forbidden getpid; exits 77 only when seccomp returns -EPERM",
    "probe mode documentation",
)

replace_one(
    "tests/fixtures/probe.S",
    "    cmp $110, %al\n    je .loopback_networking\n    cmp $70, %al",
    "    cmp $110, %al\n    je .loopback_networking\n    cmp $111, %al\n    je .loopback_disabled\n    cmp $70, %al",
    "probe mode dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    "    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n",
    "    xor %edi, %edi\n    jmp .exit\n\n.loopback_disabled:\n    mov $41, %eax\n    mov $2, %edi\n    mov $2, %esi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail35\n    mov %rax, %r12\n\n    movb $108, network_ifreq(%rip)\n    movb $111, network_ifreq+1(%rip)\n    movb $0, network_ifreq+2(%rip)\n    mov $16, %eax\n    mov %r12, %rdi\n    mov $0x8913, %esi\n    lea network_ifreq(%rip), %rdx\n    syscall\n    test %rax, %rax\n    js .fail35\n\n    movzwl network_ifreq+16(%rip), %eax\n    test $1, %eax\n    jnz .fail35\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail35\n    xor %edi, %edi\n    jmp .exit\n\n.forbidden:\n",
    "disabled loopback oracle",
)

replace_one(
    "tests/fixtures/probe.S",
    ".fail34:\n    mov $34, %edi\n\n.exit:",
    ".fail34:\n    mov $34, %edi\n    jmp .exit\n.fail35:\n    mov $35, %edi\n\n.exit:",
    "disabled loopback failure code",
)

replace_one(
    "tests/fixtures/probe.S",
    "network_addr:\n    .skip 16\nnetwork_buffer:\n    .skip 32",
    "network_addr:\n    .skip 16\n.balign 8\nnetwork_ifreq:\n    .skip 40\nnetwork_buffer:\n    .skip 32",
    "ifreq storage",
)

replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn enabled_loopback_supports_intra_sandbox_tcp() {",
    "#[test]\nfn loopback_is_down_unless_policy_enables_it() {\n    let disabled = policy(\n        \"o\",\n        &[],\n        &[\"execveat\", \"socket\", \"ioctl\", \"close\", \"exit\"],\n    );\n    assert_eq!(run(&disabled).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn enabled_loopback_supports_intra_sandbox_tcp() {",
    "disabled loopback integration evidence",
)
