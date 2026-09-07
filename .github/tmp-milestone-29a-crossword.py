from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Extend the existing mode-k raw oracle with a full-64-bit forbidden mask.
old_tail = '''    # W+X must be denied by the seccomp forbidden-mask rule with exact EPERM.
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $7, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    cmp $-1, %rax
    jne .fail29

    xor %edi, %edi
    jmp .exit
'''
new_tail = '''    # W+X must be denied by the seccomp forbidden-mask rule with exact EPERM.
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $7, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    cmp $-1, %rax
    jne .fail29

    # Full-64-bit mask: low participating bit matches but high word mismatches.
    mov $257, %eax
    mov $-100, %edi
    lea probe_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail29
    mov %rax, %r12

    mov $8, %eax
    mov %r12, %rdi
    movabs $0x0000000100000001, %rsi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail29

    # High word matches but the participating low bit mismatches.
    mov $8, %eax
    mov %r12, %rdi
    movabs $0x0000000200000000, %rsi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail29

    # Both participating low/high values match: exact EPERM is required.
    mov $8, %eax
    mov %r12, %rdi
    movabs $0x0000000200000001, %rsi
    xor %edx, %edx
    syscall
    cmp $-1, %rax
    jne .fail29

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail29

    xor %edi, %edi
    jmp .exit
'''
replace_one("tests/fixtures/probe.S", old_tail, new_tail, "cross-word raw oracle")

old_test = '''#[test]
fn seccomp_forbidden_mask_denies_wx_without_blocking_rw_or_rx() {
    let mut filtered = policy("k", &[], &["execveat", "mmap", "munmap", "exit"]);
    let mut mmap_rules = BTreeMap::new();
    mmap_rules.insert(
        2,
        SeccompArgRule {
            mask: 0x6,
            value: 0x6,
        },
    );
    filtered
        .seccomp
        .argument_forbidden_mask_rules
        .insert("mmap".to_owned(), mmap_rules);

    assert_eq!(run(&filtered).unwrap(), ChildOutcome::Exited(0));
}
'''
new_test = '''#[test]
fn seccomp_forbidden_mask_checks_full_64_bit_pattern_without_overblocking() {
    let mut filtered = policy(
        "k",
        &[],
        &["execveat", "mmap", "munmap", "openat", "lseek", "close", "exit"],
    );
    let mut mmap_rules = BTreeMap::new();
    mmap_rules.insert(
        2,
        SeccompArgRule {
            mask: 0x6,
            value: 0x6,
        },
    );
    filtered
        .seccomp
        .argument_forbidden_mask_rules
        .insert("mmap".to_owned(), mmap_rules);

    let mut lseek_rules = BTreeMap::new();
    lseek_rules.insert(
        1,
        SeccompArgRule {
            mask: 0xffff_ffff_0000_0001,
            value: 0x0000_0002_0000_0001,
        },
    );
    filtered
        .seccomp
        .argument_forbidden_mask_rules
        .insert("lseek".to_owned(), lseek_rules);

    assert_eq!(run(&filtered).unwrap(), ChildOutcome::Exited(0));
}
'''
replace_one("tests/sandbox.rs", old_test, new_test, "cross-word integration test")

# THREAT_MODEL already has a 29A executable-evidence bullet. Strengthen it with
# the cross-word oracle. README currently summarizes the semantics but has no
# corresponding evidence bullet, so do not invent a brittle placement there.
p = Path("THREAT_MODEL.md")
text = p.read_text()
old = "forbidden-mask seccomp parser/validator regressions plus a raw `mmap` oracle"
count = text.count(old)
if count != 1:
    raise SystemExit(f"THREAT_MODEL forbidden-mask evidence: expected exactly one match, got {count}")
text = text.replace(
    old,
    "forbidden-mask seccomp parser/validator regressions plus a cross-word raw `lseek` oracle where one participating low-bit mismatch and one high-word mismatch each remain allowed while the exact two-half masked match returns `EPERM`, together with a raw `mmap` oracle",
    1,
)
p.write_text(text)

p = Path("ROADMAP.md")
text = p.read_text()
old = "- a raw `mmap` oracle declares `mask=0x6,value=0x6` on protection argument 2, proves RW and RX anonymous mappings succeed, and requires exact `EPERM` for RWX;\n"
new = "- a raw `mmap` oracle declares `mask=0x6,value=0x6` on protection argument 2, proves RW and RX anonymous mappings succeed, and requires exact `EPERM` for RWX;\n- a second raw `lseek` oracle declares `mask=0xffffffff00000001,value=0x0000000200000001`, proves a low participating-bit mismatch and a high-word mismatch each continue successfully, and requires exact `EPERM` only when both 32-bit halves match the forbidden 64-bit pattern;\n"
count = text.count(old)
if count != 1:
    raise SystemExit(f"ROADMAP cross-word evidence: expected exactly one match, got {count}")
p.write_text(text.replace(old, new, 1))
