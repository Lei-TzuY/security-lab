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
    "#   z mutate an ephemeral copy-on-write root and verify merged-state behavior\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "#   z mutate an ephemeral copy-on-write root and verify merged-state behavior\n#   l fill an ephemeral copy-on-write root until the declared byte budget returns ENOSPC\n#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports",
    "raw fixture COW budget mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $122, %al\n    je .copy_on_write_root\n    cmp $115, %al",
    "    cmp $122, %al\n    je .copy_on_write_root\n    cmp $108, %al\n    je .copy_on_write_root_capacity\n    cmp $115, %al",
    "raw fixture COW budget dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".fail48_cow_stack:\n    add $32, %rsp\n    jmp .fail48\n\n.forbidden:",
    ".fail48_cow_stack:\n    add $32, %rsp\n    jmp .fail48\n\n.copy_on_write_root_capacity:\n    sub $4096, %rsp\n    mov $257, %eax\n    mov $-100, %edi\n    lea cow_capacity_path(%rip), %rsi\n    mov $577, %edx\n    mov $384, %r10d\n    syscall\n    test %rax, %rax\n    js .fail48_cow_capacity_stack\n    mov %rax, %r12\n    xor %r13d, %r13d\n\n.copy_on_write_root_capacity_write:\n    mov $1, %eax\n    mov %r12, %rdi\n    mov %rsp, %rsi\n    mov $4096, %edx\n    syscall\n    cmp $-28, %rax\n    je .copy_on_write_root_capacity_full\n    test %rax, %rax\n    jle .fail48_cow_capacity_close\n    add %rax, %r13\n    cmp $65536, %r13\n    ja .fail48_cow_capacity_close\n    jmp .copy_on_write_root_capacity_write\n\n.copy_on_write_root_capacity_full:\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail48_cow_capacity_stack\n    add $4096, %rsp\n    xor %edi, %edi\n    jmp .exit\n\n.fail48_cow_capacity_close:\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n.fail48_cow_capacity_stack:\n    add $4096, %rsp\n    jmp .fail48\n\n.forbidden:",
    "raw fixture COW budget oracle",
)

replace_one(
    "tests/sandbox.rs",
    "fn clock_nanos(clock_id: libc::clockid_t) -> i128 {",
    "#[test]\nfn copy_on_write_root_byte_budget_is_kernel_enforced() {\n    const COW_BUDGET_BYTES: u64 = 64 * 1024;\n    let created = fixture_root().join(\"cow-capacity\");\n    let _ = std::fs::remove_file(&created);\n\n    let mut cow = policy(\n        \"l\",\n        &[],\n        &[\"execveat\", \"openat\", \"write\", \"close\", \"exit\"],\n    );\n    cow.cow_root_bytes = Some(COW_BUDGET_BYTES);\n    let report = run_report(&cow).expect(\"copy-on-write root budget sandbox failed\");\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    assert!(report.enforcement.copy_on_write_root);\n    assert!(!report.enforcement.readonly_root);\n    assert!(\n        !created.exists(),\n        \"COW budget oracle persisted its upper-layer file into the host lower tree\"\n    );\n}\n\nfn clock_nanos(clock_id: libc::clockid_t) -> i128 {",
    "COW budget integration regression",
)

replace_one(
    "README.md",
    "- a raw target under COW root overwrites an existing lower file, creates a new root file, removes a lower pathname from its merged view, and observes the changed merged state; after two independent runs the trusted parent proves the original host-lower bytes are unchanged and the new file never persisted there;\n- COW root composes with the existing private scratch layer and with a declared read-only persistent volume:",
    "- a raw target under COW root overwrites an existing lower file, creates a new root file, removes a lower pathname from its merged view, and observes the changed merged state; after two independent runs the trusted parent proves the original host-lower bytes are unchanged and the new file never persisted there;\n- a separate raw target with `filesystem.cow_root_bytes = 65536` writes real 4 KiB chunks into a new merged-root file until the backing tmpfs returns exact `ENOSPC`; the oracle fails if successful payload bytes ever exceed the declared 64 KiB ceiling, and the trusted parent proves the file did not persist into the host lower tree;\n- COW root composes with the existing private scratch layer and with a declared read-only persistent volume:",
    "README COW budget evidence",
)
replace_one(
    "ROADMAP.md",
    "- a raw target modifies, creates, and removes paths in the merged root while the trusted parent proves the original lower marker remains byte-for-byte unchanged and no new file persists across two independent runs;\n- the existing private scratch mount composes above the COW root,",
    "- a raw target modifies, creates, and removes paths in the merged root while the trusted parent proves the original lower marker remains byte-for-byte unchanged and no new file persists across two independent runs;\n- a separate 64 KiB COW-budget oracle writes real 4 KiB chunks until exact `ENOSPC`, fails if successful payload bytes exceed the declared ceiling, and proves the budget-test file does not persist into the host lower tree;\n- the existing private scratch mount composes above the COW root,",
    "ROADMAP COW budget evidence",
)
