from pathlib import Path

path = Path("src/platform/linux.rs")
text = path.read_text()
old = '''        let mut filter = Vec::new();
        filter.push(stmt(BPF_LD_W_ABS, 4));
        filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(stmt(BPF_LD_W_ABS, 0));
'''
new = '''        let mut filter = vec![
            stmt(BPF_LD_W_ABS, 4),
            jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
            stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS),
            stmt(BPF_LD_W_ABS, 0),
        ];
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"seccomp filter initialization: expected one match, got {count}")
path.write_text(text.replace(old, new, 1))
