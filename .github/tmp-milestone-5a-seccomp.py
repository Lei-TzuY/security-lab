from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Policy model: argument rules are structured data, not opaque strings.
replace_one(
    "src/policy.rs",
    "const MAX_SYSCALLS: usize = 128;\n",
    "const MAX_SYSCALLS: usize = 128;\nconst MAX_SECCOMP_ARG_RULES: usize = 64;\n",
    "policy arg-rule ceiling",
)
replace_one(
    "src/policy.rs",
    '''#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompPolicy {
    /// Syscall names allowed by the policy. Every other syscall is denied with
    /// `EPERM` by the Linux x86_64 enforcement layer.
    pub allowed_syscalls: BTreeSet<String>,
}
''',
    '''#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeccompArgRule {
    /// Bits of the selected 64-bit syscall argument that participate in the
    /// equality test. Zero masks are invalid because they constrain nothing.
    pub mask: u64,
    /// Expected value after masking. Bits outside `mask` must be zero.
    pub value: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompPolicy {
    /// Syscall names allowed by the policy. Every other syscall is denied with
    /// `EPERM` by the Linux x86_64 enforcement layer.
    pub allowed_syscalls: BTreeSet<String>,
    /// Optional masked-equality constraints keyed by syscall name and argument
    /// index (0 through 5). Rules only narrow syscalls already in the allowlist.
    pub argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>>,
}
''',
    "policy seccomp structures",
)
replace_one(
    "src/policy.rs",
    '''        for name in &self.seccomp.allowed_syscalls {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(PolicyError::new(format!(
                    "invalid syscall name syntax: {name:?}"
                )));
            }
        }

        Ok(())
''',
    '''        for name in &self.seccomp.allowed_syscalls {
            if !valid_syscall_name(name) {
                return Err(PolicyError::new(format!(
                    "invalid syscall name syntax: {name:?}"
                )));
            }
        }

        let argument_rule_count = self
            .seccomp
            .argument_rules
            .values()
            .map(BTreeMap::len)
            .sum::<usize>();
        if argument_rule_count > MAX_SECCOMP_ARG_RULES {
            return Err(PolicyError::new(format!(
                "too many seccomp argument rules: {argument_rule_count} > {MAX_SECCOMP_ARG_RULES}"
            )));
        }
        for (syscall, rules) in &self.seccomp.argument_rules {
            if !valid_syscall_name(syscall) {
                return Err(PolicyError::new(format!(
                    "invalid seccomp argument-rule syscall name: {syscall:?}"
                )));
            }
            if !self.seccomp.allowed_syscalls.contains(syscall) {
                return Err(PolicyError::new(format!(
                    "seccomp argument rule for {syscall} requires that syscall in seccomp.allow"
                )));
            }
            if matches!(syscall.as_str(), "execveat" | "exit" | "exit_group") {
                return Err(PolicyError::new(format!(
                    "seccomp argument rules may not constrain launcher-critical syscall {syscall}"
                )));
            }
            for (argument_index, rule) in rules {
                if *argument_index > 5 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument index for {syscall} must be between 0 and 5"
                    )));
                }
                if rule.mask == 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument mask for {syscall}.{argument_index} must not be zero"
                    )));
                }
                if rule.value & !rule.mask != 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp argument value for {syscall}.{argument_index} sets bits outside its mask"
                    )));
                }
            }
        }

        Ok(())
''',
    "policy seccomp validation",
)
replace_one(
    "src/policy.rs",
    "        let mut seccomp = None;\n",
    "        let mut seccomp_allow = None;\n        let mut seccomp_argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>> =\n            BTreeMap::new();\n",
    "policy parser seccomp state",
)
replace_one(
    "src/policy.rs",
    '''                "seccomp.allow" => {
                    if seccomp.is_some() {
                        return Err(PolicyError::at(line_no, "duplicate seccomp.allow"));
                    }
                    let mut names = BTreeSet::new();
                    for name in value.split(',').map(str::trim) {
                        if name.is_empty() {
                            return Err(PolicyError::at(
                                line_no,
                                "seccomp.allow contains an empty syscall name",
                            ));
                        }
                        if !names.insert(name.to_owned()) {
                            return Err(PolicyError::at(
                                line_no,
                                format!("duplicate syscall in seccomp.allow: {name}"),
                            ));
                        }
                    }
                    seccomp = Some(SeccompPolicy {
                        allowed_syscalls: names,
                    });
                }
                _ => {
''',
    '''                "seccomp.allow" => {
                    if seccomp_allow.is_some() {
                        return Err(PolicyError::at(line_no, "duplicate seccomp.allow"));
                    }
                    let mut names = BTreeSet::new();
                    for name in value.split(',').map(str::trim) {
                        if name.is_empty() {
                            return Err(PolicyError::at(
                                line_no,
                                "seccomp.allow contains an empty syscall name",
                            ));
                        }
                        if !names.insert(name.to_owned()) {
                            return Err(PolicyError::at(
                                line_no,
                                format!("duplicate syscall in seccomp.allow: {name}"),
                            ));
                        }
                    }
                    seccomp_allow = Some(names);
                }
                _ if key.starts_with("seccomp.arg.") => {
                    let spec = key
                        .strip_prefix("seccomp.arg.")
                        .expect("prefix checked above");
                    let (syscall, index_text) = spec.rsplit_once('.').ok_or_else(|| {
                        PolicyError::at(
                            line_no,
                            "seccomp argument key must be seccomp.arg.<syscall>.<0..5>",
                        )
                    })?;
                    if !valid_syscall_name(syscall) {
                        return Err(PolicyError::at(
                            line_no,
                            format!("invalid seccomp argument-rule syscall name: {syscall:?}"),
                        ));
                    }
                    let argument_index = index_text.parse::<u8>().map_err(|_| {
                        PolicyError::at(line_no, "seccomp argument index must be between 0 and 5")
                    })?;
                    if argument_index > 5 {
                        return Err(PolicyError::at(
                            line_no,
                            "seccomp argument index must be between 0 and 5",
                        ));
                    }
                    let rule = parse_seccomp_arg_rule(value, line_no, key)?;
                    let syscall_rules = seccomp_argument_rules
                        .entry(syscall.to_owned())
                        .or_default();
                    if syscall_rules.insert(argument_index, rule).is_some() {
                        return Err(PolicyError::at(
                            line_no,
                            format!("duplicate seccomp argument rule: {syscall}.{argument_index}"),
                        ));
                    }
                }
                _ => {
''',
    "policy parser seccomp arg keys",
)
replace_one(
    "src/policy.rs",
    '''            seccomp: required(seccomp, "seccomp.allow")?,
''',
    '''            seccomp: SeccompPolicy {
                allowed_syscalls: required(seccomp_allow, "seccomp.allow")?,
                argument_rules: seccomp_argument_rules,
            },
''',
    "policy final seccomp model",
)
replace_one(
    "src/policy.rs",
    '''fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {
''',
    '''fn parse_seccomp_arg_rule(
    value: &str,
    line: usize,
    key: &str,
) -> Result<SeccompArgRule, PolicyError> {
    let (mask, expected) = value.split_once(':').ok_or_else(|| {
        PolicyError::at(
            line,
            format!("{key} must be formatted as <mask>:<value>"),
        )
    })?;
    Ok(SeccompArgRule {
        mask: parse_u64_literal(mask.trim(), line, key)?,
        value: parse_u64_literal(expected.trim(), line, key)?,
    })
}

fn parse_u64_literal(value: &str, line: usize, key: &str) -> Result<u64, PolicyError> {
    if let Some(hex) = value.strip_prefix("0x") {
        if hex.is_empty() {
            return Err(PolicyError::at(
                line,
                format!("{key} contains an empty hexadecimal integer"),
            ));
        }
        u64::from_str_radix(hex, 16)
            .map_err(|_| PolicyError::at(line, format!("{key} contains an invalid integer")))
    } else {
        value
            .parse::<u64>()
            .map_err(|_| PolicyError::at(line, format!("{key} contains an invalid integer")))
    }
}

fn parse_stdio_mode(value: &str, line: usize, key: &str) -> Result<StdioMode, PolicyError> {
''',
    "policy seccomp rule parser helper",
)
replace_one(
    "src/policy.rs",
    '''fn valid_env_key(key: &str) -> bool {
''',
    '''fn valid_syscall_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_env_key(key: &str) -> bool {
''',
    "policy syscall-name helper",
)
replace_one(
    "src/policy.rs",
    '''        assert!(policy.seccomp.allowed_syscalls.contains("execveat"));
    }
''',
    '''        assert!(policy.seccomp.allowed_syscalls.contains("execveat"));
        assert!(policy.seccomp.argument_rules.is_empty());
    }
''',
    "policy complete rule assertion",
)
replace_one(
    "src/policy.rs",
    '''    #[test]
    fn rejects_duplicate_syscall() {
''',
    '''    #[test]
    fn parses_masked_seccomp_argument_rule() {
        let text = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,lseek,exit_group\\n        seccomp.arg.lseek.1 = 0xffffffff0000000f:0x0000000100000008",
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        let rule = policy
            .seccomp
            .argument_rules
            .get("lseek")
            .and_then(|rules| rules.get(&1))
            .copied()
            .expect("lseek argument rule");
        assert_eq!(rule.mask, 0xffff_ffff_0000_000f);
        assert_eq!(rule.value, 0x0000_0001_0000_0008);
    }

    #[test]
    fn rejects_duplicate_seccomp_argument_rule() {
        let text = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,lseek,exit_group\\n        seccomp.arg.lseek.1 = 0xff:0x08\\n        seccomp.arg.lseek.1 = 0xff:0x08",
        );
        assert!(text.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_invalid_seccomp_argument_rule_shape() {
        for rule in [
            "seccomp.arg.lseek.6 = 0xff:0x08",
            "seccomp.arg.lseek.1 = 0:0",
            "seccomp.arg.lseek.1 = 0x0f:0x10",
        ] {
            let text = VALID.replace(
                "seccomp.allow = execveat,read,write,exit_group",
                &format!("seccomp.allow = execveat,lseek,exit_group\\n        {rule}"),
            );
            assert!(text.parse::<SandboxPolicy>().is_err(), "accepted {rule}");
        }
    }

    #[test]
    fn rejects_argument_rule_for_unallowed_or_launcher_critical_syscall() {
        let unallowed = format!("{VALID}\\nseccomp.arg.lseek.1 = 0xff:0x08");
        assert!(unallowed.parse::<SandboxPolicy>().is_err());

        let exec_rule = format!("{VALID}\\nseccomp.arg.execveat.0 = 0xff:0x00");
        assert!(exec_rule.parse::<SandboxPolicy>().is_err());

        let exit_rule = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,read,write,exit\\n        seccomp.arg.exit.0 = 0xff:0x00",
        );
        assert!(exit_rule.parse::<SandboxPolicy>().is_err());
    }

    #[test]
    fn rejects_duplicate_syscall() {
''',
    "policy seccomp argument tests",
)

# Public API re-export.
replace_one(
    "src/lib.rs",
    '''    PolicyError, ResourceLimits, SandboxPolicy, SeccompPolicy, StdioMode, StdioPolicy,
''',
    '''    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode,
    StdioPolicy,
''',
    "lib seccomp arg reexport",
)

# Linux cBPF compiler: full 64-bit masked equality over seccomp_data.args[].
replace_one(
    "src/platform/linux.rs",
    '''    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
''',
    '''    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_ALU_AND_K: u16 = 0x54;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
''',
    "linux cBPF arg constants",
)
replace_one(
    "src/platform/linux.rs",
    '''    fn compile_seccomp(policy: &SandboxPolicy) -> Result<CompiledSeccomp, SandboxError> {
        let error_exit_syscall = if policy.seccomp.allowed_syscalls.contains("exit") {
            libc::SYS_exit
        } else if policy.seccomp.allowed_syscalls.contains("exit_group") {
            libc::SYS_exit_group
        } else {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include exit or exit_group so launch failures can terminate after filter installation",
            )));
        };

        if !policy.seccomp.allowed_syscalls.contains("execveat") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execveat so the pinned child can start",
            )));
        }

        let mut numbers = Vec::with_capacity(policy.seccomp.allowed_syscalls.len());
        for name in &policy.seccomp.allowed_syscalls {
            let number = syscall_number(name).ok_or_else(|| {
                SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "unsupported Linux x86_64 syscall name: {name}"
                )))
            })?;
            numbers.push(number as u32);
        }
        numbers.sort_unstable();
        numbers.dedup();

        let mut filter = Vec::with_capacity(5 + numbers.len() * 2);
        filter.push(stmt(BPF_LD_W_ABS, 4));
        filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(stmt(BPF_LD_W_ABS, 0));
        for number in numbers {
            filter.push(jump(BPF_JMP_JEQ_K, number, 0, 1));
            filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
        }
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));

        if filter.len() > u16::MAX as usize {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp program is too large",
            )));
        }

        Ok(CompiledSeccomp {
            filter,
            error_exit_syscall,
        })
    }
''',
    '''    fn compile_seccomp(policy: &SandboxPolicy) -> Result<CompiledSeccomp, SandboxError> {
        let error_exit_syscall = if policy.seccomp.allowed_syscalls.contains("exit") {
            libc::SYS_exit
        } else if policy.seccomp.allowed_syscalls.contains("exit_group") {
            libc::SYS_exit_group
        } else {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include exit or exit_group so launch failures can terminate after filter installation",
            )));
        };

        if !policy.seccomp.allowed_syscalls.contains("execveat") {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp allowlist must include execveat so the pinned child can start",
            )));
        }

        let mut syscalls = Vec::with_capacity(policy.seccomp.allowed_syscalls.len());
        for name in &policy.seccomp.allowed_syscalls {
            let number = syscall_number(name).ok_or_else(|| {
                SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "unsupported Linux x86_64 syscall name: {name}"
                )))
            })?;
            syscalls.push((number as u32, name.as_str()));
        }
        syscalls.sort_unstable_by_key(|(number, _)| *number);
        for pair in syscalls.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "multiple syscall names resolve to Linux x86_64 number {}",
                    pair[0].0
                ))));
            }
        }

        let mut filter = Vec::new();
        filter.push(stmt(BPF_LD_W_ABS, 4));
        filter.push(jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
        filter.push(stmt(BPF_LD_W_ABS, 0));

        for (number, name) in syscalls {
            let mut checks = Vec::new();
            if let Some(rules) = policy.seccomp.argument_rules.get(name) {
                for (argument_index, rule) in rules {
                    append_seccomp_argument_checks(
                        &mut checks,
                        *argument_index,
                        rule.mask,
                        rule.value,
                    );
                }
            }
            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            if checks.len() > u8::MAX as usize {
                return Err(SandboxError::InvalidPolicy(PolicyError::new(format!(
                    "seccomp argument-check block for {name} is too large"
                ))));
            }
            filter.push(jump(BPF_JMP_JEQ_K, number, 0, checks.len() as u8));
            filter.extend(checks);
        }
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));

        if filter.len() > u16::MAX as usize {
            return Err(SandboxError::InvalidPolicy(PolicyError::new(
                "seccomp program is too large",
            )));
        }

        Ok(CompiledSeccomp {
            filter,
            error_exit_syscall,
        })
    }

    fn append_seccomp_argument_checks(
        filter: &mut Vec<libc::sock_filter>,
        argument_index: u8,
        mask: u64,
        value: u64,
    ) {
        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;
        append_seccomp_argument_word_check(
            filter,
            argument_offset,
            mask as u32,
            value as u32,
        );
        append_seccomp_argument_word_check(
            filter,
            argument_offset + 4,
            (mask >> 32) as u32,
            (value >> 32) as u32,
        );
    }

    fn append_seccomp_argument_word_check(
        filter: &mut Vec<libc::sock_filter>,
        offset: u32,
        mask: u32,
        value: u32,
    ) {
        if mask == 0 {
            return;
        }
        filter.push(stmt(BPF_LD_W_ABS, offset));
        if mask != u32::MAX {
            filter.push(stmt(BPF_ALU_AND_K, mask));
        }
        filter.push(jump(BPF_JMP_JEQ_K, value, 1, 0));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
    }
''',
    "linux seccomp compiler",
)

# Integration helper and executable oracle.
replace_one(
    "tests/sandbox.rs",
    '''    run, run_report, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy, SeccompPolicy,
    StdioMode, StdioPolicy,
''',
    '''    run, run_report, ChildOutcome, ResourceLimits, SandboxError, SandboxPolicy,
    SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,
''',
    "sandbox seccomp arg import",
)
replace_one(
    "tests/sandbox.rs",
    '''        seccomp: SeccompPolicy {
            allowed_syscalls: syscall_set(syscalls),
        },
''',
    '''        seccomp: SeccompPolicy {
            allowed_syscalls: syscall_set(syscalls),
            argument_rules: BTreeMap::new(),
        },
''',
    "sandbox default seccomp rules",
)
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn allowed_operation_succeeds() {
''',
    '''#[test]
fn seccomp_argument_filter_checks_full_64_bit_masked_value() {
    let mut filtered = policy(
        "B",
        &[],
        &["execveat", "openat", "lseek", "close", "exit"],
    );
    let mut lseek_rules = BTreeMap::new();
    lseek_rules.insert(
        1,
        SeccompArgRule {
            mask: 0xffff_ffff_0000_000f,
            value: 0x0000_0001_0000_0008,
        },
    );
    filtered
        .seccomp
        .argument_rules
        .insert("lseek".to_owned(), lseek_rules);

    assert_eq!(run(&filtered).unwrap(), ChildOutcome::Exited(0));
}

#[test]
fn allowed_operation_succeeds() {
''',
    "sandbox seccomp arg integration test",
)

# Raw target: one allowed lseek offset, then denied low/high masked mismatches.
replace_one(
    "tests/fixtures/probe.S",
    "#   A allowed write\n",
    "#   A allowed write\n#   B assert 64-bit masked seccomp argument filtering on lseek offset\n",
    "probe seccomp mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    cmp $65, %al
    je .allowed
    cmp $70, %al
''',
    '''    cmp $65, %al
    je .allowed
    cmp $66, %al
    je .seccomp_argument_filter
    cmp $70, %al
''',
    "probe seccomp mode dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    '''    xor %edi, %edi
    jmp .exit

.forbidden:
''',
    '''    xor %edi, %edi
    jmp .exit

.seccomp_argument_filter:
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
    movabs $0x0000000112345678, %rsi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail29

    mov $8, %eax
    mov %r12, %rdi
    movabs $0x0000000112345679, %rsi
    xor %edx, %edx
    syscall
    cmp $-1, %rax
    jne .fail29

    mov $8, %eax
    mov %r12, %rdi
    movabs $0x0000000212345678, %rsi
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

.forbidden:
''',
    "probe seccomp arg oracle",
)
replace_one(
    "tests/fixtures/probe.S",
    '''.fail28:
    mov $28, %edi

.exit:
''',
    '''.fail28:
    mov $28, %edi
    jmp .exit
.fail29:
    mov $29, %edi

.exit:
''',
    "probe fail29",
)
replace_one(
    "tests/fixtures/probe.S",
    '''sandbox_root:
    .asciz "/"
''',
    '''sandbox_root:
    .asciz "/"
probe_path:
    .asciz "/probe"
''',
    "probe path rodata",
)
