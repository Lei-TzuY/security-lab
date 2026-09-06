from pathlib import Path
import sys


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def add_parser_red_test() -> None:
    replace_one(
        "src/policy.rs",
        "    #[test]\n    fn parses_masked_seccomp_argument_rule() {\n",
        "    #[test]\n    fn parses_seccomp_argument_range_rule_syntax() {\n        let text = VALID.replace(\n            \"seccomp.allow = execveat,read,write,exit_group\",\n            \"seccomp.allow = execveat,lseek,exit_group\\n        seccomp.range.lseek.1 = 0x00000000fffffff0:0x0000000100000010\",\n        );\n        assert!(text.parse::<SandboxPolicy>().is_ok());\n    }\n\n    #[test]\n    fn parses_masked_seccomp_argument_rule() {\n",
        "range parser red test",
    )


def materialize_production() -> None:
    # Public policy model: keep masked equality source-compatible and add a distinct range map.
    replace_one(
        "src/policy.rs",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct SeccompArgRule {\n    /// Bits of the selected 64-bit syscall argument that participate in the\n    /// equality test. Zero masks are invalid because they constrain nothing.\n    pub mask: u64,\n    /// Expected value after masking. Bits outside `mask` must be zero.\n    pub value: u64,\n}\n\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct SeccompPolicy {\n",
        "#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct SeccompArgRule {\n    /// Bits of the selected 64-bit syscall argument that participate in the\n    /// equality test. Zero masks are invalid because they constrain nothing.\n    pub mask: u64,\n    /// Expected value after masking. Bits outside `mask` must be zero.\n    pub value: u64,\n}\n\n#[derive(Debug, Clone, Copy, PartialEq, Eq)]\npub struct SeccompArgRangeRule {\n    /// Inclusive unsigned lower bound for the selected raw 64-bit argument.\n    pub minimum: u64,\n    /// Inclusive unsigned upper bound for the selected raw 64-bit argument.\n    pub maximum: u64,\n}\n\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct SeccompPolicy {\n",
        "range rule type",
    )
    replace_one(
        "src/policy.rs",
        "    /// Optional masked-equality constraints keyed by syscall name and argument\n    /// index (0 through 5). Rules only narrow syscalls already in the allowlist.\n    pub argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>>,\n",
        "    /// Optional masked-equality constraints keyed by syscall name and argument\n    /// index (0 through 5). Rules only narrow syscalls already in the allowlist.\n    pub argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>>,\n    /// Optional inclusive unsigned 64-bit ranges keyed by syscall and argument\n    /// index. Range rules compose conjunctively with masked-equality rules.\n    pub argument_range_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRangeRule>>,\n",
        "range map field",
    )

    replace_one(
        "src/policy.rs",
        "        let argument_rule_count = self\n            .seccomp\n            .argument_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        if argument_rule_count > MAX_SECCOMP_ARG_RULES {\n            return Err(PolicyError::new(format!(\n                \"too many seccomp argument rules: {argument_rule_count} > {MAX_SECCOMP_ARG_RULES}\"\n            )));\n        }\n",
        "        let masked_rule_count = self\n            .seccomp\n            .argument_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        let range_rule_count = self\n            .seccomp\n            .argument_range_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        let argument_rule_count = masked_rule_count + range_rule_count;\n        if argument_rule_count > MAX_SECCOMP_ARG_RULES {\n            return Err(PolicyError::new(format!(\n                \"too many seccomp argument rules: {argument_rule_count} > {MAX_SECCOMP_ARG_RULES}\"\n            )));\n        }\n",
        "combined argument constraint count",
    )
    replace_one(
        "src/policy.rs",
        "        for (syscall, rules) in &self.seccomp.argument_rules {\n            if !valid_syscall_name(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"invalid seccomp argument-rule syscall name: {syscall:?}\"\n                )));\n            }\n            if !self.seccomp.allowed_syscalls.contains(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"seccomp argument rule for {syscall} requires that syscall in seccomp.allow\"\n                )));\n            }\n            if matches!(syscall.as_str(), \"execveat\" | \"exit\" | \"exit_group\") {\n                return Err(PolicyError::new(format!(\n                    \"seccomp argument rules may not constrain launcher-critical syscall {syscall}\"\n                )));\n            }\n            for (argument_index, rule) in rules {\n                if *argument_index > 5 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument index for {syscall} must be between 0 and 5\"\n                    )));\n                }\n                if rule.mask == 0 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument mask for {syscall}.{argument_index} must not be zero\"\n                    )));\n                }\n                if rule.value & !rule.mask != 0 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument value for {syscall}.{argument_index} sets bits outside its mask\"\n                    )));\n                }\n            }\n        }\n\n        Ok(())\n",
        "        for (syscall, rules) in &self.seccomp.argument_rules {\n            if !valid_syscall_name(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"invalid seccomp argument-rule syscall name: {syscall:?}\"\n                )));\n            }\n            if !self.seccomp.allowed_syscalls.contains(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"seccomp argument rule for {syscall} requires that syscall in seccomp.allow\"\n                )));\n            }\n            if matches!(syscall.as_str(), \"execveat\" | \"exit\" | \"exit_group\") {\n                return Err(PolicyError::new(format!(\n                    \"seccomp argument rules may not constrain launcher-critical syscall {syscall}\"\n                )));\n            }\n            for (argument_index, rule) in rules {\n                if *argument_index > 5 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument index for {syscall} must be between 0 and 5\"\n                    )));\n                }\n                if rule.mask == 0 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument mask for {syscall}.{argument_index} must not be zero\"\n                    )));\n                }\n                if rule.value & !rule.mask != 0 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp argument value for {syscall}.{argument_index} sets bits outside its mask\"\n                    )));\n                }\n            }\n        }\n        for (syscall, rules) in &self.seccomp.argument_range_rules {\n            if !valid_syscall_name(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"invalid seccomp range-rule syscall name: {syscall:?}\"\n                )));\n            }\n            if !self.seccomp.allowed_syscalls.contains(syscall) {\n                return Err(PolicyError::new(format!(\n                    \"seccomp range rule for {syscall} requires that syscall in seccomp.allow\"\n                )));\n            }\n            if matches!(syscall.as_str(), \"execveat\" | \"exit\" | \"exit_group\") {\n                return Err(PolicyError::new(format!(\n                    \"seccomp range rules may not constrain launcher-critical syscall {syscall}\"\n                )));\n            }\n            for (argument_index, rule) in rules {\n                if *argument_index > 5 {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp range argument index for {syscall} must be between 0 and 5\"\n                    )));\n                }\n                if rule.minimum > rule.maximum {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp range minimum for {syscall}.{argument_index} must not exceed its maximum\"\n                    )));\n                }\n                if rule.minimum == 0 && rule.maximum == u64::MAX {\n                    return Err(PolicyError::new(format!(\n                        \"seccomp range for {syscall}.{argument_index} must narrow at least one value\"\n                    )));\n                }\n            }\n        }\n\n        Ok(())\n",
        "range validation",
    )

    replace_one(
        "src/policy.rs",
        "        let mut seccomp_argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>> =\n            BTreeMap::new();\n",
        "        let mut seccomp_argument_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>> =\n            BTreeMap::new();\n        let mut seccomp_argument_range_rules: BTreeMap<\n            String,\n            BTreeMap<u8, SeccompArgRangeRule>,\n        > = BTreeMap::new();\n",
        "range parser storage",
    )
    replace_one(
        "src/policy.rs",
        "                _ if key.starts_with(\"seccomp.arg.\") => {\n",
        "                _ if key.starts_with(\"seccomp.range.\") => {\n                    let spec = key\n                        .strip_prefix(\"seccomp.range.\")\n                        .expect(\"prefix checked above\");\n                    let (syscall, index_text) = spec.rsplit_once('.').ok_or_else(|| {\n                        PolicyError::at(\n                            line_no,\n                            \"seccomp range key must be seccomp.range.<syscall>.<0..5>\",\n                        )\n                    })?;\n                    if !valid_syscall_name(syscall) {\n                        return Err(PolicyError::at(\n                            line_no,\n                            format!(\"invalid seccomp range-rule syscall name: {syscall:?}\"),\n                        ));\n                    }\n                    let argument_index = index_text.parse::<u8>().map_err(|_| {\n                        PolicyError::at(line_no, \"seccomp range argument index must be between 0 and 5\")\n                    })?;\n                    if argument_index > 5 {\n                        return Err(PolicyError::at(\n                            line_no,\n                            \"seccomp range argument index must be between 0 and 5\",\n                        ));\n                    }\n                    let rule = parse_seccomp_arg_range_rule(value, line_no, key)?;\n                    let syscall_rules = seccomp_argument_range_rules\n                        .entry(syscall.to_owned())\n                        .or_default();\n                    if syscall_rules.insert(argument_index, rule).is_some() {\n                        return Err(PolicyError::at(\n                            line_no,\n                            format!(\"duplicate seccomp range rule: {syscall}.{argument_index}\"),\n                        ));\n                    }\n                }\n                _ if key.starts_with(\"seccomp.arg.\") => {\n",
        "range parser match",
    )
    replace_one(
        "src/policy.rs",
        "            seccomp: SeccompPolicy {\n                allowed_syscalls: required(seccomp_allow, \"seccomp.allow\")?,\n                argument_rules: seccomp_argument_rules,\n            },\n",
        "            seccomp: SeccompPolicy {\n                allowed_syscalls: required(seccomp_allow, \"seccomp.allow\")?,\n                argument_rules: seccomp_argument_rules,\n                argument_range_rules: seccomp_argument_range_rules,\n            },\n",
        "range policy construction",
    )
    replace_one(
        "src/policy.rs",
        "fn parse_u64_literal(value: &str, line: usize, key: &str) -> Result<u64, PolicyError> {\n",
        "fn parse_seccomp_arg_range_rule(\n    value: &str,\n    line: usize,\n    key: &str,\n) -> Result<SeccompArgRangeRule, PolicyError> {\n    let (minimum, maximum) = value.split_once(':').ok_or_else(|| {\n        PolicyError::at(line, format!(\"{key} must be formatted as <min>:<max>\"))\n    })?;\n    Ok(SeccompArgRangeRule {\n        minimum: parse_u64_literal(minimum.trim(), line, key)?,\n        maximum: parse_u64_literal(maximum.trim(), line, key)?,\n    })\n}\n\nfn parse_u64_literal(value: &str, line: usize, key: &str) -> Result<u64, PolicyError> {\n",
        "range parse helper",
    )

    # Replace the red parser test with full parser/validation evidence and retain the masked test.
    replace_one(
        "src/policy.rs",
        "    #[test]\n    fn parses_seccomp_argument_range_rule_syntax() {\n        let text = VALID.replace(\n            \"seccomp.allow = execveat,read,write,exit_group\",\n            \"seccomp.allow = execveat,lseek,exit_group\\n        seccomp.range.lseek.1 = 0x00000000fffffff0:0x0000000100000010\",\n        );\n        assert!(text.parse::<SandboxPolicy>().is_ok());\n    }\n\n",
        "    #[test]\n    fn parses_seccomp_argument_range_rule_syntax() {\n        let text = VALID.replace(\n            \"seccomp.allow = execveat,read,write,exit_group\",\n            \"seccomp.allow = execveat,lseek,exit_group\\n        seccomp.range.lseek.1 = 0x00000000fffffff0:0x0000000100000010\",\n        );\n        let policy: SandboxPolicy = text.parse().unwrap();\n        let rule = policy\n            .seccomp\n            .argument_range_rules\n            .get(\"lseek\")\n            .and_then(|rules| rules.get(&1))\n            .copied()\n            .expect(\"lseek argument range rule\");\n        assert_eq!(rule.minimum, 0x0000_0000_ffff_fff0);\n        assert_eq!(rule.maximum, 0x0000_0001_0000_0010);\n    }\n\n    #[test]\n    fn rejects_invalid_or_duplicate_seccomp_argument_range_rule() {\n        for rule in [\n            \"seccomp.range.lseek.6 = 1:2\",\n            \"seccomp.range.lseek.1 = 2:1\",\n            \"seccomp.range.lseek.1 = 0:18446744073709551615\",\n            \"seccomp.range.lseek.1 = not-a-range\",\n        ] {\n            let text = VALID.replace(\n                \"seccomp.allow = execveat,read,write,exit_group\",\n                &format!(\"seccomp.allow = execveat,lseek,exit_group\\n        {rule}\"),\n            );\n            assert!(text.parse::<SandboxPolicy>().is_err(), \"accepted {rule}\");\n        }\n\n        let duplicate = VALID.replace(\n            \"seccomp.allow = execveat,read,write,exit_group\",\n            \"seccomp.allow = execveat,lseek,exit_group\\n        seccomp.range.lseek.1 = 1:2\\n        seccomp.range.lseek.1 = 1:2\",\n        );\n        assert!(duplicate.parse::<SandboxPolicy>().is_err());\n\n        let unallowed = format!(\"{VALID}\\nseccomp.range.lseek.1 = 1:2\");\n        assert!(unallowed.parse::<SandboxPolicy>().is_err());\n\n        let critical = format!(\"{VALID}\\nseccomp.range.execveat.0 = 1:2\");\n        assert!(critical.parse::<SandboxPolicy>().is_err());\n    }\n\n",
        "range parser tests",
    )

    # Re-export the public rule type.
    replace_one(
        "src/lib.rs",
        "    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode,\n    StdioPolicy,\n",
        "    PolicyError, ResourceLimits, SandboxPolicy, SeccompArgRangeRule, SeccompArgRule,\n    SeccompPolicy, StdioMode, StdioPolicy,\n",
        "range rule export",
    )

    # cBPF compiler: unsigned high-word/low-word comparisons with local fail-fast branches.
    replace_one(
        "src/platform/linux.rs",
        "    const BPF_ALU_AND_K: u16 = 0x54;\n    const BPF_JMP_JEQ_K: u16 = 0x15;\n",
        "    const BPF_ALU_AND_K: u16 = 0x54;\n    const BPF_JMP_JEQ_K: u16 = 0x15;\n    const BPF_JMP_JGT_K: u16 = 0x25;\n    const BPF_JMP_JGE_K: u16 = 0x35;\n",
        "range BPF operators",
    )
    replace_one(
        "src/platform/linux.rs",
        "            if let Some(rules) = policy.seccomp.argument_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.mask,\n                        rule.value,\n                    );\n                }\n            }\n            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));\n",
        "            if let Some(rules) = policy.seccomp.argument_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.mask,\n                        rule.value,\n                    );\n                }\n            }\n            if let Some(rules) = policy.seccomp.argument_range_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_range_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.minimum,\n                        rule.maximum,\n                    );\n                }\n            }\n            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));\n",
        "range compiler integration",
    )
    replace_one(
        "src/platform/linux.rs",
        "    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {\n",
        "    fn append_seccomp_argument_range_checks(\n        filter: &mut Vec<libc::sock_filter>,\n        argument_index: u8,\n        minimum: u64,\n        maximum: u64,\n    ) {\n        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;\n        let minimum_low = minimum as u32;\n        let minimum_high = (minimum >> 32) as u32;\n        let maximum_low = maximum as u32;\n        let maximum_high = (maximum >> 32) as u32;\n\n        // Unsigned lower bound. A high word above minimum skips the low-word\n        // comparison; equality requires low >= minimum_low.\n        filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));\n        filter.push(jump(BPF_JMP_JGE_K, minimum_high, 1, 0));\n        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));\n        filter.push(jump(BPF_JMP_JEQ_K, minimum_high, 0, 3));\n        filter.push(stmt(BPF_LD_W_ABS, argument_offset));\n        filter.push(jump(BPF_JMP_JGE_K, minimum_low, 1, 0));\n        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));\n\n        // Unsigned upper bound. A high word below maximum skips the low-word\n        // comparison; equality requires low <= maximum_low.\n        filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));\n        filter.push(jump(BPF_JMP_JGT_K, maximum_high, 0, 1));\n        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));\n        filter.push(jump(BPF_JMP_JEQ_K, maximum_high, 0, 3));\n        filter.push(stmt(BPF_LD_W_ABS, argument_offset));\n        filter.push(jump(BPF_JMP_JGT_K, maximum_low, 0, 1));\n        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));\n    }\n\n    fn ensure_landlock_supported(policy: &SandboxPolicy) -> Result<(), SandboxError> {\n",
        "range BPF helpers",
    )

    # Integration test policy literals and range oracle.
    replace_one(
        "tests/sandbox.rs",
        "    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, ResourceLimits,\n    SandboxError, SandboxPolicy, SeccompArgRule, SeccompPolicy, StdioMode, StdioPolicy,\n",
        "    run, run_report, run_report_with_cancel, CancellationToken, ChildOutcome, ResourceLimits,\n    SandboxError, SandboxPolicy, SeccompArgRangeRule, SeccompArgRule, SeccompPolicy, StdioMode,\n    StdioPolicy,\n",
        "range integration import",
    )
    replace_one(
        "tests/sandbox.rs",
        "        seccomp: SeccompPolicy {\n            allowed_syscalls: syscall_set(syscalls),\n            argument_rules: BTreeMap::new(),\n        },\n",
        "        seccomp: SeccompPolicy {\n            allowed_syscalls: syscall_set(syscalls),\n            argument_rules: BTreeMap::new(),\n            argument_range_rules: BTreeMap::new(),\n        },\n",
        "range helper default",
    )
    replace_one(
        "tests/sandbox.rs",
        "#[test]\nfn allowed_operation_succeeds() {\n",
        "#[test]\nfn seccomp_argument_range_checks_unsigned_64_bit_boundaries_and_composes() {\n    let mut filtered = policy(\"x\", &[], &[\"execveat\", \"openat\", \"lseek\", \"close\", \"exit\"]);\n\n    let mut lseek_ranges = BTreeMap::new();\n    lseek_ranges.insert(\n        1,\n        SeccompArgRangeRule {\n            minimum: 0x0000_0000_ffff_fff0,\n            maximum: 0x0000_0001_0000_0010,\n        },\n    );\n    filtered\n        .seccomp\n        .argument_range_rules\n        .insert(\"lseek\".to_owned(), lseek_ranges);\n\n    // Compose a masked-equality rule on the same argument: in-range odd values\n    // must still fail, proving both predicate families are conjunctive.\n    let mut lseek_masks = BTreeMap::new();\n    lseek_masks.insert(\n        1,\n        SeccompArgRule {\n            mask: 1,\n            value: 0,\n        },\n    );\n    filtered\n        .seccomp\n        .argument_rules\n        .insert(\"lseek\".to_owned(), lseek_masks);\n\n    assert_eq!(run(&filtered).unwrap(), ChildOutcome::Exited(0));\n}\n\n#[test]\nfn allowed_operation_succeeds() {\n",
        "range integration test",
    )

    # Raw fixture: cross a 32-bit boundary and distinguish range from mask denial.
    replace_one(
        "tests/fixtures/probe.S",
        "#   B assert 64-bit masked seccomp argument filtering on lseek offset\n",
        "#   B assert 64-bit masked seccomp argument filtering on lseek offset\n#   x assert unsigned 64-bit inclusive seccomp range filtering on lseek offset\n",
        "range fixture comment",
    )
    replace_one(
        "tests/fixtures/probe.S",
        "    cmp $117, %al\n    je .pidfd_signal_denied\n",
        "    cmp $117, %al\n    je .pidfd_signal_denied\n    cmp $120, %al\n    je .seccomp_argument_range\n",
        "range fixture dispatch",
    )
    replace_one(
        "tests/fixtures/probe.S",
        ".selected_handle:\n",
        ".seccomp_argument_range:\n    mov $257, %eax\n    mov $-100, %edi\n    lea probe_path(%rip), %rsi\n    xor %edx, %edx\n    xor %r10d, %r10d\n    syscall\n    test %rax, %rax\n    js .fail29\n    mov %rax, %r12\n\n    # Exact inclusive lower bound (even, so the composed mask also passes).\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x00000000fffffff0, %rsi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail29\n\n    # Cross the 32-bit word boundary inside the allowed range.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x0000000100000000, %rsi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail29\n\n    # Exact inclusive upper bound.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x0000000100000010, %rsi\n    xor %edx, %edx\n    syscall\n    test %rax, %rax\n    js .fail29\n\n    # In-range odd value: range passes, composed masked equality must deny.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x0000000100000001, %rsi\n    xor %edx, %edx\n    syscall\n    cmp $-1, %rax\n    jne .fail29\n\n    # Even value below lower bound: mask passes, range must deny.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x00000000ffffffee, %rsi\n    xor %edx, %edx\n    syscall\n    cmp $-1, %rax\n    jne .fail29\n\n    # Even value above upper bound: mask passes, range must deny.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x0000000100000012, %rsi\n    xor %edx, %edx\n    syscall\n    cmp $-1, %rax\n    jne .fail29\n\n    # High-32-bit mismatch proves the comparison is not truncated to low bits.\n    mov $8, %eax\n    mov %r12, %rdi\n    movabs $0x0000000200000000, %rsi\n    xor %edx, %edx\n    syscall\n    cmp $-1, %rax\n    jne .fail29\n\n    mov $3, %eax\n    mov %r12, %rdi\n    syscall\n    test %rax, %rax\n    js .fail29\n    xor %edi, %edi\n    jmp .exit\n\n.selected_handle:\n",
        "range fixture body",
    )


if len(sys.argv) != 2 or sys.argv[1] not in {"tests", "production"}:
    raise SystemExit("usage: script tests|production")
if sys.argv[1] == "tests":
    add_parser_red_test()
else:
    materialize_production()
