from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


def insert_before(path: str, marker: str, block: str, label: str) -> None:
    replace_one(path, marker, block + marker, label)


# --- policy surface / validation / parsing ---
replace_one(
    "src/policy.rs",
    "    /// Optional inclusive unsigned 64-bit ranges keyed by syscall and argument\n    /// index. Range rules compose conjunctively with masked-equality rules.\n    pub argument_range_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRangeRule>>,\n",
    "    /// Optional inclusive unsigned 64-bit ranges keyed by syscall and argument\n    /// index. Range rules compose conjunctively with masked-equality rules.\n    pub argument_range_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRangeRule>>,\n    /// Optional forbidden masked bit patterns keyed by syscall and argument index.\n    /// A matching pattern is denied; non-matching values continue through the\n    /// remaining conjunctive seccomp constraints for that already-allowed syscall.\n    pub argument_forbidden_mask_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRule>>,\n",
    "SeccompPolicy forbidden-mask field",
)

replace_one(
    "src/policy.rs",
    "        let range_rule_count = self\n            .seccomp\n            .argument_range_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        let argument_rule_count = masked_rule_count + range_rule_count;\n",
    "        let range_rule_count = self\n            .seccomp\n            .argument_range_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        let forbidden_mask_rule_count = self\n            .seccomp\n            .argument_forbidden_mask_rules\n            .values()\n            .map(BTreeMap::len)\n            .sum::<usize>();\n        let argument_rule_count = masked_rule_count + range_rule_count + forbidden_mask_rule_count;\n",
    "aggregate seccomp predicate ceiling",
)

validation_marker = "        for (syscall, rules) in &self.seccomp.argument_range_rules {\n"
forbidden_validation = '''        for (syscall, rules) in &self.seccomp.argument_forbidden_mask_rules {
            if !valid_syscall_name(syscall) {
                return Err(PolicyError::new(format!(
                    "invalid seccomp forbidden-mask syscall name: {syscall:?}"
                )));
            }
            if !self.seccomp.allowed_syscalls.contains(syscall) {
                return Err(PolicyError::new(format!(
                    "seccomp forbidden-mask rule for {syscall} requires that syscall in seccomp.allow"
                )));
            }
            if matches!(syscall.as_str(), "execveat" | "exit" | "exit_group") {
                return Err(PolicyError::new(format!(
                    "seccomp forbidden-mask rules may not constrain launcher-critical syscall {syscall}"
                )));
            }
            for (argument_index, rule) in rules {
                if *argument_index > 5 {
                    return Err(PolicyError::new(format!(
                        "seccomp forbidden-mask argument index for {syscall} must be between 0 and 5"
                    )));
                }
                if rule.mask == 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp forbidden-mask for {syscall}.{argument_index} must not be zero"
                    )));
                }
                if rule.value & !rule.mask != 0 {
                    return Err(PolicyError::new(format!(
                        "seccomp forbidden-mask value for {syscall}.{argument_index} sets bits outside its mask"
                    )));
                }
            }
        }
'''
insert_before("src/policy.rs", validation_marker, forbidden_validation, "forbidden-mask validation")

replace_one(
    "src/policy.rs",
    "        let mut seccomp_argument_range_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRangeRule>> =\n            BTreeMap::new();\n",
    "        let mut seccomp_argument_range_rules: BTreeMap<String, BTreeMap<u8, SeccompArgRangeRule>> =\n            BTreeMap::new();\n        let mut seccomp_argument_forbidden_mask_rules: BTreeMap<\n            String,\n            BTreeMap<u8, SeccompArgRule>,\n        > = BTreeMap::new();\n",
    "forbidden-mask parser storage",
)

range_parser_marker = '                _ if key.starts_with("seccomp.range.") => {\n'
forbidden_parser = '''                _ if key.starts_with("seccomp.deny_mask.") => {
                    let spec = key
                        .strip_prefix("seccomp.deny_mask.")
                        .expect("prefix checked above");
                    let (syscall, index_text) = spec.rsplit_once('.').ok_or_else(|| {
                        PolicyError::at(
                            line_no,
                            "seccomp forbidden-mask key must be seccomp.deny_mask.<syscall>.<0..5>",
                        )
                    })?;
                    if !valid_syscall_name(syscall) {
                        return Err(PolicyError::at(
                            line_no,
                            format!("invalid seccomp forbidden-mask syscall name: {syscall:?}"),
                        ));
                    }
                    let argument_index = index_text.parse::<u8>().map_err(|_| {
                        PolicyError::at(
                            line_no,
                            "seccomp forbidden-mask argument index must be between 0 and 5",
                        )
                    })?;
                    if argument_index > 5 {
                        return Err(PolicyError::at(
                            line_no,
                            "seccomp forbidden-mask argument index must be between 0 and 5",
                        ));
                    }
                    let rule = parse_seccomp_arg_rule(value, line_no, key)?;
                    let syscall_rules = seccomp_argument_forbidden_mask_rules
                        .entry(syscall.to_owned())
                        .or_default();
                    if syscall_rules.insert(argument_index, rule).is_some() {
                        return Err(PolicyError::at(
                            line_no,
                            format!("duplicate seccomp forbidden-mask rule: {syscall}.{argument_index}"),
                        ));
                    }
                }
'''
insert_before("src/policy.rs", range_parser_marker, forbidden_parser, "forbidden-mask parser")

replace_one(
    "src/policy.rs",
    "                argument_rules: seccomp_argument_rules,\n                argument_range_rules: seccomp_argument_range_rules,\n",
    "                argument_rules: seccomp_argument_rules,\n                argument_range_rules: seccomp_argument_range_rules,\n                argument_forbidden_mask_rules: seccomp_argument_forbidden_mask_rules,\n",
    "parsed SeccompPolicy construction",
)

policy_test_marker = "    #[test]\n    fn parses_masked_seccomp_argument_rule() {\n"
policy_test = '''    #[test]
    fn parses_and_rejects_forbidden_seccomp_mask_rule() {
        let text = VALID.replace(
            "seccomp.allow = execveat,read,write,exit_group",
            "seccomp.allow = execveat,mmap,exit_group\n        seccomp.deny_mask.mmap.2 = 0x6:0x6",
        );
        let policy: SandboxPolicy = text.parse().unwrap();
        let rule = policy
            .seccomp
            .argument_forbidden_mask_rules
            .get("mmap")
            .and_then(|rules| rules.get(&2))
            .copied()
            .expect("parsed mmap protection forbidden mask");
        assert_eq!(rule, SeccompArgRule { mask: 0x6, value: 0x6 });

        for invalid in [
            "seccomp.deny_mask.mmap.2 = 0:0",
            "seccomp.deny_mask.mmap.2 = 0x2:0x4",
            "seccomp.deny_mask.read.6 = 1:1",
            "seccomp.deny_mask.execveat.0 = 1:1",
        ] {
            let text = VALID.replace(
                "seccomp.allow = execveat,read,write,exit_group",
                &format!("seccomp.allow = execveat,mmap,read,write,exit_group\\n        {invalid}"),
            );
            assert!(text.parse::<SandboxPolicy>().is_err(), "accepted {invalid}");
        }
    }

'''
insert_before("src/policy.rs", policy_test_marker, policy_test, "forbidden-mask policy regression")

# --- Linux cBPF compiler ---
replace_one(
    "src/platform/linux.rs",
    "            if let Some(rules) = policy.seccomp.argument_range_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_range_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.minimum,\n                        rule.maximum,\n                    );\n                }\n            }\n            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));\n",
    "            if let Some(rules) = policy.seccomp.argument_range_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_range_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.minimum,\n                        rule.maximum,\n                    );\n                }\n            }\n            if let Some(rules) = policy.seccomp.argument_forbidden_mask_rules.get(name) {\n                for (argument_index, rule) in rules {\n                    append_seccomp_argument_forbidden_mask_checks(\n                        &mut checks,\n                        *argument_index,\n                        rule.mask,\n                        rule.value,\n                    );\n                }\n            }\n            checks.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));\n",
    "compile forbidden masks",
)

range_helper_marker = "    fn append_seccomp_argument_range_checks(\n"
forbidden_helper = '''    fn append_seccomp_argument_forbidden_mask_checks(
        filter: &mut Vec<libc::sock_filter>,
        argument_index: u8,
        mask: u64,
        value: u64,
    ) {
        let argument_offset = SECCOMP_DATA_ARGS_OFFSET + u32::from(argument_index) * 8;
        let low_mask = mask as u32;
        let low_value = value as u32;
        let high_mask = (mask >> 32) as u32;
        let high_value = (value >> 32) as u32;

        match (low_mask != 0, high_mask != 0) {
            (true, true) => {
                filter.push(stmt(BPF_LD_W_ABS, argument_offset));
                if low_mask != u32::MAX {
                    filter.push(stmt(BPF_ALU_AND_K, low_mask));
                }
                let high_block_len = if high_mask == u32::MAX { 3 } else { 4 };
                filter.push(jump(BPF_JMP_JEQ_K, low_value, 0, high_block_len));
                filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));
                if high_mask != u32::MAX {
                    filter.push(stmt(BPF_ALU_AND_K, high_mask));
                }
                filter.push(jump(BPF_JMP_JEQ_K, high_value, 0, 1));
                filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
            }
            (true, false) => {
                filter.push(stmt(BPF_LD_W_ABS, argument_offset));
                if low_mask != u32::MAX {
                    filter.push(stmt(BPF_ALU_AND_K, low_mask));
                }
                filter.push(jump(BPF_JMP_JEQ_K, low_value, 0, 1));
                filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
            }
            (false, true) => {
                filter.push(stmt(BPF_LD_W_ABS, argument_offset + 4));
                if high_mask != u32::MAX {
                    filter.push(stmt(BPF_ALU_AND_K, high_mask));
                }
                filter.push(jump(BPF_JMP_JEQ_K, high_value, 0, 1));
                filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | (libc::EPERM as u32)));
            }
            (false, false) => unreachable!("zero forbidden mask rejected by policy validation"),
        }
    }

'''
insert_before("src/platform/linux.rs", range_helper_marker, forbidden_helper, "forbidden-mask cBPF helper")

# --- common sandbox policy helper and executable raw oracle ---
replace_one(
    "tests/sandbox.rs",
    "            argument_rules: BTreeMap::new(),\n            argument_range_rules: BTreeMap::new(),\n",
    "            argument_rules: BTreeMap::new(),\n            argument_range_rules: BTreeMap::new(),\n            argument_forbidden_mask_rules: BTreeMap::new(),\n",
    "sandbox helper forbidden masks",
)

sandbox_test_marker = "#[test]\nfn seccomp_argument_filter_checks_full_64_bit_masked_value() {\n"
sandbox_test = '''#[test]
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
insert_before("tests/sandbox.rs", sandbox_test_marker, sandbox_test, "raw forbidden-mask integration test")

replace_one(
    "tests/fixtures/probe.S",
    "#   y assert unsigned 64-bit inclusive seccomp range filtering on lseek offset\n",
    "#   y assert unsigned 64-bit inclusive seccomp range filtering on lseek offset\n#   k assert a forbidden masked seccomp pattern allows RW/RX mmap and denies RWX\n",
    "fixture mode documentation",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $121, %al\n    je .seccomp_argument_range\n",
    "    cmp $121, %al\n    je .seccomp_argument_range\n    cmp $107, %al\n    je .seccomp_forbidden_mask\n",
    "fixture mode dispatch",
)

fixture_marker = ".seccomp_argument_filter:\n"
fixture_body = r'''.seccomp_forbidden_mask:
    # RW mapping must remain allowed.
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $3, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js .fail29
    mov %rax, %r12
    mov $11, %eax
    mov %r12, %rdi
    mov $4096, %esi
    syscall
    test %rax, %rax
    js .fail29

    # RX mapping must remain allowed.
    mov $9, %eax
    xor %edi, %edi
    mov $4096, %esi
    mov $5, %edx
    mov $0x22, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js .fail29
    mov %rax, %r12
    mov $11, %eax
    mov %r12, %rdi
    mov $4096, %esi
    syscall
    test %rax, %rax
    js .fail29

    # W+X must be denied by the seccomp forbidden-mask rule with exact EPERM.
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
insert_before("tests/fixtures/probe.S", fixture_marker, fixture_body, "forbidden-mask raw oracle")

# --- static authority manifest ---
replace_one(
    "src/authority_manifest.rs",
    "    output.push_str(\"]}}\");\n",
    "    output.push_str(\"],\\\"deny_mask\\\":[\");\n    first = true;\n    for (syscall, rules) in &policy.seccomp.argument_forbidden_mask_rules {\n        for (argument, rule) in rules {\n            if !first {\n                output.push(',');\n            }\n            first = false;\n            output.push_str(\"{\\\"syscall\\\":\");\n            push_json_string(&mut output, syscall);\n            output.push_str(\",\\\"argument\\\":\");\n            write!(&mut output, \"{argument}\").expect(\"write to String cannot fail\");\n            output.push_str(\",\\\"mask\\\":\");\n            push_hex_u64(&mut output, rule.mask);\n            output.push_str(\",\\\"value\\\":\");\n            push_hex_u64(&mut output, rule.value);\n            output.push('}');\n        }\n    }\n    output.push_str(\"]}}\");\n",
    "manifest JSON forbidden masks",
)
replace_one(
    "src/authority_manifest.rs",
    "        \"seccomp: allow={} masked={} ranges={}\",\n",
    "        \"seccomp: allow={} masked={} ranges={} deny-mask={}\",\n",
    "manifest human format",
)
replace_one(
    "src/authority_manifest.rs",
    "        policy\n            .seccomp\n            .argument_range_rules\n            .values()\n            .map(|rules| rules.len())\n            .sum::<usize>()\n    )\n",
    "        policy\n            .seccomp\n            .argument_range_rules\n            .values()\n            .map(|rules| rules.len())\n            .sum::<usize>(),\n        policy\n            .seccomp\n            .argument_forbidden_mask_rules\n            .values()\n            .map(|rules| rules.len())\n            .sum::<usize>()\n    )\n",
    "manifest human forbidden count",
)

# --- static authority delta ---
replace_one(
    "src/authority_delta.rs",
    "    let mut masked = DeltaClass::Unchanged;\n    let mut ranges = DeltaClass::Unchanged;\n",
    "    let mut masked = DeltaClass::Unchanged;\n    let mut ranges = DeltaClass::Unchanged;\n    let mut forbidden_masks = DeltaClass::Unchanged;\n",
    "delta forbidden-mask accumulator",
)
replace_one(
    "src/authority_delta.rs",
    "        ranges = combine_classes(\n            ranges,\n            compare_rule_map(\n                baseline.seccomp.argument_range_rules.get(syscall),\n                candidate.seccomp.argument_range_rules.get(syscall),\n            ),\n        );\n",
    "        ranges = combine_classes(\n            ranges,\n            compare_rule_map(\n                baseline.seccomp.argument_range_rules.get(syscall),\n                candidate.seccomp.argument_range_rules.get(syscall),\n            ),\n        );\n        forbidden_masks = combine_classes(\n            forbidden_masks,\n            compare_rule_map(\n                baseline.seccomp.argument_forbidden_mask_rules.get(syscall),\n                candidate.seccomp.argument_forbidden_mask_rules.get(syscall),\n            ),\n        );\n",
    "delta compare forbidden masks",
)
replace_one(
    "src/authority_delta.rs",
    "    push_change(\"seccomp.masked_arguments\", masked, changes);\n    push_change(\"seccomp.argument_ranges\", ranges, changes);\n",
    "    push_change(\"seccomp.masked_arguments\", masked, changes);\n    push_change(\"seccomp.argument_ranges\", ranges, changes);\n    push_change(\"seccomp.forbidden_masks\", forbidden_masks, changes);\n",
    "delta report forbidden masks",
)

# --- manifest CLI regression ---
replace_one(
    "tests/authority_manifest_cli.rs",
    "seccomp.range.lseek.1 = 4:16\n",
    "seccomp.range.lseek.1 = 4:16\nseccomp.deny_mask.lseek.2 = 0x6:0x6\n",
    "manifest fixture forbidden mask",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\n        \"\\\"ranges\\\":[{\\\"syscall\\\":\\\"lseek\\\",\\\"argument\\\":1,\\\"minimum\\\":\\\"0x0000000000000004\\\",\\\"maximum\\\":\\\"0x0000000000000010\\\"}]\"\n    ));\n",
    "    assert!(stdout.contains(\n        \"\\\"ranges\\\":[{\\\"syscall\\\":\\\"lseek\\\",\\\"argument\\\":1,\\\"minimum\\\":\\\"0x0000000000000004\\\",\\\"maximum\\\":\\\"0x0000000000000010\\\"}]\"\n    ));\n    assert!(stdout.contains(\n        \"\\\"deny_mask\\\":[{\\\"syscall\\\":\\\"lseek\\\",\\\"argument\\\":2,\\\"mask\\\":\\\"0x0000000000000006\\\",\\\"value\\\":\\\"0x0000000000000006\\\"}]\"\n    ));\n",
    "manifest JSON forbidden assertion",
)
replace_one(
    "tests/authority_manifest_cli.rs",
    "    assert!(stdout.contains(\"seccomp: allow=5 masked=1 ranges=1\\n\"));\n",
    "    assert!(stdout.contains(\"seccomp: allow=5 masked=1 ranges=1 deny-mask=1\\n\"));\n",
    "manifest human forbidden assertion",
)

# --- authority-delta regression ---
delta_marker = "#[test]\nfn lower_resource_ceiling_is_detected_as_reduction() {\n"
delta_test = '''#[test]
fn forbidden_seccomp_mask_is_modeled_as_a_restriction() {
    let root = unique_absent_root("deny-mask");
    let baseline_text = base_policy(&root).replace(
        "seccomp.allow = execveat,exit",
        "seccomp.allow = execveat,mmap,exit",
    );
    let restricted_text = format!(
        "{baseline_text}seccomp.deny_mask.mmap.2 = 0x6:0x6\n"
    );
    let baseline = TempPolicy::new("baseline", &baseline_text);
    let restricted = TempPolicy::new("restricted", &restricted_text);

    let reduced = run_json(&baseline, &restricted);
    assert_eq!(reduced.status.code(), Some(0));
    let stdout = String::from_utf8(reduced.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"reduced\""));
    assert!(stdout.contains(
        "\"field\":\"seccomp.forbidden_masks\",\"class\":\"reduced\""
    ));

    let widened = run_json(&restricted, &baseline);
    assert_eq!(widened.status.code(), Some(5));
    let stdout = String::from_utf8(widened.stdout).expect("utf8 output");
    assert!(stdout.contains("\"status\":\"widened\""));
    assert!(stdout.contains(
        "\"field\":\"seccomp.forbidden_masks\",\"class\":\"widened\""
    ));
}

'''
insert_before("tests/authority_delta_cli.rs", delta_marker, delta_test, "authority delta forbidden-mask regression")

# Fail if any known SeccompPolicy literal still lacks the new field.
for path in ["tests/sandbox.rs"]:
    text = Path(path).read_text()
    if "argument_range_rules: BTreeMap::new(),\n            argument_forbidden_mask_rules: BTreeMap::new()," not in text:
        raise SystemExit(f"{path}: SeccompPolicy helper was not updated")
