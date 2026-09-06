from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


replace_one(
    "src/lib.rs",
    "pub use report::{CapturedOutput, ChildOutcome, RunReport};",
    "pub use report::{CapturedOutput, ChildOutcome, ProcessTreeUsage, RunReport};",
    "lib usage export",
)

replace_one(
    "src/report.rs",
    "/// Detailed result for callers that need launcher-owned captured output or process-tree lifecycle evidence.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct RunReport {",
    "/// Kernel resource usage attributed to the terminated/waited-for sandbox process tree.\n///\n/// CPU fields are cumulative `RUSAGE_CHILDREN` values observed by launcher-owned\n/// namespace PID 1 after it has reaped the direct target and remaining descendants.\n/// On Linux, `max_child_rss_kib` is the largest child's peak RSS, not a concurrent\n/// whole-tree memory high-water mark.\n#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]\npub struct ProcessTreeUsage {\n    pub user_cpu_micros: u64,\n    pub system_cpu_micros: u64,\n    pub max_child_rss_kib: u64,\n}\n\n/// Detailed result for callers that need launcher-owned captured output or process-tree lifecycle evidence.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct RunReport {",
    "report usage type",
)
replace_one(
    "src/report.rs",
    "    /// Additional orphaned descendants reaped by the launcher-owned PID 1 after the direct target terminated.\n    pub reaped_descendants: u32,\n}",
    "    /// Additional orphaned descendants reaped by the launcher-owned PID 1 after the direct target terminated.\n    pub reaped_descendants: u32,\n    /// Kernel resource telemetry collected by namespace PID 1 only after the sandbox tree converges.\n    pub process_tree_usage: ProcessTreeUsage,\n}",
    "report usage field",
)

replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    pub(super) cancelled: u32,\n    pub(super) ready: u32,",
    "    pub(super) cancelled: u32,\n    pub(super) user_cpu_micros: u64,\n    pub(super) system_cpu_micros: u64,\n    pub(super) max_child_rss_kib: u64,\n    pub(super) ready: u32,",
    "lifecycle usage fields",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "                    timed_out: 0,\n                    cancelled: 0,\n                    ready: 0,",
    "                    timed_out: 0,\n                    cancelled: 0,\n                    user_cpu_micros: 0,\n                    system_cpu_micros: 0,\n                    max_child_rss_kib: 0,\n                    ready: 0,",
    "lifecycle usage init",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    pub(super) cancellation_pidfd: u32,\n    pub(super) cancellation_poll: u32,\n}",
    "    pub(super) cancellation_pidfd: u32,\n    pub(super) cancellation_poll: u32,\n    pub(super) usage: u32,\n}",
    "lifecycle usage phase",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    let reaped_descendants = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);\n\n    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).status), direct_status);",
    "    let reaped_descendants = kill_and_reap_remaining(launch_error, phases.kill, phases.reap);\n    let (user_cpu_micros, system_cpu_micros, max_child_rss_kib) =\n        match collect_process_tree_usage() {\n            Ok(usage) => usage,\n            Err(errno) => fail_errno(launch_error, phases.usage, errno),\n        };\n\n    ptr::write_volatile(ptr::addr_of_mut!((*lifecycle).status), direct_status);",
    "collect usage after reap",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).cancelled),\n        u32::from(cancelled),\n    );\n    // Publish readiness last: the host treats ready != 1 as an incomplete",
    "    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).cancelled),\n        u32::from(cancelled),\n    );\n    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).user_cpu_micros),\n        user_cpu_micros,\n    );\n    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).system_cpu_micros),\n        system_cpu_micros,\n    );\n    ptr::write_volatile(\n        ptr::addr_of_mut!((*lifecycle).max_child_rss_kib),\n        max_child_rss_kib,\n    );\n    // Publish readiness last: the host treats ready != 1 as an incomplete",
    "publish usage before ready",
)
replace_one(
    "src/platform/linux_pid_lifecycle.rs",
    "unsafe fn close_nonstdio_except(keep_fd: libc::c_int) -> Result<(), i32> {",
    "unsafe fn collect_process_tree_usage() -> Result<(u64, u64, u64), i32> {\n    let mut usage = std::mem::zeroed::<libc::rusage>();\n    let result = libc::syscall(\n        libc::SYS_getrusage,\n        libc::RUSAGE_CHILDREN,\n        &mut usage as *mut libc::rusage,\n    );\n    if result == -1 {\n        return Err(*libc::__errno_location());\n    }\n    let max_child_rss_kib = if usage.ru_maxrss > 0 {\n        usage.ru_maxrss as u64\n    } else {\n        0\n    };\n    Ok((\n        timeval_to_micros(usage.ru_utime),\n        timeval_to_micros(usage.ru_stime),\n        max_child_rss_kib,\n    ))\n}\n\nfn timeval_to_micros(value: libc::timeval) -> u64 {\n    let seconds = if value.tv_sec > 0 { value.tv_sec as u64 } else { 0 };\n    let micros = if value.tv_usec > 0 { value.tv_usec as u64 } else { 0 };\n    seconds\n        .saturating_mul(1_000_000)\n        .saturating_add(micros.min(999_999))\n}\n\nunsafe fn close_nonstdio_except(keep_fd: libc::c_int) -> Result<(), i32> {",
    "usage collector helper",
)

replace_one(
    "src/platform/linux.rs",
    "        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ResourceLimits, RunReport,\n        SandboxError, SandboxPolicy,",
    "        CancellationToken, CapturedOutput, ChildOutcome, PolicyError, ProcessTreeUsage,\n        ResourceLimits, RunReport, SandboxError, SandboxPolicy,",
    "linux usage import",
)
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_LANDLOCK_NET_RULE: u32 = 52;",
    "    const PHASE_LANDLOCK_NET_RULE: u32 = 52;\n    const PHASE_PROCESS_TREE_USAGE: u32 = 53;",
    "usage phase constant",
)
replace_one(
    "src/platform/linux.rs",
    "                cancellation_pidfd: PHASE_CANCELLATION_PIDFD,\n                cancellation_poll: PHASE_CANCELLATION_POLL,\n            },",
    "                cancellation_pidfd: PHASE_CANCELLATION_PIDFD,\n                cancellation_poll: PHASE_CANCELLATION_POLL,\n                usage: PHASE_PROCESS_TREE_USAGE,\n            },",
    "usage supervision phase",
)
replace_one(
    "src/platform/linux.rs",
    "                stdout: None,\n                reaped_descendants: 0,\n            });",
    "                stdout: None,\n                reaped_descendants: 0,\n                process_tree_usage: ProcessTreeUsage::default(),\n            });",
    "launch error report usage",
)
replace_one(
    "src/platform/linux.rs",
    "            stdout,\n            reaped_descendants: lifecycle_record.reaped_descendants,\n        })",
    "            stdout,\n            reaped_descendants: lifecycle_record.reaped_descendants,\n            process_tree_usage: ProcessTreeUsage {\n                user_cpu_micros: lifecycle_record.user_cpu_micros,\n                system_cpu_micros: lifecycle_record.system_cpu_micros,\n                max_child_rss_kib: lifecycle_record.max_child_rss_kib,\n            },\n        })",
    "normal report usage",
)
replace_one(
    "src/platform/linux.rs",
    "            PHASE_LANDLOCK_NET_RULE => \"Landlock TCP port rule installation\",\n            _ => \"unknown launch phase\",",
    "            PHASE_LANDLOCK_NET_RULE => \"Landlock TCP port rule installation\",\n            PHASE_PROCESS_TREE_USAGE => \"process-tree resource usage collection\",\n            _ => \"unknown launch phase\",",
    "usage phase label",
)

replace_one(
    "src/cli_json.rs",
    "    output.push_str(\",\\\"reaped_descendants\\\":\");\n    write!(&mut output, \"{}\", report.reaped_descendants).expect(\"write to String cannot fail\");\n    output.push('}');",
    "    output.push_str(\",\\\"reaped_descendants\\\":\");\n    write!(&mut output, \"{}\", report.reaped_descendants).expect(\"write to String cannot fail\");\n    output.push_str(\",\\\"process_tree_usage\\\":{\\\"user_cpu_micros\\\":\");\n    write!(&mut output, \"{}\", report.process_tree_usage.user_cpu_micros)\n        .expect(\"write to String cannot fail\");\n    output.push_str(\",\\\"system_cpu_micros\\\":\");\n    write!(&mut output, \"{}\", report.process_tree_usage.system_cpu_micros)\n        .expect(\"write to String cannot fail\");\n    output.push_str(\",\\\"max_child_rss_kib\\\":\");\n    write!(&mut output, \"{}\", report.process_tree_usage.max_child_rss_kib)\n        .expect(\"write to String cannot fail\");\n    output.push_str(\"}}\");",
    "json usage object",
)
replace_one(
    "src/cli_json.rs",
    "    use security_lab::{CapturedOutput, RunReport};",
    "    use security_lab::{CapturedOutput, ProcessTreeUsage, RunReport};",
    "json test import",
)
replace_one(
    "src/cli_json.rs",
    "            reaped_descendants: 3,\n        };",
    "            reaped_descendants: 3,\n            process_tree_usage: ProcessTreeUsage {\n                user_cpu_micros: 11,\n                system_cpu_micros: 22,\n                max_child_rss_kib: 33,\n            },\n        };",
    "json test usage data",
)
replace_one(
    "src/cli_json.rs",
    "{\\\"ok\\\":true,\\\"outcome\\\":{\\\"kind\\\":\\\"exited\\\",\\\"code\\\":7},\\\"stdout\\\":{\\\"encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"0022ff\\\",\\\"truncated\\\":true},\\\"reaped_descendants\\\":3}",
    "{\\\"ok\\\":true,\\\"outcome\\\":{\\\"kind\\\":\\\"exited\\\",\\\"code\\\":7},\\\"stdout\\\":{\\\"encoding\\\":\\\"hex\\\",\\\"data\\\":\\\"0022ff\\\",\\\"truncated\\\":true},\\\"reaped_descendants\\\":3,\\\"process_tree_usage\\\":{\\\"user_cpu_micros\\\":11,\\\"system_cpu_micros\\\":22,\\\"max_child_rss_kib\\\":33}}",
    "json expected usage",
)

replace_one(
    "tests/fixtures/probe.S",
    "#   R read back all configured resource limits\n",
    "#   R read back all configured resource limits\n#   x allocate and fault anonymous pages for launcher-owned resource-usage evidence\n",
    "fixture usage mode comment",
)
replace_one(
    "tests/fixtures/probe.S",
    "    cmp $82, %al\n    je .resource_limits\n",
    "    cmp $82, %al\n    je .resource_limits\n    cmp $120, %al\n    je .resource_usage\n",
    "fixture usage mode dispatch",
)
replace_one(
    "tests/fixtures/probe.S",
    ".resource_limits:\n",
    ".resource_usage:\n    mov $9, %eax\n    xor %edi, %edi\n    mov $8388608, %esi\n    mov $3, %edx\n    mov $34, %r10d\n    mov $-1, %r8\n    xor %r9d, %r9d\n    syscall\n    test %rax, %rax\n    js .fail3\n    mov %rax, %r12\n    xor %ecx, %ecx\n.resource_usage_touch:\n    movb $1, (%r12,%rcx)\n    add $4096, %rcx\n    cmp $8388608, %rcx\n    jb .resource_usage_touch\n    xor %edi, %edi\n    jmp .exit\n\n.resource_limits:\n",
    "fixture usage workload",
)

replace_one(
    "tests/sandbox.rs",
    "#[test]\nfn direct_target_is_pid2_under_launcher_owned_namespace_init() {",
    "#[test]\nfn process_tree_resource_usage_reports_kernel_accounting() {\n    let report = run_report(&policy(\n        \"x\",\n        &[],\n        &[\"execveat\", \"mmap\", \"exit\"],\n    ))\n    .unwrap();\n\n    assert_eq!(report.outcome, ChildOutcome::Exited(0));\n    assert_eq!(report.reaped_descendants, 0);\n    assert!(\n        report.process_tree_usage.max_child_rss_kib >= 4096,\n        \"8 MiB touched mapping should produce at least 4 MiB max-child RSS, got {} KiB\",\n        report.process_tree_usage.max_child_rss_kib\n    );\n}\n\n#[test]\nfn direct_target_is_pid2_under_launcher_owned_namespace_init() {",
    "integration usage evidence",
)
