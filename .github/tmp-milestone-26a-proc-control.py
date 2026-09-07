from pathlib import Path


def replace_one(path: str, old: str, new: str, label: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {count}")
    p.write_text(text.replace(old, new, 1))


# Production: private procfs is not complete until launcher-owned PID 1 also
# closes the proc/ptrace credential route to its descriptor table.
replace_one(
    "src/platform/linux.rs",
    "    const PHASE_PROCFS_MOUNT: u32 = 57;\n",
    "    const PHASE_PROCFS_MOUNT: u32 = 57;\n    const PHASE_PROCFS_PID1_HARDEN: u32 = 58;\n",
    "procfs hardening launch phase",
)

replace_one(
    "src/platform/linux.rs",
    '''    unsafe fn mount_private_procfs_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
        if libc::syscall(
            libc::SYS_mount,
            b"proc\\0".as_ptr().cast::<libc::c_char>(),
            b"/proc\\0".as_ptr().cast::<libc::c_char>(),
            b"proc\\0".as_ptr().cast::<libc::c_char>(),
            flags,
            ptr::null::<libc::c_void>(),
        ) == -1
        {
            child_fail(launch_error, PHASE_PROCFS_MOUNT, error_exit_syscall);
        }
        mark_enforcement(launch_error, ENFORCEMENT_PRIVATE_PROCFS);
    }
''',
    '''    unsafe fn mount_private_procfs_or_fail(
        launch_error: *mut LaunchErrorRecord,
        error_exit_syscall: libc::c_long,
    ) {
        let flags = (libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC) as libc::c_ulong;
        if libc::syscall(
            libc::SYS_mount,
            b"proc\\0".as_ptr().cast::<libc::c_char>(),
            b"/proc\\0".as_ptr().cast::<libc::c_char>(),
            b"proc\\0".as_ptr().cast::<libc::c_char>(),
            flags,
            ptr::null::<libc::c_void>(),
        ) == -1
        {
            child_fail(launch_error, PHASE_PROCFS_MOUNT, error_exit_syscall);
        }

        // A private procfs intentionally exposes namespace PID 1 metadata. Do
        // not also expose PID 1's launcher-owned descriptor table as a route
        // back to cancellation/deadline/pidfd control objects. Setting PID 1
        // non-dumpable before the direct target is forked makes procfs apply
        // the kernel's ptrace-access credential gate to /proc/1/fd.
        if libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_DUMPABLE,
            0,
            0,
            0,
            0,
        ) == -1
        {
            child_fail(
                launch_error,
                PHASE_PROCFS_PID1_HARDEN,
                error_exit_syscall,
            );
        }

        // This receipt bit represents the complete private-procfs boundary:
        // both the PID-namespace proc mount and the PID1 descriptor-access
        // hardening have succeeded.
        mark_enforcement(launch_error, ENFORCEMENT_PRIVATE_PROCFS);
    }
''',
    "procfs PID1 dumpability hardening",
)

replace_one(
    "src/platform/linux.rs",
    '            PHASE_PROCFS_MOUNT => "private procfs mount in PID namespace",\n',
    '            PHASE_PROCFS_MOUNT => "private procfs mount in PID namespace",\n            PHASE_PROCFS_PID1_HARDEN => "private procfs PID1 descriptor-access hardening",\n',
    "procfs hardening phase label",
)

# Raw fixture: keep the existing positive PID-visibility oracle and add a
# separate control-authority oracle.  Lower-case j was previously unused.
replace_one(
    "tests/fixtures/probe.S",
    "#   i prove private procfs exposes namespace PID 1/2 while hiding a trusted host PID\n",
    "#   i prove private procfs exposes namespace PID 1/2 while hiding a trusted host PID\n#   j prove private procfs keeps PID1 metadata visible but seals PID1 control descriptors\n",
    "procfs control mode documentation",
)

replace_one(
    "tests/fixtures/probe.S",
    "    cmp $105, %al\n    je .private_procfs\n",
    "    cmp $105, %al\n    je .private_procfs\n    cmp $106, %al\n    je .private_procfs_control_boundary\n",
    "procfs control mode dispatch",
)

replace_one(
    "tests/fixtures/probe.S",
    '''.private_procfs_fail:
    add $160, %rsp
    jmp .fail29

.selected_handle:
''',
    '''.private_procfs_fail:
    add $160, %rsp
    jmp .fail29

.private_procfs_control_boundary:
    mov 24(%rsp), %r12
    test %r12, %r12
    je .fail48
    sub $160, %rsp

    # Preserve positive PID-namespace evidence while exercising the stronger
    # control-plane boundary under real deadline/cancellation supervision.
    mov $262, %eax
    mov $-100, %edi
    lea proc_pid1_path(%rip), %rsi
    mov %rsp, %rdx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .private_procfs_control_fail

    mov $262, %eax
    mov $-100, %edi
    lea proc_pid2_path(%rip), %rsi
    mov %rsp, %rdx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .private_procfs_control_fail

    mov $262, %eax
    mov $-100, %edi
    mov %r12, %rsi
    mov %rsp, %rdx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .private_procfs_control_fail

    # PID1 metadata is deliberately not claimed secret.  status remains a
    # readable observability surface even though its fd table must be sealed.
    mov $257, %eax
    mov $-100, %edi
    lea proc_pid1_status_path(%rip), %rsi
    mov $524288, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .private_procfs_control_fail
    mov %rax, %r13
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .private_procfs_control_fail

    # PR_SET_DUMPABLE=0 on launcher-owned PID1 must make the descriptor
    # directory itself fail the procfs ptrace-access gate with EACCES.  This is
    # stronger than enumerating entries and hoping individual reopen attempts
    # fail for object-type-specific reasons.
    mov $257, %eax
    mov $-100, %edi
    lea proc_pid1_fd_path(%rip), %rsi
    mov $589824, %edx
    xor %r10d, %r10d
    syscall
    cmp $-13, %rax
    jne .private_procfs_control_unexpected_fd_access

    add $160, %rsp
    xor %edi, %edi
    jmp .exit

.private_procfs_control_unexpected_fd_access:
    test %rax, %rax
    js .private_procfs_control_fail
    mov %rax, %r13
    mov $3, %eax
    mov %r13, %rdi
    syscall

.private_procfs_control_fail:
    add $160, %rsp
    jmp .fail48

.selected_handle:
''',
    "procfs control raw oracle",
)

replace_one(
    "tests/fixtures/probe.S",
    '''.fail47:
    mov $47, %edi

.exit:
''',
    '''.fail47:
    mov $47, %edi
    jmp .exit
.fail48:
    mov $48, %edi

.exit:
''',
    "procfs control failure code",
)

replace_one(
    "tests/fixtures/probe.S",
    '''proc_pid2_path:
    .asciz "/proc/2"

.section .note.GNU-stack,"",@progbits
''',
    '''proc_pid2_path:
    .asciz "/proc/2"
proc_pid1_status_path:
    .asciz "/proc/1/status"
proc_pid1_fd_path:
    .asciz "/proc/1/fd"

.section .note.GNU-stack,"",@progbits
''',
    "procfs control paths",
)

# Integration: combine private procfs with the real launcher supervision plane.
# The token is intentionally never signalled and the deadline is only a
# watchdog, so natural target completion must win while PID1 owns its control
# descriptors.
replace_one(
    "tests/sandbox.rs",
    '''#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {
''',
    '''#[test]
fn private_procfs_seals_pid1_control_descriptors_during_supervision() {
    let host_pid = process::id();
    assert!(
        host_pid > 2,
        "host test process must not collide with namespace PID 1/2"
    );
    let host_proc_path = format!("/proc/{host_pid}");
    let cancellation = CancellationToken::new().expect("create procfs control token");
    let mut isolated = policy(
        "j",
        &[host_proc_path.as_str()],
        &["execveat", "newfstatat", "openat", "close", "exit"],
    );
    isolated.procfs_enabled = true;
    isolated.wall_clock_milliseconds = Some(5000);

    let report = run_report_with_cancel(&isolated, &cancellation)
        .expect("private procfs control-boundary sandbox run");
    assert_eq!(report.outcome, ChildOutcome::Exited(0));
    assert_eq!(report.reaped_descendants, 0);
    assert!(
        report.enforcement.private_procfs,
        "runtime receipt must require both procfs mount and PID1 access hardening"
    );
}

#[test]
fn selected_nonstdio_handle_is_exposed_only_at_declared_destination() {
''',
    "procfs control integration regression",
)
