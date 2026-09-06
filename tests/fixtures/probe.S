.global _start
.section .text

# Tiny statically linked Linux x86_64 fixture. It uses only raw syscalls so
# each integration test can grant an exact, reviewable syscall set without
# depending on glibc or the Rust runtime's startup behavior.
#
# argv[1] mode:
#   A allowed write
#   B assert 64-bit masked seccomp argument filtering on lseek offset
#   G assert one selected non-stdio handle is remapped without ambient FD leakage
#   c fork a descendant, publish cancellation readiness on fd 9, then pause
#   v read a declared persistent volume, prove it is read-only, and hide its host source path
#   w write through a declared persistent volume while root and host source paths stay confined
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM
#   E validate sanitized environment
#   C validate working directory against argv[2]
#   X exit 42
#   S self-terminate with SIGTERM
#   N open until RLIMIT_NOFILE produces EMFILE
#   P assert PR_GET_NO_NEW_PRIVS == 1
#   R read back all configured resource limits
#   W create argv[2] marker
#   D assert descriptor number in argv[2] is closed after exec
#   H assert absolute host path argv[2] is hidden by filesystem root
#   I assert namespace uid/gid are 0 and all capability sets are empty
#   M assert root is read-only while /scratch is writable
#   O assert stdin/stdout/stderr are all closed
#   T assert stdin/stderr are closed while stdout is inherited and writable
#   U assert stdout is redirected to a private scratch file and is readable there
#   V emit 256 KiB through stdout to exercise bounded launcher-owned capture
#   Y assert direct target is PID 2 with launcher-owned namespace init as PID 1
#   Z fork a live descendant that must be killed/reaped by namespace init
#   Q emit a marker, fork a descendant, then remain live past the policy deadline
#   K assert host loopback listener is unreachable from the target network namespace
#   L assert host SysV message queue key is invisible in the target IPC namespace
#   J assert target UTS nodename matches argv[2]

_start:
    mov 16(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    movzbl (%rdi), %eax
    cmp $65, %al
    je .allowed
    cmp $66, %al
    je .seccomp_argument_filter
    cmp $71, %al
    je .selected_handle
    cmp $99, %al
    je .cancellation_tree
    cmp $118, %al
    je .readonly_volume
    cmp $119, %al
    je .writable_volume
    cmp $70, %al
    je .forbidden
    cmp $69, %al
    je .environment
    cmp $67, %al
    je .cwd
    cmp $88, %al
    je .exit42
    cmp $83, %al
    je .signal
    cmp $78, %al
    je .nofile
    cmp $80, %al
    je .no_new_privs
    cmp $82, %al
    je .resource_limits
    cmp $87, %al
    je .write_marker
    cmp $68, %al
    je .descriptor_closed
    cmp $72, %al
    je .host_path_hidden
    cmp $73, %al
    je .identity_reduced
    cmp $77, %al
    je .mutability
    cmp $79, %al
    je .stdio_all_closed
    cmp $84, %al
    je .stdio_stdout_only
    cmp $85, %al
    je .stdio_stdout_redirect
    cmp $86, %al
    je .stdio_stdout_capture_stress
    cmp $89, %al
    je .pid_namespace_identity
    cmp $90, %al
    je .live_descendant
    cmp $81, %al
    je .deadline_tree
    cmp $75, %al
    je .network_isolation
    cmp $76, %al
    je .ipc_isolation
    cmp $74, %al
    je .uts_identity
    jmp .fail2

.allowed:
    mov $1, %eax
    mov $1, %edi
    lea allowed_message(%rip), %rsi
    mov $allowed_message_len, %edx
    syscall
    test %rax, %rax
    js .fail3
    xor %edi, %edi
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

.selected_handle:
    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail30
    call .parse_handle_fd
    mov %eax, %r12d
    mov 32(%rsp), %rdi
    test %rdi, %rdi
    je .fail30
    call .parse_handle_fd
    mov %eax, %r13d

    xor %eax, %eax
    mov $9, %edi
    lea selected_handle_buffer(%rip), %rsi
    mov $selected_handle_message_len, %edx
    syscall
    cmp $selected_handle_message_len, %rax
    jne .fail30

    lea selected_handle_buffer(%rip), %rdi
    lea selected_handle_message(%rip), %rsi
    mov $selected_handle_message_len, %ecx
.selected_handle_compare:
    test %ecx, %ecx
    je .selected_handle_check_closed
    movzbl (%rdi), %eax
    movzbl (%rsi), %edx
    cmp %dl, %al
    jne .fail30
    inc %rdi
    inc %rsi
    dec %ecx
    jmp .selected_handle_compare

.selected_handle_check_closed:
    mov $72, %eax
    mov %r12d, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail30

    mov $72, %eax
    mov %r13d, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail30
    xor %edi, %edi
    jmp .exit

.parse_handle_fd:
    xor %eax, %eax
    movzbl (%rdi), %edx
    test %dl, %dl
    je .fail30
.parse_handle_fd_loop:
    movzbl (%rdi), %edx
    test %dl, %dl
    je .parse_handle_fd_done
    sub $48, %edx
    cmp $9, %edx
    ja .fail30
    imul $10, %eax, %eax
    add %edx, %eax
    inc %rdi
    jmp .parse_handle_fd_loop
.parse_handle_fd_done:
    ret

.cancellation_tree:
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail31
    jz .cancellation_descendant_pause

    mov $1, %eax
    mov $9, %edi
    lea cancellation_ready_message(%rip), %rsi
    mov $cancellation_ready_message_len, %edx
    syscall
    cmp $cancellation_ready_message_len, %rax
    jne .fail31
.cancellation_parent_pause:
    mov $34, %eax
    syscall
    jmp .cancellation_parent_pause

.cancellation_descendant_pause:
    mov $34, %eax
    syscall
    jmp .cancellation_descendant_pause

.readonly_volume:
    mov $257, %eax
    mov $-100, %edi
    lea volume_marker_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail32
    mov %rax, %r12

    xor %eax, %eax
    mov %r12, %rdi
    lea volume_buffer(%rip), %rsi
    mov $volume_marker_len, %edx
    syscall
    cmp $volume_marker_len, %rax
    jne .fail32

    lea volume_buffer(%rip), %rdi
    lea volume_marker_expected(%rip), %rsi
    mov $volume_marker_len, %ecx
    repe cmpsb
    jne .fail32

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail32

    mov $257, %eax
    mov $-100, %edi
    lea volume_forbidden_write(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail32

    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail32
    mov $257, %eax
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail32

    xor %edi, %edi
    jmp .exit

.writable_volume:
    mov $257, %eax
    mov $-100, %edi
    lea writable_volume_output(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail33
    mov %rax, %r12

    mov $1, %eax
    mov %r12, %rdi
    lea writable_volume_message(%rip), %rsi
    mov $writable_volume_message_len, %edx
    syscall
    cmp $writable_volume_message_len, %rax
    jne .fail33

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail33

    mov $257, %eax
    mov $-100, %edi
    lea forbidden_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail33

    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail33
    mov $257, %eax
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail33

    xor %edi, %edi
    jmp .exit

.forbidden:
    mov $39, %eax
    syscall
    cmp $-1, %rax
    jne .fail7
    mov $77, %edi
    jmp .exit

.environment:
    mov (%rsp), %rcx
    lea 16(%rsp,%rcx,8), %r8
    xor %r9d, %r9d
.env_loop:
    mov (%r8), %rdi
    test %rdi, %rdi
    je .env_done
    cmpl $0x48544150, (%rdi)
    jne .check_allowed_env
    cmpb $61, 4(%rdi)
    je .fail4
.check_allowed_env:
    lea allowed_env(%rip), %rsi
    call .str_eq
    test %eax, %eax
    je .env_next
    mov $1, %r9d
.env_next:
    add $8, %r8
    jmp .env_loop
.env_done:
    cmp $1, %r9d
    jne .fail3
    xor %edi, %edi
    jmp .exit

.cwd:
    lea cwd_buffer(%rip), %rdi
    mov $4096, %esi
    mov $79, %eax
    syscall
    test %rax, %rax
    js .fail5
    lea cwd_buffer(%rip), %rdi
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    call .str_eq
    test %eax, %eax
    je .fail5
    xor %edi, %edi
    jmp .exit

.exit42:
    mov $42, %edi
    jmp .exit

.signal:
    mov $39, %eax
    syscall
    test %rax, %rax
    js .fail8
    mov %rax, %r12
    mov $186, %eax
    syscall
    test %rax, %rax
    js .fail8
    mov %rax, %r13
    mov $234, %eax
    mov %r12, %rdi
    mov %r13, %rsi
    mov $15, %edx
    syscall
    jmp .fail10

.nofile:
.nofile_loop:
    mov $257, %eax
    mov $-100, %edi
    lea sandbox_root(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    jns .nofile_loop
    cmp $-24, %rax
    jne .fail12
    xor %edi, %edi
    jmp .exit

.no_new_privs:
    mov $157, %eax
    mov $39, %edi
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    cmp $1, %rax
    jne .fail13
    xor %edi, %edi
    jmp .exit

.resource_limits:
    mov $0, %esi
    mov $2, %r12
    call .check_one_limit
    mov $1, %esi
    mov $1048576, %r12
    call .check_one_limit
    mov $7, %esi
    mov $32, %r12
    call .check_one_limit
    mov $9, %esi
    mov $134217728, %r12
    call .check_one_limit
    xor %edi, %edi
    jmp .exit

.check_one_limit:
    xor %edi, %edi
    xor %edx, %edx
    lea limit_buffer(%rip), %r10
    mov $302, %eax
    syscall
    test %rax, %rax
    js .fail14
    cmp %r12, limit_buffer(%rip)
    jne .fail14
    cmp %r12, limit_buffer+8(%rip)
    jne .fail14
    ret

.write_marker:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    mov $257, %eax
    mov $-100, %edi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail6
    xor %edi, %edi
    jmp .exit

.descriptor_closed:
    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    xor %r12d, %r12d
.fd_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .fd_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail2
    imul $10, %r12d, %r12d
    add %eax, %r12d
    inc %rdi
    jmp .fd_parse_loop
.fd_parsed:
    mov $72, %eax
    mov %r12d, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail15
    xor %edi, %edi
    jmp .exit

.host_path_hidden:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    mov $257, %eax
    mov $-100, %edi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail16
    xor %edi, %edi
    jmp .exit

.identity_reduced:
    mov $102, %eax
    syscall
    test %rax, %rax
    jne .fail17
    mov $104, %eax
    syscall
    test %rax, %rax
    jne .fail17

    movl $0x20080522, cap_header(%rip)
    movl $0, cap_header+4(%rip)
    lea cap_header(%rip), %rdi
    lea cap_data(%rip), %rsi
    mov $125, %eax
    syscall
    test %rax, %rax
    js .fail17

    cmpl $0, cap_data(%rip)
    jne .fail17
    cmpl $0, cap_data+4(%rip)
    jne .fail17
    cmpl $0, cap_data+8(%rip)
    jne .fail17
    cmpl $0, cap_data+12(%rip)
    jne .fail17
    cmpl $0, cap_data+16(%rip)
    jne .fail17
    cmpl $0, cap_data+20(%rip)
    jne .fail17

    xor %r12d, %r12d
.cap_bound_loop:
    cmp $41, %r12d
    je .cap_ambient_start
    mov $157, %eax
    mov $23, %edi
    mov %r12d, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne .fail17
    inc %r12d
    jmp .cap_bound_loop

.cap_ambient_start:
    xor %r12d, %r12d
.cap_ambient_loop:
    cmp $41, %r12d
    je .identity_ok
    mov $157, %eax
    mov $47, %edi
    mov $1, %esi
    mov %r12d, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax
    jne .fail17
    inc %r12d
    jmp .cap_ambient_loop

.identity_ok:
    xor %edi, %edi
    jmp .exit

.mutability:
    mov $257, %eax
    mov $-100, %edi
    lea forbidden_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail18

    mov $257, %eax
    mov $-100, %edi
    lea scratch_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail18
    mov %rax, %r12

    mov $1, %eax
    mov %r12, %rdi
    lea scratch_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail18

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail18
    xor %edi, %edi
    jmp .exit

.stdio_all_closed:
    mov $72, %eax
    xor %edi, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail19

    mov $72, %eax
    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail19

    mov $72, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail19

    xor %edi, %edi
    jmp .exit

.stdio_stdout_only:
    mov $72, %eax
    xor %edi, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail20

    mov $72, %eax
    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail20

    mov $72, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    cmp $-9, %rax
    jne .fail20

    mov $1, %eax
    mov $1, %edi
    lea stdio_message(%rip), %rsi
    mov $stdio_message_len, %edx
    syscall
    cmp $stdio_message_len, %rax
    jne .fail20

    xor %edi, %edi
    jmp .exit

.stdio_stdout_redirect:
    mov $1, %eax
    mov $1, %edi
    lea redirect_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail21

    mov $257, %eax
    mov $-100, %edi
    lea redirect_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail21
    mov %rax, %r12

    xor %eax, %eax
    mov %r12, %rdi
    lea redirect_buffer(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail21
    cmpb $82, redirect_buffer(%rip)
    jne .fail21

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail21
    xor %edi, %edi
    jmp .exit

.stdio_stdout_capture_stress:
    xor %r12d, %r12d
.capture_stress_loop:
    cmp $4096, %r12d
    je .capture_stress_done
    mov $1, %eax
    mov $1, %edi
    lea capture_chunk(%rip), %rsi
    mov $64, %edx
    syscall
    cmp $64, %rax
    jne .fail22
    inc %r12d
    jmp .capture_stress_loop
.capture_stress_done:
    xor %edi, %edi
    jmp .exit

.pid_namespace_identity:
    mov $39, %eax
    syscall
    cmp $2, %rax
    jne .fail23
    mov $110, %eax
    syscall
    cmp $1, %rax
    jne .fail23
    xor %edi, %edi
    jmp .exit

.live_descendant:
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail24
    jz .descendant_pause
    xor %edi, %edi
    jmp .exit
.descendant_pause:
    mov $34, %eax
    syscall
    jmp .descendant_pause

.deadline_tree:
    mov $1, %eax
    mov $1, %edi
    lea deadline_message(%rip), %rsi
    mov $deadline_message_len, %edx
    syscall
    cmp $deadline_message_len, %rax
    jne .fail25

    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail25
    jz .deadline_descendant_pause

    lea deadline_watchdog_sleep(%rip), %rdi
    xor %esi, %esi
    mov $35, %eax
    syscall
    test %rax, %rax
    js .fail25
    mov $99, %edi
    jmp .exit

.deadline_descendant_pause:
    mov $34, %eax
    syscall
    jmp .deadline_descendant_pause

.network_isolation:
    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    xor %r12d, %r12d
.network_port_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .network_port_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail2
    imul $10, %r12d, %r12d
    add %eax, %r12d
    cmp $65535, %r12d
    ja .fail2
    inc %rdi
    jmp .network_port_parse_loop
.network_port_parsed:
    test %r12d, %r12d
    je .fail2
    movw $2, network_addr(%rip)
    rolw $8, %r12w
    movw %r12w, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail26
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    jns .network_unexpected_reachability
    cmp $-111, %rax
    je .network_isolated
    cmp $-101, %rax
    je .network_isolated
    cmp $-113, %rax
    je .network_isolated
    jmp .fail26

.network_unexpected_reachability:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    jmp .fail26

.network_isolated:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail26
    xor %edi, %edi
    jmp .exit

.ipc_isolation:
    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    xor %r12d, %r12d
.ipc_key_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .ipc_key_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail2
    imul $10, %r12d, %r12d
    add %eax, %r12d
    inc %rdi
    jmp .ipc_key_parse_loop
.ipc_key_parsed:
    test %r12d, %r12d
    je .fail2
    mov $68, %eax
    mov %r12d, %edi
    xor %esi, %esi
    syscall
    cmp $-2, %rax
    jne .fail27
    xor %edi, %edi
    jmp .exit

.uts_identity:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    mov $63, %eax
    lea uts_buffer(%rip), %rdi
    syscall
    test %rax, %rax
    js .fail28
    lea uts_buffer+65(%rip), %rdi
    call .str_eq
    test %eax, %eax
    je .fail28
    xor %edi, %edi
    jmp .exit

.str_eq:
.str_eq_loop:
    movzbl (%rdi), %eax
    movzbl (%rsi), %edx
    cmp %dl, %al
    jne .str_not_equal
    test %al, %al
    je .str_equal
    inc %rdi
    inc %rsi
    jmp .str_eq_loop
.str_equal:
    mov $1, %eax
    ret
.str_not_equal:
    xor %eax, %eax
    ret

.fail2:
    mov $2, %edi
    jmp .exit
.fail3:
    mov $3, %edi
    jmp .exit
.fail4:
    mov $4, %edi
    jmp .exit
.fail5:
    mov $5, %edi
    jmp .exit
.fail6:
    mov $6, %edi
    jmp .exit
.fail7:
    mov $7, %edi
    jmp .exit
.fail8:
    mov $8, %edi
    jmp .exit
.fail10:
    mov $10, %edi
    jmp .exit
.fail12:
    mov $12, %edi
    jmp .exit
.fail13:
    mov $13, %edi
    jmp .exit
.fail14:
    mov $14, %edi
    jmp .exit
.fail15:
    mov $15, %edi
    jmp .exit
.fail16:
    mov $16, %edi
    jmp .exit
.fail17:
    mov $17, %edi
    jmp .exit
.fail18:
    mov $18, %edi
    jmp .exit
.fail19:
    mov $19, %edi
    jmp .exit
.fail20:
    mov $20, %edi
    jmp .exit
.fail21:
    mov $21, %edi
    jmp .exit
.fail22:
    mov $22, %edi
    jmp .exit
.fail23:
    mov $23, %edi
    jmp .exit
.fail24:
    mov $24, %edi
    jmp .exit
.fail25:
    mov $25, %edi
    jmp .exit
.fail26:
    mov $26, %edi
    jmp .exit
.fail27:
    mov $27, %edi
    jmp .exit
.fail28:
    mov $28, %edi
    jmp .exit
.fail29:
    mov $29, %edi
    jmp .exit
.fail30:
    mov $30, %edi
    jmp .exit
.fail31:
    mov $31, %edi
    jmp .exit
.fail32:
    mov $32, %edi
    jmp .exit
.fail33:
    mov $33, %edi

.exit:
    mov $60, %eax
    syscall
    ud2

.section .rodata
allowed_message:
    .ascii "allowed operation succeeded\n"
.set allowed_message_len, . - allowed_message
allowed_env:
    .asciz "SANDBOX_ALLOWED=yes"
sandbox_root:
    .asciz "/"
probe_path:
    .asciz "/probe"
forbidden_create:
    .asciz "/root-write-must-fail"
scratch_create:
    .asciz "/scratch/allowed"
scratch_byte:
    .ascii "x"
stdio_message:
    .ascii "explicit stdout inheritance succeeded\n"
.set stdio_message_len, . - stdio_message
redirect_path:
    .asciz "/scratch/stdout.log"
redirect_byte:
    .ascii "R"
capture_chunk:
    .ascii "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
selected_handle_message:
    .ascii "selected-handle-ok"
.set selected_handle_message_len, . - selected_handle_message
cancellation_ready_message:
    .ascii "cancellation-target-ready\n"
.set cancellation_ready_message_len, . - cancellation_ready_message
volume_marker_path:
    .asciz "/data/marker"
volume_forbidden_write:
    .asciz "/data/write-must-fail"
volume_marker_expected:
    .ascii "volume-marker\n"
.set volume_marker_len, . - volume_marker_expected
writable_volume_output:
    .asciz "/persist/persisted"
writable_volume_message:
    .ascii "persistent-write\n"
.set writable_volume_message_len, . - writable_volume_message
deadline_message:
    .ascii "deadline target started\n"
.set deadline_message_len, . - deadline_message
.balign 8
deadline_watchdog_sleep:
    .quad 5
    .quad 0

.section .bss
.balign 16
cwd_buffer:
    .skip 4096
limit_buffer:
    .skip 16
cap_header:
    .skip 8
cap_data:
    .skip 24
redirect_buffer:
    .skip 1
volume_buffer:
    .skip 32
selected_handle_buffer:
    .skip 64
.balign 16
uts_buffer:
    .skip 512
.balign 16
network_addr:
    .skip 16

.section .note.GNU-stack,"",@progbits
