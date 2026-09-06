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
#   n prove policy-owned loopback supports positive intra-sandbox TCP
#   o prove loopback remains down unless policy explicitly enables it
#   p write through a brokered host-loopback TCP fd while direct host reachability stays isolated
#   e write one brokered host-IPv4 UDP datagram while fresh target UDP stays isolated
#   b exchange bytes over a brokered host pathname AF_UNIX stream; direct host path stays hidden
#   q accept one connection through a launcher-brokered host-loopback TCP listening fd
#   r prove Landlock allows declared reads and returns EACCES for an undeclared visible file
#   m prove Landlock narrows regular-file mutation inside scratch and a writable persistent volume
#   s prove Landlock allows declared TCP bind/connect ports and denies undeclared ports
#   a connect selected fd 9 to argv[2] in the abstract UNIX socket namespace
#   d prove Landlock device ioctl allows /devices/urandom and denies /devices/random
#   t permission-check namespace PID1 through a target-opened pidfd; unscoped succeeds
#   u repeat the PID1 signal permission check; Landlock scope requires exact EPERM
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM
#   E validate sanitized environment
#   C validate working directory against argv[2]
#   X exit 42
#   S self-terminate with SIGTERM
#   N open until RLIMIT_NOFILE produces EMFILE
#   P assert PR_GET_NO_NEW_PRIVS == 1
#   R read back all configured resource limits
#   x allocate and fault anonymous pages for launcher-owned resource-usage evidence
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
    cmp $110, %al
    je .loopback_networking
    cmp $111, %al
    je .loopback_disabled
    cmp $112, %al
    je .brokered_host_loopback
    cmp $101, %al
    je .brokered_host_udp
    cmp $98, %al
    je .brokered_host_unix
    cmp $113, %al
    je .brokered_host_loopback_ingress
    cmp $114, %al
    je .landlock_read_envelope
    cmp $109, %al
    je .landlock_file_mutation
    cmp $115, %al
    je .landlock_tcp_ports
    cmp $97, %al
    je .abstract_unix_connect
    cmp $100, %al
    je .landlock_device_ioctl
    cmp $116, %al
    je .pidfd_signal_allowed
    cmp $117, %al
    je .pidfd_signal_denied
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
    cmp $120, %al
    je .resource_usage
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

.loopback_networking:
    movw $2, network_addr(%rip)
    movw $0xb8a5, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r12

    mov $49, %eax
    mov %r12, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail34

    mov $50, %eax
    mov %r12, %rdi
    mov $1, %esi
    syscall
    test %rax, %rax
    js .fail34

    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail34
    jz .loopback_client

    mov $43, %eax
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r13

    xor %eax, %eax
    mov %r13, %rdi
    lea network_buffer(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail34

    lea network_buffer(%rip), %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %ecx
    repe cmpsb
    jne .fail34

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail34
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail34
    xor %edi, %edi
    jmp .exit

.loopback_client:
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail34
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail34

    mov $1, %eax
    mov %r13, %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail34

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail34
    xor %edi, %edi
    jmp .exit

.loopback_disabled:
    mov $41, %eax
    mov $2, %edi
    mov $2, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail35
    mov %rax, %r12

    movb $108, network_ifreq(%rip)
    movb $111, network_ifreq+1(%rip)
    movb $0, network_ifreq+2(%rip)
    mov $16, %eax
    mov %r12, %rdi
    mov $0x8913, %esi
    lea network_ifreq(%rip), %rdx
    syscall
    test %rax, %rax
    js .fail35

    movzwl network_ifreq+16(%rip), %eax
    test $1, %eax
    jnz .fail35

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail35
    xor %edi, %edi
    jmp .exit

.brokered_host_loopback:
    mov $1, %eax
    mov $10, %edi
    lea brokered_host_message(%rip), %rsi
    mov $brokered_host_message_len, %edx
    syscall
    cmp $brokered_host_message_len, %rax
    jne .fail36

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail36

    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail36
    xor %r12d, %r12d
.brokered_port_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .brokered_port_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail36
    imul $10, %r12d, %r12d
    add %eax, %r12d
    cmp $65535, %r12d
    ja .fail36
    inc %rdi
    jmp .brokered_port_parse_loop
.brokered_port_parsed:
    test %r12d, %r12d
    je .fail36
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
    js .fail36
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    jns .brokered_unexpected_reachability
    cmp $-111, %rax
    je .brokered_direct_isolated
    cmp $-101, %rax
    je .brokered_direct_isolated
    cmp $-113, %rax
    je .brokered_direct_isolated
    jmp .fail36

.brokered_unexpected_reachability:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    jmp .fail36

.brokered_direct_isolated:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail36
    xor %edi, %edi
    jmp .exit

.brokered_host_udp:
    mov $1, %eax
    mov $10, %edi
    lea brokered_host_udp_message(%rip), %rsi
    mov $brokered_host_udp_message_len, %edx
    syscall
    cmp $brokered_host_udp_message_len, %rax
    jne .fail45

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail45

    mov 24(%rsp), %rdi
    test %rdi, %rdi
    je .fail45
    xor %r12d, %r12d
.brokered_udp_port_parse_loop:
    movzbl (%rdi), %eax
    test %al, %al
    je .brokered_udp_port_parsed
    sub $48, %eax
    cmp $9, %eax
    ja .fail45
    imul $10, %r12d, %r12d
    add %eax, %r12d
    cmp $65535, %r12d
    ja .fail45
    inc %rdi
    jmp .brokered_udp_port_parse_loop
.brokered_udp_port_parsed:
    test %r12d, %r12d
    je .fail45
    movw $2, network_addr(%rip)
    rolw $8, %r12w
    movw %r12w, network_addr+2(%rip)
    movl $0x0200007f, network_addr+4(%rip)

    mov $41, %eax
    mov $2, %edi
    mov $2, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail45
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .brokered_udp_direct_error

    mov $1, %eax
    mov %r13, %rdi
    lea brokered_host_udp_direct_probe(%rip), %rsi
    mov $brokered_host_udp_direct_probe_len, %edx
    syscall
    cmp $brokered_host_udp_direct_probe_len, %rax
    je .brokered_udp_direct_done
    cmp $-101, %rax
    je .brokered_udp_direct_done
    cmp $-111, %rax
    je .brokered_udp_direct_done
    cmp $-113, %rax
    je .brokered_udp_direct_done
    jmp .brokered_udp_direct_fail

.brokered_udp_direct_error:
    cmp $-101, %rax
    je .brokered_udp_direct_done
    cmp $-111, %rax
    je .brokered_udp_direct_done
    cmp $-113, %rax
    je .brokered_udp_direct_done
    jmp .brokered_udp_direct_fail

.brokered_udp_direct_done:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail45
    xor %edi, %edi
    jmp .exit

.brokered_udp_direct_fail:
    mov $3, %eax
    mov %r13, %rdi
    syscall
    jmp .fail45

.brokered_host_unix:
    mov $1, %eax
    mov $10, %edi
    lea brokered_host_unix_message(%rip), %rsi
    mov $brokered_host_unix_message_len, %edx
    syscall
    cmp $brokered_host_unix_message_len, %rax
    jne .fail46

    xor %r12d, %r12d
.brokered_host_unix_read_reply:
    xor %eax, %eax
    mov $10, %edi
    lea brokered_host_unix_buffer(%rip), %rsi
    add %r12, %rsi
    mov $brokered_host_unix_reply_len, %edx
    sub %r12d, %edx
    syscall
    test %rax, %rax
    jle .fail46
    add %rax, %r12
    cmp $brokered_host_unix_reply_len, %r12d
    jne .brokered_host_unix_read_reply

    lea brokered_host_unix_buffer(%rip), %rdi
    lea brokered_host_unix_reply(%rip), %rsi
    mov $brokered_host_unix_reply_len, %ecx
    repe cmpsb
    jne .fail46

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail46

    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail46
    lea host_unix_addr(%rip), %r13
    movw $1, (%r13)
    lea 2(%r13), %rdi
    xor %r15d, %r15d
.brokered_host_unix_copy_path:
    movzbl (%rsi,%r15,1), %eax
    test %al, %al
    je .brokered_host_unix_path_done
    cmp $107, %r15d
    jae .fail46
    movb %al, (%rdi,%r15,1)
    inc %r15d
    jmp .brokered_host_unix_copy_path
.brokered_host_unix_path_done:
    movb $0, (%rdi,%r15,1)
    add $3, %r15d

    mov $41, %eax
    mov $1, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail46
    mov %rax, %r12

    mov $42, %eax
    mov %r12, %rdi
    lea host_unix_addr(%rip), %rsi
    mov %r15d, %edx
    syscall
    cmp $-2, %rax
    jne .brokered_host_unix_direct_fail

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail46
    xor %edi, %edi
    jmp .exit

.brokered_host_unix_direct_fail:
    mov $3, %eax
    mov %r12, %rdi
    syscall
    jmp .fail46

.brokered_host_loopback_ingress:
    mov $1, %eax
    mov $9, %edi
    lea brokered_ingress_ready(%rip), %rsi
    mov $brokered_ingress_ready_len, %edx
    syscall
    cmp $brokered_ingress_ready_len, %rax
    jne .fail39

    mov $3, %eax
    mov $9, %edi
    syscall
    test %rax, %rax
    js .fail39

    mov $43, %eax
    mov $10, %edi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail39
    mov %rax, %r12

    xor %r13d, %r13d
.ingress_read_loop:
    mov $brokered_ingress_request_len, %edx
    sub %r13d, %edx
    jz .ingress_read_done
    xor %eax, %eax
    mov %r12, %rdi
    lea network_buffer(%rip), %rsi
    add %r13, %rsi
    syscall
    test %rax, %rax
    jg .ingress_read_progress
    je .fail39
    cmp $-4, %rax
    je .ingress_read_loop
    jmp .fail39
.ingress_read_progress:
    add %rax, %r13
    jmp .ingress_read_loop
.ingress_read_done:
    lea network_buffer(%rip), %rdi
    lea brokered_ingress_request(%rip), %rsi
    mov $brokered_ingress_request_len, %ecx
    repe cmpsb
    jne .fail39

    xor %r13d, %r13d
.ingress_write_loop:
    mov $brokered_ingress_reply_len, %edx
    sub %r13d, %edx
    jz .ingress_write_done
    mov $1, %eax
    mov %r12, %rdi
    lea brokered_ingress_reply(%rip), %rsi
    add %r13, %rsi
    syscall
    test %rax, %rax
    jg .ingress_write_progress
    cmp $-4, %rax
    je .ingress_write_loop
    jmp .fail39
.ingress_write_progress:
    add %rax, %r13
    jmp .ingress_write_loop
.ingress_write_done:
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail39

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail39
    xor %edi, %edi
    jmp .exit

.landlock_read_envelope:
    mov $257, %eax
    mov $-100, %edi
    lea landlock_allowed_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail37
    mov %rax, %r12

    xor %eax, %eax
    mov %r12, %rdi
    lea landlock_buffer(%rip), %rsi
    mov $landlock_allowed_message_len, %edx
    syscall
    cmp $landlock_allowed_message_len, %rax
    jne .fail37

    lea landlock_buffer(%rip), %rdi
    lea landlock_allowed_message(%rip), %rsi
    mov $landlock_allowed_message_len, %ecx
    repe cmpsb
    jne .fail37

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail37

    mov $257, %eax
    mov $-100, %edi
    lea landlock_denied_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-13, %rax
    jne .fail37

    xor %edi, %edi
    jmp .exit

.landlock_file_mutation:
    # Private scratch is an existing writable surface; creation must succeed.
    mov $257, %eax
    mov $-100, %edi
    lea landlock_mutation_scratch(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail38
    mov %rax, %r12

    mov $1, %eax
    mov %r12, %rdi
    lea landlock_mutation_scratch_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail38

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail38

    # Exercise TRUNCATE independently from WRITE_FILE on the allowed file.
    mov $76, %eax
    lea landlock_mutation_existing(%rip), %rdi
    xor %esi, %esi
    syscall
    test %rax, %rax
    js .fail38

    mov $257, %eax
    mov $-100, %edi
    lea landlock_mutation_existing(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail38
    mov %rax, %r12

    mov $1, %eax
    mov %r12, %rdi
    lea landlock_mutation_message(%rip), %rsi
    mov $landlock_mutation_message_len, %edx
    syscall
    cmp $landlock_mutation_message_len, %rax
    jne .fail38

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail38

    # REMOVE_FILE is independently granted beneath /persist/allowed.
    mov $87, %eax
    lea landlock_mutation_remove(%rip), %rdi
    syscall
    test %rax, %rax
    js .fail38

    # The sibling directory is on the same writable mount, so EACCES is Landlock evidence.
    mov $257, %eax
    mov $-100, %edi
    lea landlock_mutation_denied_create(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-13, %rax
    jne .fail38

    mov $87, %eax
    lea landlock_mutation_denied_remove(%rip), %rdi
    syscall
    cmp $-13, %rax
    jne .fail38

    # WRITE_FILE must be independently denied on an existing sibling file.
    mov $257, %eax
    mov $-100, %edi
    lea landlock_mutation_denied_remove(%rip), %rsi
    mov $1, %edx
    xor %r10d, %r10d
    syscall
    cmp $-13, %rax
    jne .fail38

    # TRUNCATE must also be independently denied, proving the ABI-3 right is active.
    mov $76, %eax
    lea landlock_mutation_denied_remove(%rip), %rdi
    xor %esi, %esi
    syscall
    cmp $-13, %rax
    jne .fail38

    xor %edi, %edi
    jmp .exit

.landlock_tcp_ports:
    movw $2, network_addr(%rip)
    movw $0xb5a5, network_addr+2(%rip)
    movl $0x0100007f, network_addr+4(%rip)
    movw $2, network_addr_denied(%rip)
    movw $0xb6a5, network_addr_denied+2(%rip)
    movl $0x0100007f, network_addr_denied+4(%rip)

    # Allowed local bind on TCP 42421 must succeed.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r12

    mov $49, %eax
    mov %r12, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail40

    mov $50, %eax
    mov %r12, %rdi
    mov $1, %esi
    syscall
    test %rax, %rax
    js .fail40

    # Same network namespace and seccomp authority, but undeclared bind port
    # 42422 must be denied specifically by Landlock with EACCES.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $49, %eax
    mov %r13, %rdi
    lea network_addr_denied(%rip), %rsi
    mov $16, %edx
    syscall
    cmp $-13, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40

    # Undeclared remote TCP port must likewise return Landlock EACCES rather
    # than the ordinary ECONNREFUSED result of an unserved loopback port.
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr_denied(%rip), %rsi
    mov $16, %edx
    syscall
    cmp $-13, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40

    # Positive connect on the declared remote port proves the rule does not
    # merely deny all target-created networking.
    mov $57, %eax
    syscall
    test %rax, %rax
    js .fail40
    jz .landlock_tcp_client

    mov $43, %eax
    mov %r12, %rdi
    xor %esi, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    xor %eax, %eax
    mov %r13, %rdi
    lea network_buffer(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail40

    lea network_buffer(%rip), %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %ecx
    repe cmpsb
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail40
    xor %edi, %edi
    jmp .exit

.landlock_tcp_client:
    mov $41, %eax
    mov $2, %edi
    mov $1, %esi
    xor %edx, %edx
    syscall
    test %rax, %rax
    js .fail40
    mov %rax, %r13

    mov $42, %eax
    mov %r13, %rdi
    lea network_addr(%rip), %rsi
    mov $16, %edx
    syscall
    test %rax, %rax
    js .fail40

    mov $1, %eax
    mov %r13, %rdi
    lea loopback_message(%rip), %rsi
    mov $loopback_message_len, %edx
    syscall
    cmp $loopback_message_len, %rax
    jne .fail40

    mov $3, %eax
    mov %r13, %rdi
    syscall
    test %rax, %rax
    js .fail40
    xor %edi, %edi
    jmp .exit

.abstract_unix_connect:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    lea abstract_unix_addr(%rip), %rdi
    movw $1, (%rdi)
    movb $0, 2(%rdi)
    xor %ecx, %ecx
.abstract_unix_name_copy:
    movzbl (%rsi,%rcx), %eax
    test %al, %al
    je .abstract_unix_name_done
    cmp $107, %ecx
    jae .fail42
    movb %al, 3(%rdi,%rcx)
    inc %ecx
    jmp .abstract_unix_name_copy
.abstract_unix_name_done:
    lea 3(%rcx), %edx
    mov $42, %eax
    mov $9, %edi
    lea abstract_unix_addr(%rip), %rsi
    syscall
    test %rax, %rax
    jns .abstract_unix_connected
    neg %eax
    mov %eax, %edi
    jmp .exit
.abstract_unix_connected:
    xor %edi, %edi
    jmp .exit

.landlock_device_ioctl:
    # The allowed device must be opened after Landlock restriction and its
    # RNDGETENTCNT ioctl must really succeed.
    mov $257, %eax
    mov $-100, %edi
    lea landlock_ioctl_allowed(%rip), %rsi
    mov $524288, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail44
    mov %rax, %r12

    mov $16, %eax
    mov %r12, %rdi
    mov $0x80045200, %esi
    lea landlock_ioctl_entropy(%rip), %rdx
    syscall
    test %rax, %rax
    js .fail44

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail44

    # The sibling random device is equally visible/openable but has no
    # IOCTL_DEV rule, so the same ioctl must be denied by Landlock with EACCES.
    mov $257, %eax
    mov $-100, %edi
    lea landlock_ioctl_denied(%rip), %rsi
    mov $524288, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail44
    mov %rax, %r12

    mov $16, %eax
    mov %r12, %rdi
    mov $0x80045200, %esi
    lea landlock_ioctl_entropy(%rip), %rdx
    syscall
    cmp $-13, %rax
    jne .fail44

    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail44
    xor %edi, %edi
    jmp .exit

.pidfd_signal_allowed:
    mov $434, %eax
    mov $1, %edi
    xor %esi, %esi
    syscall
    test %rax, %rax
    js .pidfd_open_errno
    mov %eax, %edi
    mov $424, %eax
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    jns .pidfd_signal_ok
    neg %eax
    mov %eax, %edi
    jmp .exit
.pidfd_signal_ok:
    xor %edi, %edi
    jmp .exit

.pidfd_signal_denied:
    mov $434, %eax
    mov $1, %edi
    xor %esi, %esi
    syscall
    test %rax, %rax
    js .pidfd_open_errno
    mov %eax, %edi
    mov $424, %eax
    xor %esi, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-1, %rax
    je .pidfd_signal_ok
    test %rax, %rax
    jns .pidfd_signal_unexpected_success
    neg %eax
    mov %eax, %edi
    jmp .exit
.pidfd_signal_unexpected_success:
    mov $42, %edi
    jmp .exit

.pidfd_open_errno:
    neg %eax
    add $100, %eax
    mov %eax, %edi
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

.resource_usage:
    mov $9, %eax
    xor %edi, %edi
    mov $8388608, %esi
    mov $3, %edx
    mov $34, %r10d
    mov $-1, %r8
    xor %r9d, %r9d
    syscall
    test %rax, %rax
    js .fail3
    mov %rax, %r12
    xor %ecx, %ecx
.resource_usage_touch:
    movb $1, (%r12,%rcx)
    add $4096, %rcx
    cmp $8388608, %rcx
    jb .resource_usage_touch
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
    jmp .exit
.fail34:
    mov $34, %edi
    jmp .exit
.fail35:
    mov $35, %edi
    jmp .exit
.fail36:
    mov $36, %edi
    jmp .exit
.fail37:
    mov $37, %edi
    jmp .exit
.fail38:
    mov $38, %edi
    jmp .exit
.fail39:
    mov $39, %edi
    jmp .exit
.fail40:
    mov $40, %edi
    jmp .exit
.fail41:
    mov $41, %edi
    jmp .exit
.fail42:
    mov $42, %edi
    jmp .exit
.fail44:
    mov $44, %edi
    jmp .exit
.fail45:
    mov $45, %edi
    jmp .exit
.fail46:
    mov $46, %edi

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
loopback_message:
    .ascii "loopback-ok"
.set loopback_message_len, . - loopback_message
brokered_host_message:
    .ascii "brokered-host-loopback-ok"
.set brokered_host_message_len, . - brokered_host_message
brokered_host_udp_message:
    .ascii "brokered-host-udp-ok"
.set brokered_host_udp_message_len, . - brokered_host_udp_message
brokered_host_unix_message:
    .ascii "brokered-host-unix-ok"
.set brokered_host_unix_message_len, . - brokered_host_unix_message
brokered_host_unix_reply:
    .ascii "host-unix-reply"
.set brokered_host_unix_reply_len, . - brokered_host_unix_reply
brokered_host_udp_direct_probe:
    .ascii "direct-host-udp-probe"
.set brokered_host_udp_direct_probe_len, . - brokered_host_udp_direct_probe
brokered_ingress_ready:
    .ascii "brokered-host-ingress-ready\n"
.set brokered_ingress_ready_len, . - brokered_ingress_ready
brokered_ingress_request:
    .ascii "brokered-host-ingress-request"
.set brokered_ingress_request_len, . - brokered_ingress_request
brokered_ingress_reply:
    .ascii "brokered-host-ingress-ok"
.set brokered_ingress_reply_len, . - brokered_ingress_reply
landlock_ioctl_allowed:
    .asciz "/devices/urandom"
landlock_ioctl_denied:
    .asciz "/devices/random"
landlock_allowed_path:
    .asciz "/landlock-allowed/marker"
landlock_denied_path:
    .asciz "/landlock-denied/secret"
landlock_allowed_message:
    .ascii "landlock-allowed\n"
.set landlock_allowed_message_len, . - landlock_allowed_message
landlock_mutation_scratch:
    .asciz "/scratch/landlock-created"
landlock_mutation_scratch_byte:
    .ascii "s"
landlock_mutation_existing:
    .asciz "/persist/allowed/existing"
landlock_mutation_remove:
    .asciz "/persist/allowed/remove-me"
landlock_mutation_denied_create:
    .asciz "/persist/denied/created"
landlock_mutation_denied_remove:
    .asciz "/persist/denied/blocked"
landlock_mutation_message:
    .ascii "landlock-persistent-write\n"
.set landlock_mutation_message_len, . - landlock_mutation_message
deadline_message:
    .ascii "deadline target started\n"
.set deadline_message_len, . - deadline_message
.balign 8
deadline_watchdog_sleep:
    .quad 5
    .quad 0

.section .bss
.balign 8
host_unix_addr:
    .zero 110
brokered_host_unix_buffer:
    .zero brokered_host_unix_reply_len
landlock_ioctl_entropy:
    .zero 4
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
network_addr_denied:
    .skip 16
abstract_unix_addr:
    .skip 110
.balign 8
network_ifreq:
    .skip 40
network_buffer:
    .skip 32
landlock_buffer:
    .skip 32

.section .note.GNU-stack,"",@progbits
