.global _start
.section .text

# Tiny statically linked Linux x86_64 fixture. It uses only raw syscalls so
# each integration test can grant an exact, reviewable syscall set without
# depending on glibc or the Rust runtime's startup behavior.
#
# argv[1] mode:
#   A allowed write
#   F forbidden getpid; exits 77 only when seccomp returns -EPERM
#   E validate sanitized environment
#   C validate working directory against argv[2]
#   X exit 42
#   S self-terminate with SIGTERM
#   N open until RLIMIT_NOFILE produces EMFILE
#   P assert PR_GET_NO_NEW_PRIVS == 1
#   R read back all configured resource limits
#   W create argv[2] marker (used to prove failed setup never executes child)
#   D assert descriptor number in argv[2] is closed after exec
#   H assert absolute host path argv[2] is hidden by filesystem root
#   I assert namespace uid/gid are 0 and all capability sets are empty

_start:
    mov 16(%rsp), %rdi
    test %rdi, %rdi
    je .fail2
    movzbl (%rdi), %eax
    cmp $65, %al
    je .allowed
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

.forbidden:
    mov $39, %eax
    syscall
    cmp $-1, %rax
    jne .fail7
    mov $77, %edi
    jmp .exit

.environment:
    # envp begins after argc, argv pointers, and argv NULL terminator.
    mov (%rsp), %rcx
    lea 16(%rsp,%rcx,8), %r8
    xor %r9d, %r9d
.env_loop:
    mov (%r8), %rdi
    test %rdi, %rdi
    je .env_done
    cmpl $0x48544150, (%rdi)       # "PATH" little endian
    jne .check_allowed_env
    cmpb $61, 4(%rdi)             # '='
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
    cmp $-24, %rax               # -EMFILE
    jne .fail12
    xor %edi, %edi
    jmp .exit

.no_new_privs:
    mov $157, %eax
    mov $39, %edi                # PR_GET_NO_NEW_PRIVS
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
    mov $0, %esi                 # RLIMIT_CPU
    mov $2, %r12
    call .check_one_limit
    mov $1, %esi                 # RLIMIT_FSIZE
    mov $1048576, %r12
    call .check_one_limit
    mov $7, %esi                 # RLIMIT_NOFILE
    mov $32, %r12
    call .check_one_limit
    mov $9, %esi                 # RLIMIT_AS
    mov $134217728, %r12
    call .check_one_limit
    xor %edi, %edi
    jmp .exit

# esi=resource, r12=expected soft/hard value.
.check_one_limit:
    xor %edi, %edi               # pid 0 = self
    xor %edx, %edx               # new_limit = NULL
    lea limit_buffer(%rip), %r10
    mov $302, %eax               # prlimit64
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
    mov $577, %edx               # O_WRONLY | O_CREAT | O_TRUNC
    mov $384, %r10d              # 0600
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
    mov $72, %eax                # fcntl
    mov %r12d, %edi
    mov $1, %esi                 # F_GETFD
    xor %edx, %edx
    syscall
    cmp $-9, %rax                # -EBADF means fd did not survive exec
    jne .fail15
    xor %edi, %edi
    jmp .exit

.host_path_hidden:
    mov 24(%rsp), %rsi
    test %rsi, %rsi
    je .fail2
    mov $257, %eax               # openat
    mov $-100, %edi              # AT_FDCWD
    xor %edx, %edx               # O_RDONLY
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax                # -ENOENT proves host path is outside root
    jne .fail16
    xor %edi, %edi
    jmp .exit

.identity_reduced:
    mov $102, %eax               # getuid
    syscall
    test %rax, %rax
    jne .fail17
    mov $104, %eax               # getgid
    syscall
    test %rax, %rax
    jne .fail17

    movl $0x20080522, cap_header(%rip)  # _LINUX_CAPABILITY_VERSION_3
    movl $0, cap_header+4(%rip)
    lea cap_header(%rip), %rdi
    lea cap_data(%rip), %rsi
    mov $125, %eax               # capget
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
    cmp $41, %r12d               # Linux capabilities 0..40 in v3 ABI
    je .cap_ambient_start
    mov $157, %eax               # prctl
    mov $23, %edi                # PR_CAPBSET_READ
    mov %r12d, %esi
    xor %edx, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax              # every bounding bit must be clear
    jne .fail17
    inc %r12d
    jmp .cap_bound_loop

.cap_ambient_start:
    xor %r12d, %r12d
.cap_ambient_loop:
    cmp $41, %r12d
    je .identity_ok
    mov $157, %eax               # prctl
    mov $47, %edi                # PR_CAP_AMBIENT
    mov $1, %esi                 # PR_CAP_AMBIENT_IS_SET
    mov %r12d, %edx
    xor %r10d, %r10d
    xor %r8d, %r8d
    syscall
    test %rax, %rax              # no ambient capability may be set
    jne .fail17
    inc %r12d
    jmp .cap_ambient_loop

.identity_ok:
    xor %edi, %edi
    jmp .exit

# rdi=a, rsi=b; eax=1 if equal including terminating NUL, else 0.
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

.section .note.GNU-stack,"",@progbits
