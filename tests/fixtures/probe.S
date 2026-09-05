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
#   W create argv[2] marker (used to prove failed setup never executes child)

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
    cmp $87, %al
    je .write_marker
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
    lea dev_null(%rip), %rsi
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
dev_null:
    .asciz "/dev/null"

.section .bss
.balign 16
cwd_buffer:
    .skip 4096
