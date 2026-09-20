.text
.globl _start
.type _start,@function
_start:
    mov 16(%rsp), %r13
    test %r13, %r13
    je .fail
    sub $192, %rsp
    mov $-1, %r12

    # Readiness for the one-shot runtime grant.
    movb $82, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 191(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail_restore

    # Receive exactly one SCM_RIGHTS descriptor.
    xor %eax, %eax
    mov %rax, 0(%rsp)
    mov %rax, 8(%rsp)
    lea 64(%rsp), %rax
    mov %rax, 16(%rsp)
    movq $1, 24(%rsp)
    lea 80(%rsp), %rax
    mov %rax, 32(%rsp)
    movq $24, 40(%rsp)
    movq $0, 48(%rsp)
    lea 144(%rsp), %rax
    mov %rax, 64(%rsp)
    movq $1, 72(%rsp)
    movq $0, 80(%rsp)
    movq $0, 88(%rsp)
    movq $0, 96(%rsp)

    mov $47, %eax
    mov $10, %edi
    mov %rsp, %rsi
    mov $0x40000000, %edx
    syscall
    cmp $1, %rax
    jne .fail_restore
    cmpb $70, 144(%rsp)
    jne .fail_restore
    testl $8, 48(%rsp)
    jne .fail_restore
    cmpq $20, 80(%rsp)
    jne .fail_restore
    cmpl $1, 88(%rsp)
    jne .fail_restore
    cmpl $1, 92(%rsp)
    jne .fail_restore
    mov 96(%rsp), %r12d
    test %r12d, %r12d
    js .fail_restore

    # Prove pre-revocation I/O reaches the real host service.
    mov $1, %eax
    mov %r12d, %edi
    lea before_revoke(%rip), %rsi
    mov $before_revoke_len, %edx
    syscall
    cmp $before_revoke_len, %rax
    jne .fail_close

    # The trusted host revokes after observing the marker. This read must wake
    # with EOF from shutdown(SHUT_RDWR), not arbitrary bytes or an error.
    xor %eax, %eax
    mov %r12d, %edi
    lea 176(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $0, %rax
    jne .fail_close

    # The original host pathname remains outside the sandbox chroot.
    mov $257, %eax
    mov $-100, %edi
    mov %r13, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail_close

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .fail_restore
    mov $-1, %r12

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail_restore

    add $192, %rsp
    xor %edi, %edi
    mov $60, %eax
    syscall

.fail_close:
    mov $3, %eax
    mov %r12d, %edi
    syscall
.fail_restore:
    add $192, %rsp
.fail:
    mov $30, %edi
    mov $60, %eax
    syscall

.section .rodata
before_revoke:
    .ascii "before-host-revoke\n"
.set before_revoke_len, . - before_revoke

.section .note.GNU-stack,"",@progbits
