.text
.globl _start
.type _start,@function
_start:
    mov 16(%rsp), %r13
    mov 24(%rsp), %r15
    test %r13, %r13
    je .fail
    test %r15, %r15
    je .fail
    sub $192, %rsp
    mov $-1, %r12

    # Round 1 selects route 0.
    movb $82, 190(%rsp)
    movb $0, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 190(%rsp), %rsi
    mov $2, %edx
    syscall
    cmp $2, %rax
    jne .fail_restore

    call receive_one_fd
    test %r12d, %r12d
    js .fail_restore

    mov $1, %eax
    mov %r12d, %edi
    lea request_a(%rip), %rsi
    mov $request_a_len, %edx
    syscall
    cmp $request_a_len, %rax
    jne .fail_close

    xor %r14d, %r14d
.read_reply_a:
    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    add %r14, %rsi
    mov $reply_a_len, %edx
    sub %r14d, %edx
    syscall
    test %rax, %rax
    jle .fail_close
    add %rax, %r14
    cmp $reply_a_len, %r14d
    jne .read_reply_a
    lea 112(%rsp), %rdi
    lea reply_a(%rip), %rsi
    mov $reply_a_len, %ecx
    repe cmpsb
    jne .fail_close

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .fail_restore
    mov $-1, %r12

    # Round 2 selects route 1.
    movb $82, 190(%rsp)
    movb $1, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 190(%rsp), %rsi
    mov $2, %edx
    syscall
    cmp $2, %rax
    jne .fail_restore

    call receive_one_fd
    test %r12d, %r12d
    js .fail_restore

    mov $1, %eax
    mov %r12d, %edi
    lea request_b(%rip), %rsi
    mov $request_b_len, %edx
    syscall
    cmp $request_b_len, %rax
    jne .fail_close

    xor %r14d, %r14d
.read_reply_b:
    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    add %r14, %rsi
    mov $reply_b_len, %edx
    sub %r14d, %edx
    syscall
    test %rax, %rax
    jle .fail_close
    add %rax, %r14
    cmp $reply_b_len, %r14d
    jne .read_reply_b
    lea 112(%rsp), %rdi
    lea reply_b(%rip), %rsi
    mov $reply_b_len, %ecx
    repe cmpsb
    jne .fail_close

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .fail_restore
    mov $-1, %r12

    # Neither trusted host service pathname is reachable in the sandbox chroot.
    mov $257, %eax
    mov $-100, %edi
    mov %r13, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail_restore

    mov $257, %eax
    mov $-100, %edi
    mov %r15, %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    cmp $-2, %rax
    jne .fail_restore

    mov $3, %eax
    mov $10, %edi
    syscall
    test %rax, %rax
    js .fail_restore

    add $192, %rsp
    xor %edi, %edi
    mov $60, %eax
    syscall

receive_one_fd:
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
    jne .receive_fail
    cmpb $70, 144(%rsp)
    jne .receive_fail
    testl $8, 48(%rsp)
    jne .receive_fail
    cmpq $20, 80(%rsp)
    jne .receive_fail
    cmpl $1, 88(%rsp)
    jne .receive_fail
    cmpl $1, 92(%rsp)
    jne .receive_fail
    mov 96(%rsp), %r12d
    ret

.receive_fail:
    mov $-1, %r12
    ret

.fail_close:
    mov $3, %eax
    mov %r12d, %edi
    syscall
.fail_restore:
    add $192, %rsp
.fail:
    mov $31, %edi
    mov $60, %eax
    syscall

.section .rodata
request_a:
    .ascii "runtime-router-a\n"
.set request_a_len, . - request_a
reply_a:
    .ascii "runtime-router-a-ok\n"
.set reply_a_len, . - reply_a
request_b:
    .ascii "runtime-router-b\n"
.set request_b_len, . - request_b
reply_b:
    .ascii "runtime-router-b-ok\n"
.set reply_b_len, . - reply_b

.section .note.GNU-stack,"",@progbits
