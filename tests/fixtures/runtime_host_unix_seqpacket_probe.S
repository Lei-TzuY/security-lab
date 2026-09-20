.text
.globl _start
.type _start,@function
_start:
    mov 16(%rsp), %r13
    test %r13, %r13
    je .fail
    sub $192, %rsp
    mov $-1, %r12

    movb $82, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 191(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail_restore

    # Receive exactly one SCM_RIGHTS seqpacket fd.
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

    # Two writes must remain two distinct SOCK_SEQPACKET messages.
    mov $1, %eax
    mov %r12d, %edi
    lea request_one(%rip), %rsi
    mov $request_one_len, %edx
    syscall
    cmp $request_one_len, %rax
    jne .fail_close

    mov $1, %eax
    mov %r12d, %edi
    lea request_two(%rip), %rsi
    mov $request_two_len, %edx
    syscall
    cmp $request_two_len, %rax
    jne .fail_close

    # Each read must return exactly one response packet.
    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    mov $32, %edx
    syscall
    cmp $reply_one_len, %rax
    jne .fail_close
    lea 112(%rsp), %rdi
    lea reply_one(%rip), %rsi
    mov $reply_one_len, %ecx
    repe cmpsb
    jne .fail_close

    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    mov $32, %edx
    syscall
    cmp $reply_two_len, %rax
    jne .fail_close
    lea 112(%rsp), %rdi
    lea reply_two(%rip), %rsi
    mov $reply_two_len, %ecx
    repe cmpsb
    jne .fail_close

    # Exact host service pathname stays outside the sandbox chroot.
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
    mov $41, %edi
    mov $60, %eax
    syscall

.section .rodata
request_one:
    .ascii "seq-one"
.set request_one_len, . - request_one
request_two:
    .ascii "seq-two-long"
.set request_two_len, . - request_two
reply_one:
    .ascii "reply-a"
.set reply_one_len, . - reply_one
reply_two:
    .ascii "reply-b-longer"
.set reply_two_len, . - reply_two

.section .note.GNU-stack,"",@progbits
