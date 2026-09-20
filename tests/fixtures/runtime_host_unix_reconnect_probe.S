.text
.globl _start
.type _start,@function
_start:
    mov 16(%rsp), %r13
    test %r13, %r13
    je .fail
    sub $192, %rsp
    mov %rsp, %r15
    mov $-1, %r12

    # Round 1 readiness.
    movb $82, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 191(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail_restore

    call receive_one_fd
    test %eax, %eax
    js .fail_restore
    mov %eax, %r12d

    mov $1, %eax
    mov %r12d, %edi
    lea request_one(%rip), %rsi
    mov $request_one_len, %edx
    syscall
    cmp $request_one_len, %rax
    jne .fail_close

    xor %r14d, %r14d
.read_reply_one:
    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    add %r14, %rsi
    mov $reply_one_len, %edx
    sub %r14d, %edx
    syscall
    test %rax, %rax
    jle .fail_close
    add %rax, %r14
    cmp $reply_one_len, %r14d
    jne .read_reply_one
    lea 112(%rsp), %rdi
    lea reply_one(%rip), %rsi
    mov $reply_one_len, %ecx
    repe cmpsb
    jne .fail_close

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .fail_restore
    mov $-1, %r12

    # Round 2 readiness on the same long-lived broker control stream.
    movb $82, 191(%rsp)
    mov $1, %eax
    mov $10, %edi
    lea 191(%rsp), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail_restore

    call receive_one_fd
    test %eax, %eax
    js .fail_restore
    mov %eax, %r12d

    mov $1, %eax
    mov %r12d, %edi
    lea request_two(%rip), %rsi
    mov $request_two_len, %edx
    syscall
    cmp $request_two_len, %rax
    jne .fail_close

    xor %r14d, %r14d
.read_reply_two:
    xor %eax, %eax
    mov %r12d, %edi
    lea 112(%rsp), %rsi
    add %r14, %rsi
    mov $reply_two_len, %edx
    sub %r14d, %edx
    syscall
    test %rax, %rax
    jle .fail_close
    add %rax, %r14
    cmp $reply_two_len, %r14d
    jne .read_reply_two
    lea 112(%rsp), %rdi
    lea reply_two(%rip), %rsi
    mov $reply_two_len, %ecx
    repe cmpsb
    jne .fail_close

    mov $3, %eax
    mov %r12d, %edi
    syscall
    test %rax, %rax
    js .fail_restore
    mov $-1, %r12

    # The service pathname remains outside the sandbox chroot.
    mov $257, %eax
    mov $-100, %edi
    mov %r13, %rsi
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

# Returns received fd in eax, or -1 on any malformed ancillary message.
receive_one_fd:
    # CALL pushes a return address. Keep all msghdr/iovec/cmsg state anchored
    # to the caller's reserved 192-byte frame through the stable r15 base.
    xor %eax, %eax
    mov %rax, 0(%r15)
    mov %rax, 8(%r15)
    lea 64(%r15), %rax
    mov %rax, 16(%r15)
    movq $1, 24(%r15)
    lea 80(%r15), %rax
    mov %rax, 32(%r15)
    movq $24, 40(%r15)
    movq $0, 48(%r15)

    lea 144(%r15), %rax
    mov %rax, 64(%r15)
    movq $1, 72(%r15)
    movq $0, 80(%r15)
    movq $0, 88(%r15)
    movq $0, 96(%r15)

    mov $47, %eax
    mov $10, %edi
    mov %r15, %rsi
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
    mov 96(%rsp), %eax
    test %eax, %eax
    js .receive_fail
    ret

.receive_fail:
    mov $-1, %eax
    ret

.fail_close:
    mov $3, %eax
    mov %r12d, %edi
    syscall
.fail_restore:
    add $192, %rsp
.fail:
    mov $29, %edi
    mov $60, %eax
    syscall

.section .rodata
request_one:
    .ascii "runtime-reconnect-one\n"
.set request_one_len, . - request_one
reply_one:
    .ascii "runtime-reconnect-one-ok\n"
.set reply_one_len, . - reply_one
request_two:
    .ascii "runtime-reconnect-two\n"
.set request_two_len, . - request_two
reply_two:
    .ascii "runtime-reconnect-two-ok\n"
.set reply_two_len, . - reply_two

.section .note.GNU-stack,"",@progbits
