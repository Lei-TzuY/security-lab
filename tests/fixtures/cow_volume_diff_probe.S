.text
.globl _start
.type _start,@function
_start:
    mov $257, %eax
    mov $-100, %edi
    lea first_path(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea first_message(%rip), %rsi
    mov $first_message_len, %edx
    syscall
    cmp $first_message_len, %rax
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea second_path(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea second_message(%rip), %rsi
    mov $second_message_len, %edx
    syscall
    cmp $second_message_len, %rax
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    xor %edi, %edi
    mov $60, %eax
    syscall

.fail:
    mov $93, %edi
    mov $60, %eax
    syscall

.section .rodata
first_path:
    .asciz "/cowa/first"
second_path:
    .asciz "/cowb/second"
first_message:
    .ascii "alpha\n"
.set first_message_len, . - first_message
second_message:
    .ascii "beta\n"
.set second_message_len, . - second_message

.section .note.GNU-stack,"",@progbits
