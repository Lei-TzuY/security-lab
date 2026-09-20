.text
.globl _start
.type _start,@function
_start:
    mov $257, %eax
    mov $-100, %edi
    lea original_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12

    xor %eax, %eax
    mov %r12, %rdi
    lea one_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail
    cmpb $'h', one_byte(%rip)
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea original_path(%rip), %rsi
    mov $513, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea private_message(%rip), %rsi
    mov $private_message_len, %edx
    syscall
    cmp $private_message_len, %rax
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea created_path(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea created_message(%rip), %rsi
    mov $created_message_len, %edx
    syscall
    cmp $created_message_len, %rax
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea original_path(%rip), %rsi
    xor %edx, %edx
    xor %r10d, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    xor %eax, %eax
    mov %r12, %rdi
    lea one_byte(%rip), %rsi
    mov $1, %edx
    syscall
    cmp $1, %rax
    jne .fail
    cmpb $'p', one_byte(%rip)
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
    mov $91, %edi
    mov $60, %eax
    syscall

.section .rodata
original_path:
    .asciz "/cowdata/original"
created_path:
    .asciz "/cowdata/created"
private_message:
    .ascii "private\n"
.set private_message_len, . - private_message
created_message:
    .ascii "created\n"
.set created_message_len, . - created_message

.section .bss
one_byte:
    .skip 1

.section .note.GNU-stack,"",@progbits
