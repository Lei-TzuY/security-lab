.text
.globl _start
.type _start,@function
_start:
    mov $257, %eax
    mov $-100, %edi
    lea readonly_one_marker(%rip), %rsi
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
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea readonly_two_marker(%rip), %rsi
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
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea readonly_one_forbidden(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail

    mov $257, %eax
    mov $-100, %edi
    lea readonly_two_forbidden(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-30, %rax
    jne .fail

    mov $257, %eax
    mov $-100, %edi
    lea writable_one_output(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea writable_one_message(%rip), %rsi
    mov $writable_one_message_len, %edx
    syscall
    cmp $writable_one_message_len, %rax
    jne .fail
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

    mov $257, %eax
    mov $-100, %edi
    lea writable_two_output(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12
    mov $1, %eax
    mov %r12, %rdi
    lea writable_two_message(%rip), %rsi
    mov $writable_two_message_len, %edx
    syscall
    cmp $writable_two_message_len, %rax
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
readonly_one_marker:
    .asciz "/data/marker"
readonly_two_marker:
    .asciz "/data2/marker"
readonly_one_forbidden:
    .asciz "/data/write-must-fail"
readonly_two_forbidden:
    .asciz "/data2/write-must-fail"
writable_one_output:
    .asciz "/persist/persisted"
writable_two_output:
    .asciz "/persist2/persisted"
writable_one_message:
    .ascii "persistent-one\n"
.set writable_one_message_len, . - writable_one_message
writable_two_message:
    .ascii "persistent-two\n"
.set writable_two_message_len, . - writable_two_message

.section .bss
one_byte:
    .skip 1

.section .note.GNU-stack,"",@progbits
