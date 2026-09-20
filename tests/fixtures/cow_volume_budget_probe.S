.text
.globl _start
.type _start,@function
_start:
    mov $257, %eax
    mov $-100, %edi
    lea output_path(%rip), %rsi
    mov $577, %edx
    mov $384, %r10d
    syscall
    cmp $-28, %rax
    je .success
    test %rax, %rax
    js .fail
    mov %rax, %r12
    xor %r13d, %r13d

.write_more:
    mov $1, %eax
    mov %r12, %rdi
    lea page(%rip), %rsi
    mov $4096, %edx
    syscall
    cmp $-28, %rax
    je .close_success
    test %rax, %rax
    js .fail
    inc %r13d
    cmp $256, %r13d
    jae .fail
    jmp .write_more

.close_success:
    mov $3, %eax
    mov %r12, %rdi
    syscall
    test %rax, %rax
    js .fail

.success:
    xor %edi, %edi
    mov $60, %eax
    syscall

.fail:
    mov $92, %edi
    mov $60, %eax
    syscall

.section .rodata
output_path:
    .asciz "/cowdata/too-big"

.section .bss
.balign 4096
page:
    .skip 4096

.section .note.GNU-stack,"",@progbits
