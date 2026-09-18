.global _start
.section .text
_start:
    # Open the interpreter path after the loader transfers control.
    mov $257, %rax
    mov $-100, %rdi
    lea loader_path(%rip), %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall
    test %rax, %rax
    js .fail
    mov %rax, %r12

    # The private copied loader mount deliberately has mode 0700, while the
    # host fixture inode is 0555. This proves the target path is the overlay.
    sub $144, %rsp
    mov $5, %rax
    mov %r12, %rdi
    mov %rsp, %rsi
    syscall
    test %rax, %rax
    js .fail_close_stack
    mov 24(%rsp), %eax
    and $511, %eax
    cmp $448, %eax
    jne .fail_close_stack
    add $144, %rsp

    mov $3, %rax
    mov %r12, %rdi
    syscall

    # The target owns write permission by mode, so EROFS proves the mount
    # itself (not mode bits) enforces immutability.
    mov $257, %rax
    mov $-100, %rdi
    lea loader_path(%rip), %rsi
    mov $1, %rdx
    xor %r10, %r10
    syscall
    cmp $-30, %rax
    jne .fail

    mov $60, %rax
    mov $73, %rdi
    syscall

.fail_close_stack:
    add $144, %rsp
.fail_close:
    mov $3, %rax
    mov %r12, %rdi
    syscall
.fail:
    mov $60, %rax
    mov $74, %rdi
    syscall

.section .rodata
loader_path:
    .asciz "/loader"
