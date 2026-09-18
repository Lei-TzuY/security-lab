.text
.globl _start
.extern sealed_dependency_value
.type _start,@function
_start:
    call sealed_dependency_value@PLT
    mov %eax, %edi
    mov $60, %eax
    syscall
.size _start, .-_start

.section .note.GNU-stack,"",@progbits
