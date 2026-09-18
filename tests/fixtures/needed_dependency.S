.text
.globl sealed_dependency_value
.type sealed_dependency_value,@function
sealed_dependency_value:
    mov $91, %eax
    ret
.size sealed_dependency_value, .-sealed_dependency_value

.section .note.GNU-stack,"",@progbits
