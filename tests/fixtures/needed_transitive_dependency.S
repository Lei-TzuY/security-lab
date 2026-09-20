.text
.globl sealed_dependency_value
.extern extra_dependency_value
.type sealed_dependency_value,@function
sealed_dependency_value:
    call extra_dependency_value@PLT
    add $74, %eax
    ret
.size sealed_dependency_value, .-sealed_dependency_value

.section .note.GNU-stack,"",@progbits
