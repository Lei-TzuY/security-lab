.text
.globl extra_dependency_value
.type extra_dependency_value,@function
extra_dependency_value:
    mov $17, %eax
    ret
.size extra_dependency_value, .-extra_dependency_value

.section .note.GNU-stack,"",@progbits
