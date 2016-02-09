.global _ReadIdtr
_ReadIdtr:
    sidt    (%rdi)
    ret

.global _ReadCr3
_ReadCr3:
    mov     %cr3,%rax
    ret

.global _ReadCr2
_ReadCr2:
    mov     %cr2,%rax
    ret

.global _ReadCr0
_ReadCr0:
    mov     %cr0,%rax
    ret