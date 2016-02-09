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

.global _AsmDisableWriteProtection
_AsmDisableWriteProtection:
    cli
    mov     %cr0, %rax
    and     $0xfffffffffffeffff,%rax
    mov     %rax, %cr0
    sti
    ret

.global _AsmEnableWriteProtection
_AsmEnableWriteProtection:
    cli
    mov     %cr0, %rax
    or      $0x10000,%rax
    mov     %rax, %cr0
    sti
    ret
