[bits 64]

section .data
    wSystemCall       dd 0
    qSyscallInsAdress dq 0

section .text
    global SetSsn

SetSsn:
    push rbp
    mov rbp, rsp
    mov [wSystemCall], ecx
    mov [qSyscallInsAdress], rdx

    mov rsp, rbp
    pop rbp
    ret
