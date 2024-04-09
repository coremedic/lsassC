.x64
.model flat, fastcall
option casemap:none
option win64:1

public WorkCallback

.data

wSyscallServiceNumber       DWORD   0
qSyscallInsAddress QWORD   0

.code

SetSyscallServiceNumber

WorkCallback PROC
    mov rbx, rdx
    mov rax, [rbx]
    mov rcx, [rbx + 08h]
    mov rdx, [rbx + 010h]
    xor r8,  r8
    mov r9,  [rbx + 018h]
    mov r10, [rbx + 020h]
    mov [rsp + 030h], r10
    mov r10, 03000h
    mov [rsp + 028h], r10
    jmp rax
WorkCallback ENDP

ProxyIndirect PROC
    mov rbx, rdx
    mov rax, [rbx]
    mov rcx, [rbx + 08h]
    mov rdx, [rbx + 010h]
    xor r8,  r8
    mov r9,  [rbx + 018h]
    mov r10, [rbx + 020h]
    mov [rsp + 030h], r10
    mov r10, 03000h
    mov [rsp + 028h], r10


end