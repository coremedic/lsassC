.x64
.model flat, fastcall
option casemap:none
option win64:1

public WorkCallback
public ProxyIndirect

.data

dwSyscallServiceNumber      DWORD   0
qwSyscallInstructionAddress QWORD   0

.code

SetSyscallServiceNumber PROC
    mov eax, dwSyscallServiceNumber
    mov qwSyscallInstructionAddress, 0
    mov dwSyscallServiceNumber, ecx
    mov qwSyscallInstructionAddress, rdx
    ret
SetSyscallServiceNumber ENDP

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
    mov rbx, rdx          ; Back up struct to rbx
    mov rax, [rbx]        ; UINT_PTR    pSyscallInstruction
    mov rcx, [rbx + 08h]  ; HANDLE      hProcess
    mov rdx, [rbx + 010h] ; PVOID*      ppBaseAddress
    xor r8,  r8           ; ULONG_PTR   ZeroBits (set to 0)
    mov r9,  [rbx + 018h] ; PSIZE_T     pRegionSize
    mov r10, [rbx + 020h] ; ULONG       ulProtect
    mov eax, [rbx + 028h] ; DWORD       dwSsn
    mov [rsp + 030h], r10 ; Stack pointer for ulProtect
    mov r10, 03000h       ; ULONG       AllocationType (MEM_COMMIT|MEM_RESERVE)
    mov [rsp + 028h], r10 ; Stack pointer for AllocationType
    jmp rax               ; Jump to  pSyscallInstruction
ProxyIndirect ENDP

end