.x64
.model flat, fastcall
;option casemap:none

.data

wSystemCall       DWORD   0
qSyscallInsAdress QWORD   0

.code

SetSsn PROC
    mov eax, wSystemCall
    mov qSyscallInsAdress, 0
    mov wSystemCall, ecx
    mov qSyscallInsAdress, rdx
    ret
SetSsn ENDP

RunSyscall PROC
    mov r10, rcx
    mov eax, wSystemCall
    jmp qword ptr [qSyscallInsAdress]
    ret
RunSyscall ENDP

end
