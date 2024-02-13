.x64
.model flat, fastcall
option casemap:none
option win64:1

public SetSsn
public RunSyscall
public RunSyscall6

.data

wSystemCall       DWORD   0
qSyscallInsAddress QWORD   0

.code

SetSsn PROC
    mov eax, wSystemCall
    mov qSyscallInsAddress, 0
    mov wSystemCall, ecx
    mov qSyscallInsAddress, rdx
    ret
SetSsn ENDP

RunSyscall PROC
    mov r10, rcx
    mov eax, wSystemCall
    jmp qword ptr [qSyscallInsAddress]
    ret
RunSyscall ENDP

RunSyscall6 PROC
    mov r10, rcx
    mov eax, wSystemCall
    jmp qword ptr [qSyscallInsAddress]
    ret
RunSyscall6 ENDP

end
