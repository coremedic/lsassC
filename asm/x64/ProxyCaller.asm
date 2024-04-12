.x64
.model flat, fastcall
option casemap:none
option win64:1

public WorkCallback
public ProxyIndirect
public DynamicProxy

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
    mov r11, [rbx]        ; UINT_PTR    pSyscallInstruction
    ;mov rcx, [rbx + 08h]  ; HANDLE      hProcess
    mov rdx, [rbx + 010h] ; PVOID*      ppBaseAddress
    xor r8,  r8           ; ULONG_PTR   ZeroBits (set to 0)
    mov r9,  [rbx + 018h] ; PSIZE_T     pRegionSize
    mov r10, [rbx + 020h] ; ULONG       ulProtect
   ; mov eax, [rbx + 024h] ; DWORD       dwSsn
    mov [rsp + 030h], r10 ; Stack pointer for ulProtect
    mov r10, 03000h       ; ULONG       AllocationType (MEM_COMMIT|MEM_RESERVE)
    mov [rsp + 028h], r10 ; Stack pointer for AllocationType
    mov eax, [rbx + 024h] ; DWORD       dwSsn
    mov r10, [rbx + 08h]
    jmp r11               ; Jump to  pSyscallInstruction
ProxyIndirect ENDP

DynamicProxy PROC
    mov rbx, rdx                    ; Back up struct to rbx
    mov r11, [rbx]                  ; UINT_PTR      pSyscallInstruction
    mov eax, [rbx + 08h]            ; DWORD         dwSsn
    mov r10, [rbx + 010h]           ; SIZE_T        argCount
    cmp r10, 4                      ; Check if there are mote than 4 args
    jle no_stack_args               ; If 4 or fewer args, just load registers

    mov r8, r10                     ; Back up argCount to r8
    sub r8, 5                       ; Calculate index for last stack arg
    lea r9, [rbx + 038h]            ; Pointer to 5th arg in pArgs

stack_args:
    mov rdx, [r9 + r8*8]            ; Load stack arg from pArgs
    mov [rsp + 028h + r8*8], rdx    ; Put stack arg on stack
    dec r8                          ; Move to previous arg
    jns stack_args                  ; Continue if more stack args remain

no_stack_args:
    mov r10, [rbx + 018h]           ; Load 1st arg
    mov rdx, [rbx + 020h]           ; Load 2nd arg
    mov r8,  [rbx + 028h]           ; Load 3rd arg
    mov r9,  [rbx + 030h]           ; Load 4th arg

    jmp r11                         ; Jump to pSyscallInstruction

DynamicProxy ENDP

end













   ; lea rdx, [r9 + 08h]
   ; mov rcx, [rdx]
   ; lea rdx, [r9 + r8*8]
   ; lea rdx, [rsp + 028h + r8*8]
   ; mov [rdx], rcx
    ;dec r8
    ;jns stack_args