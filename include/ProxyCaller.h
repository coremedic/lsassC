#ifndef LSASSC_PROXYCALLER_H
#define LSASSC_PROXYCALLER_H

#include <windows.h>

typedef struct _NTALLOCATEVIRTUALMEMORY_ARGS {
    UINT_PTR pNtAllocateVirtualMemory;   // pointer to NtAllocateVirtualMemory - rax
    HANDLE hProcess;                     // HANDLE ProcessHandle - rcx
    PVOID* address;                      // PVOID *BaseAddress - rdx; ULONG_PTR ZeroBits - 0 - r8
    PSIZE_T size;                        // PSIZE_T RegionSize - r9; ULONG AllocationType - MEM_RESERVE|MEM_COMMIT = 3000 - stack pointer
    ULONG permissions;                   // ULONG Protect - PAGE_EXECUTE_READ - 0x20 - stack pointer
} NTALLOCATEVIRTUALMEMORY_ARGS, *PNTALLOCATEVIRTUALMEMORY_ARGS;

typedef struct _NTALLOCATEVIRTUALMEMORY_INDIRECT_ARGS {
    UINT_PTR    pSyscallInstruction;
    HANDLE      hProcess;
    PVOID*      ppBaseAddress;
    PSIZE_T     pRegionSize;
    ULONG       ulProtect;
    DWORD       dwSsn;
} NTALLOCATEVIRTUALMEMORY_INDIRECT_ARGS, *PNTALLOCATEVIRTUALMEMORY_INDIRECT_ARGS;

EXTERN_C VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);


#endif //LSASSC_PROXYCALLER_H
