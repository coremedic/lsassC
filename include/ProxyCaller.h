#ifndef LSASSC_PROXYCALLER_H
#define LSASSC_PROXYCALLER_H

#include <windows.h>
#include "Macros.h"

#define MAX_SYSCALL_ARGS 16

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

//typedef struct _SYSCALL_ARGS {
//    UINT_PTR    pSyscallInstruction;
//    DWORD       dwSsn;
//    UINT_PTR    pArgs[MAX_SYSCALL_ARGS];
//} SYSCALL_ARGS, *PSYSCALL_ARGS;

template<UINT64 N>
struct SYSCALL_ARGS {
    UINT_PTR    pSyscallInstruction;
    DWORD       dwSsn;
    UINT64      argCount = N;
    UINT_PTR    pArgs[N];
};

NTSYSAPI
NTSTATUS
NTAPI
TpAllocWork(
        _Out_ PTP_WORK *WorkReturn,
        _In_ PTP_WORK_CALLBACK Callback,
        _Inout_opt_ PVOID Context,
        _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
        );

NTSYSAPI
VOID
NTAPI
TpPostWork(
        _Inout_ PTP_WORK Work
);

NTSYSAPI
VOID
NTAPI
TpReleaseWork(
        _Inout_ PTP_WORK Work
);

//typedef NTSTATUS (NTAPI* TPALLOCWORK)(PTP_WORK* ptpWrk, PTP_WORK_CALLBACK pfnwkCallback, PVOID OptionalArg, PTP_CALLBACK_ENVIRON CallbackEnvironment);
//typedef VOID (NTAPI* TPPOSTWORK)(PTP_WORK);
//typedef VOID (NTAPI* TPRELEASEWORK)(PTP_WORK);

EXTERN_C VOID CALLBACK WorkCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
EXTERN_C VOID CALLBACK ProxyIndirect(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
EXTERN_C VOID CALLBACK DynamicProxy(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);


#endif //LSASSC_PROXYCALLER_H
