#ifndef LSASSC_SYSCALLS_H
#define LSASSC_SYSCALLS_H

#include <windows.h>

typedef struct _SYSCALL {
    DWORD               dwSsn;
    unsigned long long  dwSyscallHash;
    PVOID               pSyscallInstructionAddress;
} SYSCALL, *PSYSCALL;

typedef struct _SYSCALL_API {
    SYSCALL NtAllocateVirtualMemory;
    BOOL    bInit;
} SYSCALL_API, *PSYSCALL_API;

#endif //LSASSC_SYSCALLS_H
