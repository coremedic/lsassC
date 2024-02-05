#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include "Win32.h"
#include "identity.h"

extern identity_t NtOpenProcessHash;
extern identity_t NtCloseHash;
extern identity_t NtAdjustPrivilegesTokenHash;
extern identity_t NtQuerySystemInformationHash;
extern identity_t NtReadVirtualMemoryHash;
extern identity_t NtOpenProcessTokenHash;

extern identity_t Win32uDllHash;
extern identity_t NtDllDllHash;

extern BOOL GetSyscallInst(OUT PVOID* ppSyscallInstAddress);

typedef struct _SYSCALL {
    DWORD dwSsn;
    DWORD dwSyscallHash;
    PVOID pSyscallInstAddress;
} SYSCALL, *PSYSCALL;

typedef struct _SYSCALL_API {
    SYSCALL NtOpenProcess;
    SYSCALL NtClose;
    SYSCALL NtAdjustPrivilegesToken;
    SYSCALL NtQuerySystemInformation;
    SYSCALL NtReadVirtualMemory;
    SYSCALL NtOpenProcessToken;
    BOOL    bInit;
} SYSCALL_API, *PSYSCALL_API;

#endif //SYSCALLS_H
