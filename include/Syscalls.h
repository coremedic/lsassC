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

typedef struct _SYSCALL {
    DWORD               dwSsn;
    unsigned long long  dwSyscallHash;
    PVOID               pSyscallInstAddress;
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
extern BOOL InitSyscalls(OUT PSYSCALL_API SysApi);

extern VOID SetSsn(IN DWORD dwSsn, IN PVOID pSyscallInstAddress);
#define SET_SYSCALL(Syscall)(SetSsn((DWORD)Syscall.dwSsn, (PVOID)Syscall.pSyscallInstAddress))

#endif //SYSCALLS_H
