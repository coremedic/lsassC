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

#define STATUS_SUCCESS               0x00000000
#define STATUS_UNSUCCESSFUL          0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH  0xC0000004
#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0)

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
extern SYSCALL_API g_SyscallApi;

extern VOID SetSsn(IN DWORD dwSsn, IN PVOID pSyscallInstAddress);
#define SET_SYSCALL(Syscall)(SetSsn((DWORD)Syscall.dwSsn, (PVOID)Syscall.pSyscallInstAddress))
extern RunSyscall(PVOID pArg1, PVOID pArg2, PVOID pArg3, PVOID pArg4); // 4 args

#endif //SYSCALLS_H
