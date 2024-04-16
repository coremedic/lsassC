#ifndef LSASSC_INSTANCE_H
#define LSASSC_INSTANCE_H

#include <windows.h>
#include "Native.h"
#include "Constexpr.h"
#include "ProxyCaller.h"
#include "Macros.h"

typedef struct _MODULE_CONFIG {
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   pModule;
} MODULE_CONFIG, *PMODULE_CONFIG;

typedef struct _INSTANCE  {
    struct {
        struct {
            PROXYLOAD
            ProxyLoader;
            SYSCALL<6>
            NtAllocateVirtualMemory;
            SYSCALL<6>
            NtAdjustPrivilegesToken;
            SYSCALL<5>
            NtQueryInformationProcess;
            SYSCALL<5>
            NtQueryInformationToken;
            SYSCALL<5>
            NtReadVirtualMemory;
            SYSCALL<4>
            NtQuerySystemInformation;
            SYSCALL<4>
            NtOpenProcess;
            SYSCALL<3>
            NtOpenProcessToken;
        } Api;

        struct {
            MODULE_CONFIG Ntdll;
            MODULE_CONFIG Win32u;
        } Modules;
    } Win32;
} INSTANCE, *PINSTANCE;

EXTERN PINSTANCE Instance;

#endif //LSASSC_INSTANCE_H
