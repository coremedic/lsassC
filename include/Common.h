#ifndef LSASSC_COMMON_H
#define LSASSC_COMMON_H

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
    BOOLEAN     bInit;
} MODULE_CONFIG, *PMODULE_CONFIG;

typedef struct _INSTANCE  {
    struct {
        struct {
            SYSCALL<6>NtAllocateVirtualMemory;
            SYSCALL<5>NtQueryInformationProcess;
        } Api;

        struct {
            MODULE_CONFIG Ntdll;
            MODULE_CONFIG Win32u;
        } Modules;
    } Win32;

} INSTANCE, *PINSTANCE;

EXTERN PINSTANCE Instance;

#endif //LSASSC_COMMON_H
