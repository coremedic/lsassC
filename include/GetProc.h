#ifndef GETPROC_H
#define GETPROC_H

#include <stdio.h>

#include "Syscalls.h"
#include "Win32.h"
#include "identity.h"

extern identity_t lsassHash;
extern NTSTATUS GetProcHandle(IN DWORD ProcHash, OUT HANDLE *hProc);

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p,n,a,r,s) { \
(p)->Length = sizeof(OBJECT_ATTRIBUTES); \
(p)->RootDirectory = (r); \
(p)->Attributes = (a); \
(p)->ObjectName = (n); \
(p)->SecurityDescriptor = (s); \
(p)->SecurityQualityOfService = NULL; \
}

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG           NextEntryOffset;
    ULONG           NumberOfThreads;
    ULONG           Reserved1[6];
    LARGE_INTEGER   CreateTime;
    LARGE_INTEGER   UserTime;
    LARGE_INTEGER   KernelTime;
    UNICODE_STRING  ImageName;
    ULONG           BasePriority;
    HANDLE          ProcessId;
    HANDLE          InheriredFromProcessId;
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

#endif //GETPROC_H
