#include <windows.h>
#include <cstdio>
#include <shlobj.h>
#include "ProxyCaller.h"
#include "Syscalls.h"
#pragma comment (lib, "shell32.lib")

SYSCALL_API g_syscallApi = { 0 };

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID allocatedAddress  = NULL;
    SIZE_T allocatedsize    = 0x1000;

    AddWin32uToIat();
    if (!InitSyscalls(&g_syscallApi)) {
        return 0;
    }


//    NTALLOCATEVIRTUALMEMORY_INDIRECT_ARGS ntAllocateVirtualMemoryArgs = {NULL};
//    ntAllocateVirtualMemoryArgs.pSyscallInstruction = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress;
//    ntAllocateVirtualMemoryArgs.hProcess            = (HANDLE)-1;
//    ntAllocateVirtualMemoryArgs.ppBaseAddress       = &allocatedAddress;
//    ntAllocateVirtualMemoryArgs.pRegionSize         = &allocatedsize;
//    ntAllocateVirtualMemoryArgs.ulProtect           = PAGE_EXECUTE_READWRITE;
//    ntAllocateVirtualMemoryArgs.dwSsn               = g_syscallApi.NtAllocateVirtualMemory.dwSsn;

    SYSCALL_ARGS<6> syscallArgs;
    syscallArgs.pSyscallInstruction = U_PTR(g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress);
    syscallArgs.dwSsn               = U_PTR(g_syscallApi.NtAllocateVirtualMemory.dwSsn);
    syscallArgs.pArgs[0]            = U_PTR(NtCurrentProcess());
    syscallArgs.pArgs[1]            = U_PTR(&allocatedAddress);
    syscallArgs.pArgs[2]            = U_PTR(NULL);
    syscallArgs.pArgs[3]            = U_PTR(&allocatedsize);
    syscallArgs.pArgs[4]            = U_PTR((MEM_COMMIT|MEM_RESERVE));
    syscallArgs.pArgs[5]            = U_PTR(PAGE_EXECUTE_READWRITE);
    printf("%llu\n", syscallArgs.argCount);


    __typeof__(TpAllocWork)*    TpAllocWork     = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWork");
    __typeof__(TpPostWork)*     TpPostWork      = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpPostWork");
    __typeof__(TpReleaseWork)*  TpReleaseWork   = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseWork");


    PTP_WORK WorkReturn = NULL;
    TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)DynamicProxy, &syscallArgs, NULL);
    TpPostWork(WorkReturn);
    TpReleaseWork(WorkReturn);


    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("allocatedAddress: %p\n", allocatedAddress);
    getchar();

    return 0;
}