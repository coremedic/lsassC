#include <windows.h>
#include <stdio.h>
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
    LPVOID allocatedAddress = NULL;
    SIZE_T allocatedsize    = 0x1000;

    AddWin32uToIat();
    if (!InitSyscalls(&g_syscallApi)) {
        return 0;
    }


    NTALLOCATEVIRTUALMEMORY_INDIRECT_ARGS ntAllocateVirtualMemoryArgs = {NULL};
    ntAllocateVirtualMemoryArgs.pSyscallInstruction = (UINT_PTR)g_syscallApi.NtAllocateVirtualMemory.pSyscallInstructionAddress;
    ntAllocateVirtualMemoryArgs.hProcess            = (HANDLE)-1;
    ntAllocateVirtualMemoryArgs.ppBaseAddress       = &allocatedAddress;
    ntAllocateVirtualMemoryArgs.pRegionSize         = &allocatedsize;
    ntAllocateVirtualMemoryArgs.ulProtect           = PAGE_EXECUTE_READWRITE;
    ntAllocateVirtualMemoryArgs.dwSsn               = g_syscallApi.NtAllocateVirtualMemory.dwSsn;

    __typeof__(TpAllocWork)*    TpAllocWork     = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWork");
    __typeof__(TpPostWork)*     TpPostWork      = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpPostWork");
    __typeof__(TpReleaseWork)*  TpReleaseWork   = (PVOID)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseWork");

    PTP_WORK WorkReturn = NULL;
    TpAllocWork(&WorkReturn, (PTP_WORK_CALLBACK)ProxyIndirect, &ntAllocateVirtualMemoryArgs, NULL);
    TpPostWork(WorkReturn);
    TpReleaseWork(WorkReturn);

    WaitForSingleObject((HANDLE)-1, 0x1000);
    printf("allocatedAddress: %p\n", allocatedAddress);
    getchar();

    return 0;
}