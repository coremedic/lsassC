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


    AddWin32uToIat();
    if (!InitSyscalls()) {
        return 0;
    }

    if (!SetSeDebugPrivilege()) {
        printf("[!] Failed to set SeDebugPrivilege\n");
    }

    if (!GetProcessHandle(HASHW(L"lsass.exe"), &dwLSASSId, &hLSASS)) {
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