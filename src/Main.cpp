#include <windows.h>
#include <cstdio>
#include <shlobj.h>
#include "Common.h"
#include "ProxyCaller.h"
#pragma comment (lib, "shell32.lib")

INSTANCE _Instance = {NULL};
PINSTANCE Instance = &_Instance;

HELPER _Helper  = {NULL};
PHELPER pHelper = &_Helper;

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    UINT_PTR pArgs[6];
    PVOID   pAddress  = NULL;
    SIZE_T  memSize   = 4096;

    AddWin32uToIat();
    if (!InitSyscalls()) {
        return 0;
    }

    pArgs[0] = U_PTR(NtCurrentProcess());
    pArgs[1] = U_PTR(&pAddress);
    pArgs[2] = U_PTR(NULL);
    pArgs[3] = U_PTR(&memSize);
    pArgs[4] = U_PTR((MEM_COMMIT|MEM_RESERVE));
    pArgs[5] = U_PTR(PAGE_EXECUTE_READWRITE);

    Instance->Win32.Api.NtAllocateVirtualMemory.ProxyCall(pArgs);

    printf("Memory allocated at: %p\n", pAddress);
    getchar();

    return 0;
}