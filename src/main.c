#include <stdio.h>
#include <shlobj.h>

#include "Syscalls.h"

#pragma comment (lib, "shell32.lib")

SYSCALL_API g_SyscallApi = {};

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID*  ppInstAddr  = NULL;
    BOOL    bResult     = FALSE;

    AddWin32uToIat();
    bResult = InitSyscalls(&g_SyscallApi);

    SET_SYSCALL(g_SyscallApi.NtOpenProcess);

    printf("%d\n", bResult);
    return 0;
}
