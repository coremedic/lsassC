#include <stdio.h>
#include <shlobj.h>

#include "Syscalls.h"

#pragma comment (lib, "shell32.lib")

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID*  ppInstAddr  = NULL;
    BOOL    bResult     = FALSE;

    AddWin32uToIat();
    bResult = GetSyscallInst(ppInstAddr);
    printf("[%d] %p\n", bResult, ppInstAddr);
    return 0;
}
