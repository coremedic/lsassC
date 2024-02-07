#include <stdio.h>
#include <shlobj.h>

#include "Syscalls.h"

#pragma comment (lib, "shell32.lib")

#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0)

SYSCALL_API g_SyscallApi = { 0 };

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

int main() {
    PVOID*   ppInstAddr  = NULL;
    BOOL     bResult     = FALSE;
    NTSTATUS ntStatus    = 0;

    AddWin32uToIat();
    bResult = InitSyscalls(&g_SyscallApi);

    SET_SYSCALL(g_SyscallApi.NtOpenProcess);
    if (!NT_SUCCESS(ntStatus = RunSyscall())) {
        printf("We did it!\n");
    }

    printf("%d\n", bResult);
    return 0;
}
