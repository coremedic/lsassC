#include "Common.h"

VOID
AddWin32uToIat() {

    WCHAR szPath[MAX_PATH] = { 0 };
    SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}

BOOL
FormatUnicodeString(_In_ CONST UNICODE_STRING* pUnicodeString, _Out_ PWCHAR* ppszWideString) {
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

/*!
 * @brief
 * Enables the SeDebugPrivilege
 * on the current process
 *
 * @return
 * TRUE if successful,
 * FALSE if unsuccessful
 */
BOOL
SetSeDebugPrivilege() {
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

/*!
 * @brief
 * Query system information
 * on specified SYSTEM_INFORMATION_CLASS
 *
 * @tparam SysInfoType
 * SYSTEM_INFORMATION_CLASS
 * field type
 *
 * @tparam SysInfoClass
 * SYSTEM_INFORMATION_CLASS
 * field enum
 *
 * @param ppSysInfo
 * Pointer to a
 * SysInfoType pointer
 *
 * @return
 * TRUE if successful,
 * FALSE if unsuccessful
 */
template<typename SysInfoType, SYSTEM_INFORMATION_CLASS SysInfoClass>
BOOL
QuerySystemInformation(_Out_ SysInfoType** ppSysInfo) {
    ULONG ulArrayLength = 0;

    if (!ppSysInfo) {
        return FALSE;
    }

    Instance->Win32.Api.NtQuerySystemInformation.ProxyCall(
            U_PTR(SysInfoClass),
            U_PTR(NULL),
            U_PTR(NULL),
            U_PTR(&ulArrayLength)
    );

    if (!ulArrayLength) {
        printf("[!] NtQuerySystemInformation call failed\n");
        return FALSE;
    }

    *ppSysInfo = (SysInfoType*)malloc(ulArrayLength);
    if (!*ppSysInfo) {
        printf("[!] Failed to allocate memory for information structure\n");
        return FALSE;
    }

    Instance->Win32.Api.NtQuerySystemInformation.ProxyCall(
            U_PTR(SysInfoClass),
            U_PTR(*ppSysInfo),
            U_PTR(ulArrayLength),
            U_PTR(NULL)
    );

    if (!*ppSysInfo) {
        printf("[!] NtQuerySystemInformation call failed\n");
        return FALSE;
    }

    return TRUE;
}

/*!
 * @breif
 * Fetch unique process ID
 * of process
 *
 * @param ulProcessHash
 * Hash of process name
 *
 * @return
 * Unique process ID
 */
DWORD
FetchProcessID(_In_ ULONG ulProcessHash, _Out_opt_ PHANDLE phProcessID) {
    DWORD                           dwProcessID                 = 0;
    PVOID                           pTempPtr                    = NULL;
    PSYSTEM_PROCESS_INFORMATION     pSystemProcessInformation   = NULL;

    if (!ulProcessHash) {
        goto EXIT;
    }

    if (!QuerySystemInformation<SYSTEM_PROCESS_INFORMATION, SystemProcessInformation>(&pSystemProcessInformation)) {
        pTempPtr = pSystemProcessInformation;
        goto EXIT;
    }
    pTempPtr = pSystemProcessInformation;

    while(pSystemProcessInformation->NextEntryOffset) {
        if (!pSystemProcessInformation->ImageName.Length || pSystemProcessInformation->ImageName.Length >= MAX_PATH) {
            goto NEXT;
        }

        if (HashStringW(pSystemProcessInformation->ImageName.Buffer) == ulProcessHash) {
            if (phProcessID) {
                *phProcessID = pSystemProcessInformation->UniqueProcessId;
            }

            dwProcessID = HandleToULong(pSystemProcessInformation->UniqueProcessId);
            goto EXIT;
        }

        NEXT:
        pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)(U_PTR(pSystemProcessInformation) + pSystemProcessInformation->NextEntryOffset);
    }

    EXIT:
    if (pTempPtr) {
        free(pTempPtr);
    }
    return dwProcessID;
}

/*!
 * @breif
 * Open process handle
 * with NtOpenProcess
 *
 * @param ulProcessHash
 * Hash of process name
 * (with .exe extension)
 *
 * @param pdwProcessID
 * Pointer to DWORD
 * for PID of process
 * optional
 *
 * @param phProcess
 * Pointer to HANDLE
 * for process handle
 *
 * @param accessMask
 * Desired access mask
 * for process handle
 *
 * @return
 * TRUE if successful,
 * FALSE if unsuccessful
 */
BOOL
OpenProcessHandle(_In_opt_ ULONG ulProcessHash, _Inout_opt_ PDWORD pdwProcessID, _Out_ PHANDLE phProcess, _In_ ACCESS_MASK accessMask) {
    OBJECT_ATTRIBUTES               objectAttributes            = {NULL};
    CLIENT_ID                       clientId                    = {NULL};
    HANDLE                          hProcessID                  = NULL;

    if (!phProcess) {
        return FALSE;
    }

    if (!pdwProcessID) {
        if (!ulProcessHash) {
            return FALSE;
        }
        FetchProcessID(ulProcessHash, &hProcessID);
        if (!hProcessID) {
            return FALSE;
        }
    } else if (!*pdwProcessID) {
        hProcessID = ULongToHandle(*pdwProcessID);
    } else {
        if (!ulProcessHash) {
            return FALSE;
        }
        *pdwProcessID = FetchProcessID(ulProcessHash, &hProcessID);
        if (!*pdwProcessID || !hProcessID) {
            return FALSE;
        }
    }

    clientId.UniqueProcess = hProcessID;
    clientId.UniqueThread  = 0;
    Instance->Win32.Api.NtOpenProcess.ProxyCall(
            U_PTR(phProcess),
            U_PTR(accessMask),
            U_PTR(&objectAttributes),
            U_PTR(&clientId)
    );

    if (!*phProcess) {
        printf("[!] NtOpenProcess call failed\n");
        return FALSE;
    }

    return TRUE;
}

/*!
 *
 */
BOOL
DuplicateProcessHandle(_In_ ULONG ulTargetProcessHandleHash, _Out_ PHANDLE phProcess, _In_ ACCESS_MASK desiredAccessMask) {
    BOOL                            bResult                      = FALSE;
    DWORD                           dwProcessID                  = 0;
    HANDLE                          hDupProc                     = NULL;
    PVOID                           pTempPtr                     = NULL;
    PSYSTEM_HANDLE_INFORMATION      pSystemHandleInformation     = NULL;
    PPUBLIC_OBJECT_TYPE_INFORMATION pPublicObjectTypeInformation = NULL;

    if (!ulTargetProcessHandleHash || !phProcess) {
        return bResult;
    }

    // Fetch target process ID
    dwProcessID = FetchProcessID(ulTargetProcessHandleHash, NULL);
    if (!dwProcessID) {
        return bResult;
    }

    // We need to get information on open handles
    if (!QuerySystemInformation<SYSTEM_HANDLE_INFORMATION, SystemHandleInformation>(&pSystemHandleInformation)) {
        pTempPtr = pSystemHandleInformation;
        goto EXIT;
    }
    pTempPtr = pSystemHandleInformation;

    // Loop through handles, duplicate them, query information
    for (DWORD i = 0; i < pSystemHandleInformation->Count; ++i) {
        if (pSystemHandleInformation->Handle[i].OwnerPid != dwProcessID) {
            if (!OpenProcessHandle(
                    NULL,
                    &dwProcessID,
                    &hDupProc,
                    PROCESS_DUP_HANDLE
                    )) {
                continue;
            }

            // Duplicate handle object
            Instance->Win32.Api.NtDuplicateObject.ProxyCall(
                    U_PTR(hDupProc),
                    U_PTR(pSystemHandleInformation->Handle[i].HandleValue),
                    U_PTR(NtCurrentProcess()),
                    U_PTR(phProcess),
                    U_PTR((PROCESS_QUERY_INFORMATION | PROCESS_CREATE_PROCESS)),
                    U_PTR(NULL),
                    U_PTR(NULL)
                    );
            if (!(*phProcess)) {
                CloseHandle(hDupProc);
                continue;
            }

            // Allocate memory for object type info
            pPublicObjectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(1024);
            if (!pPublicObjectTypeInformation) {
                CloseHandle(hDupProc);
                CloseHandle(*phProcess);
                continue;
            }

            // Query handle object information
            Instance->Win32.Api.NtQueryObject.ProxyCall(
                    U_PTR(hDupProc),
                    U_PTR(ObjectTypeInformation),
                    U_PTR(pPublicObjectTypeInformation),
                    U_PTR(1024),
                    U_PTR(NULL)
                    );
            if (!pPublicObjectTypeInformation->TypeName.Buffer) {
                CloseHandle(hDupProc);
                CloseHandle(*phProcess);
                free(pPublicObjectTypeInformation);
                continue;
            }

            // Check if handle object is of "Process" type
            if (!wcscmp(L"Process", pPublicObjectTypeInformation->TypeName.Buffer)) {
                CloseHandle(hDupProc);
                CloseHandle(*phProcess);
                free(pPublicObjectTypeInformation);
                continue;
            }

            // TODO: Get process ID from handle
        }
    }

    EXIT:
    if (pTempPtr) {
        free(pTempPtr);
    }
    if (pPublicObjectTypeInformation) {
        free(pPublicObjectTypeInformation);
    }
    if (hDupProc) {
        CloseHandle(hDupProc);
    }
    return bResult;
}
