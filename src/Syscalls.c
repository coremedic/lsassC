#include "Syscalls.h"

#include <stdio.h>

#define STUB_SIZE       0x20

#define UP              (-1 * STUB_SIZE)
#define DOWN            STUB_SIZE
#define SEARCH_RANGE    0xFF

#define MOV1_OPCODE     0x4C
#define R10_OPCODE      0x8B
#define RCX_OPCODE      0xD1
#define MOV2_OPCODE     0xB8
#define JMP_OPCODE      0xE9
#define RET_OPCODE      0xC3

identity_t NtOpenProcessHash             = IDENTITY("NtOpenProcess");
identity_t NtCloseHash                   = IDENTITY("NtClose");
identity_t NtAdjustPrivilegesTokenHash   = IDENTITY("NtAdjustPrivilegesTokenH");
identity_t NtQuerySystemInformationHash  = IDENTITY("NtQuerySystemInformation");
identity_t NtReadVirtualMemoryHash       = IDENTITY("NtReadVirtualMemory");
identity_t NtOpenProcessTokenHash        = IDENTITY("NtOpenProcessToken");

identity_t Win32uDllHash                 = IDENTITY("win32u.dll");
identity_t NtDllDllHash                  = IDENTITY("ntdll.dll");

typedef struct _MODULE_CONFIG
{

    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   uModule;
    BOOLEAN     bInitialized;

} MODULE_CONFIG, *PMODULE_CONFIG;

// Global
MODULE_CONFIG   g_NtdllConf   = {NULL};
MODULE_CONFIG   g_Win32uConf  = {NULL};

BOOL InitModuleConfig(OUT PMODULE_CONFIG pModuleConfig, IN ULONG_PTR ulBaseAddress) {
    PIMAGE_NT_HEADERS       pImageNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDir = NULL;

    if (ulBaseAddress == (ULONG_PTR)NULL) {
        return FALSE;
    }
    pModuleConfig -> uModule = ulBaseAddress;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pModuleConfig->uModule + ((PIMAGE_DOS_HEADER)pModuleConfig->uModule)->e_lfanew);
    if (pImageNtHeaders == NULL || pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    if (pImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return FALSE;
    }

    pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleConfig->uModule + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (pImageExportDir == NULL) {
        return FALSE;
    }

    pModuleConfig->dwNumberOfNames = pImageExportDir->NumberOfNames;
    pModuleConfig->pdwArrayOfNames = (PDWORD)(pModuleConfig->uModule + pImageExportDir->AddressOfNames);
    pModuleConfig->pdwArrayOfAddresses = (PDWORD)(pModuleConfig->uModule + pImageExportDir->AddressOfFunctions);
    pModuleConfig->pwArrayOfOrdinals = (PWORD)(pModuleConfig->uModule + pImageExportDir->AddressOfNameOrdinals);

    if (!pModuleConfig->dwNumberOfNames || !pModuleConfig->pdwArrayOfNames || !pModuleConfig->pdwArrayOfAddresses || !pModuleConfig->pwArrayOfOrdinals) {
        return FALSE;
    }

    pModuleConfig->bInitialized = TRUE;
    return TRUE;
}

unsigned int GenerateRandomInt() {
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

BOOL GetSyscallInst(OUT PVOID* ppSyscallInstAddress) {
    INT rndIdx = GenerateRandomInt() % 0x10,
        sysCnt = 0;

    if (!g_Win32uConf.bInitialized) {
        if (!InitModuleConfig(&g_Win32uConf, (ULONG_PTR)GetModuleHandleH(Win32uDllHash))) {
#ifdef DEBUG
            printf("[!] InitModuleConfig failed with error: %llu\n", GetLastError());
#endif
            return FALSE;
        }
    }

    if (g_Win32uConf.dwNumberOfNames == 0 || g_Win32uConf.pdwArrayOfNames == NULL) {
        return FALSE;
    }

    for (DWORD i = 0; i < g_Win32uConf.dwNumberOfNames; i++) {
        PCHAR pcFuncName = (PCHAR)(g_Win32uConf.uModule + g_Win32uConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(g_Win32uConf.uModule + g_Win32uConf.pdwArrayOfAddresses[g_Win32uConf.pwArrayOfOrdinals[i]]);

        if (pcFuncName == NULL || pFuncAddress == NULL)
            continue;
        for (DWORD offset = 0; offset < STUB_SIZE; offset++) {
            unsigned short* pOpcode = (unsigned short*)((ULONG_PTR)pFuncAddress + offset);
            BYTE* pRetOpcode = (BYTE*)((ULONG_PTR)pFuncAddress + offset + sizeof(unsigned short));

            if (*pOpcode == (0x052A ^ 0x25) && *pRetOpcode == RET_OPCODE) {
                if (sysCnt == rndIdx) {
                    *ppSyscallInstAddress = (PVOID)((ULONG_PTR)pFuncAddress + offset);
                    break;
                }
                sysCnt++;
            }
        }
        if (*ppSyscallInstAddress) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL FetchNtSyscall(IN unsigned long long dwSyscallHash, OUT PSYSCALL pNtSys) {
    if (!g_NtdllConf.bInitialized) {
        if (!InitModuleConfig(&g_NtdllConf, (ULONG_PTR)GetModuleHandleH(NtDllDllHash))) {
            return FALSE;
        }
    }
    if ((pNtSys->dwSyscallHash = dwSyscallHash) == NULL) {
#ifdef DEBUG
        printf("[!] pNtSys->dwSyscallHash is uninitialized\n");
#endif
        return FALSE;
    }

    for (DWORD i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

#ifdef DEBUG
        printf("[i] Syscall: %s Syscall Hash: %llu Hash: %llu\n", pcFuncName, IdentityRuntime(pcFuncName), dwSyscallHash);
#endif
        if (IdentityRuntime(pcFuncName) == dwSyscallHash) {
            if (*((PBYTE)pFuncAddress) == MOV1_OPCODE
                && *((PBYTE)pFuncAddress + 1) == R10_OPCODE
                && *((PBYTE)pFuncAddress + 2) == RCX_OPCODE
                && *((PBYTE)pFuncAddress + 3) == MOV2_OPCODE
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE    high   = *((PBYTE)pFuncAddress + 5);
                BYTE    low    = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSsn = (high << 8) | low;
                break;
            }

            if (*((PBYTE)pFuncAddress) == JMP_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }

            if (*((PBYTE)pFuncAddress + 3) == JMP_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSsn = (high << 8) | low - idx;
                        break;
                    }
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }

            break;
        }

    }

    if (pNtSys->dwSsn == NULL) {
        return FALSE;
    }

    return GetSyscallInst(&pNtSys->pSyscallInstAddress);
}

BOOL InitSyscalls(OUT PSYSCALL_API SysApi) {
    if (SysApi->bInit) {
        return TRUE;
    }

    if(!FetchNtSyscall(NtOpenProcessHash, &SysApi->NtOpenProcess)) {
        return FALSE;
    }

    /*if(!FetchNtSyscall(NtOpenProcessHash, &SysApi->NtOpenProcess)) {
        return FALSE;
    }*/


    SysApi->bInit = TRUE;
    return TRUE;
}