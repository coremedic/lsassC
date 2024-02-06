#include "Syscalls.h"

#include <stdio.h>

#define STUB_SIZE       0x20

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
MODULE_CONFIG   g_NtdllConf   = {nullptr};
MODULE_CONFIG   g_Win32uConf  = {nullptr};

BOOL InitModuleConfigs(OUT PMODULE_CONFIG pModuleConfig, IN ULONG_PTR ulBaseAddress) {
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

    printf("Win32uDllHash: %llu\n", Win32uDllHash);

    if (!g_Win32uConf.bInitialized) {
        if (!InitModuleConfigs(&g_Win32uConf, (ULONG_PTR)GetModuleHandleH(Win32uDllHash))) {
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
        printf("g_Win32uConf.dwNumberOfNames: %lu\n", g_Win32uConf.dwNumberOfNames);
        for (DWORD offset = 0; offset < STUB_SIZE; offset++) {
            unsigned short* pOpcode = (unsigned short*)((ULONG_PTR)pFuncAddress + offset);
            BYTE* pRetOpcode = (BYTE*)((ULONG_PTR)pFuncAddress + offset + sizeof(unsigned short));

            if (*pOpcode == (0x052A ^ 0x25) && *pRetOpcode == RET_OPCODE) {
                if (sysCnt == rndIdx) {
                    *ppSyscallInstAddress = (PVOID)((ULONG_PTR)pFuncAddress + offset);
                    return TRUE;
                }
                sysCnt++;
            }
        }
    }
    return FALSE;
}

// BOOL InitSyscalls(OUT PSYSCALL_API Syscalls) {
//     if (Syscalls->bInit) {
//         return TRUE;
//     }
// }