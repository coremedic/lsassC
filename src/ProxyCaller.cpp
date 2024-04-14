#include "ProxyCaller.h"
#include "Common.h"

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

unsigned int GenerateRandomInt() {
    static unsigned int state = 123456789;
    state ^= state << 13;
    state ^= state >> 17;
    state ^= state << 5;
    return state;
}

// PEB walk, I don't even understand how the fuck my PEB talk
BOOL InitModuleConfig(_Out_ PMODULE_CONFIG pModuleConfig, _In_ ULONG_PTR pBaseAddress) {
    PIMAGE_NT_HEADERS       pImageNtHeaders = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDir = NULL;

    if (!pBaseAddress) {
        return FALSE;
    }
    pModuleConfig -> pModule = pBaseAddress;

    pImageNtHeaders = (PIMAGE_NT_HEADERS)(pModuleConfig->pModule + ((PIMAGE_DOS_HEADER)pModuleConfig->pModule)->e_lfanew);
    if (!pImageNtHeaders || pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }

    if (pImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return FALSE;
    }

    pImageExportDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleConfig->pModule + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImageExportDir) {
        return FALSE;
    }

    pModuleConfig->dwNumberOfNames      = pImageExportDir->NumberOfNames;
    pModuleConfig->pdwArrayOfNames      = (PDWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfNames);
    pModuleConfig->pdwArrayOfAddresses  = (PDWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfFunctions);
    pModuleConfig->pwArrayOfOrdinals    = (PWORD)(pModuleConfig->pModule + pImageExportDir->AddressOfNameOrdinals);

    if (!pModuleConfig->dwNumberOfNames || !pModuleConfig->pdwArrayOfNames || !pModuleConfig->pdwArrayOfAddresses || !pModuleConfig->pwArrayOfOrdinals) {
        return FALSE;
    }

    pModuleConfig->bInit = TRUE;
    return TRUE;
}

// Find that syscall instruction
template<UINT64 ArgCount>
BOOL FindSyscallInstruction(_Inout_ SYSCALL<ArgCount>* pSyscall) {
    int idx = GenerateRandomInt() % 16,
        cnt = 0;

    for (DWORD i = 0; i < Instance->Win32.Modules.Win32u.dwNumberOfNames; i++) {
        PCHAR pcFuncName = (PCHAR)(Instance->Win32.Modules.Win32u.pModule + Instance->Win32.Modules.Win32u.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(Instance->Win32.Modules.Win32u.pModule + Instance->Win32.Modules.Win32u.pdwArrayOfAddresses[Instance->Win32.Modules.Win32u.pwArrayOfOrdinals[i]]);

        if (!pcFuncName || !pFuncAddress)
            continue;
        for (DWORD offset = 0; offset < STUB_SIZE; offset++) {
            unsigned short* pOpcode = (unsigned short*)((ULONG_PTR)pFuncAddress + offset);
            BYTE* pRetOpcode = (BYTE*)((ULONG_PTR)pFuncAddress + offset + sizeof(unsigned short));

            if (*pOpcode == (0x052A ^ 0x25) && *pRetOpcode == RET_OPCODE) {
                if (cnt == idx) {
                    pSyscall->pSyscallInstruction = U_PTR((PVOID)((ULONG_PTR)pFuncAddress + offset));
                    break;
                }
                cnt++;
            }
        }
        if (pSyscall->pSyscallInstruction) {
            return TRUE;
        }
    }
    return FALSE;
}

// Find syscall stub
template<UINT64 ArgCount>
BOOL FetchSyscallStub(_Inout_ SYSCALL<ArgCount>* pSyscall, _In_ ULONG ulSyscallHash) {
    for (DWORD i = 0; i < Instance->Win32.Modules.Ntdll.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(Instance->Win32.Modules.Ntdll.pModule + Instance->Win32.Modules.Ntdll.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(Instance->Win32.Modules.Ntdll.pModule + Instance->Win32.Modules.Ntdll.pdwArrayOfAddresses[Instance->Win32.Modules.Ntdll.pwArrayOfOrdinals[i]]);

        if (HashStringA(pcFuncName) == ulSyscallHash) {
            if (*((PBYTE)pFuncAddress) == MOV1_OPCODE
                && *((PBYTE)pFuncAddress + 1) == R10_OPCODE
                && *((PBYTE)pFuncAddress + 2) == RCX_OPCODE
                && *((PBYTE)pFuncAddress + 3) == MOV2_OPCODE
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE    high   = *((PBYTE)pFuncAddress + 5);
                BYTE    low    = *((PBYTE)pFuncAddress + 4);
                pSyscall->dwSsn = (high << 8) | low;
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
                        pSyscall->dwSsn = (high << 8) | low - idx;
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
                        pSyscall->dwSsn = (high << 8) | low + idx;
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
                        pSyscall->dwSsn = (high << 8) | low - idx;
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
                        pSyscall->dwSsn = (high << 8) | low + idx;
                        break;
                    }
                }
            }
            break;
        }
    }

    if (!pSyscall->dwSsn) {
        return FALSE;
    }

    return TRUE;
}

// Init all syscalls
BOOL InitSyscalls() {
    if (!InitModuleConfig(&Instance->Win32.Modules.Ntdll, (ULONG_PTR)GetModuleHandleA("ntdll.dll"))) {
        return FALSE;
    }

    if (!InitModuleConfig(&Instance->Win32.Modules.Win32u, (ULONG_PTR)GetModuleHandleA("win32u.dll"))) {
        return FALSE;
    }

    pHelper->TpAllocWork    = C_PTR(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpAllocWork"));
    pHelper->TpPostWork     = C_PTR(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpPostWork"));
    pHelper->TpReleaseWork  = C_PTR(GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseWork"));

    if (!Instance->Win32.Api.NtAllocateVirtualMemory.Init(&Instance->Win32.Api.NtAllocateVirtualMemory, HASHA("NtAllocateVirtualMemory"))) {
        return FALSE;
    }

    if (!Instance->Win32.Api.NtQueryInformationProcess.Init(&Instance->Win32.Api.NtQueryInformationProcess, HASHA("NtQueryInformationProcess"))) {
        return FALSE;
    }

    return TRUE;
}
