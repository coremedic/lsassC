#include "Win32.h"

HMODULE GetModuleHandleH(IN identity_t idModuleHash) {

    PPEB					pPeb			= NULL;
    PPEB_LDR_DATA			pLdr			= NULL;
    PLDR_DATA_TABLE_ENTRY	pDte			= NULL;

    pPeb		= (PPEB)__readgsqword(0x60);
    pLdr		= (PPEB_LDR_DATA)(pPeb->LoaderData);
    pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    if (!idModuleHash)
        return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

    while (pDte) {

        if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

            char* utf8String = UnicodeStringToUtf8(&pDte->FullDllName);
            if (IdentityRuntime(utf8String) == idModuleHash) {
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
            }
        }

        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}

