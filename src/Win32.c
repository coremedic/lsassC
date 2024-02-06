#include "Win32.h"

#include <stdio.h>

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

            CHAR	cLDllName	[MAX_PATH]	= { 0 };
            DWORD	x						= 0x00;

            while (pDte->FullDllName.Buffer[x]) {

                CHAR	wC	= pDte->FullDllName.Buffer[x];

                if (wC >= 'A' && wC <= 'Z')
                    cLDllName[x] = wC - 'A' + 'a';
                else
                    cLDllName[x] = wC;

                x++;
            }

            cLDllName[x] = '\0';

            printf("pDte->FullDllName.Buffer: %ls pDte->FullDllName.Buffer HASH: %llu\n", pDte->FullDllName.Buffer, IDENTITY(pDte->FullDllName.Buffer));
            if (IDENTITY(pDte->FullDllName.Buffer) == idModuleHash || IDENTITY(cLDllName) == idModuleHash)
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
        }

        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }

    return NULL;
}
