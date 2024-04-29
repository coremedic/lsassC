#ifndef LSASSC_UTIL_H
#define LSASSC_UTIL_H

#include <windows.h>

VOID    AddWin32uToIat      ();
BOOL    SetSeDebugPrivilege ();
BOOL    FormatUnicodeString (_In_ CONST UNICODE_STRING* pUnicodeString, _Out_ PWCHAR* ppszWideString);
DWORD   FetchProcessID      (_In_ ULONG ulProcessHash, _Out_opt_ PHANDLE phProcessID);
BOOL    OpenProcessHandle   (_In_ ULONG ulProcessHash, _Inout_opt_ PDWORD pdwProcessID, _Out_ PHANDLE phProcess, _In_ ACCESS_MASK accessMask);

#endif //LSASSC_UTIL_H
