#ifndef LSASSC_UTIL_H
#define LSASSC_UTIL_H

#include <windows.h>

VOID AddWin32uToIat();
BOOL SetSeDebugPrivilege();
BOOL GetProcessHandle(_In_ ULONG ulProcessHash, _Out_ PDWORD pdwProcessID, _Out_ PHANDLE phProcess);

#endif //LSASSC_UTIL_H