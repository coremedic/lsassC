#ifndef LSASSC_CONSTEXPR_H
#define LSASSC_CONSTEXPR_H

#include <windows.h>
#include "Macros.h"

#define HASHA(string) HashStringA((string))

CONSTEXPR ULONG CompileTimeSeed() {
    return      (__TIME__[7] - '0') * 1ULL    +
                (__TIME__[6] - '0') * 10ULL   +
                (__TIME__[4] - '0') * 60ULL   +
                (__TIME__[3] - '0') * 600ULL  +
                (__TIME__[1] - '0') * 3600ULL +
                (__TIME__[0] - '0') * 36000ULL;
}

#define H_SEED (CompileTimeSeed() % 254)
#define H_KEY  6

CONSTEXPR ULONG HashStringA(PCHAR string) {
    ULONG hash = H_SEED;
    CHAR  c    = 0;

    if (!string) {
        return 0;
    }

    while ((c = *string++)) {
        // Convert to uppercase
        c = (c >= 'a' && c <= 'z') ? c - 32 : c;

        // SDBM algorithm
        hash = (UINT8)c + (hash << H_KEY) + (hash << 16) - hash;
    }
    return hash;
}

#endif //LSASSC_CONSTEXPR_H
