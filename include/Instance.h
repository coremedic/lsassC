#ifndef LSASSC_INSTANCE_H
#define LSASSC_INSTANCE_H

#include <windows.h>
#include "Native.h"
#include "Constexpr.h"
#include "Macros.h"

typedef struct _INSTANCE {
    struct {
        struct {
        } Api;

        struct {
        } Modules;
    } Win32;
} INSTANCE, *PINSTANCE;

#endif //LSASSC_INSTANCE_H
