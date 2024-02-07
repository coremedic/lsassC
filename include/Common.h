#ifndef COMMON_H
#define COMMON_H

#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

extern char* UnicodeStringToUtf8(PUNICODE_STRING pUnicodeString);
extern const unsigned long long IdentityRuntime(const char* text);

#endif //COMMON_H
