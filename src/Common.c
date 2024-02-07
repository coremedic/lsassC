#include "Common.h"

char* UnicodeStringToUtf8(PUNICODE_STRING pUnicodeString) {
    if (pUnicodeString == NULL || pUnicodeString->Buffer == NULL) {
        return NULL;
    }

    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, pUnicodeString->Buffer, pUnicodeString->Length / sizeof(WCHAR), NULL, 0, NULL, NULL);
    if (utf8Size <= 0) {
        return NULL;
    }

    char* utf8String = (char*)malloc(utf8Size + 1);
    if (utf8String == NULL) {
        return NULL;
    }

    int result = WideCharToMultiByte(CP_UTF8, 0, pUnicodeString->Buffer, pUnicodeString->Length / sizeof(WCHAR), utf8String, utf8Size, NULL, NULL);
    if (result == 0) {
        free(utf8String);
        return NULL;
    }

    utf8String[utf8Size] = '\0';

    return utf8String;
}

const unsigned long long IdentityRuntime(const char* text) {
    if (!text) return 0;

    size_t n = strlen(text);
    unsigned long long hash = 11ull;
    const unsigned long long prime = 17ull;

    for (size_t i = 0; i < n; ++i) {
        hash = (text[i] ^ hash) * prime;
    }

    return hash;
}