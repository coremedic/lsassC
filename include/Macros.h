#ifndef LSASSC_MACROS_H
#define LSASSC_MACROS_H

// Native API macros
#define STATUS_SUCCESS               0x00000000
#define STATUS_UNSUCCESSFUL          0xC0000001
#define STATUS_INFO_LENGTH_MISMATCH  0xC0000004
#define NT_SUCCESS(STATUS) (((NTSTATUS)(STATUS)) >= 0)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

// Section macros
#define SEC_TEXT   __attribute__((section(".text")))
#define SEC_GLOBAL __attribute__((section(".global")))

// Casting macros
#define C_PTR(x)  ((PVOID)     (x))
#define U_PTR(x)  ((UINT_PTR)  (x))
#define D_TYPE(x) __typeof__(x) *x;
#define C_PTR_PTR(x) ((PVOID*) (x))

// Dereference macros
#define C_DEF(x)   (*(PVOID*) (x))

// IDE macros
#define CONSTEXPR         constexpr
#define INLINE            inline
#define STATIC            static
#define EXTERN            extern
#define AUTO              auto

#endif //LSASSC_MACROS_H
