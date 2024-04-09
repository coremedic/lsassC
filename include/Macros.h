#ifndef LSASSC_MACROS_H
#define LSASSC_MACROS_H

// Section macros
#define TEXT   __attribute__((section(".text")))
#define GLOBAL __attribute__((section(".global")))

// Casting macros
#define C_PTR(x) ((PVOID)    (x))
#define U_PTR(x) ((UINT_PTR) (x))

// Dereference macros
#define C_DEF(x)   (*(PVOID*) (x))

// IDE macros
#define CONSTEXPR         constexpr
#define INLINE            inline
#define STATIC            static
#define EXTERN            extern

#endif //LSASSC_MACROS_H
