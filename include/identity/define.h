/*
Copyright (c) 2022 Athaariq Ardhiansyah

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#ifndef __IDENTITY_TYPE_DEFINED
#define __IDENTITY_TYPE_DEFINED

typedef const unsigned long long identity_t;

#endif // #ifndef __IDENTITY_TYPE_DEFINED

#ifndef IDENTITY

#include <limits.h>

#define __IDENTITY_HASH_FUNC(s, n, i, x) (s[i < n ? n - 1 - i : 0] ^ x) * 17ull

#define __IDENTITY_ITER_63(s, x, n) x
#define __IDENTITY_ITER_62(s, x, n) (62 < n ? __IDENTITY_HASH_FUNC(s, n, 62, __IDENTITY_ITER_63(s, x, n)) : x)
#define __IDENTITY_ITER_61(s, x, n) (61 < n ? __IDENTITY_HASH_FUNC(s, n, 61, __IDENTITY_ITER_62(s, x, n)) : x)
#define __IDENTITY_ITER_60(s, x, n) (60 < n ? __IDENTITY_HASH_FUNC(s, n, 60, __IDENTITY_ITER_61(s, x, n)) : x)
#define __IDENTITY_ITER_59(s, x, n) (59 < n ? __IDENTITY_HASH_FUNC(s, n, 59, __IDENTITY_ITER_60(s, x, n)) : x)
#define __IDENTITY_ITER_58(s, x, n) (58 < n ? __IDENTITY_HASH_FUNC(s, n, 58, __IDENTITY_ITER_59(s, x, n)) : x)
#define __IDENTITY_ITER_57(s, x, n) (57 < n ? __IDENTITY_HASH_FUNC(s, n, 57, __IDENTITY_ITER_58(s, x, n)) : x)
#define __IDENTITY_ITER_56(s, x, n) (56 < n ? __IDENTITY_HASH_FUNC(s, n, 56, __IDENTITY_ITER_57(s, x, n)) : x)
#define __IDENTITY_ITER_55(s, x, n) (55 < n ? __IDENTITY_HASH_FUNC(s, n, 55, __IDENTITY_ITER_56(s, x, n)) : x)
#define __IDENTITY_ITER_54(s, x, n) (54 < n ? __IDENTITY_HASH_FUNC(s, n, 54, __IDENTITY_ITER_55(s, x, n)) : x)
#define __IDENTITY_ITER_53(s, x, n) (53 < n ? __IDENTITY_HASH_FUNC(s, n, 53, __IDENTITY_ITER_54(s, x, n)) : x)
#define __IDENTITY_ITER_52(s, x, n) (52 < n ? __IDENTITY_HASH_FUNC(s, n, 52, __IDENTITY_ITER_53(s, x, n)) : x)
#define __IDENTITY_ITER_51(s, x, n) (51 < n ? __IDENTITY_HASH_FUNC(s, n, 51, __IDENTITY_ITER_52(s, x, n)) : x)
#define __IDENTITY_ITER_50(s, x, n) (50 < n ? __IDENTITY_HASH_FUNC(s, n, 50, __IDENTITY_ITER_51(s, x, n)) : x)
#define __IDENTITY_ITER_49(s, x, n) (49 < n ? __IDENTITY_HASH_FUNC(s, n, 49, __IDENTITY_ITER_50(s, x, n)) : x)
#define __IDENTITY_ITER_48(s, x, n) (48 < n ? __IDENTITY_HASH_FUNC(s, n, 48, __IDENTITY_ITER_49(s, x, n)) : x)
#define __IDENTITY_ITER_47(s, x, n) (47 < n ? __IDENTITY_HASH_FUNC(s, n, 47, __IDENTITY_ITER_48(s, x, n)) : x)
#define __IDENTITY_ITER_46(s, x, n) (46 < n ? __IDENTITY_HASH_FUNC(s, n, 46, __IDENTITY_ITER_47(s, x, n)) : x)
#define __IDENTITY_ITER_45(s, x, n) (45 < n ? __IDENTITY_HASH_FUNC(s, n, 45, __IDENTITY_ITER_46(s, x, n)) : x)
#define __IDENTITY_ITER_44(s, x, n) (44 < n ? __IDENTITY_HASH_FUNC(s, n, 44, __IDENTITY_ITER_45(s, x, n)) : x)
#define __IDENTITY_ITER_43(s, x, n) (43 < n ? __IDENTITY_HASH_FUNC(s, n, 43, __IDENTITY_ITER_44(s, x, n)) : x)
#define __IDENTITY_ITER_42(s, x, n) (42 < n ? __IDENTITY_HASH_FUNC(s, n, 42, __IDENTITY_ITER_43(s, x, n)) : x)
#define __IDENTITY_ITER_41(s, x, n) (41 < n ? __IDENTITY_HASH_FUNC(s, n, 41, __IDENTITY_ITER_42(s, x, n)) : x)
#define __IDENTITY_ITER_40(s, x, n) (40 < n ? __IDENTITY_HASH_FUNC(s, n, 40, __IDENTITY_ITER_41(s, x, n)) : x)
#define __IDENTITY_ITER_39(s, x, n) (39 < n ? __IDENTITY_HASH_FUNC(s, n, 39, __IDENTITY_ITER_40(s, x, n)) : x)
#define __IDENTITY_ITER_38(s, x, n) (38 < n ? __IDENTITY_HASH_FUNC(s, n, 38, __IDENTITY_ITER_39(s, x, n)) : x)
#define __IDENTITY_ITER_37(s, x, n) (37 < n ? __IDENTITY_HASH_FUNC(s, n, 37, __IDENTITY_ITER_38(s, x, n)) : x)
#define __IDENTITY_ITER_36(s, x, n) (36 < n ? __IDENTITY_HASH_FUNC(s, n, 36, __IDENTITY_ITER_37(s, x, n)) : x)
#define __IDENTITY_ITER_35(s, x, n) (35 < n ? __IDENTITY_HASH_FUNC(s, n, 35, __IDENTITY_ITER_36(s, x, n)) : x)
#define __IDENTITY_ITER_34(s, x, n) (34 < n ? __IDENTITY_HASH_FUNC(s, n, 34, __IDENTITY_ITER_35(s, x, n)) : x)
#define __IDENTITY_ITER_33(s, x, n) (33 < n ? __IDENTITY_HASH_FUNC(s, n, 33, __IDENTITY_ITER_34(s, x, n)) : x)
#define __IDENTITY_ITER_32(s, x, n) (32 < n ? __IDENTITY_HASH_FUNC(s, n, 32, __IDENTITY_ITER_33(s, x, n)) : x)
#define __IDENTITY_ITER_31(s, x, n) (31 < n ? __IDENTITY_HASH_FUNC(s, n, 31, __IDENTITY_ITER_32(s, x, n)) : x)
#define __IDENTITY_ITER_30(s, x, n) (30 < n ? __IDENTITY_HASH_FUNC(s, n, 30, __IDENTITY_ITER_31(s, x, n)) : x)
#define __IDENTITY_ITER_29(s, x, n) (29 < n ? __IDENTITY_HASH_FUNC(s, n, 29, __IDENTITY_ITER_30(s, x, n)) : x)
#define __IDENTITY_ITER_28(s, x, n) (28 < n ? __IDENTITY_HASH_FUNC(s, n, 28, __IDENTITY_ITER_29(s, x, n)) : x)
#define __IDENTITY_ITER_27(s, x, n) (27 < n ? __IDENTITY_HASH_FUNC(s, n, 27, __IDENTITY_ITER_28(s, x, n)) : x)
#define __IDENTITY_ITER_26(s, x, n) (26 < n ? __IDENTITY_HASH_FUNC(s, n, 26, __IDENTITY_ITER_27(s, x, n)) : x)
#define __IDENTITY_ITER_25(s, x, n) (25 < n ? __IDENTITY_HASH_FUNC(s, n, 25, __IDENTITY_ITER_26(s, x, n)) : x)
#define __IDENTITY_ITER_24(s, x, n) (24 < n ? __IDENTITY_HASH_FUNC(s, n, 24, __IDENTITY_ITER_25(s, x, n)) : x)
#define __IDENTITY_ITER_23(s, x, n) (23 < n ? __IDENTITY_HASH_FUNC(s, n, 23, __IDENTITY_ITER_24(s, x, n)) : x)
#define __IDENTITY_ITER_22(s, x, n) (22 < n ? __IDENTITY_HASH_FUNC(s, n, 22, __IDENTITY_ITER_23(s, x, n)) : x)
#define __IDENTITY_ITER_21(s, x, n) (21 < n ? __IDENTITY_HASH_FUNC(s, n, 21, __IDENTITY_ITER_22(s, x, n)) : x)
#define __IDENTITY_ITER_20(s, x, n) (20 < n ? __IDENTITY_HASH_FUNC(s, n, 20, __IDENTITY_ITER_21(s, x, n)) : x)
#define __IDENTITY_ITER_19(s, x, n) (19 < n ? __IDENTITY_HASH_FUNC(s, n, 19, __IDENTITY_ITER_20(s, x, n)) : x)
#define __IDENTITY_ITER_18(s, x, n) (18 < n ? __IDENTITY_HASH_FUNC(s, n, 18, __IDENTITY_ITER_19(s, x, n)) : x)
#define __IDENTITY_ITER_17(s, x, n) (17 < n ? __IDENTITY_HASH_FUNC(s, n, 17, __IDENTITY_ITER_18(s, x, n)) : x)
#define __IDENTITY_ITER_16(s, x, n) (16 < n ? __IDENTITY_HASH_FUNC(s, n, 16, __IDENTITY_ITER_17(s, x, n)) : x)
#define __IDENTITY_ITER_15(s, x, n) (15 < n ? __IDENTITY_HASH_FUNC(s, n, 15, __IDENTITY_ITER_16(s, x, n)) : x)
#define __IDENTITY_ITER_14(s, x, n) (14 < n ? __IDENTITY_HASH_FUNC(s, n, 14, __IDENTITY_ITER_15(s, x, n)) : x)
#define __IDENTITY_ITER_13(s, x, n) (13 < n ? __IDENTITY_HASH_FUNC(s, n, 13, __IDENTITY_ITER_14(s, x, n)) : x)
#define __IDENTITY_ITER_12(s, x, n) (12 < n ? __IDENTITY_HASH_FUNC(s, n, 12, __IDENTITY_ITER_13(s, x, n)) : x)
#define __IDENTITY_ITER_11(s, x, n) (11 < n ? __IDENTITY_HASH_FUNC(s, n, 11, __IDENTITY_ITER_12(s, x, n)) : x)
#define __IDENTITY_ITER_10(s, x, n) (10 < n ? __IDENTITY_HASH_FUNC(s, n, 10, __IDENTITY_ITER_11(s, x, n)) : x)
#define __IDENTITY_ITER_9(s, x, n) (9 < n ? __IDENTITY_HASH_FUNC(s, n, 9, __IDENTITY_ITER_10(s, x, n)) : x)
#define __IDENTITY_ITER_8(s, x, n) (8 < n ? __IDENTITY_HASH_FUNC(s, n, 8, __IDENTITY_ITER_9(s, x, n)) : x)
#define __IDENTITY_ITER_7(s, x, n) (7 < n ? __IDENTITY_HASH_FUNC(s, n, 7, __IDENTITY_ITER_8(s, x, n)) : x)
#define __IDENTITY_ITER_6(s, x, n) (6 < n ? __IDENTITY_HASH_FUNC(s, n, 6, __IDENTITY_ITER_7(s, x, n)) : x)
#define __IDENTITY_ITER_5(s, x, n) (5 < n ? __IDENTITY_HASH_FUNC(s, n, 5, __IDENTITY_ITER_6(s, x, n)) : x)
#define __IDENTITY_ITER_4(s, x, n) (4 < n ? __IDENTITY_HASH_FUNC(s, n, 4, __IDENTITY_ITER_5(s, x, n)) : x)
#define __IDENTITY_ITER_3(s, x, n) (3 < n ? __IDENTITY_HASH_FUNC(s, n, 3, __IDENTITY_ITER_4(s, x, n)) : x)
#define __IDENTITY_ITER_2(s, x, n) (2 < n ? __IDENTITY_HASH_FUNC(s, n, 2, __IDENTITY_ITER_3(s, x, n)) : x)
#define __IDENTITY_ITER_1(s, x, n) (1 < n ? __IDENTITY_HASH_FUNC(s, n, 1, __IDENTITY_ITER_2(s, x, n)) : x)
#define __IDENTITY_ITER_0(s, x, n) (0 < n ? __IDENTITY_HASH_FUNC(s, n, 0, __IDENTITY_ITER_1(s, x, n)) : x)

#define IDENTITY(text) ((identity_t) /* */ __IDENTITY_ITER_0(text, 11ull, (sizeof text - 1)))

#define IDENTITY_INT(text) ((int)(__IDENTITY_ITER_0(text, 11ull, (sizeof text - 1)) & UINT_MAX))

#endif // #ifndef IDENTITY