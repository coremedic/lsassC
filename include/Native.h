#ifndef LSASSC_NATIVE_H
#define LSASSC_NATIVE_H

#include <windows.h>

NTSYSAPI
NTSTATUS
NTAPI
TpAllocWork(
        _Out_ PTP_WORK *WorkReturn,
        _In_ PTP_WORK_CALLBACK Callback,
        _Inout_opt_ PVOID Context,
        _In_opt_ PTP_CALLBACK_ENVIRON CallbackEnviron
);

NTSYSAPI
VOID
NTAPI
TpPostWork(
        _Inout_ PTP_WORK Work
);

NTSYSAPI
VOID
NTAPI
TpReleaseWork(
        _Inout_ PTP_WORK Work
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtAllocateVirtualMemory(
        _In_ HANDLE ProcessHandle,
        _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
        _In_ ULONG_PTR ZeroBits,
        _Inout_ PSIZE_T RegionSize,
        _In_ ULONG AllocationType,
        _In_ ULONG Protect
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQueryInformationProcess(
        _In_ HANDLE ProcessHandle,
        _In_ PROCESSINFOCLASS ProcessInformationClass,
        _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
        _In_ ULONG ProcessInformationLength,
        _Out_opt_ PULONG ReturnLength
);

#endif //LSASSC_NATIVE_H
