#include "Common.h"

template<typename T>
struct GlobalData {
    UINT32 magic;
    T data;

    static constexpr
    UINT32 MAGIC = 0x17171717;

    explicit
    GlobalData(const T &data) : magic{MAGIC}, data{data} {}

    static
    NTSTATUS Init(_Inout_ GlobalData<T>* data) {
        if (!data) {
            return STATUS_INVALID_PARAMETER;
        }

        if (NumberOfHeaps() == MaximumNumberOfHeaps()) {
            return STATUS_NO_MEMORY;
        }
        ProcessHeaps()[NumberOfHeaps()++] = data;

        return STATUS_SUCCESS;
    }

    static
    T* Get() {
        for (UINT32 i = 0; i < NumberOfHeaps(); ++i) {
            GlobalData<T>* data = (GlobalData<T>*)ProcessHeaps()[i];
            if (data->magic == MAGIC) {
                return data->instance;
            }

            return NULL;
        }
    }
};

using Instance = GlobalData<INSTANCE>;

EXTERN_C
INIT
VOID Init() {

}

