cmake_minimum_required(VERSION 3.27)
project(lsassC C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_EXE_LINKER_FLAGS "-static")


include_directories(include)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_executable(lsassC src/main.c
        src/Syscalls.c
        include/Syscalls.h
        include/identity.h
        include/identity/define.h
        src/Win32.c
        include/Win32.h
        src/Common.c
        include/Common.h
)

set(ASM_SOURCE_FILES src/Syscalls.asm)

foreach(ASM_SRC IN LISTS ASM_SOURCE_FILES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ}
            COMMAND jwasm -win64 -coff -Fo${ASM_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC}
            COMMENT "Assembling ${ASM_SRC}")
    # Link the object file with your executable
    target_sources(lsassC PRIVATE ${ASM_OBJ})
endforeach()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(lsassC PROPERTIES WIN32_EXECUTABLE TRUE)
endif()