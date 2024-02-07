cmake_minimum_required(VERSION 3.27)
project(lsassC C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_EXE_LINKER_FLAGS "-static")

enable_language(ASM_NASM)

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
        src/Syscalls.asm)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set_target_properties(lsassC PROPERTIES WIN32_EXECUTABLE TRUE)
endif()