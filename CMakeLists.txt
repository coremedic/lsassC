cmake_minimum_required(VERSION 3.28)
project(lsassC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories(include)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG)
endif()

add_compile_options(
        -Os -s -fno-asynchronous-unwind-tables -fno-ident
        -falign-functions=1 -falign-jumps=1 -falign-labels=1
        -fpack-struct=8 -masm=intel -fpermissive
)

add_link_options(
        -Wl,-s,--no-seh
        -Wl,--as-needed,--no-whole-archive
)

file(GLOB_RECURSE ALL_CXX_FILES "${PROJECT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE ALL_C_FILES "${PROJECT_SOURCE_DIR}/src/*.c")
file(GLOB_RECURSE ALL_CXX_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE ALL_C_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/*.h")

set_source_files_properties(${ALL_C_FILES} PROPERTIES LANGUAGE CXX)

add_executable(
        lsassC
        src/Main.cpp
        src/ProxyCaller.cpp
        include/Macros.h
        include/ProxyCaller.h
        include/Constexpr.h
        include/Instance.h
        include/Native.h
        include/Common.h
)

set(ASM_SOURCE_FILES asm/x64/ProxyCaller.asm)

foreach(ASM_SRC IN LISTS ASM_SOURCE_FILES)
    get_filename_component(ASM_OBJ ${ASM_SRC} NAME_WE)
    set(ASM_OBJ ${CMAKE_CURRENT_BINARY_DIR}/${ASM_OBJ}.obj)
    add_custom_command(OUTPUT ${ASM_OBJ}
            COMMAND jwasm -win64 -coff -Fo${ASM_OBJ} ${CMAKE_CURRENT_SOURCE_DIR}/${ASM_SRC}
            DEPENDS ${ASM_SRC}
            COMMENT "Assembling ${ASM_SRC}")
    target_sources(lsassC PRIVATE ${ASM_OBJ})
endforeach()
