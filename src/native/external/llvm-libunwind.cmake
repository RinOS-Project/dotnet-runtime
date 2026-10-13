# IMPORTANT: do not use add_compile_options(), add_definitions() or similar functions here since it will leak to the including projects

if(NOT CLR_CMAKE_TARGET_ARCH_WASM)
  include_directories(BEFORE "${CMAKE_CURRENT_LIST_DIR}/llvm-libunwind/include")
endif()

set (LLVM_LIBUNWIND_SOURCES_BASE
    src/Unwind-EHABI.cpp
    src/libunwind.cpp
)

# CoreCLR's RinOS image uses the Itanium exception ABI on x86_64.  The
# compiler-generated cleanup paths need these entry points in addition to the
# C++ support in libunwind.cpp.
set(LLVM_LIBUNWIND_C_SOURCES_BASE
    src/UnwindLevel1.c
    src/UnwindLevel1-gcc-ext.c
)
set_source_files_properties(
    "${CMAKE_CURRENT_LIST_DIR}/llvm-libunwind/src/UnwindLevel1.c"
    "${CMAKE_CURRENT_LIST_DIR}/llvm-libunwind/src/UnwindLevel1-gcc-ext.c"
    PROPERTIES COMPILE_FLAGS "-std=c99 -fexceptions")
list(APPEND LLVM_LIBUNWIND_SOURCES_BASE ${LLVM_LIBUNWIND_C_SOURCES_BASE})

set(LLVM_LIBUNWIND_ASM_SOURCES_BASE
    src/UnwindRegistersRestore.S
    src/UnwindRegistersSave.S
)

addprefix(LLVM_LIBUNWIND_SOURCES "${CMAKE_CURRENT_LIST_DIR}/llvm-libunwind" "${LLVM_LIBUNWIND_SOURCES_BASE}")
addprefix(LLVM_LIBUNWIND_ASM_SOURCES "${CMAKE_CURRENT_LIST_DIR}/llvm-libunwind" "${LLVM_LIBUNWIND_ASM_SOURCES_BASE}")
