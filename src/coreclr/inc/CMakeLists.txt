set( CORGUIDS_IDL_SOURCES
  cordebug.idl
  xcordebug.idl
  clrdata.idl
  clrinternal.idl
  xclrdata.idl
  corprof.idl
  corsym.idl
  sospriv.idl
  dacdbi.idl
)

if(CLR_CMAKE_HOST_WIN32)
    #Build for corguids is done in two steps:
    #1. compile .idl to *_i.c : This is done using custom midl command
    #2. compile *_i.c to .lib

    # Get the current list of definitions to pass to midl
    get_compile_definitions(MIDL_DEFINITIONS)
    get_include_directories(MIDL_INCLUDE_DIRECTORIES)

    if(CLR_CMAKE_TARGET_RINOS)
        # MIDL is a host-side COM/IDL compiler, but pal.h uses POSIX-shaped
        # declarations from both the RinOS libc and SDK (strings.h, stat,
        # socket ABI, and friends). Keep those include roots available while
        # MIDL_PASS guards in the target headers suppress inline implementations
        # and syscall assembly that MIDL cannot parse.
    endif()

    if(CLR_CMAKE_TARGET_RINOS)
        # MIDL does not define MIDL_PASS for this custom invocation, while
        # RinOS syscall headers contain inline assembly that MIDL cannot parse.
        list(APPEND MIDL_DEFINITIONS -DMIDL_PASS)
    endif()


    # Run custom midl command over each idl file
    FIND_PROGRAM( MIDL midl.exe )
    if(MIDL)
        # The target is RinOS, so the normal Windows SDK include discovery is
        # not populated by CMake.  MIDL still needs the SDK IDL imports (most
        # notably Unknwn.Idl) while compiling the COM contracts on a Windows
        # host.  Derive the selected SDK include root from midl.exe itself.
        get_filename_component(_RINOS_MIDL_VERSION_BIN "${MIDL}" DIRECTORY)
        get_filename_component(_RINOS_MIDL_VERSION_DIR "${_RINOS_MIDL_VERSION_BIN}" DIRECTORY)
        get_filename_component(_RINOS_WINDOWS_KITS_ROOT "${_RINOS_MIDL_VERSION_DIR}" DIRECTORY)
        get_filename_component(_RINOS_WINDOWS_KITS_ROOT "${_RINOS_WINDOWS_KITS_ROOT}" DIRECTORY)
        get_filename_component(_RINOS_MIDL_VERSION "${_RINOS_MIDL_VERSION_DIR}" NAME)
        set(_RINOS_WINDOWS_SDK_INCLUDE
            "${_RINOS_WINDOWS_KITS_ROOT}/Include/${_RINOS_MIDL_VERSION}")
        foreach(_RINOS_MIDL_SUBDIR IN ITEMS shared um ucrt)
            if(IS_DIRECTORY "${_RINOS_WINDOWS_SDK_INCLUDE}/${_RINOS_MIDL_SUBDIR}")
                list(APPEND MIDL_INCLUDE_DIRECTORIES
                    "-I${_RINOS_WINDOWS_SDK_INCLUDE}/${_RINOS_MIDL_SUBDIR}")
            endif()
        endforeach()

        # pal.h also includes the C compiler's fundamental headers (for
        # example float.h).  Recover the MSVC include root from the host
        # Clang installation so MIDL can preprocess those headers without
        # substituting RinOS libc or an incomplete SDK-only view.
        get_filename_component(_RINOS_LLVM_BIN "${CMAKE_C_COMPILER}" DIRECTORY)
        get_filename_component(_RINOS_LLVM_X64 "${_RINOS_LLVM_BIN}" DIRECTORY)
        get_filename_component(_RINOS_LLVM_ROOT "${_RINOS_LLVM_X64}" DIRECTORY)
        get_filename_component(_RINOS_VC_TOOLS_ROOT "${_RINOS_LLVM_ROOT}" DIRECTORY)
        get_filename_component(_RINOS_VC_ROOT "${_RINOS_VC_TOOLS_ROOT}" DIRECTORY)
        file(GLOB _RINOS_MSVC_INCLUDE_DIRS
            "${_RINOS_VC_ROOT}/Tools/MSVC/*/include")
        foreach(_RINOS_MSVC_INCLUDE IN LISTS _RINOS_MSVC_INCLUDE_DIRS)
            list(APPEND MIDL_INCLUDE_DIRECTORIES
                "-I${_RINOS_MSVC_INCLUDE}")
        endforeach()
    endif()
    foreach(GENERATE_IDL IN LISTS CORGUIDS_IDL_SOURCES)
        get_filename_component(IDLNAME ${GENERATE_IDL} NAME_WE)
        set(OUT_NAME ${CMAKE_CURRENT_BINARY_DIR}/idls_out/${IDLNAME}_i.c)
        list(APPEND CORGUIDS_SOURCES ${OUT_NAME})
        add_custom_command(OUTPUT ${OUT_NAME}
                      COMMAND ${MIDL} ${MIDL_INCLUDE_DIRECTORIES} /nologo /no_stamp /h ${CMAKE_CURRENT_BINARY_DIR}/idls_out/${IDLNAME}.h ${MIDL_DEFINITIONS} /out ${CMAKE_CURRENT_BINARY_DIR}/idls_out ${CMAKE_CURRENT_SOURCE_DIR}/${GENERATE_IDL}
                      DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${GENERATE_IDL}
                      COMMENT "Compiling ${GENERATE_IDL}")
    endforeach(GENERATE_IDL)

    set_source_files_properties(${CORGUIDS_SOURCES}
                            PROPERTIES GENERATED TRUE)

    # Compile *_i.c as C files. The Windows compiler switch is not understood
    # by the clang RinOS target used for a Windows-hosted cross build.
    if(NOT CLR_CMAKE_TARGET_RINOS)
        add_compile_options(/TC)
    endif()

else(CLR_CMAKE_HOST_WIN32)

    #The MIDL tool exists for Windows only, so for other systems, we have the prebuilt xxx_i.cpp files checked in

    add_compile_options(-D_MIDL_USE_GUIDDEF_)
    foreach(IDL_SOURCE IN LISTS CORGUIDS_IDL_SOURCES)
        get_filename_component(IDLNAME ${IDL_SOURCE} NAME_WE)
        set(C_SOURCE ../pal/prebuilt/idl/${IDLNAME}_i.cpp)
        list(APPEND CORGUIDS_SOURCES ${C_SOURCE})
    endforeach(IDL_SOURCE)

endif(CLR_CMAKE_HOST_WIN32)

# Compile *_i.cpp to lib
add_library_clr(corguids OBJECT ${CORGUIDS_SOURCES})

# Binplace the inc files for packaging later.

install (FILES cfi.h
               cor.h
               cordebuginfo.h
               coredistools.h
               corhdr.h
               corinfo.h
               corjit.h
               corjithost.h
               opcode.def
               openum.h
               gcinfoencoder.h
               gcinfotypes.h
               DESTINATION inc)
