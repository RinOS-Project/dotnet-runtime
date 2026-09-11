# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

if (CLR_CMAKE_HOST_APPLE)
    # Prevent exporting symbols from dotnet. This is necessary to avoid a problem with
    # local typeinfo for standard C++ EH types like std::bad_alloc, std::out_of_range etc.
    # being exposed for binding for external shared libraries and causing mismatch in
    # catch type matching.
    add_link_options(LINKER:-no_exported_symbols)
endif()

if(CLR_CMAKE_TARGET_WIN32)
    list(APPEND SOURCES
        dotnet.manifest
        dotnet.rc)
endif()

list(APPEND SOURCES
    hostfxr_resolver.cpp
    dotnet.cpp
)

add_executable(dotnet ${SOURCES})

if(CLR_CMAKE_TARGET_RINOS)
    # The linker output is an intermediate ELF image.  The final .rin image is
    # produced by the signed packaging step below; never confuse the two.
    set_target_properties(dotnet PROPERTIES OUTPUT_NAME "dotnet.elf")
endif()

target_link_libraries(dotnet PRIVATE hostmisc fxr_resolver)

add_sanitizer_runtime_support(dotnet)

if(NOT CLR_CMAKE_TARGET_WIN32)
    disable_pax_mprotect(dotnet)
endif()

if(NOT CLR_CMAKE_TARGET_RINOS)
    install_with_stripped_symbols(dotnet TARGETS corehost)
elseif(NOT RINOS_ENABLE_NATIVE_PACKAGING)
    message(STATUS "RinOS native packaging is disabled; dotnet ELF will not be installed")
endif()
add_version_info_to_target(dotnet)

if(CLR_CMAKE_TARGET_RINOS AND RINOS_ENABLE_NATIVE_PACKAGING)
    if(NOT RINOS_SIGN_KEY OR NOT RINOS_PUBLIC_KEY)
        message(FATAL_ERROR
            "RinOS native packaging requires RINOS_SIGN_KEY and RINOS_PUBLIC_KEY")
    endif()
    if(NOT DEFINED RINOS_REPO_ROOT)
        message(FATAL_ERROR "RINOS_REPO_ROOT is required for RinOS native packaging")
    endif()
    include("${RINOS_REPO_ROOT}/scripts/dotnet/cmake/RinOSDotnetPackaging.cmake")
    set(_rinos_dotnet_image "${CMAKE_CURRENT_BINARY_DIR}/dotnet.rin")
    rinos_dotnet_package_elf(
        INPUT "$<TARGET_FILE:dotnet>"
        OUTPUT "${_rinos_dotnet_image}"
        KIND executable
        SIGN_KEY "${RINOS_SIGN_KEY}"
        PUBLIC_KEY "${RINOS_PUBLIC_KEY}"
        DEPENDS dotnet)
    add_custom_target(dotnet_rin ALL DEPENDS "${_rinos_dotnet_image}")
    install(FILES "${_rinos_dotnet_image}" DESTINATION corehost)
endif()

if (CLR_CMAKE_HOST_APPLE)
    adhoc_sign_with_entitlements(dotnet "${CLR_ENG_NATIVE_DIR}/entitlements.plist")
endif()
