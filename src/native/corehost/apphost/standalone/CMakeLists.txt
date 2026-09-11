# Licensed to the .NET Foundation under one or more agreements.
# The .NET Foundation licenses this file to you under the MIT license.

include_directories(..)

set(SOURCES
    ../apphost.c
    ../bundle_marker.c
    ./apphost_hostfxr_resolver.c
)

set(HEADERS
    ../bundle_marker.h
    ../../hostmisc/pal.h
    ../apphost_hostfxr_resolver.h
)

add_compile_definitions(FEATURE_APPHOST)

if(CLR_CMAKE_TARGET_WIN32)
    list(APPEND SOURCES
        ../apphost.windows.c)
    list(APPEND HEADERS
        ../apphost.windows.h)

    add_compile_definitions(UNICODE)
endif()

list(APPEND SOURCES ${HEADERS})

add_executable(apphost ${SOURCES} ${RESOURCES})

if(CLR_CMAKE_TARGET_RINOS)
    # Keep the linked ELF private to the packaging step.  A RinOS apphost is
    # distributed only as a signed .rin image, never as an installable ELF.
    set_target_properties(apphost PROPERTIES OUTPUT_NAME "apphost.elf")
endif()

target_link_libraries(apphost PRIVATE fxr_resolver)

if(CLR_CMAKE_TARGET_WIN32)
    target_link_libraries(apphost PRIVATE hostmisc_c minipal_objects shell32)

    # Disable manifest generation into the file .exe on Windows
    target_link_options(apphost PRIVATE "/MANIFEST:NO")

    # Enable CET-compatibility
    if (CLR_CMAKE_HOST_ARCH_AMD64)
        target_link_options(apphost PRIVATE "/CETCOMPAT")
    endif()
else()
    if(CLR_CMAKE_TARGET_RINOS)
        # RinOS libc owns math and loader entry points.  The target output is
        # still an intermediate ELF image until the signed .rin packaging step.
        target_link_libraries(apphost PRIVATE hostmisc_c minipal_objects)
    else()
        target_link_libraries(apphost PRIVATE hostmisc_c minipal_objects m)
        disable_pax_mprotect(apphost)
    endif()
endif()

add_sanitizer_runtime_support(apphost)

if(NOT CLR_CMAKE_TARGET_RINOS)
    install_with_stripped_symbols(apphost TARGETS corehost)
elseif(RINOS_ENABLE_NATIVE_PACKAGING)
    if(NOT RINOS_SIGN_KEY OR NOT RINOS_PUBLIC_KEY)
        message(FATAL_ERROR
            "RinOS apphost packaging requires RINOS_SIGN_KEY and RINOS_PUBLIC_KEY")
    endif()
    if(NOT DEFINED RINOS_REPO_ROOT)
        message(FATAL_ERROR "RINOS_REPO_ROOT is required for RinOS native packaging")
    endif()
    include("${RINOS_REPO_ROOT}/scripts/dotnet/cmake/RinOSDotnetPackaging.cmake")
    set(_rinos_apphost_image "${CMAKE_CURRENT_BINARY_DIR}/apphost.rin")
    rinos_dotnet_package_elf(
        INPUT "$<TARGET_FILE:apphost>"
        OUTPUT "${_rinos_apphost_image}"
        KIND executable
        SIGN_KEY "${RINOS_SIGN_KEY}"
        PUBLIC_KEY "${RINOS_PUBLIC_KEY}"
        DEPENDS apphost)
    add_custom_target(apphost_rin ALL DEPENDS "${_rinos_apphost_image}")
    install(FILES "${_rinos_apphost_image}" DESTINATION corehost)
elseif(NOT RINOS_ENABLE_NATIVE_PACKAGING)
    message(STATUS "RinOS native packaging is disabled; apphost ELF will not be installed")
endif()

if (CLR_CMAKE_HOST_APPLE)
    adhoc_sign_with_entitlements(apphost "${CLR_ENG_NATIVE_DIR}/entitlements.plist")
endif()
