project(System.Net.Security.Native C)

if(CLR_CMAKE_TARGET_ARCH_WASM)
    message(FATAL_ERROR "Not implemented for WASM")
endif()

add_compile_options(-Wno-incompatible-pointer-types-discards-qualifiers)

set(NATIVE_LIBS_EXTRA)
if (CLR_CMAKE_TARGET_RINOS)
    # RinOS TLS is provided by System.Security.Cryptography.Native through
    # the product RinTLS adapter.  This library is the separate GSSAPI PAL
    # used by Negotiate/Kerberos/NTLM; do not discover or link a host GSS
    # implementation while producing a target RLL.  The target PAL returns a
    # stable unsupported status so managed callers fail closed.
    set(NATIVEGSS_SOURCES
        pal_gssapi_rinos.c
    )
else()
    include(${CMAKE_CURRENT_LIST_DIR}/extra_libs.cmake)
    append_extra_security_libs(NATIVE_LIBS_EXTRA)

    set(NATIVEGSS_SOURCES
        pal_gssapi.c
    )
endif()

if (GEN_SHARED_LIB)
    add_library(System.Net.Security.Native
        SHARED
        ${NATIVEGSS_SOURCES}
        ${VERSION_FILE_PATH}
    )
endif()

if (NOT GEN_SHARED_LIB AND NOT CLR_CMAKE_TARGET_APPLE_MOBILE AND NOT CLR_CMAKE_TARGET_ANDROID AND NOT CLR_CMAKE_TARGET_BROWSER AND NOT CLR_CMAKE_TARGET_WASI)
    set(NATIVEGSS_SOURCES ${NATIVEGSS_SOURCES} entrypoints.c)
endif()

add_library(System.Net.Security.Native-Static
    STATIC
    ${NATIVEGSS_SOURCES}
)

set_target_properties(System.Net.Security.Native-Static PROPERTIES OUTPUT_NAME System.Net.Security.Native CLEAN_DIRECT_OUTPUT 1)

if (GEN_SHARED_LIB)
    target_link_libraries(System.Net.Security.Native
        PRIVATE
        ${NATIVE_LIBS_EXTRA}
    )

    if (NOT CLR_CMAKE_TARGET_APPLE_MOBILE AND NOT CLR_CMAKE_TARGET_ANDROID AND NOT CLR_CMAKE_TARGET_BROWSER AND NOT CLR_CMAKE_TARGET_WASI)
        add_custom_command(TARGET System.Net.Security.Native POST_BUILD
            COMMENT "Verifying System.Net.Security.Native entry points against entrypoints.c "
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../verify-entrypoints.sh
                $<TARGET_FILE:System.Net.Security.Native>
                ${CMAKE_CURRENT_SOURCE_DIR}/entrypoints.c
                ${CMAKE_NM}
            VERBATIM
        )
    endif()

    install_with_stripped_symbols (System.Net.Security.Native PROGRAMS .)
endif()

install (TARGETS System.Net.Security.Native-Static DESTINATION ${STATIC_LIB_DESTINATION} COMPONENT libs)
