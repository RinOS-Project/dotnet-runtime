# Required for StaticOpenSslLinking
cmake_minimum_required(VERSION 3.10..3.26)

project(System.Security.Cryptography.Native C)

if(CLR_CMAKE_TARGET_ARCH_WASM)
    message(FATAL_ERROR "Not implemented for WASM")
endif()

# These are happening inside of OpenSSL-defined macros out of our control
add_compile_options(-Wno-cast-align)
add_compile_options(-Wno-reserved-id-macro)
add_compile_options(-Wno-documentation)
add_compile_options(-Wno-used-but-marked-unused)

add_definitions(-DOPENSSL_API_COMPAT=0x10100000L)

# On OpenBSD, the base system provides LibreSSL in /usr, while packaged OpenSSL
# is installed under versioned eopenssl* prefixes. In distro-agnostic mode,
# prefer the newest packaged OpenSSL discovered in the sysroot.
if (CLR_CMAKE_TARGET_OPENBSD AND FEATURE_DISTRO_AGNOSTIC_SSL)
    file(GLOB _openbsd_eopenssl_configs "${CMAKE_SYSROOT}/usr/local/lib/eopenssl*/cmake/OpenSSL/OpenSSLConfig.cmake")
    if (_openbsd_eopenssl_configs)
        list(SORT _openbsd_eopenssl_configs)
        list(REVERSE _openbsd_eopenssl_configs)
        list(GET _openbsd_eopenssl_configs 0 _openbsd_eopenssl_config)

        get_filename_component(_openbsd_openssl_dir "${_openbsd_eopenssl_config}" DIRECTORY)
        get_filename_component(_openbsd_openssl_prefix "${_openbsd_openssl_dir}" DIRECTORY)
        get_filename_component(_openbsd_openssl_prefix "${_openbsd_openssl_prefix}" DIRECTORY)
        get_filename_component(_openbsd_openssl_name "${_openbsd_openssl_prefix}" NAME)

        unset(OPENSSL_CRYPTO_LIBRARY CACHE)
        unset(OPENSSL_SSL_LIBRARY CACHE)
        set(OpenSSL_DIR "${_openbsd_openssl_dir}" CACHE PATH "OpenSSL config directory" FORCE)

        if (EXISTS "${CMAKE_SYSROOT}/usr/local/include/${_openbsd_openssl_name}")
            set(OPENSSL_INCLUDE_DIR "${CMAKE_SYSROOT}/usr/local/include/${_openbsd_openssl_name}" CACHE PATH "OpenSSL include directory" FORCE)
        endif()
    endif()
endif()

include(${CMAKE_CURRENT_LIST_DIR}/extra_libs.cmake)

set(NATIVE_LIBS_EXTRA)
if (CLR_CMAKE_TARGET_RINOS)
    if (NOT RINOS_REPO_ROOT)
        message(FATAL_ERROR "RinOS cryptography requires RINOS_REPO_ROOT")
    endif()
    include_directories(
        "${RINOS_REPO_ROOT}/libs/rintls"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto"
        "${RINOS_REPO_ROOT}/libs/bearssl/inc"
        "${RINOS_REPO_ROOT}/libs/bearssl/src"
    )
else()
    append_extra_cryptography_libs(NATIVE_LIBS_EXTRA)
endif()

include_directories(${OPENSSL_INCLUDE_DIR})

if (CLR_CMAKE_TARGET_RINOS)
    # The target crypto boundary is product-owned.  Do not compile any of the
    # OpenSSL PAL sources for RinOS; the product adapter exports only the
    # algorithms that have a checked-in RinTLS implementation.
    file(GLOB RINOS_BEARSSL_I31_SOURCES CONFIGURE_DEPENDS
        "${RINOS_REPO_ROOT}/libs/bearssl/src/int/i31_*.c")
    set(NATIVECRYPTO_SOURCES
        rinos_crypto.c
        rinos_aes.c
        rinos_ecdh.c
        rinos_ecdsa.c
        rinos_rsa.c
        rinos_tls.c
        "${RINOS_REPO_ROOT}/libs/rintls/rintls.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/aes.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/bignum.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/ecdh.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/hmac.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/rsa.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/rsa_webcrypto.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/sha1.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/sha256.c"
        "${RINOS_REPO_ROOT}/libs/rintls/crypto/sha3.c"
        "${RINOS_REPO_ROOT}/libs/rintls/tls/handshake.c"
        "${RINOS_REPO_ROOT}/libs/rintls/tls/record.c"
        "${RINOS_REPO_ROOT}/libs/rintls/x509/cert.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/codec/enc32be.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/codec/dec32be.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/codec/dec64be.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/codec/enc64be.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/codec/ccopy.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/hash/dig_size.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/hash/mgf1.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/hash/sha1.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/hash/sha2big.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/hash/sha2small.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/mac/hmac.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rand/hmac_drbg.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_keygen.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_keygen_bounded.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_keygen_inner.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_modulus.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_oaep_decrypt.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_oaep_encrypt.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_pkcs1_sign.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_pkcs1_vrfy.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_priv.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_privexp.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_pub.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_i31_pubexp.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_oaep_pad.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_oaep_unpad.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_pkcs1_sig_pad.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/rsa/rsa_pkcs1_sig_unpad.c"
        "${RINOS_REPO_ROOT}/libs/bearssl/src/int/i32_div32.c"
        ${RINOS_BEARSSL_I31_SOURCES}
    )
else()
    set(NATIVECRYPTO_SOURCES
        apibridge_30.c
        memory_debug.c
        openssl.c
        pal_asn1.c
        pal_bignum.c
        pal_bio.c
        pal_dsa.c
        pal_ecc_import_export.c
        pal_eckey.c
        pal_err.c
        pal_evp.c
        pal_evp_cipher.c
        pal_evp_kdf.c
        pal_evp_kem.c
        pal_evp_mac.c
        pal_evp_pkey.c
        pal_evp_pkey_dsa.c
        pal_evp_pkey_ecdh.c
        pal_evp_pkey_ecdsa.c
        pal_evp_pkey_eckey.c
        pal_evp_pkey_rsa.c
        pal_evp_pkey_raw_signverify.c
        pal_evp_pkey_ml_dsa.c
        pal_evp_pkey_slh_dsa.c
        pal_evp_pkey_x25519.c
        pal_hmac.c
        pal_ocsp.c
        pal_pkcs7.c
        pal_ssl.c
        pal_x509.c
        pal_x509_name.c
        pal_x509_root.c
        pal_x509ext.c
    )
endif()

if (LOCAL_BUILD)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    add_definitions(-DLOCAL_BUILD)
    add_definitions(-DPALEXPORT=EXTERN_C)
    add_definitions(-DTARGET_UNIX)
    # For minipal files
    include_directories(../../)
    include_directories(../Common)
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    configure_file(
        ../Common/pal_config.h.in
        ${CMAKE_CURRENT_BINARY_DIR}/pal_config.h)
endif()

if (FEATURE_DISTRO_AGNOSTIC_SSL AND NOT CLR_CMAKE_TARGET_RINOS)
    list(APPEND NATIVECRYPTO_SOURCES
        opensslshim.c
    )
    add_definitions(-DFEATURE_DISTRO_AGNOSTIC_SSL)
    add_compile_options(-pthread)
    add_linker_flag(-pthread)
endif()

add_library(objlib OBJECT ${NATIVECRYPTO_SOURCES} ${VERSION_FILE_PATH})

if (GEN_SHARED_LIB)
    add_library(System.Security.Cryptography.Native.OpenSsl
        SHARED
        $<TARGET_OBJECTS:objlib>
    )
endif()

if (CLR_CMAKE_TARGET_RINOS)
    set(NATIVECRYPTO_ENTRYPOINTS rinos_entrypoints.c)
else()
    set(NATIVECRYPTO_ENTRYPOINTS entrypoints.c)
endif()

add_library(System.Security.Cryptography.Native.OpenSsl-Static
    STATIC
    $<TARGET_OBJECTS:objlib>
    ${NATIVECRYPTO_ENTRYPOINTS}
)

set_target_properties(System.Security.Cryptography.Native.OpenSsl-Static PROPERTIES OUTPUT_NAME System.Security.Cryptography.Native.OpenSsl CLEAN_DIRECT_OUTPUT 1)

if (GEN_SHARED_LIB)
    if (FEATURE_DISTRO_AGNOSTIC_SSL)
        # on macOS, Haiku, and Alpine the link step fails with undefined symbols, and the script
        # doesn't run.
        # if the build succeeds, the script would succeed, except it uses a Linux-only command.
        #
        # on Linux, the build will succeed with undefined symbols, then the script reports them
        # and fails the build for us.
        if (NOT APPLE AND NOT CLR_CMAKE_TARGET_LINUX_MUSL AND NOT CLR_CMAKE_TARGET_HAIKU)
            add_custom_command(TARGET System.Security.Cryptography.Native.OpenSsl POST_BUILD
                COMMENT "Verifying System.Security.Cryptography.Native.OpenSsl.so dependencies"
                COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../verify-so.sh
                    $<TARGET_FILE:System.Security.Cryptography.Native.OpenSsl>
                    "Verification failed. System.Security.Cryptography.Native.OpenSsl.so has undefined dependencies. These are likely OpenSSL APIs that need to be added to opensslshim.h"
                VERBATIM
            )
        endif()
    endif()

    add_custom_command(TARGET System.Security.Cryptography.Native.OpenSsl POST_BUILD
        COMMENT "Verifying System.Security.Cryptography.Native.OpenSsl entry points against entrypoints.c "
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../verify-entrypoints.sh
            $<TARGET_FILE:System.Security.Cryptography.Native.OpenSsl>
            ${CMAKE_CURRENT_SOURCE_DIR}/entrypoints.c
            ${CMAKE_NM}
        VERBATIM
    )

    target_link_libraries(System.Security.Cryptography.Native.OpenSsl
        PRIVATE
        ${NATIVE_LIBS_EXTRA}
    )
endif()

message(STATUS "OPENSSL_INCLUDE_DIR:    ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
message(STATUS "OPENSSL_SSL_LIBRARY:    ${OPENSSL_SSL_LIBRARY}")
message(STATUS "OPENSSL_VERSION:        ${OPENSSL_VERSION}")

include(configure.cmake)

if (GEN_SHARED_LIB)
    install_with_stripped_symbols (System.Security.Cryptography.Native.OpenSsl PROGRAMS .)
endif()

install (TARGETS System.Security.Cryptography.Native.OpenSsl-Static DESTINATION ${STATIC_LIB_DESTINATION} COMPONENT libs)
