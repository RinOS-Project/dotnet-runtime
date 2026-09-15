// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//*****************************************************************************
// sha256.h
//

//
// contains implementation of sha256 hash algorithm
//
//*****************************************************************************
#ifndef HAVE_SHA256_H
#define HAVE_SHA256_H

#ifdef _WIN32
inline HRESULT Sha256Hash(BYTE* pSrc, DWORD srcSize, BYTE* pDst, DWORD dstSize)
{
    if (dstSize != 32)
    {
        return E_FAIL;
    }

    BCRYPT_ALG_HANDLE  algHandle  = NULL;
    BCRYPT_HASH_HANDLE hashHandle = NULL;

    NTSTATUS status = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0);

    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = BCryptCreateHash(algHandle, &hashHandle, NULL, 0, NULL, 0, 0);

    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = BCryptHashData(hashHandle, pSrc, srcSize, 0);

    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    status = BCryptFinishHash(hashHandle, pDst, dstSize, 0);

cleanup:
    if (hashHandle != NULL)
    {
         BCryptDestroyHash(hashHandle);
    }

    if (algHandle != NULL)
    {
        BCryptCloseAlgorithmProvider(algHandle, 0);
    }

    return status;
}
#elif defined(__APPLE__)
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonDigest.h>

inline HRESULT Sha256Hash(BYTE* pSrc, DWORD srcSize, BYTE* pDst, DWORD dstSize)
{
    if (dstSize != CC_SHA256_DIGEST_LENGTH)
    {
        return E_FAIL;
    }

    CC_SHA256(pSrc, (CC_LONG)srcSize, pDst);
    return S_OK;
}
#elif defined(TARGET_RINOS)
// RinOS does not ship OpenSSL headers or an OpenSSL provider.  ilasm still
// needs SHA-256 for deterministic metadata/PDB output, so use the product
// RinTLS implementation that is linked into the target crypto PAL.
#include <stdint.h>
#ifndef _RIN_TYPES_DEFINED
#define _RIN_TYPES_DEFINED
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;
#endif
extern "C" {
    #include "crypto/sha256.h"
}

inline bool IsOpenSslAvailable()
{
    // Keep the existing ilasm availability contract: the product SHA-256
    // implementation is always present in the RinOS static crypto boundary.
    return true;
}

inline HRESULT Sha256Hash(BYTE* pSrc, DWORD srcSize, BYTE* pDst, DWORD dstSize)
{
    if (dstSize != SHA256_DIGEST_SIZE)
    {
        return E_FAIL;
    }

    sha256(pSrc, (rin_size_t)srcSize, pDst);
    return S_OK;
}
#else
extern "C" {
    #include "openssl.h"
    #include "pal_evp.h"
}

inline bool IsOpenSslAvailable()
{
    return CryptoNative_OpenSslAvailable() != 0;
}

inline HRESULT Sha256Hash(BYTE* pSrc, DWORD srcSize, BYTE* pDst, DWORD dstSize)
{
    if (CryptoNative_EnsureOpenSslInitialized() || (dstSize != 32))
    {
        return E_FAIL;
    }

    uint32_t hashLength = 0;

    if (!CryptoNative_EvpDigestOneShot(CryptoNative_EvpSha256(), pSrc, srcSize, pDst, &hashLength))
    {
        return E_FAIL;
    }

    return S_OK;
}
#endif

#endif // HAVE_SHA256_H
