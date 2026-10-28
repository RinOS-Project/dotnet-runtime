// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS product crypto adapter.
 *
 * This file intentionally exposes the small SHA-2/SHA-3 boundary that is
 * implemented by RinTLS.  The exported names retain the CoreCLR
 * System.Security.Cryptography.Native ABI, while no OpenSSL object or host
 * provider is linked into the RinOS target.
 */

#include <stdint.h>
#include <stddef.h>

#include "../Common/pal_compiler.h"
#include "rinos_crypto_adapter.h"
#include "sha256.h"
#include "sha3.h"
#include "hmac.h"

#define RINOS_CRYPTO_MAGIC UINT32_C(0x52494E43)
#define RINOS_XOF_MAGIC UINT32_C(0x52494E58)
#define RINOS_KMAC_MAGIC UINT32_C(0x52494E4B)

enum
{
    RINOS_SHA256 = 1,
    RINOS_SHA384 = 2,
    RINOS_SHA512 = 3,
    RINOS_SHA3_256 = 4,
    RINOS_SHA3_384 = 5,
    RINOS_SHA3_512 = 6,
    RINOS_SHAKE128 = 7,
    RINOS_SHAKE256 = 8,
    RINOS_KMAC128 = 1,
    RINOS_KMAC256 = 2,
};

typedef struct
{
    uint32_t magic;
    uint32_t algorithm;
    union
    {
        sha256_ctx sha256;
        sha512_ctx sha512;
        sha3_ctx sha3;
    } state;
} rinos_hash_context;

typedef struct
{
    uint32_t magic;
    uint32_t algorithm;
    union
    {
        hmac_sha256_ctx sha256;
        hmac_sha384_ctx sha384;
        hmac_sha512_ctx sha512;
        hmac_sha3_256_ctx sha3_256;
        hmac_sha3_384_ctx sha3_384;
        hmac_sha3_512_ctx sha3_512;
    } state;
} rinos_hmac_context;

typedef struct
{
    uint32_t magic;
    uint32_t algorithm;
    sha3_ctx state;
} rinos_xof_context;

typedef struct
{
    uint32_t magic;
    uint32_t algorithm;
    uint32_t xof;
    sha3_ctx seed;
    sha3_ctx state;
} rinos_kmac_context;

static int rinos_hash_size(uint32_t algorithm)
{
    switch (algorithm)
    {
        case RINOS_SHA256:
            return SHA256_DIGEST_SIZE;
        case RINOS_SHA384:
            return SHA384_DIGEST_SIZE;
        case RINOS_SHA512:
            return SHA512_DIGEST_SIZE;
        case RINOS_SHA3_256:
            return SHA3_256_DIGEST_SIZE;
        case RINOS_SHA3_384:
            return SHA3_384_DIGEST_SIZE;
        case RINOS_SHA3_512:
            return SHA3_512_DIGEST_SIZE;
        default:
            return 0;
    }
}

static int rinos_hmac_size(uint32_t algorithm)
{
    switch (algorithm)
    {
        case RINOS_SHA256:
            return HMAC_SHA256_SIZE;
        case RINOS_SHA384:
            return HMAC_SHA384_SIZE;
        case RINOS_SHA512:
            return HMAC_SHA512_SIZE;
        case RINOS_SHA3_256:
            return HMAC_SHA3_256_SIZE;
        case RINOS_SHA3_384:
            return HMAC_SHA3_384_SIZE;
        case RINOS_SHA3_512:
            return HMAC_SHA3_512_SIZE;
        default:
            return 0;
    }
}

static int rinos_hash_valid(const rinos_hash_context* context)
{
    return context != NULL && context->magic == RINOS_CRYPTO_MAGIC &&
        rinos_hash_size(context->algorithm) != 0;
}

static int rinos_hmac_valid(const rinos_hmac_context* context)
{
    return context != NULL && context->magic == RINOS_CRYPTO_MAGIC &&
        rinos_hmac_size(context->algorithm) != 0;
}

static u32 rinos_xof_rate(uint32_t algorithm)
{
    switch (algorithm)
    {
        case RINOS_SHAKE128:
            return 168u;
        case RINOS_SHAKE256:
            return 136u;
        default:
            return 0u;
    }
}

static u32 rinos_kmac_rate(uint32_t algorithm)
{
    switch (algorithm)
    {
        case RINOS_KMAC128:
            return 168u;
        case RINOS_KMAC256:
            return 136u;
        default:
            return 0u;
    }
}

static int rinos_xof_valid(const rinos_xof_context* context)
{
    return context != NULL && context->magic == RINOS_XOF_MAGIC &&
        rinos_xof_rate(context->algorithm) != 0u;
}

static int rinos_kmac_valid(const rinos_kmac_context* context)
{
    return context != NULL && context->magic == RINOS_KMAC_MAGIC &&
        rinos_kmac_rate(context->algorithm) != 0u && context->xof <= 1u;
}

PALEXPORT void* CryptoNative_RinOSHashCreate(int32_t algorithm)
{
    if (rinos_hash_size((uint32_t)algorithm) == 0)
        return NULL;

    rinos_hash_context* context = (rinos_hash_context*)rintls_malloc(sizeof(*context));
    if (context == NULL)
        return NULL;

    context->magic = RINOS_CRYPTO_MAGIC;
    context->algorithm = (uint32_t)algorithm;
    if (algorithm == RINOS_SHA256)
        sha256_init(&context->state.sha256);
    else if (algorithm == RINOS_SHA384)
        sha384_init(&context->state.sha512);
    else if (algorithm == RINOS_SHA512)
        sha512_init(&context->state.sha512);
    else if (algorithm == RINOS_SHA3_256)
        sha3_256_init(&context->state.sha3);
    else if (algorithm == RINOS_SHA3_384)
        sha3_384_init(&context->state.sha3);
    else
        sha3_512_init(&context->state.sha3);

    return context;
}

PALEXPORT void* CryptoNative_RinOSHashClone(const void* source)
{
    const rinos_hash_context* source_context = (const rinos_hash_context*)source;
    if (!rinos_hash_valid(source_context))
        return NULL;

    rinos_hash_context* clone = (rinos_hash_context*)rintls_malloc(sizeof(*clone));
    if (clone != NULL)
        rintls_memcpy(clone, source_context, sizeof(*clone));
    return clone;
}

PALEXPORT int32_t CryptoNative_RinOSHashUpdate(void* handle, const uint8_t* data, int32_t length)
{
    rinos_hash_context* context = (rinos_hash_context*)handle;
    if (!rinos_hash_valid(context) || length < 0 || (data == NULL && length != 0))
        return 0;

    if (context->algorithm == RINOS_SHA256)
        sha256_update(&context->state.sha256, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA384)
        sha384_update(&context->state.sha512, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA512)
        sha512_update(&context->state.sha512, data, (rin_size_t)length);
    else
        sha3_update(&context->state.sha3, data, (rin_size_t)length);
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSHashFinal(void* handle, uint8_t* destination, int32_t destination_length)
{
    rinos_hash_context* context = (rinos_hash_context*)handle;
    int size;
    if (!rinos_hash_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0) ||
        destination_length < (size = rinos_hash_size(context->algorithm)))
        return 0;

    if (context->algorithm == RINOS_SHA256)
        sha256_final(&context->state.sha256, destination);
    else if (context->algorithm == RINOS_SHA384)
        sha384_final(&context->state.sha512, destination);
    else if (context->algorithm == RINOS_SHA512)
        sha512_final(&context->state.sha512, destination);
    else
        sha3_final(&context->state.sha3, destination);
    return size;
}

PALEXPORT int32_t CryptoNative_RinOSHashCurrent(const void* handle, uint8_t* destination, int32_t destination_length)
{
    const rinos_hash_context* context = (const rinos_hash_context*)handle;
    rinos_hash_context copy;
    int size;
    if (!rinos_hash_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0) ||
        destination_length < (size = rinos_hash_size(context->algorithm)))
        return 0;

    rintls_memcpy(&copy, context, sizeof(copy));
    if (copy.algorithm == RINOS_SHA256)
        sha256_final(&copy.state.sha256, destination);
    else if (copy.algorithm == RINOS_SHA384)
        sha384_final(&copy.state.sha512, destination);
    else if (copy.algorithm == RINOS_SHA512)
        sha512_final(&copy.state.sha512, destination);
    else
        sha3_final(&copy.state.sha3, destination);
    rintls_secure_zero(&copy, sizeof(copy));
    return size;
}

PALEXPORT int32_t CryptoNative_RinOSHashReset(void* handle)
{
    rinos_hash_context* context = (rinos_hash_context*)handle;
    if (!rinos_hash_valid(context))
        return 0;

    if (context->algorithm == RINOS_SHA256)
        sha256_init(&context->state.sha256);
    else if (context->algorithm == RINOS_SHA384)
        sha384_init(&context->state.sha512);
    else if (context->algorithm == RINOS_SHA512)
        sha512_init(&context->state.sha512);
    else if (context->algorithm == RINOS_SHA3_256)
        sha3_256_init(&context->state.sha3);
    else if (context->algorithm == RINOS_SHA3_384)
        sha3_384_init(&context->state.sha3);
    else
        sha3_512_init(&context->state.sha3);
    return 1;
}

PALEXPORT void CryptoNative_RinOSHashDestroy(void* handle)
{
    rinos_hash_context* context = (rinos_hash_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}

PALEXPORT void* CryptoNative_RinOSXofCreate(int32_t algorithm)
{
    u32 rate = rinos_xof_rate((uint32_t)algorithm);
    rinos_xof_context* context;

    if (rate == 0u) return NULL;
    context = (rinos_xof_context*)rintls_malloc(sizeof(*context));
    if (context == NULL) return NULL;
    context->magic = RINOS_XOF_MAGIC;
    context->algorithm = (uint32_t)algorithm;
    sha3_xof_init(&context->state, rate, 0x1fu);
    return context;
}

PALEXPORT void* CryptoNative_RinOSXofClone(const void* source)
{
    const rinos_xof_context* source_context = (const rinos_xof_context*)source;
    rinos_xof_context* clone;

    if (!rinos_xof_valid(source_context)) return NULL;
    clone = (rinos_xof_context*)rintls_malloc(sizeof(*clone));
    if (clone != NULL) rintls_memcpy(clone, source_context, sizeof(*clone));
    return clone;
}

PALEXPORT int32_t CryptoNative_RinOSXofUpdate(void* handle, const uint8_t* data, int32_t length)
{
    rinos_xof_context* context = (rinos_xof_context*)handle;
    if (!rinos_xof_valid(context) || length < 0 || (data == NULL && length != 0))
        return 0;
    sha3_update(&context->state, data, (rin_size_t)length);
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSXofFinal(void* handle, uint8_t* destination, int32_t destination_length)
{
    rinos_xof_context* context = (rinos_xof_context*)handle;
    if (!rinos_xof_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0)) return 0;
    return sha3_xof_squeeze(&context->state, destination, (rin_size_t)destination_length);
}

PALEXPORT int32_t CryptoNative_RinOSXofCurrent(const void* handle, uint8_t* destination, int32_t destination_length)
{
    const rinos_xof_context* context = (const rinos_xof_context*)handle;
    sha3_ctx copy;
    int result;

    if (!rinos_xof_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0)) return 0;
    rintls_memcpy(&copy, &context->state, sizeof(copy));
    result = sha3_xof_squeeze(&copy, destination, (rin_size_t)destination_length);
    rintls_secure_zero(&copy, sizeof(copy));
    return result;
}

PALEXPORT int32_t CryptoNative_RinOSXofReset(void* handle)
{
    rinos_xof_context* context = (rinos_xof_context*)handle;
    u32 rate;

    if (!rinos_xof_valid(context)) return 0;
    rate = rinos_xof_rate(context->algorithm);
    sha3_xof_init(&context->state, rate, 0x1fu);
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSXofRead(void* handle, uint8_t* destination, int32_t destination_length)
{
    return CryptoNative_RinOSXofFinal(handle, destination, destination_length);
}

PALEXPORT int32_t CryptoNative_RinOSXofOneShot(
    int32_t algorithm, const uint8_t* source, int32_t source_length,
    uint8_t* destination, int32_t destination_length)
{
    rinos_xof_context* context;
    int32_t result;

    if (source_length < 0 || destination_length < 0 ||
        (source == NULL && source_length != 0) ||
        (destination == NULL && destination_length != 0)) return 0;
    context = (rinos_xof_context*)CryptoNative_RinOSXofCreate(algorithm);
    if (context == NULL) return 0;
    if (!CryptoNative_RinOSXofUpdate(context, source, source_length)) {
        CryptoNative_RinOSXofDestroy(context);
        return 0;
    }
    result = CryptoNative_RinOSXofFinal(context, destination, destination_length);
    CryptoNative_RinOSXofDestroy(context);
    return result;
}

PALEXPORT void CryptoNative_RinOSXofDestroy(void* handle)
{
    rinos_xof_context* context = (rinos_xof_context*)handle;
    if (context == NULL) return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}

PALEXPORT void* CryptoNative_RinOSKmacCreate(
    int32_t algorithm, const uint8_t* key, int32_t key_length,
    const uint8_t* customization, int32_t customization_length, int32_t xof)
{
    u32 rate = rinos_kmac_rate((uint32_t)algorithm);
    rinos_kmac_context* context;

    if (rate == 0u || key_length < 0 || customization_length < 0 ||
        xof < 0 || xof > 1 || (key == NULL && key_length != 0) ||
        (customization == NULL && customization_length != 0)) return NULL;
    context = (rinos_kmac_context*)rintls_malloc(sizeof(*context));
    if (context == NULL) return NULL;
    context->magic = RINOS_KMAC_MAGIC;
    context->algorithm = (uint32_t)algorithm;
    context->xof = (uint32_t)xof;
    if (!sha3_kmac_init(&context->seed, rate, key, (rin_size_t)key_length,
                        customization, (rin_size_t)customization_length, xof)) {
        rintls_secure_zero(context, sizeof(*context));
        rintls_mem_free(context);
        return NULL;
    }
    rintls_memcpy(&context->state, &context->seed, sizeof(context->state));
    return context;
}

PALEXPORT void* CryptoNative_RinOSKmacClone(const void* source)
{
    const rinos_kmac_context* source_context = (const rinos_kmac_context*)source;
    rinos_kmac_context* clone;

    if (!rinos_kmac_valid(source_context)) return NULL;
    clone = (rinos_kmac_context*)rintls_malloc(sizeof(*clone));
    if (clone != NULL) rintls_memcpy(clone, source_context, sizeof(*clone));
    return clone;
}

PALEXPORT int32_t CryptoNative_RinOSKmacUpdate(void* handle, const uint8_t* data, int32_t length)
{
    rinos_kmac_context* context = (rinos_kmac_context*)handle;
    if (!rinos_kmac_valid(context) || length < 0 || (data == NULL && length != 0))
        return 0;
    sha3_update(&context->state, data, (rin_size_t)length);
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSKmacFinal(void* handle, uint8_t* destination, int32_t destination_length)
{
    rinos_kmac_context* context = (rinos_kmac_context*)handle;
    if (!rinos_kmac_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0)) return 0;
    return sha3_kmac_finalize(&context->state, destination,
                              (rin_size_t)destination_length, (int)context->xof);
}

PALEXPORT int32_t CryptoNative_RinOSKmacCurrent(const void* handle, uint8_t* destination, int32_t destination_length)
{
    const rinos_kmac_context* context = (const rinos_kmac_context*)handle;
    rinos_kmac_context copy;
    int32_t result;
    if (!rinos_kmac_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0)) return 0;
    rintls_memcpy(&copy, context, sizeof(copy));
    result = sha3_kmac_finalize(&copy.state, destination,
                                (rin_size_t)destination_length,
                                (int)copy.xof);
    rintls_secure_zero(&copy, sizeof(copy));
    return result;
}

PALEXPORT int32_t CryptoNative_RinOSKmacReset(void* handle)
{
    rinos_kmac_context* context = (rinos_kmac_context*)handle;
    if (!rinos_kmac_valid(context)) return 0;
    rintls_memcpy(&context->state, &context->seed, sizeof(context->state));
    return 1;
}

PALEXPORT void CryptoNative_RinOSKmacDestroy(void* handle)
{
    rinos_kmac_context* context = (rinos_kmac_context*)handle;
    if (context == NULL) return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}

PALEXPORT int32_t CryptoNative_RinOSKmacOneShot(
    int32_t algorithm, const uint8_t* key, int32_t key_length,
    const uint8_t* source, int32_t source_length,
    const uint8_t* customization, int32_t customization_length,
    uint8_t* destination, int32_t destination_length, int32_t xof)
{
    rinos_kmac_context* context;
    int32_t result;

    if (source_length < 0 || destination_length < 0 ||
        (source == NULL && source_length != 0) ||
        (destination == NULL && destination_length != 0)) return 0;
    context = (rinos_kmac_context*)CryptoNative_RinOSKmacCreate(
        algorithm, key, key_length, customization, customization_length, xof);
    if (context == NULL) return 0;
    if (!CryptoNative_RinOSKmacUpdate(context, source, source_length)) {
        CryptoNative_RinOSKmacDestroy(context);
        return 0;
    }
    result = CryptoNative_RinOSKmacFinal(context, destination, destination_length);
    CryptoNative_RinOSKmacDestroy(context);
    return result;
}

PALEXPORT void* CryptoNative_RinOSHmacCreate(int32_t algorithm, const uint8_t* key, int32_t key_length)
{
    if (rinos_hmac_size((uint32_t)algorithm) == 0 || key_length < 0 ||
        (key == NULL && key_length != 0))
        return NULL;

    rinos_hmac_context* context = (rinos_hmac_context*)rintls_malloc(sizeof(*context));
    if (context == NULL)
        return NULL;

    context->magic = RINOS_CRYPTO_MAGIC;
    context->algorithm = (uint32_t)algorithm;
    if (algorithm == RINOS_SHA256)
        hmac_sha256_init(&context->state.sha256, key, (rin_size_t)key_length);
    else if (algorithm == RINOS_SHA384)
        hmac_sha384_init(&context->state.sha384, key, (rin_size_t)key_length);
    else if (algorithm == RINOS_SHA512)
        hmac_sha512_init(&context->state.sha512, key, (rin_size_t)key_length);
    else if (algorithm == RINOS_SHA3_256)
        hmac_sha3_256_init(&context->state.sha3_256, key, (rin_size_t)key_length);
    else if (algorithm == RINOS_SHA3_384)
        hmac_sha3_384_init(&context->state.sha3_384, key, (rin_size_t)key_length);
    else
        hmac_sha3_512_init(&context->state.sha3_512, key, (rin_size_t)key_length);
    return context;
}

PALEXPORT void* CryptoNative_RinOSHmacClone(const void* source)
{
    const rinos_hmac_context* source_context = (const rinos_hmac_context*)source;
    if (!rinos_hmac_valid(source_context))
        return NULL;

    rinos_hmac_context* clone = (rinos_hmac_context*)rintls_malloc(sizeof(*clone));
    if (clone != NULL)
        rintls_memcpy(clone, source_context, sizeof(*clone));
    return clone;
}

PALEXPORT int32_t CryptoNative_RinOSHmacUpdate(void* handle, const uint8_t* data, int32_t length)
{
    rinos_hmac_context* context = (rinos_hmac_context*)handle;
    if (!rinos_hmac_valid(context) || length < 0 || (data == NULL && length != 0))
        return 0;

    if (context->algorithm == RINOS_SHA256)
        hmac_sha256_update(&context->state.sha256, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA384)
        hmac_sha384_update(&context->state.sha384, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA512)
        hmac_sha512_update(&context->state.sha512, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA3_256)
        hmac_sha3_256_update(&context->state.sha3_256, data, (rin_size_t)length);
    else if (context->algorithm == RINOS_SHA3_384)
        hmac_sha3_384_update(&context->state.sha3_384, data, (rin_size_t)length);
    else
        hmac_sha3_512_update(&context->state.sha3_512, data, (rin_size_t)length);
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSHmacFinal(void* handle, uint8_t* destination, int32_t destination_length)
{
    rinos_hmac_context* context = (rinos_hmac_context*)handle;
    int size;
    if (!rinos_hmac_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0) ||
        destination_length < (size = rinos_hmac_size(context->algorithm)))
        return 0;

    if (context->algorithm == RINOS_SHA256)
        hmac_sha256_final(&context->state.sha256, destination);
    else if (context->algorithm == RINOS_SHA384)
        hmac_sha384_final(&context->state.sha384, destination);
    else if (context->algorithm == RINOS_SHA512)
        hmac_sha512_final(&context->state.sha512, destination);
    else if (context->algorithm == RINOS_SHA3_256)
        hmac_sha3_256_final(&context->state.sha3_256, destination);
    else if (context->algorithm == RINOS_SHA3_384)
        hmac_sha3_384_final(&context->state.sha3_384, destination);
    else
        hmac_sha3_512_final(&context->state.sha3_512, destination);
    return size;
}

PALEXPORT int32_t CryptoNative_RinOSHmacCurrent(const void* handle, uint8_t* destination, int32_t destination_length)
{
    const rinos_hmac_context* context = (const rinos_hmac_context*)handle;
    rinos_hmac_context copy;
    int size;
    if (!rinos_hmac_valid(context) || destination_length < 0 ||
        (destination == NULL && destination_length != 0) ||
        destination_length < (size = rinos_hmac_size(context->algorithm)))
        return 0;

    rintls_memcpy(&copy, context, sizeof(copy));
    if (copy.algorithm == RINOS_SHA256)
        hmac_sha256_final(&copy.state.sha256, destination);
    else if (copy.algorithm == RINOS_SHA384)
        hmac_sha384_final(&copy.state.sha384, destination);
    else if (copy.algorithm == RINOS_SHA512)
        hmac_sha512_final(&copy.state.sha512, destination);
    else if (copy.algorithm == RINOS_SHA3_256)
        hmac_sha3_256_final(&copy.state.sha3_256, destination);
    else if (copy.algorithm == RINOS_SHA3_384)
        hmac_sha3_384_final(&copy.state.sha3_384, destination);
    else
        hmac_sha3_512_final(&copy.state.sha3_512, destination);
    rintls_secure_zero(&copy, sizeof(copy));
    return size;
}

PALEXPORT int32_t CryptoNative_RinOSHmacReset(void* handle)
{
    rinos_hmac_context* context = (rinos_hmac_context*)handle;
    if (!rinos_hmac_valid(context))
        return 0;

    /* key_block is the normalized HMAC key, so it is sufficient to rebuild
     * the keyed inner/outer states without retaining a second managed copy. */
    if (context->algorithm == RINOS_SHA256)
        hmac_sha256_init(&context->state.sha256, context->state.sha256.key_block, SHA256_BLOCK_SIZE);
    else if (context->algorithm == RINOS_SHA384)
        hmac_sha384_init(&context->state.sha384, context->state.sha384.key_block, SHA384_BLOCK_SIZE);
    else if (context->algorithm == RINOS_SHA512)
        hmac_sha512_init(&context->state.sha512, context->state.sha512.key_block, SHA512_BLOCK_SIZE);
    else if (context->algorithm == RINOS_SHA3_256)
        hmac_sha3_256_init(&context->state.sha3_256, context->state.sha3_256.key_block, SHA3_256_RATE);
    else if (context->algorithm == RINOS_SHA3_384)
        hmac_sha3_384_init(&context->state.sha3_384, context->state.sha3_384.key_block, SHA3_384_RATE);
    else
        hmac_sha3_512_init(&context->state.sha3_512, context->state.sha3_512.key_block, SHA3_512_RATE);
    return 1;
}

PALEXPORT void CryptoNative_RinOSHmacDestroy(void* handle)
{
    rinos_hmac_context* context = (rinos_hmac_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}

PALEXPORT int32_t CryptoNative_GetRandomBytes(uint8_t* buffer, int32_t length)
{
    if (length < 0 || (buffer == NULL && length != 0))
        return 0;
    if (length == 0)
        return 1;
    if (rintls_get_random(buffer, (rin_size_t)length) != 0)
    {
        rintls_secure_zero(buffer, (rin_size_t)length);
        return 0;
    }
    return 1;
}
