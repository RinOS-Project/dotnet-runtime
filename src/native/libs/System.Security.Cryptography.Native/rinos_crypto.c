// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS product crypto adapter.
 *
 * This file intentionally exposes the small SHA-2 boundary that is already
 * implemented by RinTLS.  The exported names retain the CoreCLR
 * System.Security.Cryptography.Native ABI, while no OpenSSL object or host
 * provider is linked into the RinOS target.
 */

#include <stdint.h>
#include <stddef.h>

#include "../Common/pal_compiler.h"
#include "sha256.h"
#include "hmac.h"
#include "platform/rin_platform.h"

#define RINOS_CRYPTO_MAGIC UINT32_C(0x52494E43)

enum
{
    RINOS_SHA256 = 1,
    RINOS_SHA384 = 2,
    RINOS_SHA512 = 3,
};

typedef struct
{
    uint32_t magic;
    uint32_t algorithm;
    union
    {
        sha256_ctx sha256;
        sha512_ctx sha512;
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
    } state;
} rinos_hmac_context;

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
    else
        sha512_init(&context->state.sha512);

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
    else
        sha512_update(&context->state.sha512, data, (rin_size_t)length);
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
    else
        sha512_final(&context->state.sha512, destination);
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
    else
        sha512_final(&copy.state.sha512, destination);
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
    else
        sha512_init(&context->state.sha512);
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
    else
        hmac_sha384_init(&context->state.sha384, key, (rin_size_t)key_length);
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
    else
        hmac_sha384_update(&context->state.sha384, data, (rin_size_t)length);
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
    else
        hmac_sha384_final(&context->state.sha384, destination);
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
    else
        hmac_sha384_final(&copy.state.sha384, destination);
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
    else
        hmac_sha384_init(&context->state.sha384, context->state.sha384.key_block, SHA384_BLOCK_SIZE);
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
