// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS ECDSA adapter.
 *
 * The first product curve is P-256.  The adapter owns the fixed-width
 * ECParameters representation and passes only validated P-256 material into
 * the freestanding RinTLS implementation.  There is deliberately no OpenSSL
 * fallback on the RinOS target.
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "ecdh.h"
#include "platform/rin_platform.h"

#define RINOS_ECDSA_MAGIC UINT32_C(0x52454344)
#define RINOS_ECDSA_CURVE_P256 23
#define RINOS_ECDSA_PRIVATE_KEY_SIZE 32
#define RINOS_ECDSA_PUBLIC_KEY_SIZE 65
#define RINOS_ECDSA_SIGNATURE_SIZE 64
#define RINOS_ECDSA_HASH_SHA256_SIZE 32

typedef struct
{
    uint32_t magic;
    uint32_t has_private_key;
    uint8_t private_key[RINOS_ECDSA_PRIVATE_KEY_SIZE];
    uint8_t public_key[RINOS_ECDSA_PUBLIC_KEY_SIZE];
} rinos_ecdsa_context;

static int rinos_ecdsa_context_valid(const rinos_ecdsa_context* context)
{
    return context != NULL && context->magic == RINOS_ECDSA_MAGIC &&
        context->has_private_key <= 1u &&
        p256_validate_public(context->public_key,
                             RINOS_ECDSA_PUBLIC_KEY_SIZE) == ECDH_OK &&
        (!context->has_private_key ||
         p256_validate_private(context->private_key,
                               RINOS_ECDSA_PRIVATE_KEY_SIZE) == ECDH_OK);
}

static int rinos_ecdsa_copy_output(uint8_t* destination, int32_t capacity,
                                   int32_t* written, const uint8_t* source,
                                   int32_t source_length)
{
    if (!written)
        return 0;
    *written = 0;
    if (capacity < 0 || capacity < source_length ||
        (source_length != 0 && destination == NULL))
        return 0;
    if (source_length != 0)
        rintls_memcpy(destination, source, (rin_size_t)source_length);
    *written = source_length;
    return 1;
}

PALEXPORT void* CryptoNative_RinOSEcdsaCreate(void)
{
    rinos_ecdsa_context* context =
        (rinos_ecdsa_context*)rintls_malloc(sizeof(*context));
    if (context == NULL)
        return NULL;
    rintls_secure_zero(context, sizeof(*context));
    context->magic = RINOS_ECDSA_MAGIC;
    return context;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaGenerateKey(void* handle)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    p256_keypair_t key_pair;

    if (!context || context->magic != RINOS_ECDSA_MAGIC)
        return 0;

    rintls_secure_zero(&key_pair, sizeof(key_pair));
    if (p256_keygen(&key_pair) != ECDH_OK)
        goto fail;

    rintls_memcpy(context->private_key, key_pair.private_key,
                  RINOS_ECDSA_PRIVATE_KEY_SIZE);
    rintls_memcpy(context->public_key, key_pair.public_key,
                  RINOS_ECDSA_PUBLIC_KEY_SIZE);
    context->has_private_key = 1u;
    rintls_secure_zero(&key_pair, sizeof(key_pair));
    return 1;

fail:
    rintls_secure_zero(&key_pair, sizeof(key_pair));
    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    context->has_private_key = 0u;
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    uint8_t derived_public_key[RINOS_ECDSA_PUBLIC_KEY_SIZE];
    uint32_t has_private_key;

    if (!context || context->magic != RINOS_ECDSA_MAGIC ||
        private_key_length < 0 || public_key_length != RINOS_ECDSA_PUBLIC_KEY_SIZE ||
        (private_key_length != 0 && private_key == NULL) || public_key == NULL ||
        p256_validate_public(public_key, RINOS_ECDSA_PUBLIC_KEY_SIZE) != ECDH_OK)
        return 0;

    has_private_key = private_key_length != 0;
    if (has_private_key &&
        (private_key_length != RINOS_ECDSA_PRIVATE_KEY_SIZE ||
         p256_validate_private(private_key, RINOS_ECDSA_PRIVATE_KEY_SIZE) != ECDH_OK))
        return 0;

    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    if (has_private_key &&
        (p256_compute_public(derived_public_key, private_key) != ECDH_OK ||
         rintls_secure_compare(derived_public_key, public_key,
                               RINOS_ECDSA_PUBLIC_KEY_SIZE) != 0))
        goto fail;

    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    if (has_private_key)
        rintls_memcpy(context->private_key, private_key,
                      RINOS_ECDSA_PRIVATE_KEY_SIZE);
    rintls_memcpy(context->public_key, public_key,
                  RINOS_ECDSA_PUBLIC_KEY_SIZE);
    context->has_private_key = has_private_key;
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return 1;

fail:
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaGetKeySize(const void* handle)
{
    const rinos_ecdsa_context* context =
        (const rinos_ecdsa_context*)handle;
    return rinos_ecdsa_context_valid(context) ? 256 : 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length)
{
    const rinos_ecdsa_context* context =
        (const rinos_ecdsa_context*)handle;
    int32_t private_length = include_private ? RINOS_ECDSA_PRIVATE_KEY_SIZE : 0;

    if (private_key_length)
        *private_key_length = 0;
    if (public_key_length)
        *public_key_length = 0;
    if (!rinos_ecdsa_context_valid(context) ||
        (include_private != 0 && include_private != 1) ||
        (include_private && !context->has_private_key))
        goto fail;

    if (!rinos_ecdsa_copy_output(private_key, private_key_capacity,
                                 private_key_length, context->private_key,
                                 private_length) ||
        !rinos_ecdsa_copy_output(public_key, public_key_capacity,
                                 public_key_length, context->public_key,
                                 RINOS_ECDSA_PUBLIC_KEY_SIZE))
        goto fail;
    return 1;

fail:
    if (private_key && private_key_capacity > 0)
        rintls_secure_zero(private_key, (rin_size_t)private_key_capacity);
    if (public_key && public_key_capacity > 0)
        rintls_secure_zero(public_key, (rin_size_t)public_key_capacity);
    if (private_key_length)
        *private_key_length = 0;
    if (public_key_length)
        *public_key_length = 0;
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaSignHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length)
{
    const rinos_ecdsa_context* context =
        (const rinos_ecdsa_context*)handle;

    if (signature_length)
        *signature_length = 0;
    if (!rinos_ecdsa_context_valid(context) || !context->has_private_key ||
        hash_length != RINOS_ECDSA_HASH_SHA256_SIZE || hash == NULL ||
        signature_capacity < RINOS_ECDSA_SIGNATURE_SIZE || signature == NULL ||
        signature_length == NULL)
        goto fail;
    if (ecdsa_p256_sign(signature, hash, context->private_key) != ECDH_OK)
        goto fail;
    *signature_length = RINOS_ECDSA_SIGNATURE_SIZE;
    return 1;

fail:
    if (signature && signature_capacity > 0)
        rintls_secure_zero(signature, (rin_size_t)signature_capacity);
    if (signature_length)
        *signature_length = 0;
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaVerifyHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    const uint8_t* signature, int32_t signature_length)
{
    const rinos_ecdsa_context* context =
        (const rinos_ecdsa_context*)handle;
    if (!rinos_ecdsa_context_valid(context) ||
        hash_length != RINOS_ECDSA_HASH_SHA256_SIZE || hash == NULL ||
        signature_length != RINOS_ECDSA_SIGNATURE_SIZE || signature == NULL)
        return 0;
    return ecdsa_p256_verify(signature, signature_length, hash, hash_length,
                             context->public_key,
                             RINOS_ECDSA_PUBLIC_KEY_SIZE) == ECDH_OK;
}

PALEXPORT void CryptoNative_RinOSEcdsaDestroy(void* handle)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
