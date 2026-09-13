// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS ECDH adapter.
 *
 * The product currently exposes P-256 ECDH through the fixed-width EC
 * parameter boundary.  Public points are validated before they enter the
 * RinTLS arithmetic, and raw agreement output is cleared on every failure.
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "ecdh.h"
#include "platform/rin_platform.h"

#define RINOS_ECDH_MAGIC UINT32_C(0x52454448)
#define RINOS_ECDH_PRIVATE_KEY_SIZE 32
#define RINOS_ECDH_PUBLIC_KEY_SIZE 65
#define RINOS_ECDH_SECRET_SIZE 32

typedef struct
{
    uint32_t magic;
    uint32_t has_private_key;
    uint8_t private_key[RINOS_ECDH_PRIVATE_KEY_SIZE];
    uint8_t public_key[RINOS_ECDH_PUBLIC_KEY_SIZE];
} rinos_ecdh_context;

static int rinos_ecdh_context_valid(const rinos_ecdh_context* context)
{
    return context != NULL && context->magic == RINOS_ECDH_MAGIC &&
        context->has_private_key <= 1u &&
        p256_validate_public(context->public_key,
                             RINOS_ECDH_PUBLIC_KEY_SIZE) == ECDH_OK &&
        (!context->has_private_key ||
         p256_validate_private(context->private_key,
                               RINOS_ECDH_PRIVATE_KEY_SIZE) == ECDH_OK);
}

static int rinos_ecdh_copy_output(uint8_t* destination, int32_t capacity,
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

PALEXPORT void* CryptoNative_RinOSEcdhCreate(void)
{
    rinos_ecdh_context* context =
        (rinos_ecdh_context*)rintls_malloc(sizeof(*context));
    if (context == NULL)
        return NULL;
    rintls_secure_zero(context, sizeof(*context));
    context->magic = RINOS_ECDH_MAGIC;
    return context;
}

PALEXPORT int32_t CryptoNative_RinOSEcdhGenerateKey(void* handle)
{
    rinos_ecdh_context* context = (rinos_ecdh_context*)handle;
    p256_keypair_t key_pair;

    if (!context || context->magic != RINOS_ECDH_MAGIC)
        return 0;
    rintls_secure_zero(&key_pair, sizeof(key_pair));
    if (p256_keygen(&key_pair) != ECDH_OK)
        goto fail;

    rintls_memcpy(context->private_key, key_pair.private_key,
                  RINOS_ECDH_PRIVATE_KEY_SIZE);
    rintls_memcpy(context->public_key, key_pair.public_key,
                  RINOS_ECDH_PUBLIC_KEY_SIZE);
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

PALEXPORT int32_t CryptoNative_RinOSEcdhImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length)
{
    rinos_ecdh_context* context = (rinos_ecdh_context*)handle;
    uint8_t derived_public_key[RINOS_ECDH_PUBLIC_KEY_SIZE];
    uint32_t has_private_key;

    if (!context || context->magic != RINOS_ECDH_MAGIC ||
        private_key_length < 0 || public_key_length != RINOS_ECDH_PUBLIC_KEY_SIZE ||
        (private_key_length != 0 && private_key == NULL) || public_key == NULL ||
        p256_validate_public(public_key, RINOS_ECDH_PUBLIC_KEY_SIZE) != ECDH_OK)
        return 0;

    has_private_key = private_key_length != 0;
    if (has_private_key &&
        (private_key_length != RINOS_ECDH_PRIVATE_KEY_SIZE ||
         p256_validate_private(private_key, RINOS_ECDH_PRIVATE_KEY_SIZE) != ECDH_OK))
        return 0;

    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    if (has_private_key &&
        (p256_compute_public(derived_public_key, private_key) != ECDH_OK ||
         rintls_secure_compare(derived_public_key, public_key,
                               RINOS_ECDH_PUBLIC_KEY_SIZE) != 0))
        goto fail;

    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    if (has_private_key)
        rintls_memcpy(context->private_key, private_key,
                      RINOS_ECDH_PRIVATE_KEY_SIZE);
    rintls_memcpy(context->public_key, public_key,
                  RINOS_ECDH_PUBLIC_KEY_SIZE);
    context->has_private_key = has_private_key;
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return 1;

fail:
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdhGetKeySize(const void* handle)
{
    const rinos_ecdh_context* context =
        (const rinos_ecdh_context*)handle;
    return rinos_ecdh_context_valid(context) ? 256 : 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdhExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length)
{
    const rinos_ecdh_context* context = (const rinos_ecdh_context*)handle;
    int32_t private_length = include_private ? RINOS_ECDH_PRIVATE_KEY_SIZE : 0;

    if (private_key_length)
        *private_key_length = 0;
    if (public_key_length)
        *public_key_length = 0;
    if (!rinos_ecdh_context_valid(context) ||
        (include_private != 0 && include_private != 1) ||
        (include_private && !context->has_private_key))
        goto fail;
    if (!rinos_ecdh_copy_output(private_key, private_key_capacity,
                                private_key_length, context->private_key,
                                private_length) ||
        !rinos_ecdh_copy_output(public_key, public_key_capacity,
                                public_key_length, context->public_key,
                                RINOS_ECDH_PUBLIC_KEY_SIZE))
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

PALEXPORT int32_t CryptoNative_RinOSEcdhDeriveRawSecret(
    const void* handle, const uint8_t* peer_public_key,
    int32_t peer_public_key_length, uint8_t* secret, int32_t secret_capacity,
    int32_t* secret_length)
{
    const rinos_ecdh_context* context = (const rinos_ecdh_context*)handle;

    if (secret_length)
        *secret_length = 0;
    if (!rinos_ecdh_context_valid(context) || !context->has_private_key ||
        peer_public_key_length != RINOS_ECDH_PUBLIC_KEY_SIZE ||
        peer_public_key == NULL || secret_capacity < RINOS_ECDH_SECRET_SIZE ||
        secret == NULL || secret_length == NULL ||
        p256_validate_public(peer_public_key, RINOS_ECDH_PUBLIC_KEY_SIZE) != ECDH_OK)
        goto fail;
    if (p256_ecdh(secret, context->private_key, peer_public_key,
                  RINOS_ECDH_PUBLIC_KEY_SIZE) != ECDH_OK)
        goto fail;
    *secret_length = RINOS_ECDH_SECRET_SIZE;
    return 1;

fail:
    if (secret && secret_capacity > 0)
        rintls_secure_zero(secret, (rin_size_t)secret_capacity);
    if (secret_length)
        *secret_length = 0;
    return 0;
}

PALEXPORT void CryptoNative_RinOSEcdhDestroy(void* handle)
{
    rinos_ecdh_context* context = (rinos_ecdh_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
