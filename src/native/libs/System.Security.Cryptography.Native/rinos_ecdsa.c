// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS ECDSA adapter.
 *
 * The adapter exposes the fixed-width NIST ECParameters representation used
 * by System.Security.Cryptography and delegates the curve arithmetic to the
 * product-owned RinTLS implementation. P-256 retains its existing
 * specialized primitive; P-384 and P-521 use the audited NIST primitives in
 * the same ecdh.c translation unit.
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "rinos_crypto_adapter.h"
#include "ecdh.h"

#define RINOS_ECDSA_MAGIC UINT32_C(0x52454344)
#define RINOS_ECDSA_MAX_PRIVATE_KEY_SIZE 66
#define RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE 133
#define RINOS_ECDSA_MAX_SIGNATURE_SIZE 132

typedef struct
{
    uint32_t magic;
    uint32_t curve;
    uint32_t has_private_key;
    uint8_t private_key[RINOS_ECDSA_MAX_PRIVATE_KEY_SIZE];
    uint8_t public_key[RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE];
} rinos_ecdsa_context;

static int rinos_ecdsa_curve_sizes(int32_t curve, int32_t* key_size,
                                   int32_t* private_size, int32_t* public_size,
                                   int32_t* hash_size, int32_t* signature_size)
{
    if (!key_size || !private_size || !public_size || !hash_size ||
        !signature_size)
        return 0;

    switch (curve) {
    case ECDSA_CURVE_P256:
        *key_size = 256;
        *private_size = 32;
        *public_size = 65;
        *hash_size = 32;
        *signature_size = 64;
        return 1;
    case ECDSA_CURVE_P384:
        *key_size = 384;
        *private_size = 48;
        *public_size = 97;
        *hash_size = 48;
        *signature_size = 96;
        return 1;
    case ECDSA_CURVE_P521:
        *key_size = 521;
        *private_size = 66;
        *public_size = 133;
        *hash_size = 64;
        *signature_size = 132;
        return 1;
    default:
        *key_size = 0;
        *private_size = 0;
        *public_size = 0;
        *hash_size = 0;
        *signature_size = 0;
        return 0;
    }
}

static int rinos_ecdsa_validate_public(int32_t curve,
                                       const uint8_t* public_key,
                                       int32_t public_key_length)
{
    if (curve == ECDSA_CURVE_P256)
        return p256_validate_public(public_key,
                                    (rin_size_t)public_key_length) == ECDH_OK;
    return ecdsa_nist_validate_public(curve, public_key,
                                      (rin_size_t)public_key_length) == ECDH_OK;
}

static int rinos_ecdsa_derive_public(int32_t curve, uint8_t* public_key,
                                     int32_t public_key_capacity,
                                     const uint8_t* private_key,
                                     int32_t private_key_length)
{
    if (curve == ECDSA_CURVE_P256)
        return public_key_capacity >= 65 && private_key_length == 32 &&
            p256_compute_public(public_key, private_key) == ECDH_OK;
    return ecdsa_nist_public_from_private(
               curve, public_key, (rin_size_t)public_key_capacity, private_key,
               (rin_size_t)private_key_length) == ECDH_OK;
}

static int rinos_ecdsa_context_valid(const rinos_ecdsa_context* context)
{
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;
    uint8_t derived_public_key[RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE];
    int valid = 0;

    if (!context || context->magic != RINOS_ECDSA_MAGIC ||
        context->has_private_key > 1u ||
        !rinos_ecdsa_curve_sizes((int32_t)context->curve, &key_size,
                                 &private_size, &public_size, &hash_size,
                                 &signature_size) ||
        !rinos_ecdsa_validate_public((int32_t)context->curve,
                                     context->public_key, public_size))
        return 0;

    if (!context->has_private_key)
        return 1;

    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    valid = rinos_ecdsa_derive_public(
                (int32_t)context->curve, derived_public_key,
                RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE, context->private_key,
                private_size) &&
        rintls_secure_compare(derived_public_key, context->public_key,
                              (rin_size_t)public_size) == 0;
    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    return valid;
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

PALEXPORT int32_t CryptoNative_RinOSEcdsaGenerateKey(void* handle,
                                                    int32_t curve)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    p256_keypair_t p256_key_pair;
    uint8_t private_key[RINOS_ECDSA_MAX_PRIVATE_KEY_SIZE];
    uint8_t public_key[RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE];
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;
    int generated = 0;
    int attempt;

    if (!context || context->magic != RINOS_ECDSA_MAGIC ||
        !rinos_ecdsa_curve_sizes(curve, &key_size, &private_size, &public_size,
                                 &hash_size, &signature_size))
        return 0;

    rintls_secure_zero(&p256_key_pair, sizeof(p256_key_pair));
    rintls_secure_zero(private_key, sizeof(private_key));
    rintls_secure_zero(public_key, sizeof(public_key));
    if (curve == ECDSA_CURVE_P256) {
        generated = p256_keygen(&p256_key_pair) == ECDH_OK;
        if (generated) {
            rintls_memcpy(private_key, p256_key_pair.private_key,
                          (rin_size_t)private_size);
            rintls_memcpy(public_key, p256_key_pair.public_key,
                          (rin_size_t)public_size);
        }
    } else {
        for (attempt = 0; attempt < 128 && !generated; attempt++) {
            if (rintls_random_bytes(private_key, (rin_size_t)private_size) != 0)
                break;
            if (curve == ECDSA_CURVE_P521)
                private_key[0] &= 0x01u;
            generated = rinos_ecdsa_derive_public(
                curve, public_key, RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE, private_key,
                private_size);
        }
    }

    if (!generated || !rinos_ecdsa_validate_public(curve, public_key, public_size))
        goto fail;

    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    rintls_memcpy(context->private_key, private_key, (rin_size_t)private_size);
    rintls_memcpy(context->public_key, public_key, (rin_size_t)public_size);
    context->curve = (uint32_t)curve;
    context->has_private_key = 1u;
    rintls_secure_zero(&p256_key_pair, sizeof(p256_key_pair));
    rintls_secure_zero(private_key, sizeof(private_key));
    rintls_secure_zero(public_key, sizeof(public_key));
    return 1;

fail:
    rintls_secure_zero(&p256_key_pair, sizeof(p256_key_pair));
    rintls_secure_zero(private_key, sizeof(private_key));
    rintls_secure_zero(public_key, sizeof(public_key));
    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    context->curve = 0u;
    context->has_private_key = 0u;
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaImportParameters(
    void* handle, int32_t curve, const uint8_t* private_key,
    int32_t private_key_length, const uint8_t* public_key,
    int32_t public_key_length)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    uint8_t derived_public_key[RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE];
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;
    uint32_t has_private_key;

    if (!context || context->magic != RINOS_ECDSA_MAGIC ||
        !rinos_ecdsa_curve_sizes(curve, &key_size, &private_size, &public_size,
                                 &hash_size, &signature_size) ||
        private_key_length < 0 || public_key_length != public_size ||
        (private_key_length != 0 && private_key == NULL) || public_key == NULL ||
        !rinos_ecdsa_validate_public(curve, public_key, public_key_length))
        return 0;

    has_private_key = private_key_length != 0;
    if (has_private_key && private_key_length != private_size)
        return 0;

    rintls_secure_zero(derived_public_key, sizeof(derived_public_key));
    if (has_private_key &&
        (!rinos_ecdsa_derive_public(curve, derived_public_key,
                                    RINOS_ECDSA_MAX_PUBLIC_KEY_SIZE,
                                    private_key, private_key_length) ||
         rintls_secure_compare(derived_public_key, public_key,
                               (rin_size_t)public_size) != 0))
        goto fail;

    rintls_secure_zero(context->private_key, sizeof(context->private_key));
    rintls_secure_zero(context->public_key, sizeof(context->public_key));
    if (has_private_key)
        rintls_memcpy(context->private_key, private_key,
                      (rin_size_t)private_size);
    rintls_memcpy(context->public_key, public_key, (rin_size_t)public_size);
    context->curve = (uint32_t)curve;
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
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;

    if (!rinos_ecdsa_context_valid(context) ||
        !rinos_ecdsa_curve_sizes((int32_t)context->curve, &key_size,
                                 &private_size, &public_size, &hash_size,
                                 &signature_size))
        return 0;
    return key_size;
}

PALEXPORT int32_t CryptoNative_RinOSEcdsaExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length)
{
    const rinos_ecdsa_context* context =
        (const rinos_ecdsa_context*)handle;
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;
    int32_t private_length;

    if (private_key_length)
        *private_key_length = 0;
    if (public_key_length)
        *public_key_length = 0;
    if (!rinos_ecdsa_context_valid(context) ||
        !rinos_ecdsa_curve_sizes((int32_t)context->curve, &key_size,
                                 &private_size, &public_size, &hash_size,
                                 &signature_size) ||
        (include_private != 0 && include_private != 1) ||
        (include_private && !context->has_private_key))
        goto fail;

    private_length = include_private ? private_size : 0;
    if (!rinos_ecdsa_copy_output(private_key, private_key_capacity,
                                 private_key_length, context->private_key,
                                 private_length) ||
        !rinos_ecdsa_copy_output(public_key, public_key_capacity,
                                 public_key_length, context->public_key,
                                 public_size))
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
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;

    if (signature_length)
        *signature_length = 0;
    if (!rinos_ecdsa_context_valid(context) || !context->has_private_key ||
        !rinos_ecdsa_curve_sizes((int32_t)context->curve, &key_size,
                                 &private_size, &public_size, &hash_size,
                                 &signature_size) ||
        hash_length != hash_size || hash == NULL ||
        signature_capacity < signature_size || signature == NULL ||
        signature_length == NULL)
        goto fail;

    if (context->curve == ECDSA_CURVE_P256) {
        if (ecdsa_p256_sign(signature, hash, context->private_key) != ECDH_OK)
            goto fail;
    } else if (ecdsa_nist_sign(
                   (int32_t)context->curve, signature,
                   (rin_size_t)signature_capacity, hash,
                   (rin_size_t)hash_length, context->private_key,
                   (rin_size_t)private_size) != ECDH_OK) {
        goto fail;
    }
    *signature_length = signature_size;
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
    int key_size;
    int private_size;
    int public_size;
    int hash_size;
    int signature_size;

    if (!rinos_ecdsa_context_valid(context) ||
        !rinos_ecdsa_curve_sizes((int32_t)context->curve, &key_size,
                                 &private_size, &public_size, &hash_size,
                                 &signature_size) ||
        hash_length != hash_size || hash == NULL ||
        signature_length != signature_size || signature == NULL)
        return 0;

    if (context->curve == ECDSA_CURVE_P256)
        return ecdsa_p256_verify(signature, (rin_size_t)signature_length, hash,
                                 (rin_size_t)hash_length, context->public_key,
                                 (rin_size_t)public_size) == ECDH_OK;
    return ecdsa_nist_verify(
               (int32_t)context->curve, signature,
               (rin_size_t)signature_length, hash, (rin_size_t)hash_length,
               context->public_key, (rin_size_t)public_size) == ECDH_OK;
}

PALEXPORT void CryptoNative_RinOSEcdsaDestroy(void* handle)
{
    rinos_ecdsa_context* context = (rinos_ecdsa_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
