// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS AES-GCM adapter.
 *
 * This is deliberately a small, product-owned boundary.  The managed
 * AesGcm implementation performs the public argument validation; this layer
 * repeats the bounds checks before entering the freestanding product code and
 * never falls back to a host crypto provider.
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "aes.h"
#include "platform/rin_platform.h"

#define RINOS_AES_GCM_MAGIC UINT32_C(0x52474145)
#define RINOS_AES_GCM_NONCE_SIZE 12
#define RINOS_AES_GCM_MIN_TAG_SIZE 12
#define RINOS_AES_GCM_MAX_TAG_SIZE 16

typedef struct
{
    uint32_t magic;
    int32_t key_length;
    uint8_t key[AES256_KEY_SIZE];
} rinos_aes_gcm_context;

static int rinos_aes_key_length_valid(int32_t key_length)
{
    return key_length == AES128_KEY_SIZE ||
        key_length == AES192_KEY_SIZE ||
        key_length == AES256_KEY_SIZE;
}

static int rinos_aes_context_valid(const rinos_aes_gcm_context* context)
{
    return context != NULL && context->magic == RINOS_AES_GCM_MAGIC &&
        rinos_aes_key_length_valid(context->key_length);
}

static int rinos_aes_length_valid(int32_t length)
{
    /* rin_size_t is 32-bit in a freestanding RinOS build.  The product GCM
     * implementation multiplies these lengths by eight while recording the
     * GHASH length, so reject values which could wrap before that operation. */
    return length >= 0 && (uint64_t)(uint32_t)length <= UINT32_MAX / 8u;
}

static int rinos_aes_arguments_valid(
    const rinos_aes_gcm_context* context,
    const uint8_t* nonce,
    int32_t nonce_length,
    const uint8_t* aad,
    int32_t aad_length,
    const uint8_t* input,
    int32_t input_length,
    uint8_t* output,
    int32_t output_length,
    const uint8_t* tag,
    int32_t tag_length)
{
    return rinos_aes_context_valid(context) && nonce != NULL &&
        nonce_length == RINOS_AES_GCM_NONCE_SIZE &&
        rinos_aes_length_valid(aad_length) &&
        (aad != NULL || aad_length == 0) &&
        rinos_aes_length_valid(input_length) &&
        (input != NULL || input_length == 0) &&
        (output != NULL || output_length == 0) && output_length == input_length &&
        tag != NULL && tag_length >= RINOS_AES_GCM_MIN_TAG_SIZE &&
        tag_length <= RINOS_AES_GCM_MAX_TAG_SIZE;
}

PALEXPORT void* CryptoNative_RinOSAesGcmCreate(const uint8_t* key, int32_t key_length)
{
    if (!rinos_aes_key_length_valid(key_length) || key == NULL)
        return NULL;

    rinos_aes_gcm_context* context =
        (rinos_aes_gcm_context*)rintls_malloc(sizeof(*context));
    if (context == NULL)
        return NULL;

    context->magic = RINOS_AES_GCM_MAGIC;
    context->key_length = key_length;
    rintls_memcpy(context->key, key, (rin_size_t)key_length);
    return context;
}

PALEXPORT int32_t CryptoNative_RinOSAesGcmEncrypt(
    const void* handle,
    const uint8_t* nonce,
    int32_t nonce_length,
    const uint8_t* aad,
    int32_t aad_length,
    const uint8_t* plaintext,
    int32_t plaintext_length,
    uint8_t* ciphertext,
    int32_t ciphertext_length,
    uint8_t* tag,
    int32_t tag_length)
{
    const rinos_aes_gcm_context* context =
        (const rinos_aes_gcm_context*)handle;
    if (!rinos_aes_arguments_valid(context, nonce, nonce_length, aad, aad_length,
                                   plaintext, plaintext_length, ciphertext,
                                   ciphertext_length, tag, tag_length))
        return 0;

    aes_gcm_ctx gcm;
    uint8_t full_tag[AES_GCM_TAG_SIZE];
    if (aes_gcm_init(&gcm, context->key, context->key_length) != 0)
        return 0;

    aes_gcm_set_iv(&gcm, nonce, (rin_size_t)nonce_length);
    if (aad_length != 0)
        aes_gcm_aad(&gcm, aad, (rin_size_t)aad_length);
    if (plaintext_length != 0)
    {
        rintls_memcpy(ciphertext, plaintext, (rin_size_t)plaintext_length);
        aes_gcm_encrypt_inplace(&gcm, ciphertext, (rin_size_t)plaintext_length);
    }
    aes_gcm_finish(&gcm, full_tag);
    rintls_memcpy(tag, full_tag, (rin_size_t)tag_length);

    rintls_secure_zero(full_tag, sizeof(full_tag));
    rintls_secure_zero(&gcm, sizeof(gcm));
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSAesGcmDecrypt(
    const void* handle,
    const uint8_t* nonce,
    int32_t nonce_length,
    const uint8_t* aad,
    int32_t aad_length,
    const uint8_t* ciphertext,
    int32_t ciphertext_length,
    const uint8_t* tag,
    int32_t tag_length,
    uint8_t* plaintext,
    int32_t plaintext_length)
{
    const rinos_aes_gcm_context* context =
        (const rinos_aes_gcm_context*)handle;
    if (!rinos_aes_arguments_valid(context, nonce, nonce_length, aad, aad_length,
                                   ciphertext, ciphertext_length, plaintext,
                                   plaintext_length, tag, tag_length))
        return 0;

    aes_gcm_ctx gcm;
    uint8_t full_tag[AES_GCM_TAG_SIZE];
    if (aes_gcm_init(&gcm, context->key, context->key_length) != 0)
        return 0;

    aes_gcm_set_iv(&gcm, nonce, (rin_size_t)nonce_length);
    if (aad_length != 0)
        aes_gcm_aad(&gcm, aad, (rin_size_t)aad_length);
    if (ciphertext_length != 0)
    {
        rintls_memcpy(plaintext, ciphertext, (rin_size_t)ciphertext_length);
        aes_gcm_decrypt_inplace(&gcm, plaintext, (rin_size_t)ciphertext_length);
    }
    aes_gcm_finish(&gcm, full_tag);
    int result = rintls_secure_compare(full_tag, tag, (rin_size_t)tag_length);
    if (result != 0 && plaintext_length != 0)
        rintls_secure_zero(plaintext, (rin_size_t)plaintext_length);

    rintls_secure_zero(full_tag, sizeof(full_tag));
    rintls_secure_zero(&gcm, sizeof(gcm));
    return result == 0 ? 1 : 0;
}

PALEXPORT void CryptoNative_RinOSAesGcmDestroy(void* handle)
{
    rinos_aes_gcm_context* context = (rinos_aes_gcm_context*)handle;
    if (context == NULL)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
