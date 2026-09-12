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
#define RINOS_AES_CIPHER_MAGIC UINT32_C(0x52434950)
#define RINOS_AES_GCM_NONCE_SIZE 12
#define RINOS_AES_GCM_MIN_TAG_SIZE 12
#define RINOS_AES_GCM_MAX_TAG_SIZE 16

#define RINOS_AES_MODE_ECB 0
#define RINOS_AES_MODE_CBC 1
#define RINOS_AES_MODE_CFB 2

typedef struct
{
    uint32_t magic;
    int32_t key_length;
    uint8_t key[AES256_KEY_SIZE];
} rinos_aes_gcm_context;

typedef struct
{
    uint32_t magic;
    uint32_t mode;
    uint32_t feedback_size;
    uint32_t encrypting;
    aes_ctx aes;
    uint8_t iv[AES_BLOCK_SIZE];
} rinos_aes_cipher_context;

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

static int rinos_aes_cipher_mode_valid(uint32_t mode, uint32_t feedback_size)
{
    if (mode == RINOS_AES_MODE_ECB || mode == RINOS_AES_MODE_CBC)
        return feedback_size == 0u;
    return mode == RINOS_AES_MODE_CFB &&
        (feedback_size == 1u || feedback_size == AES_BLOCK_SIZE);
}

static int rinos_aes_cipher_context_valid(
    const rinos_aes_cipher_context* context)
{
    return context != NULL && context->magic == RINOS_AES_CIPHER_MAGIC &&
        (context->aes.nr == 10 || context->aes.nr == 12 ||
         context->aes.nr == 14) &&
        rinos_aes_cipher_mode_valid(context->mode, context->feedback_size) &&
        context->encrypting <= 1u;
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

PALEXPORT void* CryptoNative_RinOSAesCreate(
    const uint8_t* key, int32_t key_length, int32_t mode,
    int32_t feedback_size, const uint8_t* iv, int32_t iv_length,
    int32_t encrypting)
{
    if (!rinos_aes_key_length_valid(key_length) || key == NULL ||
        (mode < RINOS_AES_MODE_ECB || mode > RINOS_AES_MODE_CFB) ||
        feedback_size < 0 ||
        !rinos_aes_cipher_mode_valid((uint32_t)mode,
                                     (uint32_t)feedback_size) ||
        encrypting < 0 || encrypting > 1 || iv_length < 0 ||
        (mode == RINOS_AES_MODE_ECB
            ? iv_length != 0
            : iv_length != AES_BLOCK_SIZE || iv == NULL))
        return NULL;

    rinos_aes_cipher_context* context =
        (rinos_aes_cipher_context*)rintls_malloc(sizeof(*context));
    if (context == NULL || aes_init(&context->aes, key, key_length) != 0)
    {
        if (context != NULL) rintls_mem_free(context);
        return NULL;
    }

    context->magic = RINOS_AES_CIPHER_MAGIC;
    context->mode = (uint32_t)mode;
    context->feedback_size = (uint32_t)feedback_size;
    context->encrypting = (uint32_t)encrypting;
    rintls_memset(context->iv, 0, sizeof(context->iv));
    if (iv_length != 0) rintls_memcpy(context->iv, iv, AES_BLOCK_SIZE);
    return context;
}

PALEXPORT int32_t CryptoNative_RinOSAesTransform(
    void* handle, const uint8_t* input, int32_t input_length,
    uint8_t* output, int32_t output_length)
{
    rinos_aes_cipher_context* context =
        (rinos_aes_cipher_context*)handle;
    if (!rinos_aes_cipher_context_valid(context) || input_length < 0 ||
        output_length < 0 || output_length < input_length ||
        (input_length != 0 && input == NULL) ||
        (input_length != 0 && output == NULL) ||
        ((context->mode == RINOS_AES_MODE_ECB ||
          context->mode == RINOS_AES_MODE_CBC ||
          (context->mode == RINOS_AES_MODE_CFB &&
           context->feedback_size == AES_BLOCK_SIZE)) &&
         (input_length % AES_BLOCK_SIZE) != 0))
        return -1;

    if (context->mode == RINOS_AES_MODE_CFB &&
        context->feedback_size == 1u)
    {
        int32_t index;
        for (index = 0; index < input_length; ++index)
        {
            uint8_t stream[AES_BLOCK_SIZE];
            uint8_t value = input[index];
            uint8_t ciphertext;
            uint32_t shift;
            aes_encrypt_block(&context->aes, context->iv, stream);
            ciphertext = (uint8_t)(value ^ stream[0]);
            output[index] = ciphertext;
            for (shift = 0u; shift + 1u < AES_BLOCK_SIZE; ++shift)
                context->iv[shift] = context->iv[shift + 1u];
            context->iv[AES_BLOCK_SIZE - 1u] = context->encrypting
                ? ciphertext : value;
            rintls_secure_zero(stream, sizeof(stream));
        }
        return input_length;
    }

    int32_t offset;
    for (offset = 0; offset < input_length; offset += AES_BLOCK_SIZE)
    {
        uint8_t block[AES_BLOCK_SIZE];
        uint8_t ciphertext[AES_BLOCK_SIZE];
        uint32_t index;
        if (context->mode == RINOS_AES_MODE_ECB)
        {
            if (context->encrypting)
                aes_encrypt_block(&context->aes, input + offset, block);
            else
                aes_decrypt_block(&context->aes, input + offset, block);
            rintls_memcpy(output + offset, block, AES_BLOCK_SIZE);
        }
        else if (context->mode == RINOS_AES_MODE_CBC)
        {
            if (context->encrypting)
            {
                for (index = 0u; index < AES_BLOCK_SIZE; ++index)
                    block[index] = (uint8_t)(input[offset + index] ^
                                             context->iv[index]);
                aes_encrypt_block(&context->aes, block, ciphertext);
                rintls_memcpy(output + offset, ciphertext, AES_BLOCK_SIZE);
                rintls_memcpy(context->iv, ciphertext, AES_BLOCK_SIZE);
            }
            else
            {
                rintls_memcpy(ciphertext, input + offset, AES_BLOCK_SIZE);
                aes_decrypt_block(&context->aes, ciphertext, block);
                for (index = 0u; index < AES_BLOCK_SIZE; ++index)
                    output[offset + index] = (uint8_t)(block[index] ^
                                                       context->iv[index]);
                rintls_memcpy(context->iv, ciphertext, AES_BLOCK_SIZE);
            }
        }
        else
        {
            aes_encrypt_block(&context->aes, context->iv, block);
            for (index = 0u; index < AES_BLOCK_SIZE; ++index)
            {
                ciphertext[index] = (uint8_t)(input[offset + index] ^
                                              block[index]);
                output[offset + index] = ciphertext[index];
            }
            rintls_memcpy(context->iv,
                          context->encrypting ? ciphertext : input + offset,
                          AES_BLOCK_SIZE);
        }
        rintls_secure_zero(block, sizeof(block));
        rintls_secure_zero(ciphertext, sizeof(ciphertext));
    }
    return input_length;
}

PALEXPORT int32_t CryptoNative_RinOSAesReset(
    void* handle, const uint8_t* iv, int32_t iv_length)
{
    rinos_aes_cipher_context* context =
        (rinos_aes_cipher_context*)handle;
    if (!rinos_aes_cipher_context_valid(context) || iv_length < 0 ||
        (context->mode == RINOS_AES_MODE_ECB
            ? iv_length != 0
            : iv_length != AES_BLOCK_SIZE || iv == NULL))
        return 0;
    rintls_memset(context->iv, 0, sizeof(context->iv));
    if (iv_length != 0) rintls_memcpy(context->iv, iv, AES_BLOCK_SIZE);
    return 1;
}

PALEXPORT void CryptoNative_RinOSAesDestroy(void* handle)
{
    rinos_aes_cipher_context* context =
        (rinos_aes_cipher_context*)handle;
    if (context == NULL) return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
