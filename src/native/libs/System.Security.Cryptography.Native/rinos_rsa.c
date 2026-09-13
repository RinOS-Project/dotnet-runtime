// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS RSA adapter.
 *
 * The managed RSA implementation deals in RSAParameters and padding objects;
 * this file is the deliberately narrow native boundary for those operations.
 * It owns no host/OpenSSL state and keeps all key material inside the bounded
 * RinTLS RSA provider.
 */

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include "platform/rin_platform.h"
#include "rsa_webcrypto.h"

#define RINOS_RSA_MAGIC UINT32_C(0x52534152)
#define RINOS_RSA_PADDING_PKCS1 1
#define RINOS_RSA_PADDING_OAEP 2
#define RINOS_RSA_SIGNATURE_PKCS1 1
#define RINOS_RSA_SIGNATURE_PSS 2

typedef struct
{
    uint32_t magic;
    int32_t has_private;
    rintls_rsa_private_key key;
} rinos_rsa_context;

static int rinos_rsa_context_valid(const rinos_rsa_context* context)
{
    return context != NULL && context->magic == RINOS_RSA_MAGIC;
}

static int rinos_rsa_length_valid(int32_t length, rin_size_t maximum)
{
    return length >= 0 && (uint32_t)length <= maximum;
}

static int rinos_rsa_copy_integer(
    uint8_t* destination, uint16_t* destination_length, rin_size_t maximum,
    const uint8_t* source, int32_t source_length)
{
    rin_size_t offset = 0u;
    rin_size_t length;

    if (!destination || !destination_length ||
        !rinos_rsa_length_valid(source_length, maximum) ||
        (source_length != 0 && source == NULL))
        return 0;
    length = (rin_size_t)(uint32_t)source_length;
    while (offset < length && source[offset] == 0u)
        ++offset;
    length -= offset;
    if (length == 0u || length > maximum)
        return 0;
    rintls_memset(destination, 0, maximum);
    rintls_memcpy(destination, source + offset, length);
    *destination_length = (uint16_t)length;
    return 1;
}

static int rinos_rsa_hash_length(int32_t hash_algorithm)
{
    switch (hash_algorithm) {
    case RINTLS_RSA_HASH_SHA1:
        return 20;
    case RINTLS_RSA_HASH_SHA256:
        return 32;
    case RINTLS_RSA_HASH_SHA384:
        return 48;
    case RINTLS_RSA_HASH_SHA512:
        return 64;
    default:
        return 0;
    }
}

static int rinos_rsa_export_field(
    uint8_t* destination, int32_t capacity, int32_t* length,
    const uint8_t* source, rin_size_t source_length)
{
    if (!length || capacity < 0 || (capacity != 0 && !destination) ||
        (rin_size_t)(uint32_t)capacity < source_length)
        return 0;
    *length = 0;
    if (source_length != 0u)
        rintls_memcpy(destination, source, source_length);
    *length = (int32_t)source_length;
    return 1;
}

static void rinos_rsa_clear_export(
    uint8_t* modulus, int32_t modulus_capacity, int32_t* modulus_length,
    uint8_t* exponent, int32_t exponent_capacity, int32_t* exponent_length,
    uint8_t* private_exponent, int32_t private_exponent_capacity,
    int32_t* private_exponent_length, uint8_t* prime1, int32_t prime1_capacity,
    int32_t* prime1_length, uint8_t* prime2, int32_t prime2_capacity,
    int32_t* prime2_length, uint8_t* exponent1, int32_t exponent1_capacity,
    int32_t* exponent1_length, uint8_t* exponent2, int32_t exponent2_capacity,
    int32_t* exponent2_length, uint8_t* coefficient,
    int32_t coefficient_capacity, int32_t* coefficient_length)
{
    if (modulus && modulus_capacity >= 0)
        rintls_secure_zero(modulus, (rin_size_t)(uint32_t)modulus_capacity);
    if (exponent && exponent_capacity >= 0)
        rintls_secure_zero(exponent, (rin_size_t)(uint32_t)exponent_capacity);
    if (private_exponent && private_exponent_capacity >= 0)
        rintls_secure_zero(private_exponent,
                           (rin_size_t)(uint32_t)private_exponent_capacity);
    if (prime1 && prime1_capacity >= 0)
        rintls_secure_zero(prime1, (rin_size_t)(uint32_t)prime1_capacity);
    if (prime2 && prime2_capacity >= 0)
        rintls_secure_zero(prime2, (rin_size_t)(uint32_t)prime2_capacity);
    if (exponent1 && exponent1_capacity >= 0)
        rintls_secure_zero(exponent1,
                           (rin_size_t)(uint32_t)exponent1_capacity);
    if (exponent2 && exponent2_capacity >= 0)
        rintls_secure_zero(exponent2,
                           (rin_size_t)(uint32_t)exponent2_capacity);
    if (coefficient && coefficient_capacity >= 0)
        rintls_secure_zero(coefficient,
                           (rin_size_t)(uint32_t)coefficient_capacity);
    if (modulus_length)
        *modulus_length = 0;
    if (exponent_length)
        *exponent_length = 0;
    if (private_exponent_length)
        *private_exponent_length = 0;
    if (prime1_length)
        *prime1_length = 0;
    if (prime2_length)
        *prime2_length = 0;
    if (exponent1_length)
        *exponent1_length = 0;
    if (exponent2_length)
        *exponent2_length = 0;
    if (coefficient_length)
        *coefficient_length = 0;
}

static int rinos_rsa_validate_key(const rintls_rsa_private_key* key,
                                  int has_private)
{
    uint8_t representative[RINTLS_RSA_MAX_MODULUS_BYTES];
    uint8_t result[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t result_length = 0u;
    int valid = 0;

    rintls_secure_zero(representative, sizeof(representative));
    rintls_secure_zero(result, sizeof(result));
    if (!key || key->public_key.modulus_len == 0u)
        goto done;
    representative[key->public_key.modulus_len - 1u] = 1u;
    if (has_private) {
        valid = rintls_rsa_raw_private(key, representative,
                                       key->public_key.modulus_len, result,
                                       sizeof(result), &result_length) == 0;
    } else {
        valid = rintls_rsa_raw_public(&key->public_key, representative,
                                      key->public_key.modulus_len, result,
                                      sizeof(result), &result_length) == 0;
    }
done:
    rintls_secure_zero(result, sizeof(result));
    rintls_secure_zero(representative, sizeof(representative));
    return valid;
}

static int rinos_rsa_pkcs1_encrypt(
    const rintls_rsa_public_key* public_key, const uint8_t* message,
    rin_size_t message_length, uint8_t* output, rin_size_t output_capacity,
    rin_size_t* output_length)
{
    uint8_t encoded[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t padding_length;
    rin_size_t index;
    int result = -1;

    rintls_secure_zero(encoded, sizeof(encoded));
    if (!public_key || (!message && message_length != 0u) ||
        message_length > public_key->modulus_len - 11u ||
        output_capacity < public_key->modulus_len || !output_length)
        goto done;
    padding_length = public_key->modulus_len - message_length - 3u;
    encoded[0] = 0u;
    encoded[1] = 2u;
    for (index = 0u; index < padding_length; ++index) {
        do {
            if (rintls_get_random(encoded + 2u + index, 1u) != 0)
                goto done;
        } while (encoded[2u + index] == 0u);
    }
    encoded[2u + padding_length] = 0u;
    rintls_memcpy(encoded + 3u + padding_length, message, message_length);
    result = rintls_rsa_raw_public(public_key, encoded, public_key->modulus_len,
                                   output, output_capacity, output_length);
done:
    if (result != 0 && output_length)
        *output_length = 0u;
    rintls_secure_zero(encoded, sizeof(encoded));
    return result;
}

static int rinos_rsa_pkcs1_decrypt(
    const rintls_rsa_private_key* private_key, const uint8_t* encrypted,
    rin_size_t encrypted_length, uint8_t* output, rin_size_t output_capacity,
    rin_size_t* output_length)
{
    uint8_t encoded[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t delimiter;
    rin_size_t message_length;
    int result = -1;

    rintls_secure_zero(encoded, sizeof(encoded));
    if (!private_key || !encrypted || encrypted_length != private_key->public_key.modulus_len ||
        !output_length)
        goto done;
    if (rintls_rsa_raw_private(private_key, encrypted, encrypted_length, encoded,
                               sizeof(encoded), &message_length) != 0 ||
        message_length != private_key->public_key.modulus_len ||
        encoded[0] != 0u || encoded[1] != 2u)
        goto done;
    delimiter = 2u;
    while (delimiter < message_length && encoded[delimiter] != 0u)
        ++delimiter;
    if (delimiter < 10u || delimiter >= message_length)
        goto done;
    message_length -= delimiter + 1u;
    if (message_length > output_capacity ||
        (message_length != 0u && !output))
        goto done;
    if (message_length != 0u)
        rintls_memcpy(output, encoded + delimiter + 1u, message_length);
    *output_length = message_length;
    result = 0;
done:
    if (result != 0 && output && output_capacity <= RINTLS_RSA_MAX_MODULUS_BYTES)
        rintls_secure_zero(output, output_capacity);
    if (result != 0 && output_length)
        *output_length = 0u;
    rintls_secure_zero(encoded, sizeof(encoded));
    return result;
}

PALEXPORT void* CryptoNative_RinOSRsaCreate(void)
{
    rinos_rsa_context* context =
        (rinos_rsa_context*)rintls_malloc(sizeof(*context));
    if (!context)
        return NULL;
    rintls_secure_zero(context, sizeof(*context));
    context->magic = RINOS_RSA_MAGIC;
    return context;
}

PALEXPORT int32_t CryptoNative_RinOSRsaGenerateKey(
    void* handle, int32_t key_size, int32_t public_exponent)
{
    rinos_rsa_context* context = (rinos_rsa_context*)handle;
    if (!rinos_rsa_context_valid(context) || key_size < 0)
        return 0;
    context->has_private = 0;
    if (rintls_rsa_generate_keypair((u32)key_size, (u32)public_exponent,
                                    &context->key) != 0)
        return 0;
    context->has_private = 1;
    return 1;
}

PALEXPORT int32_t CryptoNative_RinOSRsaImportParameters(
    void* handle, const uint8_t* modulus, int32_t modulus_length,
    const uint8_t* exponent, int32_t exponent_length,
    const uint8_t* private_exponent, int32_t private_exponent_length,
    const uint8_t* prime1, int32_t prime1_length,
    const uint8_t* prime2, int32_t prime2_length,
    const uint8_t* exponent1, int32_t exponent1_length,
    const uint8_t* exponent2, int32_t exponent2_length,
    const uint8_t* coefficient, int32_t coefficient_length)
{
    rinos_rsa_context* context = (rinos_rsa_context*)handle;
    rintls_rsa_private_key imported;
    uint16_t imported_exponent_length;
    int has_private;
    int private_fields_complete;

    if (!rinos_rsa_context_valid(context))
        return 0;
    rintls_secure_zero(&imported, sizeof(imported));
    imported_exponent_length = 0u;
    has_private = private_exponent_length != 0 || prime1_length != 0 ||
        prime2_length != 0 || exponent1_length != 0 || exponent2_length != 0 ||
        coefficient_length != 0;
    private_fields_complete = private_exponent_length != 0 &&
        prime1_length != 0 && prime2_length != 0 && exponent1_length != 0 &&
        exponent2_length != 0 && coefficient_length != 0;
    if ((has_private && !private_fields_complete) ||
        !rinos_rsa_copy_integer(imported.public_key.modulus,
                                &imported.public_key.modulus_len,
                                sizeof(imported.public_key.modulus), modulus,
                                modulus_length) ||
        !rinos_rsa_copy_integer(imported.public_key.public_exponent,
                                &imported_exponent_length,
                                sizeof(imported.public_key.public_exponent),
                                exponent, exponent_length))
        goto fail;
    if (imported_exponent_length > UINT8_MAX)
        goto fail;
    imported.public_key.public_exponent_len =
        (uint8_t)imported_exponent_length;
    if (imported.public_key.modulus_len < RINTLS_RSA_MIN_MODULUS_BITS / 8u ||
        imported.public_key.modulus_len > RINTLS_RSA_MAX_MODULUS_BYTES ||
        (imported.public_key.modulus_len & 7u) != 0u ||
        (imported.public_key.modulus[0] & 0x80u) == 0u ||
        imported.public_key.public_exponent_len >
            RINTLS_RSA_MAX_PUBLIC_EXPONENT_BYTES)
        goto fail;
    imported.public_key.modulus_bits =
        (uint16_t)(imported.public_key.modulus_len * 8u);
    if (has_private &&
        (!rinos_rsa_copy_integer(imported.private_exponent,
                                 &imported.private_exponent_len,
                                 sizeof(imported.private_exponent),
                                 private_exponent, private_exponent_length) ||
         !rinos_rsa_copy_integer(imported.prime1, &imported.prime1_len,
                                 sizeof(imported.prime1), prime1, prime1_length) ||
         !rinos_rsa_copy_integer(imported.prime2, &imported.prime2_len,
                                 sizeof(imported.prime2), prime2, prime2_length) ||
         !rinos_rsa_copy_integer(imported.exponent1, &imported.exponent1_len,
                                 sizeof(imported.exponent1), exponent1,
                                 exponent1_length) ||
         !rinos_rsa_copy_integer(imported.exponent2, &imported.exponent2_len,
                                 sizeof(imported.exponent2), exponent2,
                                 exponent2_length) ||
         !rinos_rsa_copy_integer(imported.coefficient,
                                 &imported.coefficient_len,
                                 sizeof(imported.coefficient), coefficient,
                                 coefficient_length)))
        goto fail;
    if (!rinos_rsa_validate_key(&imported, has_private))
        goto fail;
    rintls_secure_zero(&context->key, sizeof(context->key));
    rintls_memcpy(&context->key, &imported, sizeof(imported));
    context->has_private = has_private;
    rintls_secure_zero(&imported, sizeof(imported));
    return 1;
fail:
    rintls_secure_zero(&imported, sizeof(imported));
    return 0;
}

PALEXPORT int32_t CryptoNative_RinOSRsaGetKeySize(const void* handle)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    return rinos_rsa_context_valid(context) ? context->key.public_key.modulus_bits : 0;
}

PALEXPORT int32_t CryptoNative_RinOSRsaExportParameters(
    const void* handle, int32_t include_private,
    uint8_t* modulus, int32_t modulus_capacity, int32_t* modulus_length,
    uint8_t* exponent, int32_t exponent_capacity, int32_t* exponent_length,
    uint8_t* private_exponent, int32_t private_exponent_capacity,
    int32_t* private_exponent_length, uint8_t* prime1, int32_t prime1_capacity,
    int32_t* prime1_length, uint8_t* prime2, int32_t prime2_capacity,
    int32_t* prime2_length, uint8_t* exponent1, int32_t exponent1_capacity,
    int32_t* exponent1_length, uint8_t* exponent2, int32_t exponent2_capacity,
    int32_t* exponent2_length, uint8_t* coefficient,
    int32_t coefficient_capacity, int32_t* coefficient_length)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    const rintls_rsa_private_key* key;
    int result = 0;

    if (!rinos_rsa_context_valid(context) ||
        (include_private != 0 && include_private != 1))
        goto done;
    key = &context->key;
    if (!rinos_rsa_export_field(modulus, modulus_capacity, modulus_length,
                                key->public_key.modulus,
                                key->public_key.modulus_len) ||
        !rinos_rsa_export_field(exponent, exponent_capacity, exponent_length,
                                key->public_key.public_exponent,
                                key->public_key.public_exponent_len))
        goto done;
    if (include_private && context->has_private) {
        if (!rinos_rsa_export_field(
                private_exponent, private_exponent_capacity,
                private_exponent_length, key->private_exponent,
                key->private_exponent_len) ||
            !rinos_rsa_export_field(prime1, prime1_capacity, prime1_length,
                                    key->prime1, key->prime1_len) ||
            !rinos_rsa_export_field(prime2, prime2_capacity, prime2_length,
                                    key->prime2, key->prime2_len) ||
            !rinos_rsa_export_field(exponent1, exponent1_capacity,
                                    exponent1_length, key->exponent1,
                                    key->exponent1_len) ||
            !rinos_rsa_export_field(exponent2, exponent2_capacity,
                                    exponent2_length, key->exponent2,
                                    key->exponent2_len) ||
            !rinos_rsa_export_field(coefficient, coefficient_capacity,
                                    coefficient_length, key->coefficient,
                                    key->coefficient_len))
            goto done;
    } else {
        if (!rinos_rsa_export_field(private_exponent, private_exponent_capacity,
                                    private_exponent_length, NULL, 0u) ||
            !rinos_rsa_export_field(prime1, prime1_capacity, prime1_length,
                                    NULL, 0u) ||
            !rinos_rsa_export_field(prime2, prime2_capacity, prime2_length,
                                    NULL, 0u) ||
            !rinos_rsa_export_field(exponent1, exponent1_capacity,
                                    exponent1_length, NULL, 0u) ||
            !rinos_rsa_export_field(exponent2, exponent2_capacity,
                                    exponent2_length, NULL, 0u) ||
            !rinos_rsa_export_field(coefficient, coefficient_capacity,
                                    coefficient_length, NULL, 0u))
            goto done;
    }
    result = 1;
done:
    if (!result)
        rinos_rsa_clear_export(
            modulus, modulus_capacity, modulus_length, exponent,
            exponent_capacity, exponent_length, private_exponent,
            private_exponent_capacity, private_exponent_length, prime1,
            prime1_capacity, prime1_length, prime2, prime2_capacity,
            prime2_length, exponent1, exponent1_capacity, exponent1_length,
            exponent2, exponent2_capacity, exponent2_length, coefficient,
            coefficient_capacity, coefficient_length);
    return result;
}

PALEXPORT int32_t CryptoNative_RinOSRsaEncrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    uint8_t input_copy[RINTLS_RSA_MAX_MODULUS_BYTES];
    uint8_t result[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t result_length = 0u;
    int operation_result = -1;

    rintls_secure_zero(input_copy, sizeof(input_copy));
    rintls_secure_zero(result, sizeof(result));
    if (!rinos_rsa_context_valid(context) || !output_length ||
        !rinos_rsa_length_valid(input_length, sizeof(input_copy)) ||
        output_capacity < 0 ||
        (input_length != 0 && !input) ||
        (output_capacity != 0 && !output) ||
        output_capacity < context->key.public_key.modulus_len)
        goto done;
    *output_length = 0;
    if (input_length != 0)
        rintls_memcpy(input_copy, input, (rin_size_t)(uint32_t)input_length);
    if (padding == RINOS_RSA_PADDING_PKCS1) {
        operation_result = rinos_rsa_pkcs1_encrypt(
            &context->key.public_key, input_copy, (rin_size_t)(uint32_t)input_length,
            result, sizeof(result), &result_length);
    } else if (padding == RINOS_RSA_PADDING_OAEP &&
               rinos_rsa_hash_length(hash_algorithm) != 0) {
        operation_result = rintls_rsa_oaep_encrypt(
            (u32)hash_algorithm, &context->key.public_key, NULL, 0u, input_copy,
            (rin_size_t)(uint32_t)input_length, result, sizeof(result),
            &result_length);
    }
    if (operation_result != 0 || result_length != context->key.public_key.modulus_len)
        goto done;
    rintls_memcpy(output, result, result_length);
    *output_length = (int32_t)result_length;
    operation_result = 0;
done:
    if (operation_result != 0 && output &&
        (uint32_t)output_capacity <= RINTLS_RSA_MAX_MODULUS_BYTES)
        rintls_secure_zero(output, (rin_size_t)(uint32_t)output_capacity);
    if (operation_result != 0 && output_length)
        *output_length = 0;
    rintls_secure_zero(result, sizeof(result));
    rintls_secure_zero(input_copy, sizeof(input_copy));
    return operation_result == 0;
}

PALEXPORT int32_t CryptoNative_RinOSRsaDecrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    uint8_t input_copy[RINTLS_RSA_MAX_MODULUS_BYTES];
    uint8_t result[RINTLS_RSA_MAX_MODULUS_BYTES];
    rin_size_t result_length = 0u;
    int operation_result = -1;

    rintls_secure_zero(input_copy, sizeof(input_copy));
    rintls_secure_zero(result, sizeof(result));
    if (!rinos_rsa_context_valid(context) || !context->has_private ||
        !output_length || !rinos_rsa_length_valid(input_length, sizeof(input_copy)) ||
        (input_length != 0 && !input) || output_capacity < 0 ||
        (output_capacity != 0 && !output) ||
        input_length != context->key.public_key.modulus_len)
        goto done;
    *output_length = 0;
    rintls_memcpy(input_copy, input, (rin_size_t)(uint32_t)input_length);
    if (padding == RINOS_RSA_PADDING_PKCS1) {
        operation_result = rinos_rsa_pkcs1_decrypt(
            &context->key, input_copy, (rin_size_t)(uint32_t)input_length, result,
            sizeof(result), &result_length);
    } else if (padding == RINOS_RSA_PADDING_OAEP &&
               rinos_rsa_hash_length(hash_algorithm) != 0) {
        operation_result = rintls_rsa_oaep_decrypt(
            (u32)hash_algorithm, &context->key, input_copy,
            (rin_size_t)(uint32_t)input_length, NULL, 0u, result, sizeof(result),
            &result_length);
    }
    if (operation_result != 0 || result_length > (rin_size_t)(uint32_t)output_capacity)
        goto done;
    if (result_length != 0u)
        rintls_memcpy(output, result, result_length);
    *output_length = (int32_t)result_length;
    operation_result = 0;
done:
    if (operation_result != 0 && output &&
        (uint32_t)output_capacity <= RINTLS_RSA_MAX_MODULUS_BYTES)
        rintls_secure_zero(output, (rin_size_t)(uint32_t)output_capacity);
    if (operation_result != 0 && output_length)
        *output_length = 0;
    rintls_secure_zero(result, sizeof(result));
    rintls_secure_zero(input_copy, sizeof(input_copy));
    return operation_result == 0;
}

PALEXPORT int32_t CryptoNative_RinOSRsaSignHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    uint8_t digest[64];
    rin_size_t produced_length = 0u;
    int hash_size = rinos_rsa_hash_length(hash_algorithm);
    int operation_result = -1;

    rintls_secure_zero(digest, sizeof(digest));
    if (!rinos_rsa_context_valid(context) || !context->has_private ||
        !signature_length || !hash || hash_length != hash_size ||
        salt_length < 0 || signature_capacity < 0 ||
        (signature_capacity != 0 && !signature))
        goto done;
    *signature_length = 0;
    rintls_memcpy(digest, hash, (rin_size_t)(uint32_t)hash_length);
    if (padding == RINOS_RSA_SIGNATURE_PKCS1) {
        operation_result = rintls_rsa_pkcs1_sign_digest(
            (u32)hash_algorithm, &context->key, digest,
            (rin_size_t)(uint32_t)hash_length, signature,
            (rin_size_t)(uint32_t)signature_capacity, &produced_length);
    } else if (padding == RINOS_RSA_SIGNATURE_PSS) {
        operation_result = rintls_rsa_pss_sign_digest(
            (u32)hash_algorithm, &context->key, digest,
            (rin_size_t)(uint32_t)hash_length, (u32)salt_length, signature,
            (rin_size_t)(uint32_t)signature_capacity, &produced_length);
    }
    if (operation_result != 0)
        goto done;
    *signature_length = (int32_t)produced_length;
done:
    if (operation_result != 0 && signature &&
        (uint32_t)signature_capacity <= RINTLS_RSA_MAX_MODULUS_BYTES)
        rintls_secure_zero(signature, (rin_size_t)(uint32_t)signature_capacity);
    if (operation_result != 0 && signature_length)
        *signature_length = 0;
    rintls_secure_zero(digest, sizeof(digest));
    return operation_result == 0;
}

PALEXPORT int32_t CryptoNative_RinOSRsaVerifyHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    const uint8_t* signature, int32_t signature_length)
{
    const rinos_rsa_context* context = (const rinos_rsa_context*)handle;
    uint8_t digest[64];
    int hash_size = rinos_rsa_hash_length(hash_algorithm);
    int result = 0;

    rintls_secure_zero(digest, sizeof(digest));
    if (!rinos_rsa_context_valid(context) || !hash || hash_length != hash_size ||
        salt_length < 0 || !signature || signature_length < 0 ||
        signature_length != context->key.public_key.modulus_len)
        goto done;
    rintls_memcpy(digest, hash, (rin_size_t)(uint32_t)hash_length);
    if (padding == RINOS_RSA_SIGNATURE_PKCS1) {
        result = rintls_rsa_pkcs1_verify_digest(
                     (u32)hash_algorithm, &context->key.public_key, digest,
                     (rin_size_t)(uint32_t)hash_length, signature,
                     (rin_size_t)(uint32_t)signature_length) ==
            RINTLS_RSA_VERIFY_VALID;
    } else if (padding == RINOS_RSA_SIGNATURE_PSS) {
        result = rintls_rsa_pss_verify_digest(
                     (u32)hash_algorithm, &context->key.public_key, digest,
                     (rin_size_t)(uint32_t)hash_length, (u32)salt_length,
                     signature, (rin_size_t)(uint32_t)signature_length) ==
            RINTLS_RSA_VERIFY_VALID;
    }
done:
    rintls_secure_zero(digest, sizeof(digest));
    return result;
}

PALEXPORT void CryptoNative_RinOSRsaDestroy(void* handle)
{
    rinos_rsa_context* context = (rinos_rsa_context*)handle;
    if (!context)
        return;
    rintls_secure_zero(context, sizeof(*context));
    rintls_mem_free(context);
}
