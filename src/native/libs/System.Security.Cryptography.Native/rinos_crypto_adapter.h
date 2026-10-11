// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef RINOS_CRYPTO_ADAPTER_H
#define RINOS_CRYPTO_ADAPTER_H

#include <stdint.h>

/* RinTLS headers are product-owned inputs and are compiled under the .NET
 * native library's -Weverything -Werror policy. Keep their existing ABI
 * conversions from turning into errors in every adapter that includes them. */
#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#    pragma clang diagnostic ignored "-Wcast-qual"
#    pragma clang diagnostic ignored "-Wtautological-type-limit-compare"
#endif
#include "platform/rin_platform.h"
#if defined(__clang__)
#    pragma clang diagnostic pop
#endif

#ifdef __cplusplus
extern "C" {
#endif

void* CryptoNative_RinOSHashCreate(int32_t algorithm);
void* CryptoNative_RinOSHashClone(const void* source);
int32_t CryptoNative_RinOSHashUpdate(void* handle, const uint8_t* data, int32_t length);
int32_t CryptoNative_RinOSHashFinal(void* handle, uint8_t* destination, int32_t destination_length);
int32_t CryptoNative_RinOSHashCurrent(const void* handle, uint8_t* destination, int32_t destination_length);
int32_t CryptoNative_RinOSHashReset(void* handle);
void CryptoNative_RinOSHashDestroy(void* handle);

void* CryptoNative_RinOSHmacCreate(int32_t algorithm, const uint8_t* key, int32_t key_length);
void* CryptoNative_RinOSHmacClone(const void* source);
int32_t CryptoNative_RinOSHmacUpdate(void* handle, const uint8_t* data, int32_t length);
int32_t CryptoNative_RinOSHmacFinal(void* handle, uint8_t* destination, int32_t destination_length);
int32_t CryptoNative_RinOSHmacCurrent(const void* handle, uint8_t* destination, int32_t destination_length);
int32_t CryptoNative_RinOSHmacReset(void* handle);
void CryptoNative_RinOSHmacDestroy(void* handle);

int32_t CryptoNative_GetRandomBytes(uint8_t* buffer, int32_t length);

void* CryptoNative_RinOSAesGcmCreate(const uint8_t* key, int32_t key_length);
int32_t CryptoNative_RinOSAesGcmEncrypt(
    const void* handle, const uint8_t* nonce, int32_t nonce_length,
    const uint8_t* aad, int32_t aad_length, const uint8_t* plaintext,
    int32_t plaintext_length, uint8_t* ciphertext, int32_t ciphertext_length,
    uint8_t* tag, int32_t tag_length);
int32_t CryptoNative_RinOSAesGcmDecrypt(
    const void* handle, const uint8_t* nonce, int32_t nonce_length,
    const uint8_t* aad, int32_t aad_length, const uint8_t* ciphertext,
    int32_t ciphertext_length, const uint8_t* tag, int32_t tag_length,
    uint8_t* plaintext, int32_t plaintext_length);
void CryptoNative_RinOSAesGcmDestroy(void* handle);
void* CryptoNative_RinOSAesCreate(
    const uint8_t* key, int32_t key_length, int32_t mode,
    int32_t feedback_size, const uint8_t* iv, int32_t iv_length,
    int32_t encrypting);
int32_t CryptoNative_RinOSAesTransform(
    void* handle, const uint8_t* input, int32_t input_length,
    uint8_t* output, int32_t output_length);
int32_t CryptoNative_RinOSAesReset(
    void* handle, const uint8_t* iv, int32_t iv_length);
void CryptoNative_RinOSAesDestroy(void* handle);

void* CryptoNative_RinOSEcdhCreate(void);
int32_t CryptoNative_RinOSEcdhGenerateKey(void* handle);
int32_t CryptoNative_RinOSEcdhImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length);
int32_t CryptoNative_RinOSEcdhGetKeySize(const void* handle);
int32_t CryptoNative_RinOSEcdhExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length);
int32_t CryptoNative_RinOSEcdhDeriveRawSecret(
    const void* handle, const uint8_t* peer_public_key,
    int32_t peer_public_key_length, uint8_t* secret, int32_t secret_capacity,
    int32_t* secret_length);
void CryptoNative_RinOSEcdhDestroy(void* handle);

void* CryptoNative_RinOSEcdsaCreate(void);
int32_t CryptoNative_RinOSEcdsaGenerateKey(void* handle);
int32_t CryptoNative_RinOSEcdsaImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length);
int32_t CryptoNative_RinOSEcdsaGetKeySize(const void* handle);
int32_t CryptoNative_RinOSEcdsaExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length);
int32_t CryptoNative_RinOSEcdsaSignHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length);
int32_t CryptoNative_RinOSEcdsaVerifyHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    const uint8_t* signature, int32_t signature_length);
void CryptoNative_RinOSEcdsaDestroy(void* handle);

#ifdef __cplusplus
}
#endif

#endif /* RINOS_CRYPTO_ADAPTER_H */
