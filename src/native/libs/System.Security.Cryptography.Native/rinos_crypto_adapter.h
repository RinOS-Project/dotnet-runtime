// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef RINOS_CRYPTO_ADAPTER_H
#define RINOS_CRYPTO_ADAPTER_H

#include <stdint.h>
#include "../Common/pal_compiler.h"

/* RinTLS headers are product-owned inputs and are compiled under the .NET
 * native library's -Weverything -Werror policy. Keep their existing ABI
 * conversions from turning into errors in every adapter that includes them. */
#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wimplicit-int-conversion"
#    pragma clang diagnostic ignored "-Wcast-qual"
#    pragma clang diagnostic ignored "-Wtautological-type-limit-compare"
#    pragma clang diagnostic ignored "-Wc++-keyword"
#endif
#include "platform/rin_platform.h"
#if defined(__clang__)
#    pragma clang diagnostic pop
#endif

#ifdef __cplusplus
extern "C" {
#endif

PALEXPORT void* CryptoNative_RinOSHashCreate(int32_t algorithm);
PALEXPORT void* CryptoNative_RinOSHashClone(const void* source);
PALEXPORT int32_t CryptoNative_RinOSHashUpdate(void* handle, const uint8_t* data, int32_t length);
PALEXPORT int32_t CryptoNative_RinOSHashFinal(void* handle, uint8_t* destination, int32_t destination_length);
PALEXPORT int32_t CryptoNative_RinOSHashCurrent(const void* handle, uint8_t* destination, int32_t destination_length);
PALEXPORT int32_t CryptoNative_RinOSHashReset(void* handle);
PALEXPORT void CryptoNative_RinOSHashDestroy(void* handle);

PALEXPORT void* CryptoNative_RinOSHmacCreate(int32_t algorithm, const uint8_t* key, int32_t key_length);
PALEXPORT void* CryptoNative_RinOSHmacClone(const void* source);
PALEXPORT int32_t CryptoNative_RinOSHmacUpdate(void* handle, const uint8_t* data, int32_t length);
PALEXPORT int32_t CryptoNative_RinOSHmacFinal(void* handle, uint8_t* destination, int32_t destination_length);
PALEXPORT int32_t CryptoNative_RinOSHmacCurrent(const void* handle, uint8_t* destination, int32_t destination_length);
PALEXPORT int32_t CryptoNative_RinOSHmacReset(void* handle);
PALEXPORT void CryptoNative_RinOSHmacDestroy(void* handle);

PALEXPORT int32_t CryptoNative_GetRandomBytes(uint8_t* buffer, int32_t length);

PALEXPORT void* CryptoNative_RinOSAesGcmCreate(const uint8_t* key, int32_t key_length);
PALEXPORT int32_t CryptoNative_RinOSAesGcmEncrypt(
    const void* handle, const uint8_t* nonce, int32_t nonce_length,
    const uint8_t* aad, int32_t aad_length, const uint8_t* plaintext,
    int32_t plaintext_length, uint8_t* ciphertext, int32_t ciphertext_length,
    uint8_t* tag, int32_t tag_length);
PALEXPORT int32_t CryptoNative_RinOSAesGcmDecrypt(
    const void* handle, const uint8_t* nonce, int32_t nonce_length,
    const uint8_t* aad, int32_t aad_length, const uint8_t* ciphertext,
    int32_t ciphertext_length, const uint8_t* tag, int32_t tag_length,
    uint8_t* plaintext, int32_t plaintext_length);
PALEXPORT void CryptoNative_RinOSAesGcmDestroy(void* handle);
PALEXPORT void* CryptoNative_RinOSAesCreate(
    const uint8_t* key, int32_t key_length, int32_t mode,
    int32_t feedback_size, const uint8_t* iv, int32_t iv_length,
    int32_t encrypting);
PALEXPORT int32_t CryptoNative_RinOSAesTransform(
    void* handle, const uint8_t* input, int32_t input_length,
    uint8_t* output, int32_t output_length);
PALEXPORT int32_t CryptoNative_RinOSAesReset(
    void* handle, const uint8_t* iv, int32_t iv_length);
PALEXPORT void CryptoNative_RinOSAesDestroy(void* handle);

PALEXPORT void* CryptoNative_RinOSEcdhCreate(void);
PALEXPORT int32_t CryptoNative_RinOSEcdhGenerateKey(void* handle);
PALEXPORT int32_t CryptoNative_RinOSEcdhImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length);
PALEXPORT int32_t CryptoNative_RinOSEcdhGetKeySize(const void* handle);
PALEXPORT int32_t CryptoNative_RinOSEcdhExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length);
PALEXPORT int32_t CryptoNative_RinOSEcdhDeriveRawSecret(
    const void* handle, const uint8_t* peer_public_key,
    int32_t peer_public_key_length, uint8_t* secret, int32_t secret_capacity,
    int32_t* secret_length);
PALEXPORT void CryptoNative_RinOSEcdhDestroy(void* handle);

PALEXPORT void* CryptoNative_RinOSEcdsaCreate(void);
PALEXPORT int32_t CryptoNative_RinOSEcdsaGenerateKey(void* handle);
PALEXPORT int32_t CryptoNative_RinOSEcdsaImportParameters(
    void* handle, const uint8_t* private_key, int32_t private_key_length,
    const uint8_t* public_key, int32_t public_key_length);
PALEXPORT int32_t CryptoNative_RinOSEcdsaGetKeySize(const void* handle);
PALEXPORT int32_t CryptoNative_RinOSEcdsaExportParameters(
    const void* handle, int32_t include_private, uint8_t* private_key,
    int32_t private_key_capacity, int32_t* private_key_length,
    uint8_t* public_key, int32_t public_key_capacity, int32_t* public_key_length);
PALEXPORT int32_t CryptoNative_RinOSEcdsaSignHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length);
PALEXPORT int32_t CryptoNative_RinOSEcdsaVerifyHash(
    const void* handle, const uint8_t* hash, int32_t hash_length,
    const uint8_t* signature, int32_t signature_length);
PALEXPORT void CryptoNative_RinOSEcdsaDestroy(void* handle);

PALEXPORT void* CryptoNative_RinOSRsaCreate(void);
PALEXPORT int32_t CryptoNative_RinOSRsaGenerateKey(
    void* handle, int32_t key_size, int32_t public_exponent);
PALEXPORT int32_t CryptoNative_RinOSRsaImportParameters(
    void* handle, const uint8_t* modulus, int32_t modulus_length,
    const uint8_t* exponent, int32_t exponent_length,
    const uint8_t* private_exponent, int32_t private_exponent_length,
    const uint8_t* prime1, int32_t prime1_length,
    const uint8_t* prime2, int32_t prime2_length,
    const uint8_t* exponent1, int32_t exponent1_length,
    const uint8_t* exponent2, int32_t exponent2_length,
    const uint8_t* coefficient, int32_t coefficient_length);
PALEXPORT int32_t CryptoNative_RinOSRsaGetKeySize(const void* handle);
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
    int32_t coefficient_capacity, int32_t* coefficient_length);
PALEXPORT int32_t CryptoNative_RinOSRsaEncrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length);
PALEXPORT int32_t CryptoNative_RinOSRsaDecrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length);
PALEXPORT int32_t CryptoNative_RinOSRsaSignHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length);
PALEXPORT int32_t CryptoNative_RinOSRsaVerifyHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    const uint8_t* signature, int32_t signature_length);
PALEXPORT void CryptoNative_RinOSRsaDestroy(void* handle);

PALEXPORT int32_t CryptoNative_RinOSX509VerifySignature(
    const uint8_t* certificate_der, int32_t certificate_length,
    const uint8_t* issuer_der, int32_t issuer_length);

PALEXPORT void* CryptoNative_RinTlsCreate(int32_t is_server, const char* hostname,
                                uint32_t options, uint64_t trusted_time,
                                int32_t* error);
PALEXPORT void CryptoNative_RinTlsDestroy(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsSetCipherSuites(
    void* handle, const uint16_t* cipher_suites, int32_t cipher_suite_count);
PALEXPORT int32_t CryptoNative_RinTlsLoadTrustStore(
    void* handle, const uint8_t* bundle, int32_t bundle_length);
PALEXPORT int32_t CryptoNative_RinTlsHandshake(
    void* handle, const uint8_t* input, int32_t input_length, int32_t* consumed);
PALEXPORT int32_t CryptoNative_RinTlsSetClientCertificate(
    void* handle, const uint8_t* certificate_list,
    int32_t certificate_list_length, void* signer, void* signer_opaque);
PALEXPORT int32_t CryptoNative_RinTlsSetServerCertificate(
    void* handle, const uint8_t* certificate_list,
    int32_t certificate_list_length, void* signer, void* signer_opaque);
PALEXPORT int32_t CryptoNative_RinTlsClientCertificateRequested(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsPendingOutputLength(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsReadOutput(
    void* handle, uint8_t* destination, int32_t capacity);
PALEXPORT int32_t CryptoNative_RinTlsEncrypt(
    void* handle, const uint8_t* plaintext, int32_t plaintext_length,
    int32_t* consumed);
PALEXPORT int32_t CryptoNative_RinTlsDecrypt(
    void* handle, const uint8_t* encrypted, int32_t encrypted_length,
    uint8_t* plaintext, int32_t plaintext_capacity, int32_t* consumed,
    int32_t* written);
PALEXPORT int32_t CryptoNative_RinTlsShutdown(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsIsClosed(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsGetVersion(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsGetCipherSuite(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsGetApplicationProtocolLength(
    void* handle, int32_t* length);
PALEXPORT int32_t CryptoNative_RinTlsCopyApplicationProtocol(
    void* handle, uint8_t* destination, int32_t capacity);
PALEXPORT int32_t CryptoNative_RinTlsGetError(void* handle);
PALEXPORT int32_t CryptoNative_RinTlsGetPeerCertificateLength(
    void* handle, int32_t* length);
PALEXPORT int32_t CryptoNative_RinTlsCopyPeerCertificate(
    void* handle, uint8_t* destination, int32_t capacity);
PALEXPORT int32_t CryptoNative_RinTlsGetPeerCertificateChainLength(
    void* handle, int32_t* length);
PALEXPORT int32_t CryptoNative_RinTlsCopyPeerCertificateChain(
    void* handle, uint8_t* destination, int32_t capacity);
PALEXPORT int32_t CryptoNative_RinTlsGetPeerRevocationEndpoint(
    void* handle, int32_t source, uint8_t* destination, int32_t capacity,
    int32_t* length);
PALEXPORT int32_t CryptoNative_RinTlsGetPeerRevocationEndpointAt(
    void* handle, int32_t certificate_index, int32_t source,
    uint8_t* destination, int32_t capacity, int32_t* length);
PALEXPORT int32_t CryptoNative_RinTlsVerifyPeerRevocation(
    void* handle, int32_t source, const uint8_t* response,
    int32_t response_length, uint64_t sequence, uint64_t trusted_unix_time,
    int32_t* status);
PALEXPORT int32_t CryptoNative_RinTlsVerifyPeerRevocationAt(
    void* handle, int32_t certificate_index, int32_t source,
    const uint8_t* response, int32_t response_length, uint64_t sequence,
    uint64_t trusted_unix_time, int32_t* status);
PALEXPORT int32_t CryptoNative_RinOSX509GetRevocationEndpoint(
    const uint8_t* certificate_der, int32_t certificate_length,
    int32_t source, uint8_t* destination, int32_t capacity, int32_t* length);
PALEXPORT int32_t CryptoNative_RinOSX509VerifyRevocation(
    const uint8_t* certificate_der, int32_t certificate_length,
    const uint8_t* issuer_der, int32_t issuer_length, int32_t source,
    const uint8_t* response, int32_t response_length,
    uint64_t trusted_unix_time, uint64_t sequence, int32_t* status);
PALEXPORT int32_t CryptoNative_RinOSX509LookupRevocation(
    const uint8_t* certificate_der, int32_t certificate_length,
    const uint8_t* issuer_der, int32_t issuer_length,
    uint64_t trusted_unix_time, int32_t* status);

#ifdef __cplusplus
}
#endif

#endif /* RINOS_CRYPTO_ADAPTER_H */
