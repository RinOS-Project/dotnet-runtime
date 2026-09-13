// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <stdint.h>

#include "../Common/pal_compiler.h"
#include <minipal/entrypoints.h>

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

void* CryptoNative_RinOSRsaCreate(void);
int32_t CryptoNative_RinOSRsaGenerateKey(void* handle, int32_t key_size,
                                         int32_t public_exponent);
int32_t CryptoNative_RinOSRsaImportParameters(
    void* handle, const uint8_t* modulus, int32_t modulus_length,
    const uint8_t* exponent, int32_t exponent_length,
    const uint8_t* private_exponent, int32_t private_exponent_length,
    const uint8_t* prime1, int32_t prime1_length,
    const uint8_t* prime2, int32_t prime2_length,
    const uint8_t* exponent1, int32_t exponent1_length,
    const uint8_t* exponent2, int32_t exponent2_length,
    const uint8_t* coefficient, int32_t coefficient_length);
int32_t CryptoNative_RinOSRsaGetKeySize(const void* handle);
int32_t CryptoNative_RinOSRsaExportParameters(
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
int32_t CryptoNative_RinOSRsaEncrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length);
int32_t CryptoNative_RinOSRsaDecrypt(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* input, int32_t input_length, uint8_t* output,
    int32_t output_capacity, int32_t* output_length);
int32_t CryptoNative_RinOSRsaSignHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    uint8_t* signature, int32_t signature_capacity, int32_t* signature_length);
int32_t CryptoNative_RinOSRsaVerifyHash(
    const void* handle, int32_t padding, int32_t hash_algorithm,
    const uint8_t* hash, int32_t hash_length, int32_t salt_length,
    const uint8_t* signature, int32_t signature_length);
void CryptoNative_RinOSRsaDestroy(void* handle);

void* CryptoNative_RinTlsCreate(int32_t is_server, const char* hostname,
                                uint32_t options, uint64_t trusted_time,
                                int32_t* error);
void CryptoNative_RinTlsDestroy(void* handle);
int32_t CryptoNative_RinTlsLoadTrustStore(void* handle,
                                          const uint8_t* bundle,
                                          int32_t bundle_length);
int32_t CryptoNative_RinTlsHandshake(void* handle, const uint8_t* input,
                                     int32_t input_length, int32_t* consumed);
int32_t CryptoNative_RinTlsSetClientCertificate(
    void* handle, const uint8_t* certificate_list, int32_t certificate_list_length,
    void* signer, void* signer_opaque);
int32_t CryptoNative_RinTlsClientCertificateRequested(void* handle);
int32_t CryptoNative_RinTlsPendingOutputLength(void* handle);
int32_t CryptoNative_RinTlsReadOutput(void* handle, uint8_t* destination,
                                      int32_t capacity);
int32_t CryptoNative_RinTlsEncrypt(void* handle, const uint8_t* plaintext,
                                   int32_t plaintext_length, int32_t* consumed);
int32_t CryptoNative_RinTlsDecrypt(void* handle, const uint8_t* encrypted,
                                   int32_t encrypted_length, uint8_t* plaintext,
                                   int32_t plaintext_capacity, int32_t* consumed,
                                   int32_t* written);
int32_t CryptoNative_RinTlsShutdown(void* handle);
int32_t CryptoNative_RinTlsIsClosed(void* handle);
int32_t CryptoNative_RinTlsGetVersion(void* handle);
int32_t CryptoNative_RinTlsGetCipherSuite(void* handle);
int32_t CryptoNative_RinTlsGetError(void* handle);
int32_t CryptoNative_RinTlsGetPeerCertificateLength(void* handle,
                                                    int32_t* length);
int32_t CryptoNative_RinTlsCopyPeerCertificate(void* handle, uint8_t* destination,
                                               int32_t capacity);

static const Entry s_cryptoNative[] =
{
    DllImportEntry(CryptoNative_RinOSHashCreate)
    DllImportEntry(CryptoNative_RinOSHashClone)
    DllImportEntry(CryptoNative_RinOSHashUpdate)
    DllImportEntry(CryptoNative_RinOSHashFinal)
    DllImportEntry(CryptoNative_RinOSHashCurrent)
    DllImportEntry(CryptoNative_RinOSHashReset)
    DllImportEntry(CryptoNative_RinOSHashDestroy)
    DllImportEntry(CryptoNative_RinOSHmacCreate)
    DllImportEntry(CryptoNative_RinOSHmacClone)
    DllImportEntry(CryptoNative_RinOSHmacUpdate)
    DllImportEntry(CryptoNative_RinOSHmacFinal)
    DllImportEntry(CryptoNative_RinOSHmacCurrent)
    DllImportEntry(CryptoNative_RinOSHmacReset)
    DllImportEntry(CryptoNative_RinOSHmacDestroy)
    DllImportEntry(CryptoNative_GetRandomBytes)
    DllImportEntry(CryptoNative_RinOSAesGcmCreate)
    DllImportEntry(CryptoNative_RinOSAesGcmEncrypt)
    DllImportEntry(CryptoNative_RinOSAesGcmDecrypt)
    DllImportEntry(CryptoNative_RinOSAesGcmDestroy)
    DllImportEntry(CryptoNative_RinOSAesCreate)
    DllImportEntry(CryptoNative_RinOSAesTransform)
    DllImportEntry(CryptoNative_RinOSAesReset)
    DllImportEntry(CryptoNative_RinOSAesDestroy)
    DllImportEntry(CryptoNative_RinOSRsaCreate)
    DllImportEntry(CryptoNative_RinOSRsaGenerateKey)
    DllImportEntry(CryptoNative_RinOSRsaImportParameters)
    DllImportEntry(CryptoNative_RinOSRsaGetKeySize)
    DllImportEntry(CryptoNative_RinOSRsaExportParameters)
    DllImportEntry(CryptoNative_RinOSRsaEncrypt)
    DllImportEntry(CryptoNative_RinOSRsaDecrypt)
    DllImportEntry(CryptoNative_RinOSRsaSignHash)
    DllImportEntry(CryptoNative_RinOSRsaVerifyHash)
    DllImportEntry(CryptoNative_RinOSRsaDestroy)
    DllImportEntry(CryptoNative_RinTlsCreate)
    DllImportEntry(CryptoNative_RinTlsDestroy)
    DllImportEntry(CryptoNative_RinTlsLoadTrustStore)
    DllImportEntry(CryptoNative_RinTlsHandshake)
    DllImportEntry(CryptoNative_RinTlsSetClientCertificate)
    DllImportEntry(CryptoNative_RinTlsClientCertificateRequested)
    DllImportEntry(CryptoNative_RinTlsPendingOutputLength)
    DllImportEntry(CryptoNative_RinTlsReadOutput)
    DllImportEntry(CryptoNative_RinTlsEncrypt)
    DllImportEntry(CryptoNative_RinTlsDecrypt)
    DllImportEntry(CryptoNative_RinTlsShutdown)
    DllImportEntry(CryptoNative_RinTlsIsClosed)
    DllImportEntry(CryptoNative_RinTlsGetVersion)
    DllImportEntry(CryptoNative_RinTlsGetCipherSuite)
    DllImportEntry(CryptoNative_RinTlsGetError)
    DllImportEntry(CryptoNative_RinTlsGetPeerCertificateLength)
    DllImportEntry(CryptoNative_RinTlsCopyPeerCertificate)
};

EXTERN_C const void* CryptoResolveDllImport(const char* name);

EXTERN_C const void* CryptoResolveDllImport(const char* name)
{
    return minipal_resolve_dllimport(s_cryptoNative, ARRAY_SIZE(s_cryptoNative), name);
}
