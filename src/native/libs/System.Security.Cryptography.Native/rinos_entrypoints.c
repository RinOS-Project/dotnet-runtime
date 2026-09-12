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

void* CryptoNative_RinTlsCreate(int32_t is_server, const char* hostname,
                                uint32_t options, uint64_t trusted_time,
                                int32_t* error);
void CryptoNative_RinTlsDestroy(void* handle);
int32_t CryptoNative_RinTlsLoadTrustStore(void* handle,
                                          const uint8_t* bundle,
                                          int32_t bundle_length);
int32_t CryptoNative_RinTlsHandshake(void* handle, const uint8_t* input,
                                     int32_t input_length, int32_t* consumed);
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
    DllImportEntry(CryptoNative_RinTlsCreate)
    DllImportEntry(CryptoNative_RinTlsDestroy)
    DllImportEntry(CryptoNative_RinTlsLoadTrustStore)
    DllImportEntry(CryptoNative_RinTlsHandshake)
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
