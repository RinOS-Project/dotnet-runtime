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
};

EXTERN_C const void* CryptoResolveDllImport(const char* name);

EXTERN_C const void* CryptoResolveDllImport(const char* name)
{
    return minipal_resolve_dllimport(s_cryptoNative, ARRAY_SIZE(s_cryptoNative), name);
}
