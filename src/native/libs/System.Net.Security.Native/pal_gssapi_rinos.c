// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS deliberately has no host GSSAPI/Kerberos dependency.  TLS is owned
 * by the product RinTLS adapter; this PAL is only the native boundary for
 * Negotiate/Kerberos/NTLM.  Keep every exported entry point present so the
 * managed interop surface resolves deterministically, then report the
 * product's unsupported status without dereferencing caller-owned handles.
 */

#include "pal_gssapi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/auth_provider_abi.h"

#include <stdint.h>

#define RINOS_GSS_S_COMPLETE ((uint32_t)0u)
#define RINOS_GSS_S_UNAVAILABLE ((uint32_t)(16u << 16))

#if defined(__GNUC__) || defined(__clang__)
#define RINOS_AUTH_PROVIDER_WEAK __attribute__((weak))
#else
#define RINOS_AUTH_PROVIDER_WEAK
#endif

extern const RinAuthProviderV1* rin_auth_provider_get_v1(void)
    RINOS_AUTH_PROVIDER_WEAK;

static const RinAuthProviderV1* rinos_gss_provider(void)
{
    const RinAuthProviderV1* provider;
    if (rin_auth_provider_get_v1 == NULL)
    {
        return NULL;
    }

    provider = rin_auth_provider_get_v1();
    if (provider == NULL ||
        provider->struct_size != sizeof(*provider) ||
        provider->version != RIN_AUTH_PROVIDER_ABI_VERSION ||
        provider->reserved0 != 0u ||
        (provider->package_mask & RIN_AUTH_PROVIDER_KNOWN_PACKAGES) == 0u ||
        (provider->package_mask & ~RIN_AUTH_PROVIDER_KNOWN_PACKAGES) != 0u ||
        provider->max_token_size == 0u ||
        provider->max_token_size > RIN_AUTH_PROVIDER_MAX_TOKEN_SIZE ||
        provider->release_buffer == NULL ||
        provider->display_minor_status == NULL ||
        provider->display_major_status == NULL ||
        provider->import_user_name == NULL ||
        provider->import_principal_name == NULL ||
        provider->release_name == NULL ||
        provider->acquire_acceptor_cred == NULL ||
        provider->initiate_cred_spnego == NULL ||
        provider->release_cred == NULL ||
        provider->init_sec_context == NULL ||
        provider->init_sec_context_ex == NULL ||
        provider->accept_sec_context == NULL ||
        provider->delete_sec_context == NULL ||
        provider->wrap == NULL ||
        provider->unwrap == NULL ||
        provider->get_mic == NULL ||
        provider->verify_mic == NULL ||
        provider->initiate_cred_with_password == NULL ||
        provider->is_ntlm_installed == NULL ||
        provider->get_user == NULL)
    {
        return NULL;
    }

    return provider;
}

static uint32_t rinos_gss_complete(uint32_t* minorStatus)
{
    if (minorStatus != NULL)
    {
        *minorStatus = 0;
    }

    return RINOS_GSS_S_COMPLETE;
}

static uint32_t rinos_gss_unavailable(uint32_t* minorStatus)
{
    if (minorStatus != NULL)
    {
        *minorStatus = 0;
    }

    return RINOS_GSS_S_UNAVAILABLE;
}

static uint32_t rinos_gss_map_provider_status(uint32_t providerStatus)
{
    switch (providerStatus)
    {
        case RIN_AUTH_PROVIDER_OK:
            return RINOS_GSS_S_COMPLETE;
        case RIN_AUTH_PROVIDER_CONTINUE_NEEDED:
            return PAL_GSS_CONTINUE_NEEDED;
        case RIN_AUTH_PROVIDER_UNAVAILABLE:
        case RIN_AUTH_PROVIDER_ABI_MISMATCH:
        default:
            /* Never leak provider-local status values into the GSS ABI. */
            return RINOS_GSS_S_UNAVAILABLE;
    }
}

static uint32_t rinos_gss_package_bit(uint32_t packageType)
{
    switch (packageType)
    {
        case PAL_GSS_NEGOTIATE:
            return RIN_AUTH_PROVIDER_PACKAGE_NEGOTIATE;
        case PAL_GSS_NTLM:
            return RIN_AUTH_PROVIDER_PACKAGE_NTLM;
        case PAL_GSS_KERBEROS:
            return RIN_AUTH_PROVIDER_PACKAGE_KERBEROS;
        default:
            return 0u;
    }
}

static int rinos_gss_supports_package(const RinAuthProviderV1* provider,
                                      uint32_t packageType)
{
    uint32_t packageBit = rinos_gss_package_bit(packageType);
    return packageBit != 0u && (provider->package_mask & packageBit) != 0u;
}

static void rinos_gss_clear_buffer(PAL_GssBuffer* outBuffer)
{
    if (outBuffer != NULL)
    {
        outBuffer->length = 0;
        outBuffer->data = NULL;
    }
}

static int rinos_gss_prepare_provider_buffer(
    const RinAuthProviderV1* provider, PAL_GssBuffer* outBuffer)
{
    if (outBuffer == NULL)
    {
        return 0;
    }

    if (outBuffer->data != NULL)
    {
        provider->release_buffer(provider->context,
                                 outBuffer->data, outBuffer->length);
    }
    rinos_gss_clear_buffer(outBuffer);
    return 1;
}

static uint32_t rinos_gss_finish_provider_buffer(
    const RinAuthProviderV1* provider, uint32_t* minorStatus,
    uint32_t status, PAL_GssBuffer* outBuffer)
{
    uint32_t mappedStatus = rinos_gss_map_provider_status(status);

    if (mappedStatus != RINOS_GSS_S_COMPLETE &&
        mappedStatus != PAL_GSS_CONTINUE_NEEDED)
    {
        if (outBuffer != NULL && outBuffer->data != NULL)
        {
            provider->release_buffer(provider->context,
                                     outBuffer->data, outBuffer->length);
        }
        rinos_gss_clear_buffer(outBuffer);
        return rinos_gss_unavailable(minorStatus);
    }

    if (outBuffer == NULL ||
        outBuffer->length > provider->max_token_size ||
        (outBuffer->length != 0u && outBuffer->data == NULL))
    {
        if (outBuffer != NULL && outBuffer->data != NULL)
        {
            provider->release_buffer(provider->context,
                                     outBuffer->data, outBuffer->length);
        }
        rinos_gss_clear_buffer(outBuffer);
        return rinos_gss_unavailable(minorStatus);
    }

    if (minorStatus != NULL && mappedStatus == RINOS_GSS_S_COMPLETE)
    {
        *minorStatus = 0;
    }

    return mappedStatus;
}

static uint32_t rinos_gss_release_status(uint32_t* minorStatus, int32_t hadHandle)
{
    return hadHandle ? rinos_gss_unavailable(minorStatus) : rinos_gss_complete(minorStatus);
}

PALEXPORT void NetSecurityNative_ReleaseGssBuffer(void* buffer, uint64_t length)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        provider->release_buffer(provider->context, buffer, length);
        return;
    }

    (void)buffer;
    (void)length;
}

PALEXPORT uint32_t NetSecurityNative_DisplayMinorStatus(
    uint32_t* minorStatus, uint32_t statusValue, PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->display_minor_status(
            provider->context, minorStatus, statusValue,
            (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)statusValue;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_DisplayMajorStatus(
    uint32_t* minorStatus, uint32_t statusValue, PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->display_major_status(
            provider->context, minorStatus, statusValue,
            (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)statusValue;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ImportUserName(
    uint32_t* minorStatus, char* inputName, uint32_t inputNameLen, GssName** outputName)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->import_user_name(
            provider->context, minorStatus, inputName, inputNameLen,
            (void**)outputName));
    }

    (void)inputName;
    (void)inputNameLen;
    if (outputName != NULL)
    {
        *outputName = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ImportPrincipalName(
    uint32_t* minorStatus, char* inputName, uint32_t inputNameLen, GssName** outputName)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->import_principal_name(
            provider->context, minorStatus, inputName, inputNameLen,
            (void**)outputName));
    }

    (void)inputName;
    (void)inputNameLen;
    if (outputName != NULL)
    {
        *outputName = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ReleaseName(uint32_t* minorStatus, GssName** inputName)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->release_name(
            provider->context, minorStatus, (void**)inputName));
    }

    int32_t hadHandle;
    if (inputName == NULL)
    {
        return rinos_gss_unavailable(minorStatus);
    }

    hadHandle = *inputName != NULL;
    *inputName = NULL;
    return rinos_gss_release_status(minorStatus, hadHandle);
}

PALEXPORT uint32_t NetSecurityNative_AcquireAcceptorCred(uint32_t* minorStatus, GssCredId** outputCredHandle)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->acquire_acceptor_cred(
            provider->context, minorStatus, (void**)outputCredHandle));
    }

    if (outputCredHandle != NULL)
    {
        *outputCredHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_InitiateCredSpNego(
    uint32_t* minorStatus, GssName* desiredName, GssCredId** outputCredHandle)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL &&
        (provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_NEGOTIATE) != 0u)
    {
        return rinos_gss_map_provider_status(provider->initiate_cred_spnego(
            provider->context, minorStatus, desiredName,
            (void**)outputCredHandle));
    }

    (void)desiredName;
    if (outputCredHandle != NULL)
    {
        *outputCredHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ReleaseCred(uint32_t* minorStatus, GssCredId** credHandle)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->release_cred(
            provider->context, minorStatus, (void**)credHandle));
    }

    int32_t hadHandle;
    if (credHandle == NULL)
    {
        return rinos_gss_unavailable(minorStatus);
    }

    hadHandle = *credHandle != NULL;
    *credHandle = NULL;
    return rinos_gss_release_status(minorStatus, hadHandle);
}

PALEXPORT uint32_t NetSecurityNative_InitSecContext(
    uint32_t* minorStatus,
    GssCredId* claimantCredHandle,
    GssCtxId** contextHandle,
    uint32_t packageType,
    GssName* targetName,
    uint32_t reqFlags,
    uint8_t* inputBytes,
    uint32_t inputLength,
    PAL_GssBuffer* outBuffer,
    uint32_t* retFlags,
    int32_t* isNtlmUsed)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL && rinos_gss_supports_package(provider, packageType))
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->init_sec_context(
            provider->context, minorStatus, claimantCredHandle,
            (void**)contextHandle, packageType, targetName, reqFlags,
            inputBytes, inputLength, (RinAuthProviderBufferV1*)outBuffer,
            retFlags, isNtlmUsed), outBuffer);
    }

    (void)claimantCredHandle;
    (void)packageType;
    (void)targetName;
    (void)reqFlags;
    (void)inputBytes;
    (void)inputLength;
    if (contextHandle != NULL)
    {
        *contextHandle = NULL;
    }
    if (retFlags != NULL)
    {
        *retFlags = 0;
    }
    if (isNtlmUsed != NULL)
    {
        *isNtlmUsed = 0;
    }
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_InitSecContextEx(
    uint32_t* minorStatus,
    GssCredId* claimantCredHandle,
    GssCtxId** contextHandle,
    uint32_t packageType,
    void* cbt,
    int32_t cbtSize,
    GssName* targetName,
    uint32_t reqFlags,
    uint8_t* inputBytes,
    uint32_t inputLength,
    PAL_GssBuffer* outBuffer,
    uint32_t* retFlags,
    int32_t* isNtlmUsed)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL && rinos_gss_supports_package(provider, packageType))
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->init_sec_context_ex(
            provider->context, minorStatus, claimantCredHandle,
            (void**)contextHandle, packageType, cbt, cbtSize, targetName,
            reqFlags, inputBytes, inputLength,
            (RinAuthProviderBufferV1*)outBuffer, retFlags, isNtlmUsed), outBuffer);
    }

    (void)cbt;
    (void)cbtSize;
    return NetSecurityNative_InitSecContext(
        minorStatus,
        claimantCredHandle,
        contextHandle,
        packageType,
        targetName,
        reqFlags,
        inputBytes,
        inputLength,
        outBuffer,
        retFlags,
        isNtlmUsed);
}

PALEXPORT uint32_t NetSecurityNative_AcceptSecContext(
    uint32_t* minorStatus,
    GssCredId* acceptorCredHandle,
    GssCtxId** contextHandle,
    void* cbt,
    int32_t cbtSize,
    uint8_t* inputBytes,
    uint32_t inputLength,
    PAL_GssBuffer* outBuffer,
    uint32_t* retFlags,
    int32_t* isNtlmUsed)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->accept_sec_context(
            provider->context, minorStatus, acceptorCredHandle,
            (void**)contextHandle, cbt, cbtSize, inputBytes, inputLength,
            (RinAuthProviderBufferV1*)outBuffer, retFlags, isNtlmUsed), outBuffer);
    }

    (void)acceptorCredHandle;
    (void)cbt;
    (void)cbtSize;
    (void)inputBytes;
    (void)inputLength;
    if (contextHandle != NULL)
    {
        *contextHandle = NULL;
    }
    if (retFlags != NULL)
    {
        *retFlags = 0;
    }
    if (isNtlmUsed != NULL)
    {
        *isNtlmUsed = 0;
    }
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_DeleteSecContext(uint32_t* minorStatus, GssCtxId** contextHandle)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->delete_sec_context(
            provider->context, minorStatus, (void**)contextHandle));
    }

    int32_t hadHandle;
    if (contextHandle == NULL)
    {
        return rinos_gss_unavailable(minorStatus);
    }

    hadHandle = *contextHandle != NULL;
    *contextHandle = NULL;
    return rinos_gss_release_status(minorStatus, hadHandle);
}

PALEXPORT uint32_t NetSecurityNative_Wrap(
    uint32_t* minorStatus,
    GssCtxId* contextHandle,
    int32_t* isEncrypt,
    uint8_t* inputBytes,
    int32_t count,
    PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->wrap(
            provider->context, minorStatus, contextHandle, isEncrypt,
            inputBytes, count, (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)contextHandle;
    (void)isEncrypt;
    (void)inputBytes;
    (void)count;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_Unwrap(
    uint32_t* minorStatus,
    GssCtxId* contextHandle,
    int32_t* isEncrypt,
    uint8_t* inputBytes,
    int32_t count,
    PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->unwrap(
            provider->context, minorStatus, contextHandle, isEncrypt,
            inputBytes, count, (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)contextHandle;
    (void)isEncrypt;
    (void)inputBytes;
    (void)count;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_GetMic(
    uint32_t* minorStatus,
    GssCtxId* contextHandle,
    uint8_t* inputBytes,
    int32_t inputLength,
    PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->get_mic(
            provider->context, minorStatus, contextHandle, inputBytes,
            inputLength, (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)contextHandle;
    (void)inputBytes;
    (void)inputLength;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_VerifyMic(
    uint32_t* minorStatus,
    GssCtxId* contextHandle,
    uint8_t* inputBytes,
    int32_t inputLength,
    uint8_t* tokenBytes,
    int32_t tokenLength)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_map_provider_status(provider->verify_mic(
            provider->context, minorStatus, contextHandle, inputBytes,
            inputLength, tokenBytes, tokenLength));
    }

    (void)contextHandle;
    (void)inputBytes;
    (void)inputLength;
    (void)tokenBytes;
    (void)tokenLength;
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_InitiateCredWithPassword(
    uint32_t* minorStatus,
    int32_t packageType,
    GssName* desiredName,
    char* password,
    uint32_t passwdLen,
    GssCredId** outputCredHandle)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL && rinos_gss_supports_package(provider, (uint32_t)packageType))
    {
        return rinos_gss_map_provider_status(provider->initiate_cred_with_password(
            provider->context, minorStatus, packageType, desiredName,
            password, passwdLen, (void**)outputCredHandle));
    }

    (void)packageType;
    (void)desiredName;
    (void)password;
    (void)passwdLen;
    if (outputCredHandle != NULL)
    {
        *outputCredHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_IsNtlmInstalled(void)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL &&
        (provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_NTLM) != 0u)
    {
        return provider->is_ntlm_installed(provider->context);
    }

    return 0;
}

PALEXPORT uint32_t NetSecurityNative_IsKerberosInstalled(void)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    return provider != NULL &&
        (provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_KERBEROS) != 0u;
}

PALEXPORT uint32_t NetSecurityNative_GetUser(
    uint32_t* minorStatus, GssCtxId* contextHandle, PAL_GssBuffer* outBuffer)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_buffer(provider, minorStatus,
            provider->get_user(
            provider->context, minorStatus, contextHandle,
            (RinAuthProviderBufferV1*)outBuffer), outBuffer);
    }

    (void)contextHandle;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT int32_t NetSecurityNative_EnsureGssInitialized(void)
{
    if (rinos_gss_provider() == NULL)
    {
        return -1;
    }

    return 0;
}
