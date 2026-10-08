// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*
 * RinOS deliberately has no host GSSAPI/Kerberos dependency.  TLS is owned
 * by the product RinTLS adapter; this PAL is the native boundary for the
 * product Negotiate/Kerberos/NTLM provider.  The RinOS target also links the
 * process-local Kerberos owner client below the PAL, while the RFC 4120/4121
 * token provider remains a separate capability.  Keep every exported entry
 * point present so the managed interop surface resolves deterministically,
 * then report unsupported status without dereferencing caller-owned handles.
 */

#include "pal_gssapi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/auth_provider_abi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_credential_owner_abi.h"
#include "../../../../../../public-base/RinOS-SDK/include/rin/net/kerberos_operation_owner_abi.h"

#include <stdint.h>

#define RINOS_GSS_S_COMPLETE ((uint32_t)0u)
#define RINOS_GSS_S_UNAVAILABLE ((uint32_t)(16u << 16))

#if defined(__GNUC__) || defined(__clang__)
#define RINOS_AUTH_PROVIDER_WEAK __attribute__((weak))
#else
#define RINOS_AUTH_PROVIDER_WEAK
#endif

#if defined(RINOS_AUTH_PROVIDER_LINKED)
extern const RinAuthProviderV1* rin_auth_provider_get_v1(void);
#else
extern const RinAuthProviderV1* rin_auth_provider_get_v1(void)
    RINOS_AUTH_PROVIDER_WEAK;
#endif

#if defined(RINOS_KERBEROS_OWNER_LINKED)
/* The target static archive must retain the owner object: a strong reference
 * from the PAL makes the archive linker extract it when the PAL is selected.
 * Host contract builds intentionally omit this definition and use the weak
 * boundary below so the PAL remains independently testable. */
extern const RinKerberosCredentialOwnerV1*
    rin_kerberos_credential_owner_get_v1(void);
extern const RinKerberosOperationOwnerV1*
    rin_kerberos_operation_owner_get_v1(void);
#else
extern const RinKerberosCredentialOwnerV1*
    rin_kerberos_credential_owner_get_v1(void) RINOS_AUTH_PROVIDER_WEAK;
extern const RinKerberosOperationOwnerV1*
    rin_kerberos_operation_owner_get_v1(void) RINOS_AUTH_PROVIDER_WEAK;
#endif

static int rinos_gss_kerberos_owner_valid(const RinAuthProviderV1* provider)
{
    const RinKerberosCredentialOwnerV1* owner;
    const RinKerberosOperationOwnerV1* operation_owner;

    if ((provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_KERBEROS) == 0u)
    {
        return 1;
    }

    /* A Kerberos capability without both real default-credential owners is
     * an invalid advertisement.  In particular, the PAL must not turn a
     * provider-local success stub into DefaultCredentials. */
#if !defined(RINOS_KERBEROS_OWNER_LINKED)
    if (rin_kerberos_credential_owner_get_v1 == NULL)
    {
        return 0;
    }
#endif

    owner = rin_kerberos_credential_owner_get_v1();
    operation_owner = rin_kerberos_operation_owner_get_v1();
    return owner != NULL && operation_owner != NULL &&
        owner->struct_size == sizeof(*owner) &&
        owner->version == RIN_KERBEROS_CREDENTIAL_OWNER_ABI_VERSION &&
        owner->reserved0 == 0u &&
        (owner->capability_mask &
            RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES) ==
            RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES &&
        (owner->capability_mask &
            ~RIN_KERBEROS_CREDENTIAL_OWNER_KNOWN_CAPABILITIES) == 0u &&
        owner->acquire_session_initiator != NULL &&
        owner->acquire_acceptor_keytab != NULL &&
        owner->release_credential != NULL &&
        owner->get_session_principal != NULL &&
        operation_owner->struct_size == sizeof(*operation_owner) &&
        operation_owner->version ==
            RIN_KERBEROS_OPERATION_OWNER_ABI_VERSION &&
        operation_owner->reserved0 == 0u &&
        operation_owner->operation != NULL;
}

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
        ((provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_NTLM) != 0u &&
         (provider->initiate_cred_with_password == NULL ||
          provider->is_ntlm_installed == NULL)) ||
        provider->get_user == NULL ||
        !rinos_gss_kerberos_owner_valid(provider))
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

static uint32_t rinos_gss_local_error(uint32_t* minorStatus,
                                      uint32_t majorStatus)
{
    if (minorStatus != NULL)
    {
        *minorStatus = 0;
    }

    return majorStatus;
}

static void rinos_gss_clear_buffer(PAL_GssBuffer* outBuffer);

static uint32_t rinos_gss_local_buffer_error(
    const RinAuthProviderV1* provider, uint32_t* minorStatus,
    PAL_GssBuffer* outBuffer, uint32_t majorStatus)
{
    if (provider != NULL && outBuffer != NULL && outBuffer->data != NULL)
    {
        provider->release_buffer(provider->context, outBuffer->data,
                                 outBuffer->length);
    }
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_local_error(minorStatus, majorStatus);
}

static uint32_t rinos_gss_map_provider_status(uint32_t providerStatus)
{
    switch (providerStatus)
    {
        case RIN_AUTH_PROVIDER_OK:
            return RINOS_GSS_S_COMPLETE;
        case RIN_AUTH_PROVIDER_CONTINUE_NEEDED:
            return PAL_GSS_CONTINUE_NEEDED;
        case RIN_AUTH_PROVIDER_CONTEXT_EXPIRED:
            return PAL_GSS_S_CONTEXT_EXPIRED;
        case RIN_AUTH_PROVIDER_BAD_BINDINGS:
            return PAL_GSS_S_BAD_BINDINGS;
        case RIN_AUTH_PROVIDER_DEFECTIVE_TOKEN:
            return PAL_GSS_S_DEFECTIVE_TOKEN;
        case RIN_AUTH_PROVIDER_DEFECTIVE_CREDENTIAL:
            return PAL_GSS_S_DEFECTIVE_CREDENTIAL;
        case RIN_AUTH_PROVIDER_CREDENTIALS_EXPIRED:
            return PAL_GSS_S_CREDENTIALS_EXPIRED;
        case RIN_AUTH_PROVIDER_KRB_ERROR:
            /* A standards-shaped KRB-ERROR is a mechanism protocol failure,
             * not a malformed GSS input token.  Preserve its output token
             * while exposing RFC 2743 GSS_S_FAILURE to the caller. */
            return PAL_GSS_S_FAILURE;
        case RIN_AUTH_PROVIDER_UNAVAILABLE:
        case RIN_AUTH_PROVIDER_ABI_MISMATCH:
        default:
            /* Never leak provider-local status values into the GSS ABI. */
            return RINOS_GSS_S_UNAVAILABLE;
    }
}

/* The Kerberos provider preserves RFC 4120 AP error codes in the high-bit
 * minor-status namespace.  Do not infer a GSS supplementary status from an
 * arbitrary provider-local value: only the standards-defined replay error
 * is admitted here. */
static uint32_t rinos_gss_map_kerberos_supplementary(
    uint32_t providerStatus, const uint32_t* minorStatus)
{
    const uint32_t protocolErrorBit = UINT32_C(0x80000000);
    const uint32_t krbApErrRepeat = UINT32_C(34);
    uint32_t errorCode;

    if (providerStatus != RIN_AUTH_PROVIDER_KRB_ERROR ||
        minorStatus == NULL || (*minorStatus & protocolErrorBit) == 0u)
        return 0u;
    errorCode = *minorStatus & ~protocolErrorBit;
    return errorCode == krbApErrRepeat ? PAL_GSS_S_DUPLICATE_TOKEN : 0u;
}

/* MIT krb5 treats an expired service ticket returned during initiator
 * establishment as an expired credential (see its init_sec_context path).
 * Preserve that standards-shaped classification at the PAL boundary while
 * leaving the other KRB-ERROR values as mechanism failure until their
 * direction-specific GSS mapping is implemented. */
static uint32_t rinos_gss_map_kerberos_major(
    uint32_t providerStatus, const uint32_t* minorStatus)
{
    const uint32_t protocolErrorBit = UINT32_C(0x80000000);
    const uint32_t krbApErrTicketExpired = UINT32_C(32);

    if (providerStatus == RIN_AUTH_PROVIDER_KRB_ERROR &&
        minorStatus != NULL && (*minorStatus & protocolErrorBit) != 0u &&
        (*minorStatus & ~protocolErrorBit) == krbApErrTicketExpired)
        return PAL_GSS_S_CREDENTIALS_EXPIRED;

    return rinos_gss_map_provider_status(providerStatus);
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

static int rinos_gss_valid_input_buffer(const void* data, uint64_t length)
{
    return length == 0u || data != NULL;
}

static int rinos_gss_valid_channel_binding(const void* data, int32_t length)
{
    return length >= 0 && (length == 0 || data != NULL);
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
    uint32_t mappedStatus = rinos_gss_map_kerberos_major(status, minorStatus);
    mappedStatus |= rinos_gss_map_kerberos_supplementary(status, minorStatus);
    const int preserve_error_token = status == RIN_AUTH_PROVIDER_KRB_ERROR;

    if (mappedStatus != RINOS_GSS_S_COMPLETE &&
        mappedStatus != PAL_GSS_CONTINUE_NEEDED && !preserve_error_token)
    {
        if (outBuffer != NULL && outBuffer->data != NULL)
        {
            provider->release_buffer(provider->context,
                                     outBuffer->data, outBuffer->length);
        }
        rinos_gss_clear_buffer(outBuffer);
        return rinos_gss_local_error(minorStatus, mappedStatus);
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

typedef uint32_t (*RinAuthProviderReleaseHandleCallback)(
    void* context, uint32_t* minor_status, void** input);

static uint32_t rinos_gss_finish_provider_handle(
    const RinAuthProviderV1* provider, uint32_t* minorStatus,
    uint32_t status, void** outputHandle,
    RinAuthProviderReleaseHandleCallback release)
{
    uint32_t mappedStatus = rinos_gss_map_kerberos_major(status, minorStatus);

    /* A failed acquire must never leak a provider-owned opaque handle into
     * the SafeHandle marshaller. A successful acquire without a handle is
     * equally invalid and is treated as provider unavailability. */
    if (mappedStatus != RINOS_GSS_S_COMPLETE ||
        outputHandle == NULL || *outputHandle == NULL)
    {
        if (provider != NULL && outputHandle != NULL &&
            *outputHandle != NULL && release != NULL)
        {
            /* A failing acquire/import callback may have allocated an opaque
             * provider object before returning its status.  Return that
             * object through the matching provider owner before hiding the
             * handle from the SafeHandle marshaller. */
            (void)release(provider->context, minorStatus, outputHandle);
        }
        if (outputHandle != NULL)
        {
            *outputHandle = NULL;
        }
        return mappedStatus;
    }

    return mappedStatus;
}

static uint32_t rinos_gss_finish_provider_context(
    const RinAuthProviderV1* provider, uint32_t* minorStatus,
    uint32_t status, GssCtxId** contextHandle, uint32_t* retFlags,
    int32_t* isNtlmUsed, PAL_GssBuffer* outBuffer,
    RinAuthProviderReleaseHandleCallback release)
{
    uint32_t mappedStatus = rinos_gss_finish_provider_buffer(
        provider, minorStatus, status, outBuffer);
    const uint32_t savedMinorStatus =
        minorStatus != NULL ? *minorStatus : 0u;

    /* GSS-API returns a context handle on both COMPLETE and CONTINUE_NEEDED.
     * A provider that reports success without one cannot make progress on a
     * subsequent token exchange. Do not publish its output token as a
     * successful authentication step; release it and fail closed instead. */
    if ((mappedStatus == RINOS_GSS_S_COMPLETE ||
         mappedStatus == PAL_GSS_CONTINUE_NEEDED) &&
        (contextHandle == NULL || *contextHandle == NULL))
    {
        if (outBuffer != NULL && outBuffer->data != NULL)
        {
            provider->release_buffer(provider->context,
                                     outBuffer->data, outBuffer->length);
        }
        rinos_gss_clear_buffer(outBuffer);
        if (retFlags != NULL)
        {
            *retFlags = 0;
        }
        if (isNtlmUsed != NULL)
        {
            *isNtlmUsed = 0;
        }
        return rinos_gss_unavailable(minorStatus);
    }

    /* A provider must not leave a failed security-context handle or status
     * flags reachable through the managed SafeHandle path.  This is the
     * context analogue of rinos_gss_finish_provider_handle: provider-owned
     * output is failure-atomic even when a buggy provider filled it before
     * returning UNAVAILABLE or an unknown local status. */
    if (mappedStatus != RINOS_GSS_S_COMPLETE &&
        mappedStatus != PAL_GSS_CONTINUE_NEEDED)
    {
        if (provider != NULL && contextHandle != NULL &&
            *contextHandle != NULL && release != NULL)
        {
            /* A provider can allocate a context before reporting failure.
             * Release that provider-owned object before hiding it from the
             * managed SafeHandle path. */
            (void)release(provider->context, minorStatus,
                          (void**)contextHandle);
        }
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
        /* Context teardown can overwrite minorStatus while releasing the
         * provider handle. Preserve the original mechanism error details. */
        if (minorStatus != NULL) *minorStatus = savedMinorStatus;
    }

    return mappedStatus;
}

static uint32_t rinos_gss_release_provider_handle(
    const RinAuthProviderV1* provider, uint32_t* minorStatus, void** input,
    RinAuthProviderReleaseHandleCallback release)
{
    uint32_t status;

    if (input == NULL || release == NULL)
    {
        return rinos_gss_unavailable(minorStatus);
    }

    /* Releasing an absent GSS object is a successful no-op.  Do not ask a
     * provider to interpret a NULL object: this is PAL-owned lifetime state,
     * not a provider operation. */
    if (*input == NULL)
    {
        return rinos_gss_complete(minorStatus);
    }

    status = release(provider->context, minorStatus, input);

    /* Provider callbacks receive the address so they can release their
     * opaque object. The PAL owns the ABI-visible pointer lifetime: clear it
     * even when the provider reports an error or forgets to consume it, so a
     * failed cleanup can never be retried through a stale handle. */
    *input = NULL;
    return rinos_gss_map_provider_status(status);
}

static uint32_t rinos_gss_release_status(uint32_t* minorStatus, int32_t hadHandle)
{
    return hadHandle ? rinos_gss_unavailable(minorStatus) : rinos_gss_complete(minorStatus);
}

PALEXPORT void NetSecurityNative_ReleaseGssBuffer(void* buffer, uint64_t length)
{
    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL && buffer != NULL)
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
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
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
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
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
    /* The provider callback writes an opaque handle through this pointer. Do
     * not call into product code when the managed/native caller supplied no
     * writable result location. */
    if (outputName == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (!rinos_gss_valid_input_buffer(inputName, inputNameLen))
    {
        *outputName = NULL;
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        *outputName = NULL;
        return rinos_gss_finish_provider_handle(provider, minorStatus,
            provider->import_user_name(
            provider->context, minorStatus, inputName, inputNameLen,
                (void**)outputName), (void**)outputName,
            provider->release_name);
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
    if (outputName == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (!rinos_gss_valid_input_buffer(inputName, inputNameLen))
    {
        *outputName = NULL;
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        *outputName = NULL;
        return rinos_gss_finish_provider_handle(provider, minorStatus,
            provider->import_principal_name(
            provider->context, minorStatus, inputName, inputNameLen,
                (void**)outputName), (void**)outputName,
            provider->release_name);
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
    if (inputName == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_release_provider_handle(
            provider, minorStatus, (void**)inputName, provider->release_name);
    }

    int32_t hadHandle;
    hadHandle = *inputName != NULL;
    *inputName = NULL;
    return rinos_gss_release_status(minorStatus, hadHandle);
}

PALEXPORT uint32_t NetSecurityNative_AcquireAcceptorCred(uint32_t* minorStatus, GssCredId** outputCredHandle)
{
    if (outputCredHandle == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        *outputCredHandle = NULL;
        return rinos_gss_finish_provider_handle(provider, minorStatus,
            provider->acquire_acceptor_cred(
                provider->context, minorStatus, (void**)outputCredHandle),
            (void**)outputCredHandle, provider->release_cred);
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
    if (outputCredHandle == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL &&
        (provider->package_mask & RIN_AUTH_PROVIDER_PACKAGE_NEGOTIATE) != 0u)
    {
        *outputCredHandle = NULL;
        return rinos_gss_finish_provider_handle(provider, minorStatus,
            provider->initiate_cred_spnego(
                provider->context, minorStatus, desiredName,
                (void**)outputCredHandle), (void**)outputCredHandle,
            provider->release_cred);
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
    if (credHandle == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL)
    {
        return rinos_gss_release_provider_handle(
            provider, minorStatus, (void**)credHandle, provider->release_cred);
    }

    int32_t hadHandle;
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (retFlags != NULL)
    {
        *retFlags = 0;
    }
    if (isNtlmUsed != NULL)
    {
        *isNtlmUsed = 0;
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, inputLength))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (targetName == NULL)
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_NAME);
    }
    if (provider != NULL &&
        !rinos_gss_supports_package(provider, packageType))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_MECH);
    }
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_context(provider, minorStatus,
            provider->init_sec_context(
            provider->context, minorStatus, claimantCredHandle,
            (void**)contextHandle, packageType, targetName, reqFlags,
            inputBytes, inputLength, (RinAuthProviderBufferV1*)outBuffer,
                retFlags, isNtlmUsed), contextHandle, retFlags,
            isNtlmUsed, outBuffer, provider->delete_sec_context);
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (retFlags != NULL)
    {
        *retFlags = 0;
    }
    if (isNtlmUsed != NULL)
    {
        *isNtlmUsed = 0;
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, inputLength))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (!rinos_gss_valid_channel_binding(cbt, cbtSize))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_BINDINGS);
    }
    if (targetName == NULL)
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_NAME);
    }
    if (provider != NULL &&
        !rinos_gss_supports_package(provider, packageType))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_MECH);
    }
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_context(provider, minorStatus,
            provider->init_sec_context_ex(
            provider->context, minorStatus, claimantCredHandle,
            (void**)contextHandle, packageType, cbt, cbtSize, targetName,
            reqFlags, inputBytes, inputLength,
                (RinAuthProviderBufferV1*)outBuffer, retFlags, isNtlmUsed),
            contextHandle, retFlags, isNtlmUsed, outBuffer,
            provider->delete_sec_context);
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, inputLength))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
    if (!rinos_gss_valid_channel_binding(cbt, cbtSize))
    {
        *contextHandle = NULL;
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_BINDINGS);
    }
    if (retFlags != NULL)
    {
        *retFlags = 0;
    }
    if (isNtlmUsed != NULL)
    {
        *isNtlmUsed = 0;
    }
    if (provider != NULL)
    {
        if (!rinos_gss_prepare_provider_buffer(provider, outBuffer))
        {
            return rinos_gss_unavailable(minorStatus);
        }
        return rinos_gss_finish_provider_context(provider, minorStatus,
            provider->accept_sec_context(
            provider->context, minorStatus, acceptorCredHandle,
            (void**)contextHandle, cbt, cbtSize, inputBytes, inputLength,
            (RinAuthProviderBufferV1*)outBuffer, retFlags, isNtlmUsed),
            contextHandle, retFlags, isNtlmUsed, outBuffer,
            provider->delete_sec_context);
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (provider != NULL)
    {
        return rinos_gss_release_provider_handle(
            provider, minorStatus, (void**)contextHandle,
            provider->delete_sec_context);
    }

    int32_t hadHandle;
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_NO_CONTEXT);
    }
    if (isEncrypt == NULL || outBuffer == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (count < 0)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_STRUCTURE);
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, (uint64_t)count))
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_NO_CONTEXT);
    }
    if (isEncrypt == NULL || outBuffer == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (count < 0)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_STRUCTURE);
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, (uint64_t)count))
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_NO_CONTEXT);
    }
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
    if (inputLength < 0)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_BAD_STRUCTURE);
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, (uint64_t)inputLength))
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer,
            PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_error(minorStatus, PAL_GSS_S_NO_CONTEXT);
    }
    if (inputLength < 0 || tokenLength < 0)
    {
        return rinos_gss_local_error(minorStatus, PAL_GSS_S_BAD_STRUCTURE);
    }
    if (!rinos_gss_valid_input_buffer(inputBytes, (uint64_t)inputLength) ||
        !rinos_gss_valid_input_buffer(tokenBytes, (uint64_t)tokenLength))
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }
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
    /* A provider must never receive a non-empty password with no backing
     * address.  This is the password analogue of the token/name input guards
     * above: the provider owns the actual credential acquisition, while the
     * PAL owns the native pointer/length safety boundary. */
    if (outputCredHandle == NULL ||
        !rinos_gss_valid_input_buffer(password, passwdLen))
    {
        if (outputCredHandle != NULL)
        {
            *outputCredHandle = NULL;
        }
        return rinos_gss_local_error(
            minorStatus, outputCredHandle == NULL
                ? PAL_GSS_S_CALL_INACCESSIBLE_WRITE
                : PAL_GSS_S_CALL_INACCESSIBLE_READ);
    }

    const RinAuthProviderV1* provider = rinos_gss_provider();
    if (provider != NULL &&
        !rinos_gss_supports_package(provider, (uint32_t)packageType))
    {
        *outputCredHandle = NULL;
        return rinos_gss_local_error(minorStatus, PAL_GSS_S_BAD_MECH);
    }
    if (provider != NULL &&
        provider->initiate_cred_with_password != NULL)
    {
        *outputCredHandle = NULL;
        return rinos_gss_finish_provider_handle(provider, minorStatus,
            provider->initiate_cred_with_password(
                provider->context, minorStatus, packageType, desiredName,
                password, passwdLen, (void**)outputCredHandle),
            (void**)outputCredHandle, provider->release_cred);
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
        (provider->is_ntlm_installed != NULL) &&
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
    if (contextHandle == NULL)
    {
        return rinos_gss_local_buffer_error(
            provider, minorStatus, outBuffer, PAL_GSS_S_NO_CONTEXT);
    }
    if (outBuffer == NULL)
    {
        return rinos_gss_local_error(
            minorStatus, PAL_GSS_S_CALL_INACCESSIBLE_WRITE);
    }
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
