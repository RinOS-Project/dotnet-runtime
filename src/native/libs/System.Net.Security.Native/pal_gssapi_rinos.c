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

#include <stdint.h>

#define RINOS_GSS_S_UNAVAILABLE ((uint32_t)(16u << 16))

static uint32_t rinos_gss_unavailable(uint32_t* minorStatus)
{
    if (minorStatus != NULL)
    {
        *minorStatus = 0;
    }

    return RINOS_GSS_S_UNAVAILABLE;
}

static void rinos_gss_clear_buffer(PAL_GssBuffer* outBuffer)
{
    if (outBuffer != NULL)
    {
        outBuffer->length = 0;
        outBuffer->data = NULL;
    }
}

PALEXPORT void NetSecurityNative_ReleaseGssBuffer(void* buffer, uint64_t length)
{
    (void)buffer;
    (void)length;
}

PALEXPORT uint32_t NetSecurityNative_DisplayMinorStatus(
    uint32_t* minorStatus, uint32_t statusValue, PAL_GssBuffer* outBuffer)
{
    (void)statusValue;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_DisplayMajorStatus(
    uint32_t* minorStatus, uint32_t statusValue, PAL_GssBuffer* outBuffer)
{
    (void)statusValue;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ImportUserName(
    uint32_t* minorStatus, char* inputName, uint32_t inputNameLen, GssName** outputName)
{
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
    if (inputName != NULL)
    {
        *inputName = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_AcquireAcceptorCred(uint32_t* minorStatus, GssCredId** outputCredHandle)
{
    if (outputCredHandle != NULL)
    {
        *outputCredHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_InitiateCredSpNego(
    uint32_t* minorStatus, GssName* desiredName, GssCredId** outputCredHandle)
{
    (void)desiredName;
    if (outputCredHandle != NULL)
    {
        *outputCredHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_ReleaseCred(uint32_t* minorStatus, GssCredId** credHandle)
{
    if (credHandle != NULL)
    {
        *credHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
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
    if (contextHandle != NULL)
    {
        *contextHandle = NULL;
    }
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT uint32_t NetSecurityNative_Wrap(
    uint32_t* minorStatus,
    GssCtxId* contextHandle,
    int32_t* isEncrypt,
    uint8_t* inputBytes,
    int32_t count,
    PAL_GssBuffer* outBuffer)
{
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
    return 0;
}

PALEXPORT uint32_t NetSecurityNative_GetUser(
    uint32_t* minorStatus, GssCtxId* contextHandle, PAL_GssBuffer* outBuffer)
{
    (void)contextHandle;
    rinos_gss_clear_buffer(outBuffer);
    return rinos_gss_unavailable(minorStatus);
}

PALEXPORT int32_t NetSecurityNative_EnsureGssInitialized(void)
{
    return -1;
}
