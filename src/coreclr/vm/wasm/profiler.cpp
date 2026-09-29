// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "common.h"

#ifdef PROFILING_SUPPORTED
#include "asmconstants.h"
#include "proftoeeinterfaceimpl.h"

UINT_PTR ProfileGetIPFromPlatformSpecificHandle(void* pPlatformSpecificHandle)
{
    // WASM has no native profiler handle/register context.  An unknown IP is
    // represented by the same zero sentinel used by the WASM helper layer.
    UNREFERENCED_PARAMETER(pPlatformSpecificHandle);
    return 0;
}

void ProfileSetFunctionIDInPlatformSpecificHandle(void* pPlatformSpecificHandle, FunctionID functionId)
{
    // There is no platform-specific profiler handle to mutate on WASM.
    UNREFERENCED_PARAMETER(pPlatformSpecificHandle);
    UNREFERENCED_PARAMETER(functionId);
}

ProfileArgIterator::ProfileArgIterator(MetaSig* pSig, void* pPlatformSpecificHandle)
    : m_argIterator(pSig)
{
    // Keep the signature iterator constructible; the native argument-frame
    // owner is unavailable, so the accessors below report no values.
    UNREFERENCED_PARAMETER(pPlatformSpecificHandle);
}

ProfileArgIterator::~ProfileArgIterator()
{
}

LPVOID ProfileArgIterator::GetNextArgAddr()
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetHiddenArgValue(void)
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetThis(void)
{
    return nullptr;
}

LPVOID ProfileArgIterator::GetReturnBufferAddr(void)
{
    return nullptr;
}


#endif // PROFILING_SUPPORTED
