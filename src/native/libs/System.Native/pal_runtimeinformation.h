// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#pragma once

#include "pal_compiler.h"
#include "pal_types.h"

PALEXPORT char* SystemNative_GetUnixRelease(void);

PALEXPORT int32_t SystemNative_GetUnixVersion(char* version, int* capacity);

PALEXPORT int32_t SystemNative_GetOSArchitecture(void);

/* Returns the authenticated capability snapshot of the calling process. */
PALEXPORT int32_t SystemNative_GetProcessCapabilities(uint64_t* capabilities);

/* Returns a stable, non-secret identity for the calling RinOS credential
 * snapshot.  The value is only suitable for partitioning connection pools;
 * it is not an authentication token. */
PALEXPORT int32_t SystemNative_GetRinOSCredentialIdentity(
    char* identity, int32_t* capacity);
