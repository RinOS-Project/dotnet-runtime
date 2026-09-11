// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef RINOS_PAL_H
#define RINOS_PAL_H

// RinOS keeps the Unix path grammar for managed files, while native images
// use RinOS' signed formats.  Keep these values in one target header so host
// probing cannot silently inherit Linux' .so/.exe conventions.
#define RINOS_NATIVE_EXECUTABLE_EXT ".rin"
#define RINOS_NATIVE_LIBRARY_EXT ".rll"
#define RINOS_NATIVE_LIBRARY_PREFIX ""
#define RINOS_RUNTIME_ROOT "/System/Dotnet"
#define RINOS_NATIVE_ASSET_SUBPATH "runtimes/rinos-x64/native"

#endif // RINOS_PAL_H
