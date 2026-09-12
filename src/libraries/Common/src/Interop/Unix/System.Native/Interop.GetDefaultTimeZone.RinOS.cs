// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Sys
    {
#if TARGET_RINOS
        [LibraryImport(Interop.Libraries.SystemNative, EntryPoint = "SystemNative_GetDefaultTimeZone", StringMarshalling = StringMarshalling.Utf8, SetLastError = true)]
        internal static partial string? GetDefaultTimeZone();

        [LibraryImport(Interop.Libraries.SystemNative, EntryPoint = "SystemNative_GetTimeZoneGeneration")]
        internal static partial uint GetTimeZoneGeneration();
#endif
    }
}
