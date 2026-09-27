// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Sys
    {
        internal enum SysConfName
        {
            _SC_CLK_TCK = 1,
            _SC_PAGESIZE = 2,
            _SC_PHYS_PAGES = 3,
            _SC_AVPHYS_PAGES = 4
        }

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_SysConf", SetLastError = true)]
        internal static partial long SysConf(SysConfName name);

#if TARGET_RINOS
        [StructLayout(LayoutKind.Sequential)]
        internal struct RinOSMemoryAvailability
        {
            internal uint Flags;
            internal uint Reserved;
            internal ulong AvailableVmBytes;
            internal ulong TotalFreeVirtualBytes;
            internal ulong LargestFreeVirtualExtentBytes;
        }

        internal const uint RinOSMemoryAvailabilityVmValid = 0x1u;
        internal const uint RinOSMemoryAvailabilityVirtualValid = 0x2u;

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSMemoryAvailability", SetLastError = true)]
        internal static partial int GetRinOSMemoryAvailability(
            out RinOSMemoryAvailability availability);
#endif
    }
}
