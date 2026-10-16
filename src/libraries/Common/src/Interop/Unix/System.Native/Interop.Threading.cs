// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal unsafe partial class Sys
    {
        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_CreateThread")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static unsafe partial bool CreateThread(IntPtr stackSize, delegate* unmanaged<IntPtr, IntPtr> startAddress, IntPtr parameter);

#if TARGET_RINOS
        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetThreadScheduling")]
        [return: MarshalAs(UnmanagedType.I4)]
        internal static partial int GetThreadScheduling(uint threadId, out int policy, out int priority);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_SetThreadScheduling")]
        [return: MarshalAs(UnmanagedType.I4)]
        internal static partial int SetThreadScheduling(uint threadId, int policy, int priority);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_SetThreadName", StringMarshalling = StringMarshalling.Utf8)]
        [return: MarshalAs(UnmanagedType.I4)]
        internal static partial int SetThreadName(uint threadId, string name);
#endif

#if TARGET_OSX
        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetUInt64OSThreadId")]
        internal static unsafe partial ulong GetUInt64OSThreadId();
#else
        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_TryGetUInt32OSThreadId")]
        internal static unsafe partial uint TryGetUInt32OSThreadId();
#endif
    }
}
