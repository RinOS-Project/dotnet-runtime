// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS
using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

internal static partial class Interop
{
    internal static partial class Sys
    {
        [LibraryImport(Libraries.SystemNative,
            EntryPoint = "SystemNative_GetRinOSCommandLineArgCount",
            SetLastError = true)]
        internal static partial int GetRinOSCommandLineArgCount();

        [LibraryImport(Libraries.SystemNative,
            EntryPoint = "SystemNative_GetRinOSCommandLineArg",
            SetLastError = true)]
        private static partial int GetRinOSCommandLineArg(
            int index, byte[] argument, ref int capacity);

        internal static bool TryGetRinOSCommandLineArg(int index, out string? argument)
        {
            const int InitialCapacity = 256;
            int capacity = InitialCapacity;
            byte[] buffer = new byte[capacity];
            int result = GetRinOSCommandLineArg(index, buffer, ref capacity);
            if (result != 0 && capacity > buffer.Length)
            {
                buffer = new byte[capacity];
                result = GetRinOSCommandLineArg(index, buffer, ref capacity);
            }

            if (result != 0)
            {
                argument = null;
                return false;
            }

            unsafe
            {
                fixed (byte* pointer = buffer)
                {
                    argument = Utf8StringMarshaller.ConvertToManaged(pointer);
                }
            }

            return argument is not null;
        }
    }
}
#endif
