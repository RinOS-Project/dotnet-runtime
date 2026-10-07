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
            EntryPoint = "SystemNative_GetRinOSCredentialIdentity",
            SetLastError = true)]
        private static partial int GetRinOSCredentialIdentity(
            byte[] identity, ref int capacity);

        internal static string GetRinOSCredentialIdentity()
        {
            int capacity = 512;
            byte[] identity = new byte[capacity];
            if (GetRinOSCredentialIdentity(identity, ref capacity) != 0 &&
                capacity > identity.Length)
            {
                identity = new byte[capacity];
                if (GetRinOSCredentialIdentity(identity, ref capacity) != 0)
                {
                    return string.Empty;
                }
            }

            unsafe
            {
                fixed (byte* pointer = identity)
                {
                    return Utf8StringMarshaller.ConvertToManaged(pointer) ??
                        string.Empty;
                }
            }
        }
    }
}
#endif
