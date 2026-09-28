// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative,
            EntryPoint = "CryptoNative_RinOSX509VerifySignature")]
        internal static partial int RinOSX509VerifySignature(
            byte[] certificateDer,
            int certificateLength,
            byte[] issuerDer,
            int issuerLength);
    }
}

#endif
