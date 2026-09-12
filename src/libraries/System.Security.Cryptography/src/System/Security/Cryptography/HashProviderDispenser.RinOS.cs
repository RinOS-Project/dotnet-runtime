// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        internal static bool KmacSupported(string algorithmId)
        {
            _ = algorithmId;
            return false;
        }

        internal static partial class OneShotHashProvider
        {
            public static void KmacData(
                string algorithmId,
                ReadOnlySpan<byte> key,
                ReadOnlySpan<byte> source,
                Span<byte> destination,
                ReadOnlySpan<byte> customizationString,
                bool xof)
            {
                _ = algorithmId;
                _ = key;
                _ = source;
                _ = destination;
                _ = customizationString;
                _ = xof;
                Debug.Fail("Caller should have checked if KMAC was available first.");
                throw new PlatformNotSupportedException("RinOS does not provide KMAC.");
            }

            public static void HashDataXof(
                string hashAlgorithmId,
                ReadOnlySpan<byte> source,
                Span<byte> destination)
            {
                _ = hashAlgorithmId;
                _ = source;
                _ = destination;
                Debug.Fail("Caller should have checked if XOFs were available first.");
                throw new PlatformNotSupportedException("RinOS does not provide SHAKE/XOF.");
            }
        }
    }
}
