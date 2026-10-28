// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Security.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        internal static bool KmacSupported(string algorithmId)
        {
            return algorithmId == HashAlgorithmNames.KMAC128 ||
                algorithmId == HashAlgorithmNames.KMAC256;
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
                int algorithm = algorithmId switch
                {
                    HashAlgorithmNames.KMAC128 => 1,
                    HashAlgorithmNames.KMAC256 => 2,
                    _ => throw new CryptographicException($"Unknown RinOS KMAC algorithm: {algorithmId}")
                };

                unsafe
                {
                    fixed (byte* pKey = key)
                    fixed (byte* pSource = source)
                    fixed (byte* pDestination = destination)
                    fixed (byte* pCustomization = customizationString)
                    {
                        if (Interop.Crypto.RinOSKmacOneShot(
                                algorithm,
                                pKey,
                                key.Length,
                                pSource,
                                source.Length,
                                pCustomization,
                                customizationString.Length,
                                pDestination,
                                destination.Length,
                                xof ? 1 : 0) == 0)
                        {
                            throw new CryptographicException("RinOS KMAC operation failed.");
                        }
                    }
                }
            }

            public static void HashDataXof(
                string hashAlgorithmId,
                ReadOnlySpan<byte> source,
                Span<byte> destination)
            {
                int algorithm = hashAlgorithmId switch
                {
                    HashAlgorithmNames.SHAKE128 => 7,
                    HashAlgorithmNames.SHAKE256 => 8,
                    _ => throw new CryptographicException($"Unknown RinOS XOF algorithm: {hashAlgorithmId}")
                };

                unsafe
                {
                    fixed (byte* pSource = source)
                    fixed (byte* pDestination = destination)
                    {
                        if (Interop.Crypto.RinOSXofOneShot(
                                algorithm,
                                pSource,
                                source.Length,
                                pDestination,
                                destination.Length) == 0)
                        {
                            throw new CryptographicException("RinOS XOF operation failed.");
                        }
                    }
                }
            }
        }
    }
}
