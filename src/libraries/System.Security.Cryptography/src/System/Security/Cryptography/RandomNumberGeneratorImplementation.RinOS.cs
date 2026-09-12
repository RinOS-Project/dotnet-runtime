// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography
{
    internal sealed partial class RandomNumberGeneratorImplementation
    {
        private static unsafe void GetBytes(byte* buffer, int count)
        {
            if (!Interop.Crypto.GetRandomBytes(buffer, count))
            {
                throw new CryptographicException(
                    "RinOS product entropy source failed.");
            }
        }
    }
}
