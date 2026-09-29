// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Http
{
    internal static class CurrentUserIdentityProvider
    {
        public static string GetIdentity()
        {
            // RinOS resolves Environment.UserName through the product passwd/account ABI.
            // This value partitions default-credential connection pools; it does not mint
            // credentials and must not be treated as Kerberos/NTLM authentication material.
            string identity = Environment.UserName;
            if (string.IsNullOrWhiteSpace(identity))
            {
                // Never collapse an unavailable product identity into the shared empty
                // identity used by non-default-credential pools.
                throw new PlatformNotSupportedException(
                    "RinOS product account identity is unavailable.");
            }

            return identity;
        }
    }
}
