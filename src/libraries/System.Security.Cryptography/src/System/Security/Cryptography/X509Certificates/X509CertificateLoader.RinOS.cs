// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        private static partial ICertificatePal LoadCertificatePal(ReadOnlySpan<byte> data) =>
            CertificatePal.FromBlob(
                data,
                Microsoft.Win32.SafeHandles.SafePasswordHandle.InvalidHandle,
                X509KeyStorageFlags.EphemeralKeySet);

        private static partial ICertificatePal LoadCertificatePalFromFile(string path) =>
            CertificatePal.FromFile(
                path,
                Microsoft.Win32.SafeHandles.SafePasswordHandle.InvalidHandle,
                X509KeyStorageFlags.EphemeralKeySet);
    }
}

#endif
