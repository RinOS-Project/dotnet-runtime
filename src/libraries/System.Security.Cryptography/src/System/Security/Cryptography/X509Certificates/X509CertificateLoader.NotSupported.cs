// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Security.Cryptography.X509Certificates
{
    public static partial class X509CertificateLoader
    {
        private static partial ICertificatePal LoadCertificatePal(ReadOnlySpan<byte> data)
        {
            return CertificatePal.FromBlob(
                data,
                Microsoft.Win32.SafeHandles.SafePasswordHandle.InvalidHandle,
                X509KeyStorageFlags.EphemeralKeySet);
        }

        private static partial ICertificatePal LoadCertificatePalFromFile(string path)
        {
            return CertificatePal.FromFile(
                path,
                Microsoft.Win32.SafeHandles.SafePasswordHandle.InvalidHandle,
                X509KeyStorageFlags.EphemeralKeySet);
        }

        private static partial Pkcs12Return LoadPkcs12(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }

        private static partial X509Certificate2Collection LoadPkcs12Collection(
            ref BagState bagState,
            ReadOnlySpan<char> password,
            X509KeyStorageFlags keyStorageFlags)
        {
            throw new PlatformNotSupportedException(SR.SystemSecurityCryptographyX509Certificates_PlatformNotSupported);
        }
    }
}
