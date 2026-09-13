// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    internal static partial class CertificatePal
    {
#pragma warning disable IDE0060
        internal static partial ICertificatePal FromHandle(IntPtr handle)
        {
            return RinOSCertificatePal.FromHandle(handle);
        }

        internal static partial ICertificatePal FromOtherCert(X509Certificate copyFrom)
        {
            return RinOSCertificatePal.FromOtherCert(copyFrom);
        }

        internal static partial ICertificatePal FromBlob(
            ReadOnlySpan<byte> rawData,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            return RinOSCertificatePal.FromBlob(rawData, password, keyStorageFlags);
        }

        internal static partial ICertificatePal FromFile(
            string fileName,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            return RinOSCertificatePal.FromFile(fileName, password, keyStorageFlags);
        }
#pragma warning restore IDE0060
    }
}
