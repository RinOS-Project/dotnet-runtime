// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Security.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    // PKCS#12 container construction is shared with the Unix PAL.  RinOS only
    // supplies the key-specific encrypted PKCS#8 export and keeps all key
    // ownership in the managed certificate PAL.
    internal sealed class RinOSExportProvider : UnixExportProvider
    {
        internal RinOSExportProvider(ICertificatePalCore singleCertPal)
            : base(singleCertPal)
        {
        }

        internal RinOSExportProvider(X509Certificate2Collection certs)
            : base(certs)
        {
        }

        protected override byte[] ExportPkcs8(
            ICertificatePalCore certificatePal,
            PbeParameters pbeParameters,
            ReadOnlySpan<char> password)
        {
            if (certificatePal is not RinOSCertificatePal rinCertificate ||
                !rinCertificate.HasPrivateKey)
            {
                throw new CryptographicException(
                    "RinOS PKCS#12 export requires a RinOS private key.");
            }

            using (RSA? rsa = rinCertificate.GetRSAPrivateKey())
            {
                if (rsa is not null)
                {
                    return rsa.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
                }
            }

            using (ECDsa? ecdsa = rinCertificate.GetECDsaPrivateKey())
            {
                if (ecdsa is not null)
                {
                    return ecdsa.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
                }
            }

            using (ECDiffieHellman? ecdh = rinCertificate.GetECDiffieHellmanPrivateKey())
            {
                if (ecdh is not null)
                {
                    return ecdh.ExportEncryptedPkcs8PrivateKey(password, pbeParameters);
                }
            }

            throw new PlatformNotSupportedException(
                "RinOS PKCS#12 export supports RSA, ECDSA, and ECDH private keys.");
        }

        protected override byte[] ExportPkcs7() =>
            throw new PlatformNotSupportedException(
                "RinOS does not export PKCS#7 certificate collections.");
    }
}

#endif
