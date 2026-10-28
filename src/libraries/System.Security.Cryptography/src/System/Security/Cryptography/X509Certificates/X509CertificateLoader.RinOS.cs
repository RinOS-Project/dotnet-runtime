// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Security.Cryptography;

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

        private static partial Pkcs12Return FromCertAndKey(
            CertAndKey certAndKey, ImportState importState)
        {
            RinOSCertificatePal certificate = (RinOSCertificatePal)certAndKey.Cert!;
            if (certAndKey.Key is null)
            {
                return new Pkcs12Return(certificate);
            }

            RinOSCertificatePal certificateWithKey = certAndKey.Key.Key switch
            {
                RSA rsa => (RinOSCertificatePal)certificate.CopyWithPrivateKey(rsa),
                ECDsa ecdsa => (RinOSCertificatePal)certificate.CopyWithPrivateKey(ecdsa),
                ECDiffieHellman ecdh =>
                    (RinOSCertificatePal)certificate.CopyWithPrivateKey(ecdh),
                _ => throw new PlatformNotSupportedException(
                    "RinOS PKCS#12 supports RSA and named NIST EC private keys.")
            };

            // CopyWithPrivateKey clones the key into the new immutable PAL.
            // The parser's ownership is transferred only after that succeeds.
            certAndKey.Key.Dispose();
            certificate.Dispose();
            return new Pkcs12Return(certificateWithKey);
        }

        private static partial Pkcs12Key? CreateKey(
            string algorithm, ReadOnlySpan<byte> pkcs8) => algorithm switch
        {
            Oids.Rsa or Oids.RsaPss =>
                new AsymmetricAlgorithmPkcs12PrivateKey(pkcs8, static () => RSA.Create()),
            Oids.EcPublicKey =>
                new AsymmetricAlgorithmPkcs12PrivateKey(pkcs8, static () => ECDsa.Create()),
            Oids.EcDiffieHellman =>
                new AsymmetricAlgorithmPkcs12PrivateKey(pkcs8, static () => ECDiffieHellman.Create()),
            _ => null,
        };

        private static partial ICertificatePalCore LoadX509Der(
            ReadOnlyMemory<byte> data) => new RinOSCertificatePal(data.Span);

        static partial void InitializeImportState(
            ref ImportState importState, X509KeyStorageFlags keyStorageFlags)
        {
            // RinOS only exposes ephemeral managed key ownership.  The public
            // loader still validates all flag combinations before reaching
            // this hook; no platform key container is created here.
        }

        private partial struct ImportState
        {
            partial void DisposeCore()
            {
                this = default;
            }
        }
    }
}

#endif
