// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    // RinOS certificates are immutable managed DER values.  This PAL deliberately
    // has no OpenSSL or native-handle dependency; private-key and store operations
    // remain separate product capabilities.
    internal sealed class RinOSCertificatePal : ICertificatePal
    {
        private CertificateData _certificate;
        private bool _disposed;
        private X500DistinguishedName? _subjectName;
        private X500DistinguishedName? _issuerName;

        internal RinOSCertificatePal(ReadOnlySpan<byte> rawData)
        {
            try
            {
                _certificate = new CertificateData(rawData.ToArray());
            }
            catch (AsnContentException e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        internal static ICertificatePal FromBlob(
            ReadOnlySpan<byte> rawData,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            ArgumentNullException.ThrowIfNull(password);

            if (!password.DangerousGetSpan().IsEmpty)
            {
                throw new CryptographicException("RinOS certificate PAL accepts DER certificates without a password.");
            }

            if (rawData.IsEmpty)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return new RinOSCertificatePal(rawData);
        }

        internal static ICertificatePal FromFile(
            string fileName,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            ArgumentException.ThrowIfNullOrEmpty(fileName);
            return FromBlob(File.ReadAllBytes(fileName), password, keyStorageFlags);
        }

        public bool HasPrivateKey => false;

        public IntPtr Handle
        {
            get
            {
                ThrowIfDisposed();
                return IntPtr.Zero;
            }
        }

        public string Issuer
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.IssuerName;
            }
        }

        public string Subject
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.SubjectName;
            }
        }

        public string LegacyIssuer => IssuerName.Decode(X500DistinguishedNameFlags.None);

        public string LegacySubject => SubjectName.Decode(X500DistinguishedNameFlags.None);

        public byte[] Thumbprint
        {
            get
            {
                ThrowIfDisposed();
                byte[] thumbprint = new byte[20];
                Sha1ForNonSecretPurposes.HashData(_certificate.RawData, thumbprint);
                return thumbprint;
            }
        }

        public string KeyAlgorithm
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.PublicKeyAlgorithm.AlgorithmId ?? string.Empty;
            }
        }

        public byte[]? KeyAlgorithmParameters
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.PublicKeyAlgorithm.Parameters is byte[] parameters
                    ? (byte[])parameters.Clone()
                    : null;
            }
        }

        public byte[] PublicKeyValue
        {
            get
            {
                ThrowIfDisposed();
                return (byte[])_certificate.PublicKey.Clone();
            }
        }

        public byte[] SerialNumber
        {
            get
            {
                ThrowIfDisposed();
                return (byte[])_certificate.SerialNumber.Clone();
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.SignatureAlgorithm.AlgorithmId ?? string.Empty;
            }
        }

        public DateTime NotAfter
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.NotAfter;
            }
        }

        public DateTime NotBefore
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.NotBefore;
            }
        }

        public byte[] RawData
        {
            get
            {
                ThrowIfDisposed();
                return (byte[])_certificate.RawData.Clone();
            }
        }

        public int Version
        {
            get
            {
                ThrowIfDisposed();
                return _certificate.Version + 1;
            }
        }

        public bool Archived
        {
            get
            {
                ThrowIfDisposed();
                return false;
            }
            set => throw new PlatformNotSupportedException(
                SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, "Archived"));
        }

        public string FriendlyName
        {
            get
            {
                ThrowIfDisposed();
                return string.Empty;
            }
            set => throw new PlatformNotSupportedException(
                SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, "FriendlyName"));
        }

        public X500DistinguishedName SubjectName
        {
            get
            {
                ThrowIfDisposed();
                return _subjectName ??= new X500DistinguishedName(_certificate.Subject.RawData);
            }
        }

        public X500DistinguishedName IssuerName
        {
            get
            {
                ThrowIfDisposed();
                return _issuerName ??= new X500DistinguishedName(_certificate.Issuer.RawData);
            }
        }

        public PolicyData GetPolicyData()
        {
            ThrowIfDisposed();
            PolicyData result = default;

            foreach (X509Extension extension in Extensions)
            {
                switch (extension.Oid?.Value)
                {
                    case Oids.ApplicationCertPolicies:
                        result.ApplicationCertPolicies = extension.RawData;
                        break;
                    case Oids.CertPolicies:
                        result.CertPolicies = extension.RawData;
                        break;
                    case Oids.CertPolicyMappings:
                        result.CertPolicyMappings = extension.RawData;
                        break;
                    case Oids.CertPolicyConstraints:
                        result.CertPolicyConstraints = extension.RawData;
                        break;
                    case Oids.EnhancedKeyUsage:
                        result.EnhancedKeyUsage = extension.RawData;
                        break;
                    case Oids.InhibitAnyPolicyExtension:
                        result.InhibitAnyPolicyExtension = extension.RawData;
                        break;
                }
            }

            return result;
        }

        public IEnumerable<X509Extension> Extensions
        {
            get
            {
                ThrowIfDisposed();

                foreach (X509Extension extension in _certificate.Extensions)
                {
                    yield return new X509Extension(extension.Oid!, extension.RawData, extension.Critical);
                }
            }
        }

        public RSA? GetRSAPrivateKey() => null;
        public DSA? GetDSAPrivateKey() => null;
        public ECDsa? GetECDsaPrivateKey() => null;
        public ECDiffieHellman? GetECDiffieHellmanPrivateKey() => null;
        public MLDsa? GetMLDsaPrivateKey() => null;
        public MLKem? GetMLKemPrivateKey() => null;
        public SlhDsa? GetSlhDsaPrivateKey() => null;

        public string GetNameInfo(X509NameType nameType, bool forIssuer)
        {
            ThrowIfDisposed();
            return _certificate.GetNameInfo(nameType, forIssuer);
        }

        public void AppendPrivateKeyInfo(StringBuilder sb)
        {
            ArgumentNullException.ThrowIfNull(sb);
        }

        public ICertificatePal CopyWithPrivateKey(DSA privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(ECDsa privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(RSA privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(ECDiffieHellman privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(MLDsa privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(MLKem privateKey) => ThrowPrivateKeyUnsupported();
        public ICertificatePal CopyWithPrivateKey(SlhDsa privateKey) => ThrowPrivateKeyUnsupported();

        public byte[] Export(X509ContentType contentType, SafePasswordHandle password)
        {
            ThrowIfDisposed();
            if (contentType != X509ContentType.Cert || !password.DangerousGetSpan().IsEmpty)
            {
                throw new PlatformNotSupportedException("RinOS certificate PAL exports DER certificates only.");
            }

            return RawData;
        }

        public byte[] ExportPkcs12(Pkcs12ExportPbeParameters exportParameters, SafePasswordHandle password) =>
            throw new PlatformNotSupportedException("RinOS certificate PAL does not export PKCS#12.");

        public byte[] ExportPkcs12(PbeParameters exportParameters, SafePasswordHandle password) =>
            throw new PlatformNotSupportedException("RinOS certificate PAL does not export PKCS#12.");

        public void Dispose()
        {
            _disposed = true;
            _certificate = default;
            _subjectName = null;
            _issuerName = null;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(RinOSCertificatePal));
            }
        }

        private ICertificatePal ThrowPrivateKeyUnsupported()
        {
            ThrowIfDisposed();
            throw new PlatformNotSupportedException("RinOS certificate PAL does not attach private keys.");
        }

        internal static ICertificatePal FromHandle(IntPtr handle) =>
            throw new PlatformNotSupportedException("RinOS certificates do not expose native handles.");

        internal static ICertificatePal FromOtherCert(X509Certificate copyFrom)
        {
            ArgumentNullException.ThrowIfNull(copyFrom);
            return FromBlob(copyFrom.GetRawCertData(), SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.EphemeralKeySet);
        }
    }

    internal static partial class CertificatePal
    {
        internal static partial ICertificatePal FromHandle(IntPtr handle) =>
            RinOSCertificatePal.FromHandle(handle);

        internal static partial ICertificatePal FromOtherCert(X509Certificate copyFrom) =>
            RinOSCertificatePal.FromOtherCert(copyFrom);

        internal static partial ICertificatePal FromBlob(
            ReadOnlySpan<byte> rawData,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags) =>
            RinOSCertificatePal.FromBlob(rawData, password, keyStorageFlags);

        internal static partial ICertificatePal FromFile(
            string fileName,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags) =>
            RinOSCertificatePal.FromFile(fileName, password, keyStorageFlags);
    }
}

#endif
