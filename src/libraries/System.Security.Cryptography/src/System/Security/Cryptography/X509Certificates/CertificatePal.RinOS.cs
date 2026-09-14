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
        private AsymmetricAlgorithm? _privateKey;
        private X500DistinguishedName? _subjectName;
        private X500DistinguishedName? _issuerName;

        internal RinOSCertificatePal(
            ReadOnlySpan<byte> rawData,
            AsymmetricAlgorithm? privateKey = null)
        {
            try
            {
                _certificate = new CertificateData(rawData.ToArray());
                _privateKey = privateKey;
            }
            catch (AsnContentException e)
            {
                privateKey?.Dispose();
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

        public bool HasPrivateKey => _privateKey is not null;

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

        public RSA? GetRSAPrivateKey()
        {
            ThrowIfDisposed();
            return _privateKey is RSA rsa ? CloneRsa(rsa) : null;
        }

        public DSA? GetDSAPrivateKey()
        {
            ThrowIfDisposed();
            return null;
        }

        public ECDsa? GetECDsaPrivateKey()
        {
            ThrowIfDisposed();
            return _privateKey is ECDsa ecdsa ? CloneEcdsa(ecdsa) : null;
        }

        public ECDiffieHellman? GetECDiffieHellmanPrivateKey()
        {
            ThrowIfDisposed();
            return _privateKey is ECDiffieHellman ecdh ? CloneEcdh(ecdh) : null;
        }
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
            ThrowIfDisposed();
            if (!HasPrivateKey)
            {
                return;
            }

            sb.AppendLine();
            sb.AppendLine();
            sb.AppendLine("[Private Key]");
        }

        public ICertificatePal CopyWithPrivateKey(DSA privateKey) => ThrowAlgorithmUnsupported(privateKey);
        public ICertificatePal CopyWithPrivateKey(ECDsa privateKey) => CopyWithPrivateKeyCore(privateKey);
        public ICertificatePal CopyWithPrivateKey(RSA privateKey) => CopyWithPrivateKeyCore(privateKey);
        public ICertificatePal CopyWithPrivateKey(ECDiffieHellman privateKey) => CopyWithPrivateKeyCore(privateKey);
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
            _privateKey?.Dispose();
            _privateKey = null;
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

        private ICertificatePal CopyWithPrivateKeyCore(AsymmetricAlgorithm privateKey)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(privateKey);
            if (HasPrivateKey)
            {
                throw new InvalidOperationException(SR.Cryptography_Cert_AlreadyHasPrivateKey);
            }

            AsymmetricAlgorithm clone = privateKey switch
            {
                RSA rsa => CloneRsa(rsa),
                ECDsa ecdsa => CloneEcdsa(ecdsa),
                ECDiffieHellman ecdh => CloneEcdh(ecdh),
                _ => throw new PlatformNotSupportedException(
                    "RinOS certificate PAL supports RSA, ECDSA, and ECDH private keys.")
            };

            try
            {
                return new RinOSCertificatePal(_certificate.RawData, clone);
            }
            catch
            {
                clone.Dispose();
                throw;
            }
        }

        private ICertificatePal ThrowAlgorithmUnsupported(AsymmetricAlgorithm privateKey)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(privateKey);
            throw new PlatformNotSupportedException(
                "RinOS certificate PAL does not support DSA private keys.");
        }

        private ICertificatePal ThrowPrivateKeyUnsupported()
        {
            ThrowIfDisposed();
            throw new PlatformNotSupportedException("RinOS certificate PAL does not attach private keys.");
        }

        private static RSA CloneRsa(RSA source)
        {
            RSA clone = RSA.Create();
            RSAParameters parameters = default;
            try
            {
                parameters = source.ExportParameters(true);
                clone.ImportParameters(parameters);
                return clone;
            }
            catch
            {
                clone.Dispose();
                throw;
            }
            finally
            {
                Clear(parameters);
            }
        }

        private static ECDsa CloneEcdsa(ECDsa source)
        {
            ECDsa clone = ECDsa.Create();
            ECParameters parameters = default;
            try
            {
                parameters = source.ExportParameters(true);
                clone.ImportParameters(parameters);
                return clone;
            }
            catch
            {
                clone.Dispose();
                throw;
            }
            finally
            {
                Clear(parameters);
            }
        }

        private static ECDiffieHellman CloneEcdh(ECDiffieHellman source)
        {
            ECDiffieHellman clone = ECDiffieHellman.Create();
            ECParameters parameters = default;
            try
            {
                parameters = source.ExportParameters(true);
                clone.ImportParameters(parameters);
                return clone;
            }
            catch
            {
                clone.Dispose();
                throw;
            }
            finally
            {
                Clear(parameters);
            }
        }

        private static void Clear(RSAParameters parameters)
        {
            Clear(parameters.Modulus);
            Clear(parameters.Exponent);
            Clear(parameters.D);
            Clear(parameters.P);
            Clear(parameters.Q);
            Clear(parameters.DP);
            Clear(parameters.DQ);
            Clear(parameters.InverseQ);
        }

        private static void Clear(ECParameters parameters)
        {
            Clear(parameters.Q.X);
            Clear(parameters.Q.Y);
            Clear(parameters.D);
        }

        private static void Clear(byte[]? value)
        {
            if (value is not null)
            {
                CryptographicOperations.ZeroMemory(value);
            }
        }

        internal static ICertificatePal FromHandle(IntPtr handle) =>
            throw new PlatformNotSupportedException("RinOS certificates do not expose native handles.");

        internal static ICertificatePal FromOtherCert(X509Certificate copyFrom)
        {
            ArgumentNullException.ThrowIfNull(copyFrom);
            return FromBlob(copyFrom.GetRawCertData(), SafePasswordHandle.InvalidHandle, X509KeyStorageFlags.EphemeralKeySet);
        }

        internal bool TryGetBasicConstraints(out bool certificateAuthority, out int? pathLengthConstraint)
        {
            ThrowIfDisposed();

            foreach (X509Extension extension in _certificate.Extensions)
            {
                if (extension.Oid?.Value != Oids.BasicConstraints2)
                {
                    continue;
                }

                X509BasicConstraintsExtension constraints = new X509BasicConstraintsExtension(extension, extension.Critical);
                certificateAuthority = constraints.CertificateAuthority;
                pathLengthConstraint = constraints.HasPathLengthConstraint
                    ? constraints.PathLengthConstraint
                    : null;
                return true;
            }

            certificateAuthority = false;
            pathLengthConstraint = null;
            return false;
        }

        internal bool AllowsCertificateSigning()
        {
            ThrowIfDisposed();

            foreach (X509Extension extension in _certificate.Extensions)
            {
                if (extension.Oid?.Value != Oids.KeyUsage)
                {
                    continue;
                }

                try
                {
                    X509KeyUsageExtension keyUsage = new X509KeyUsageExtension(extension, extension.Critical);
                    return (keyUsage.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0;
                }
                catch (CryptographicException)
                {
                    return false;
                }
            }

            return true;
        }

        internal bool VerifySignatureBy(RinOSCertificatePal issuer)
        {
            ThrowIfDisposed();
            ArgumentNullException.ThrowIfNull(issuer);
            issuer.ThrowIfDisposed();

            byte[] toBeSigned = GetTbsCertificate();
            byte[] signature = _certificate.SignatureValue;
            using AsymmetricAlgorithm publicKey = X509Pal.Instance.DecodePublicKey(
                new Oid(issuer.KeyAlgorithm),
                issuer.PublicKeyValue,
                issuer.KeyAlgorithmParameters,
                issuer);

            return _certificate.SignatureAlgorithm.AlgorithmId switch
            {
                Oids.RsaPkcs1Sha1 => publicKey is RSA rsa &&
                    rsa.VerifyData(toBeSigned, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
                Oids.RsaPkcs1Sha256 => publicKey is RSA rsa &&
                    rsa.VerifyData(toBeSigned, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
                Oids.RsaPkcs1Sha384 => publicKey is RSA rsa &&
                    rsa.VerifyData(toBeSigned, signature, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
                Oids.RsaPkcs1Sha512 => publicKey is RSA rsa &&
                    rsa.VerifyData(toBeSigned, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
                Oids.ECDsaWithSha256 => publicKey is ECDsa ecdsa &&
                    ecdsa.VerifyData(toBeSigned, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
                _ => false,
            };
        }

        private byte[] GetTbsCertificate()
        {
            ValueAsnReader reader = new ValueAsnReader(_certificate.RawData, AsnEncodingRules.DER);
            ValueAsnReader certificate = reader.ReadSequence();
            byte[] tbsCertificate = certificate.ReadEncodedValue().ToArray();
            certificate.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            return tbsCertificate;
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
