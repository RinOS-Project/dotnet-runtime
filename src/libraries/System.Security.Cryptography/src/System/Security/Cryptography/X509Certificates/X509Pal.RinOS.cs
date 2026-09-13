// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class RinOSX509Pal : IX509Pal
    {
        public AsymmetricAlgorithm DecodePublicKey(
            Oid oid,
            byte[] encodedKeyValue,
            byte[]? encodedParameters,
            ICertificatePal? certificatePal)
        {
            byte[] subjectPublicKeyInfo = EncodeSubjectPublicKeyInfo(oid, encodedKeyValue, encodedParameters);

            return oid.Value switch
            {
                Oids.Rsa => ImportRsa(subjectPublicKeyInfo),
                Oids.EcPublicKey => ImportEcdsa(subjectPublicKeyInfo),
                _ => throw new PlatformNotSupportedException("RinOS public-key decoding supports RSA and P-256 EC keys.")
            };
        }

        public ECDsa DecodeECDsaPublicKey(ICertificatePal? certificatePal)
        {
            ArgumentNullException.ThrowIfNull(certificatePal);
            return ImportEcdsa(EncodeSubjectPublicKeyInfo(
                new Oid(certificatePal.KeyAlgorithm),
                certificatePal.PublicKeyValue,
                certificatePal.KeyAlgorithmParameters));
        }

        public ECDiffieHellman DecodeECDiffieHellmanPublicKey(ICertificatePal? certificatePal)
        {
            ArgumentNullException.ThrowIfNull(certificatePal);
            return ImportEcdh(EncodeSubjectPublicKeyInfo(
                new Oid(certificatePal.KeyAlgorithm),
                certificatePal.PublicKeyValue,
                certificatePal.KeyAlgorithmParameters));
        }

        public string X500DistinguishedNameDecode(byte[] encodedDistinguishedName, X500DistinguishedNameFlags flag) =>
            new X500DistinguishedName(encodedDistinguishedName).Decode(flag);

        public byte[] X500DistinguishedNameEncode(string distinguishedName, X500DistinguishedNameFlags flag) =>
            new X500DistinguishedName(distinguishedName, flag).RawData;

        public string X500DistinguishedNameFormat(byte[] encodedDistinguishedName, bool multiLine) =>
            new X500DistinguishedName(encodedDistinguishedName).Format(multiLine);

        public X509ContentType GetCertContentType(ReadOnlySpan<byte> rawData)
        {
            try
            {
                _ = new CertificateData(rawData.ToArray());
                return X509ContentType.Cert;
            }
            catch (AsnContentException)
            {
                return X509ContentType.Unknown;
            }
            catch (CryptographicException)
            {
                return X509ContentType.Unknown;
            }
        }

        public X509ContentType GetCertContentType(string fileName) =>
            GetCertContentType(File.ReadAllBytes(fileName));

        private static RSA ImportRsa(byte[] subjectPublicKeyInfo)
        {
            RSA rsa = RSA.Create();
            try
            {
                rsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
                return rsa;
            }
            catch
            {
                rsa.Dispose();
                throw;
            }
        }

        private static ECDsa ImportEcdsa(byte[] subjectPublicKeyInfo)
        {
            ECDsa ecdsa = ECDsa.Create();
            try
            {
                ecdsa.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
                return ecdsa;
            }
            catch
            {
                ecdsa.Dispose();
                throw;
            }
        }

        private static ECDiffieHellman ImportEcdh(byte[] subjectPublicKeyInfo)
        {
            ECDiffieHellman ecdh = ECDiffieHellman.Create();
            try
            {
                ecdh.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);
                return ecdh;
            }
            catch
            {
                ecdh.Dispose();
                throw;
            }
        }

        private static byte[] EncodeSubjectPublicKeyInfo(
            Oid oid,
            byte[] encodedKeyValue,
            byte[]? encodedParameters)
        {
            AsnWriter writer = new(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.PushSequence();
            writer.WriteObjectIdentifier(oid.Value ?? string.Empty);
            if (encodedParameters is null)
            {
                writer.WriteNull();
            }
            else
            {
                writer.WriteEncodedValue(encodedParameters);
            }
            writer.PopSequence();
            writer.WriteBitString(encodedKeyValue, 0);
            writer.PopSequence();
            return writer.Encode();
        }
    }

    internal static partial class X509Pal
    {
        private static partial IX509Pal BuildSingleton() => new RinOSX509Pal();
    }
}

#endif
