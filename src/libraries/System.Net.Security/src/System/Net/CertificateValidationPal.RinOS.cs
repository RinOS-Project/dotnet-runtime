// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace System.Net
{
    internal static partial class CertificateValidationPal
    {
        // Keep the managed allocation bounded by RinTLS's Certificate message
        // limit. The native PAL validates the same limit, but this boundary
        // must remain fail-closed if a future product adapter regresses.
        private const int MaxPeerCertificateBytes = 8 * 1024;
        private const int MaxPeerCertificateChainBytes = 64 * 1024;
        private const int MaxPeerCertificates = 5;

        internal static SslPolicyErrors VerifyCertificateProperties(
            SafeDeleteContext? securityContext,
            X509Chain chain,
            X509Certificate2 remoteCertificate,
            bool checkCertName,
            bool isServer,
            string? hostName)
        {
            // RinTLS has already verified the complete received chain, hostname,
            // certificate validity and Rin CA anchor against its authenticated
            // trusted-time snapshot before it reports handshake completion. The
            // managed chain is rebuilt only to enforce SslStream's EKU and
            // application/certificate policy projection; hostname remains owned
            // by the product verifier and never routes through OpenSSL.
            _ = checkCertName;
            _ = isServer;
            _ = hostName;
            if (securityContext is not RinSslHandle handle ||
                handle.TrustedUnixTime == 0u)
            {
                return SslPolicyErrors.RemoteCertificateChainErrors;
            }

            chain.ChainPolicy.VerificationTime =
                DateTimeOffset.FromUnixTimeSeconds((long)handle.TrustedUnixTime).UtcDateTime;
            chain.ChainPolicy.VerificationTimeIgnored = false;

            X509RevocationMode revocationMode = chain.ChainPolicy.RevocationMode;
            X509RevocationFlag revocationFlag = chain.ChainPolicy.RevocationFlag;
            bool chainValid;
            if (revocationMode == X509RevocationMode.NoCheck)
            {
                chainValid = chain.Build(remoteCertificate);
            }
            else
            {
                // RinOSChainPal deliberately does not perform network I/O.
                // Build the authenticated managed chain first, then ask the
                // RinTLS/workerd boundary for signed revocation evidence.
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                try
                {
                    chainValid = chain.Build(remoteCertificate);
                }
                finally
                {
                    chain.ChainPolicy.RevocationMode = revocationMode;
                }

                if (chainValid)
                {
                    RinOSRevocationStatus status = RinOSRevocationClient.CheckPeer(
                        handle, chain, revocationMode, revocationFlag,
                        chain.ChainPolicy.UrlRetrievalTimeout);
                    if (status != RinOSRevocationStatus.Good)
                    {
                        chainValid = false;
                    }
                }
            }

            return chainValid
                ? SslPolicyErrors.None
                : SslPolicyErrors.RemoteCertificateChainErrors;
        }

        private static X509Certificate2? GetRemoteCertificate(
            SafeDeleteContext? securityContext,
            bool retrieveChainCertificates,
            ref X509Chain? chain,
            X509ChainPolicy? chainPolicy)
        {
            if (securityContext is not RinSslHandle handle)
            {
                return null;
            }

            int result = Interop.RinTls.GetPeerCertificateLength(handle,
                                                                  out int length);
            if (result == -4)
            {
                return null;
            }
            if (result != 0 || length <= 0 || length > MaxPeerCertificateBytes)
            {
                throw new AuthenticationException(
                    result != 0
                        ? $"RinTLS certificate error {result}."
                        : "RinTLS peer certificate exceeds the managed size limit.");
            }

            byte[] der = new byte[length];
            result = Interop.RinTls.CopyPeerCertificate(handle, der);
            if (result != 0)
            {
                throw new AuthenticationException($"RinTLS certificate copy error {result}.");
            }

            if (retrieveChainCertificates)
            {
                chain ??= new X509Chain();
                if (chainPolicy != null)
                {
                    chain.ChainPolicy = chainPolicy;
                }

                AddPeerCertificateChain(handle, der, chain);
            }

            return new X509Certificate2(der);
        }

        private static void AddPeerCertificateChain(
            RinSslHandle handle, byte[] leafDer, X509Chain chain)
        {
            int result = Interop.RinTls.GetPeerCertificateChainLength(
                handle, out int length);
            if (result != 0 || length < 8 || length > MaxPeerCertificateChainBytes)
            {
                throw new AuthenticationException(
                    result != 0
                        ? $"RinTLS certificate-chain error {result}."
                        : "RinTLS peer certificate chain has an invalid size.");
            }

            byte[] encoded = new byte[length];
            result = Interop.RinTls.CopyPeerCertificateChain(handle, encoded);
            if (result != 0)
            {
                throw new AuthenticationException(
                    $"RinTLS certificate-chain copy error {result}.");
            }

            uint count = ReadUInt32LittleEndian(encoded, 0);
            if (count == 0u || count > (uint)MaxPeerCertificates)
            {
                throw new AuthenticationException(
                    "RinTLS peer certificate chain has an invalid count.");
            }

            int offset = sizeof(uint);
            for (uint index = 0u; index < count; index++)
            {
                if (offset > encoded.Length - sizeof(uint))
                {
                    throw new AuthenticationException(
                        "RinTLS peer certificate chain is truncated.");
                }

                uint certificateLength = ReadUInt32LittleEndian(encoded, offset);
                offset += sizeof(uint);
                if (certificateLength == 0u ||
                    certificateLength > (uint)MaxPeerCertificateBytes ||
                    certificateLength > (uint)(encoded.Length - offset))
                {
                    throw new AuthenticationException(
                        "RinTLS peer certificate chain contains an invalid DER length.");
                }

                int certificateSize = checked((int)certificateLength);
                X509Certificate2 certificate = new X509Certificate2(
                    encoded.AsSpan(offset, certificateSize).ToArray());
                offset += certificateSize;

                if (index == 0u)
                {
                    bool matchesLeaf = certificate.RawDataMemory.Span.SequenceEqual(leafDer);
                    certificate.Dispose();
                    if (!matchesLeaf)
                    {
                        throw new AuthenticationException(
                            "RinTLS peer certificate chain leaf does not match the peer certificate.");
                    }
                }
                else
                {
                    chain.ChainPolicy.ExtraStore.Add(certificate);
                }
            }

            if (offset != encoded.Length)
            {
                throw new AuthenticationException(
                    "RinTLS peer certificate chain has trailing data.");
            }
        }

        private static uint ReadUInt32LittleEndian(byte[] buffer, int offset) =>
            (uint)(buffer[offset] |
                   (buffer[offset + 1] << 8) |
                   (buffer[offset + 2] << 16) |
                   (buffer[offset + 3] << 24));

        internal static bool IsLocalCertificateUsed(SafeFreeCredentials? _,
                                                    SafeDeleteContext? securityContext)
            => securityContext is RinSslHandle handle && handle.ClientCertificateConfigured;

        internal static string[] GetRequestCertificateAuthorities(
            SafeDeleteContext _)
            => Array.Empty<string>();

        static partial void CheckSupportsStore(StoreLocation storeLocation,
                                               ref bool hasSupport)
        {
            if (storeLocation == StoreLocation.LocalMachine)
            {
                hasSupport = false;
            }
        }

        private static X509Store OpenStore(StoreLocation storeLocation)
        {
            Debug.Assert(storeLocation == StoreLocation.CurrentUser);
            X509Store store = new X509Store(StoreName.My, storeLocation);
            store.Open(OpenFlags.ReadOnly);
            return store;
        }
    }
}
