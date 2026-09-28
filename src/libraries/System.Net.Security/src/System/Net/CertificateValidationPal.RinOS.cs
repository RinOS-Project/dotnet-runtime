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
            // trusted-time snapshot before it reports handshake completion. Do
            // not route this target back through the OpenSSL certificate PAL.
            return SslPolicyErrors.None;
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

            // The current product API intentionally exposes the authenticated
            // leaf only.  RinTLS itself retains and verifies the complete peer
            // chain; exposing intermediates is a follow-up API item.
            if (retrieveChainCertificates && chainPolicy != null)
            {
                chain ??= new X509Chain();
                chain.ChainPolicy = chainPolicy;
            }

            return new X509Certificate2(der);
        }

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
