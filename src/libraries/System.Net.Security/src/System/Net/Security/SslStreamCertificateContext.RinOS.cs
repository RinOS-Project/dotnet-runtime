// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Cryptography.X509Certificates;

namespace System.Net.Security
{
    public partial class SslStreamCertificateContext
    {
        private const bool TrimRootCertificate = false;
        private const bool ChainBuildNeedsTrustedRoot = false;

        private SslStreamCertificateContext(
            X509Certificate2 target,
            System.Collections.ObjectModel.ReadOnlyCollection<X509Certificate2> intermediates,
            SslCertificateTrust? trust)
        {
            TargetCertificate = target;
            IntermediateCertificates = intermediates;
            Trust = trust;
        }

        partial void AddRootCertificate(X509Certificate2? rootCertificate,
                                        ref bool transferredOwnership)
        {
            transferredOwnership = false;
        }

        partial void SetNoOcspFetch(bool noOcspFetch)
        {
        }

        partial void ReleasePlatformSpecificResources()
        {
        }
    }
}
