// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    // RinOS has a product-owned DER trust bundle instead of an OpenSSL or
    // native certificate-store API.  This PAL builds a bounded managed chain
    // from that Root store plus the caller's extra/custom certificates.
    internal sealed class RinOSChainPal : IChainPal
    {
        private const int MaximumChainLength = 16;
        private readonly List<X509Certificate2> _ownedCertificates;

        private RinOSChainPal(
            List<X509Certificate2> ownedCertificates,
            X509ChainElement[] chainElements,
            X509ChainStatus[] chainStatus)
        {
            _ownedCertificates = ownedCertificates;
            ChainElements = chainElements;
            ChainStatus = chainStatus;
        }

        public X509ChainElement[]? ChainElements { get; }
        public X509ChainStatus[]? ChainStatus { get; }
        public SafeX509ChainHandle? SafeHandle => null;

        public bool? Verify(X509VerificationFlags flags, out Exception? exception)
        {
            exception = null;
            return UnixChainVerifier.Verify(ChainElements!, flags);
        }

        public void Dispose()
        {
            foreach (X509Certificate2 certificate in _ownedCertificates)
            {
                certificate.Dispose();
            }

            _ownedCertificates.Clear();
        }

        internal static RinOSChainPal Build(
            ICertificatePal certificate,
            X509Certificate2Collection? extraStore,
            X509Certificate2Collection? customTrustStore,
            X509ChainTrustMode trustMode,
            X509RevocationMode revocationMode,
            DateTime verificationTime)
        {
            List<X509Certificate2> ownedCertificates = new List<X509Certificate2>();

            try
            {
                X509Certificate2 leaf = CloneCertificate(certificate);
                ownedCertificates.Add(leaf);

                List<X509Certificate2> candidates = new List<X509Certificate2>();
                AddClones(candidates, ownedCertificates, extraStore);

                List<X509Certificate2> trustRoots = new List<X509Certificate2>();
                if (trustMode == X509ChainTrustMode.CustomRootTrust)
                {
                    AddClones(trustRoots, ownedCertificates, customTrustStore);
                    candidates.AddRange(trustRoots);
                }
                else
                {
                    using (IStorePal rootStore = RinOSStorePal.OpenSystemRoot(OpenFlags.ReadOnly))
                    {
                        X509Certificate2Collection roots = new X509Certificate2Collection();
                        rootStore.CloneTo(roots);
                        foreach (X509Certificate2 root in roots)
                        {
                            ownedCertificates.Add(root);
                            trustRoots.Add(root);
                            candidates.Add(root);
                        }
                    }
                }

                List<X509Certificate2> chainCertificates = new List<X509Certificate2> { leaf };
                List<List<X509ChainStatus>> elementStatuses = new List<List<X509ChainStatus>>
                {
                    new List<X509ChainStatus>(),
                };

                DateTime verificationUtc = verificationTime.ToUniversalTime();
                X509Certificate2 current = leaf;
                int caCertificatesBelowCurrent = 0;

                for (int depth = 0; depth < MaximumChainLength; depth++)
                {
                    RinOSCertificatePal currentPal = GetRinOSPal(current);
                    AddTimeStatus(current, elementStatuses[^1], verificationUtc);

                    if (current.SubjectName.RawData.Span.SequenceEqual(current.IssuerName.RawData.Span))
                    {
                        if (!ContainsCertificate(trustRoots, current))
                        {
                            AddStatus(
                                elementStatuses[^1],
                                X509ChainStatusFlags.UntrustedRoot,
                                "The certificate is not trusted by the RinOS Root store.");
                        }

                        break;
                    }

                    X509Certificate2? issuer = null;
                    X509Certificate2? firstNameMatch = null;
                    foreach (X509Certificate2 candidate in candidates)
                    {
                        if (ContainsCertificate(chainCertificates, candidate) ||
                            !candidate.SubjectName.RawData.Span.SequenceEqual(current.IssuerName.RawData.Span))
                        {
                            continue;
                        }

                        firstNameMatch ??= candidate;
                        try
                        {
                            if (currentPal.VerifySignatureBy(GetRinOSPal(candidate)))
                            {
                                issuer = candidate;
                                break;
                            }
                        }
                        catch (CryptographicException)
                        {
                            // Unsupported key or signature algorithms are an
                            // invalid issuer candidate, not a trust success.
                        }
                        catch (PlatformNotSupportedException)
                        {
                            // Keep chain construction deterministic for a
                            // certificate whose algorithm RinOS cannot verify.
                        }
                    }

                    if (issuer is null)
                    {
                        if (firstNameMatch is null)
                        {
                            AddStatus(
                                elementStatuses[^1],
                                X509ChainStatusFlags.PartialChain,
                                "The issuer certificate is not present in the RinOS certificate sources.");
                        }
                        else
                        {
                            AddStatus(
                                elementStatuses[^1],
                                X509ChainStatusFlags.NotSignatureValid,
                                "The issuer signature could not be verified by the RinOS crypto PAL.");
                            chainCertificates.Add(firstNameMatch);
                            elementStatuses.Add(new List<X509ChainStatus>());
                            AddTimeStatus(firstNameMatch, elementStatuses[^1], verificationUtc);
                        }

                        break;
                    }

                    RinOSCertificatePal issuerPal = GetRinOSPal(issuer);
                    if (chainCertificates.Count >= MaximumChainLength)
                    {
                        AddStatus(
                            elementStatuses[^1],
                            X509ChainStatusFlags.Cyclic,
                            "The RinOS chain length limit was exceeded or the chain is cyclic.");
                        break;
                    }

                    chainCertificates.Add(issuer);
                    elementStatuses.Add(new List<X509ChainStatus>());

                    if (!issuerPal.TryGetBasicConstraints(out bool isCertificateAuthority, out int? pathLengthConstraint) ||
                        !isCertificateAuthority ||
                        !issuerPal.AllowsCertificateSigning())
                    {
                        AddStatus(
                            elementStatuses[^1],
                            X509ChainStatusFlags.InvalidBasicConstraints,
                            "The issuer is not permitted to sign certificates.");
                        break;
                    }

                    if (pathLengthConstraint.HasValue && caCertificatesBelowCurrent > pathLengthConstraint.Value)
                    {
                        AddStatus(
                            elementStatuses[^1],
                            X509ChainStatusFlags.InvalidBasicConstraints,
                            "The certificate path length constraint was exceeded.");
                        break;
                    }

                    caCertificatesBelowCurrent++;
                    current = issuer;
                }

                if (revocationMode != X509RevocationMode.NoCheck)
                {
                    foreach (List<X509ChainStatus> statuses in elementStatuses)
                    {
                        AddStatus(
                            statuses,
                            X509ChainStatusFlags.RevocationStatusUnknown,
                            "RinOS does not provide a revocation-data transport in this PAL.");
                    }
                }

                X509ChainElement[] chainElements = new X509ChainElement[chainCertificates.Count];
                List<X509ChainStatus> allStatuses = new List<X509ChainStatus>();
                for (int index = 0; index < chainCertificates.Count; index++)
                {
                    X509ChainStatus[] statuses = elementStatuses[index].ToArray();
                    chainElements[index] = new X509ChainElement(chainCertificates[index], statuses, string.Empty);
                    allStatuses.AddRange(statuses);
                }

                return new RinOSChainPal(ownedCertificates, chainElements, allStatuses.ToArray());
            }
            catch
            {
                DisposeCertificates(ownedCertificates);
                throw;
            }
        }

        private static void AddClones(
            List<X509Certificate2> destination,
            List<X509Certificate2> ownedCertificates,
            X509Certificate2Collection? source)
        {
            if (source is null)
            {
                return;
            }

            foreach (X509Certificate2 certificate in source)
            {
                X509Certificate2 clone = new X509Certificate2(certificate);
                destination.Add(clone);
                ownedCertificates.Add(clone);
            }
        }

        private static X509Certificate2 CloneCertificate(ICertificatePal certificate)
        {
            return new X509Certificate2(
                RinOSCertificatePal.FromBlob(
                    certificate.RawData,
                    SafePasswordHandle.InvalidHandle,
                    X509KeyStorageFlags.EphemeralKeySet));
        }

        private static RinOSCertificatePal GetRinOSPal(X509Certificate2 certificate)
        {
            return certificate.Pal as RinOSCertificatePal ??
                throw new PlatformNotSupportedException("RinOS chain verification requires the managed RinOS certificate PAL.");
        }

        private static bool ContainsCertificate(List<X509Certificate2> certificates, X509Certificate2 candidate)
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                if (certificate.RawData.AsSpan().SequenceEqual(candidate.RawData))
                {
                    return true;
                }
            }

            return false;
        }

        private static void AddTimeStatus(
            X509Certificate2 certificate,
            List<X509ChainStatus> statuses,
            DateTime verificationTime)
        {
            if (verificationTime < certificate.NotBefore.ToUniversalTime() ||
                verificationTime > certificate.NotAfter.ToUniversalTime())
            {
                AddStatus(
                    statuses,
                    X509ChainStatusFlags.NotTimeValid,
                    "The certificate is not valid at the requested verification time.");
            }
        }

        private static void AddStatus(
            List<X509ChainStatus> statuses,
            X509ChainStatusFlags status,
            string information)
        {
            foreach (X509ChainStatus existing in statuses)
            {
                if (existing.Status == status)
                {
                    return;
                }
            }

            statuses.Add(new X509ChainStatus
            {
                Status = status,
                StatusInformation = information,
            });
        }

        private static void DisposeCertificates(List<X509Certificate2> certificates)
        {
            foreach (X509Certificate2 certificate in certificates)
            {
                certificate.Dispose();
            }

            certificates.Clear();
        }
    }

    internal static partial class ChainPal
    {
        internal static partial IChainPal FromHandle(IntPtr chainContext) =>
            throw new PlatformNotSupportedException("RinOS certificate chains do not expose native handles.");

        internal static partial bool ReleaseSafeX509ChainHandle(IntPtr handle) => true;

        internal static partial IChainPal? BuildChain(
            bool useMachineContext,
            ICertificatePal cert,
            X509Certificate2Collection? extraStore,
            OidCollection? applicationPolicy,
            OidCollection? certificatePolicy,
            X509RevocationMode revocationMode,
            X509RevocationFlag revocationFlag,
            X509Certificate2Collection? customTrustStore,
            X509ChainTrustMode trustMode,
            DateTime verificationTime,
            TimeSpan timeout,
            bool disableAia)
        {
            _ = useMachineContext;
            _ = revocationFlag;
            _ = timeout;
            _ = disableAia;

            if (applicationPolicy is { Count: > 0 } || certificatePolicy is { Count: > 0 })
            {
                throw new PlatformNotSupportedException(
                    "RinOS chain verification does not yet implement application or certificate policy OIDs.");
            }

            if (trustMode != X509ChainTrustMode.System && trustMode != X509ChainTrustMode.CustomRootTrust)
            {
                throw new ArgumentOutOfRangeException(nameof(trustMode));
            }

            return RinOSChainPal.Build(
                cert,
                extraStore,
                customTrustStore,
                trustMode,
                revocationMode,
                verificationTime);
        }
    }
}

#endif
