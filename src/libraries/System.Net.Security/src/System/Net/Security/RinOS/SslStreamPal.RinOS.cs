// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal static class SslStreamPal
    {
        private const string TrustStorePath = "/System/Trust/roots.rinca";
        private const int MaxTrustStoreBytes = 4 * 1024 * 1024;
        private const int MaxCustomTrustAnchors = 256;
        private const long MaxTrustedUnixTime = 253402300799L;

        internal const bool StartMutualAuthAsAnonymous = false;
        // RinTLS performs hostname, validity and trust-anchor verification before
        // reporting a completed handshake. SslStream still invokes the managed
        // callback after completion so callers retain the normal callback surface.
        internal const bool CertValidationInCallback = true;
        internal const bool CanEncryptEmptyMessage = false;
        internal const bool CanGenerateCustomAlerts = false;

        public static Exception GetException(SecurityStatusPal status)
            => status.Exception ?? new RinTlsException((int)status.ErrorCode);

        internal static bool CanGenerateCustomAlertsForContext(SafeDeleteContext? _)
            => CanGenerateCustomAlerts;

        public static void VerifyPackageInfo()
        {
        }

        public static SecurityStatusPal SelectApplicationProtocol(
            SafeFreeCredentials? _, SafeDeleteSslContext? _,
            SslAuthenticationOptions sslAuthenticationOptions,
            ReadOnlySpan<byte> clientProtocols)
        {
            if (clientProtocols.Length != 0 ||
                (sslAuthenticationOptions.ApplicationProtocols?.Count ?? 0) != 0)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS ALPN is not available in the current product API.");
            }

            return new SecurityStatusPal(SecurityStatusPalErrorCode.OK);
        }

#pragma warning disable IDE0060
        public static ProtocolToken AcceptSecurityContext(
            ref SafeFreeCredentials? credential,
            ref SafeDeleteSslContext? context,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            if (sslAuthenticationOptions.IsServer)
            {
                consumed = 0;
                return Unsupported("RinTLS currently exposes a client-only TLS API.");
            }

            return HandshakeInternal(ref context, inputBuffer, out consumed,
                                     sslAuthenticationOptions);
        }

        public static ProtocolToken InitializeSecurityContext(
            ref SafeFreeCredentials? credential,
            ref SafeDeleteSslContext? context,
            string? _, ReadOnlySpan<byte> inputBuffer, out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
            => HandshakeInternal(ref context, inputBuffer, out consumed,
                                 sslAuthenticationOptions);

        public static SafeFreeCredentials? AcquireCredentialsHandle(
            SslAuthenticationOptions _, bool __)
            => null;

        public static ProtocolToken EncryptMessage(
            SafeDeleteSslContext securityContext, ReadOnlyMemory<byte> input,
            int _, int __)
        {
            ProtocolToken token = default;
            token.RentBuffer = true;

            try
            {
                RinSslHandle handle = GetHandle(securityContext);
                int result = Interop.RinTls.Encrypt(handle, input.Span,
                                                    out int consumed);
                if (result == 0 && consumed != input.Length)
                {
                    token.Status = new SecurityStatusPal(
                        SecurityStatusPalErrorCode.InternalError,
                        new RinTlsException(-1, "RinTLS did not consume the plaintext."));
                    return token;
                }

                DrainOutput(handle, ref token);
                token.Status = MapNativeError(result, handle);
            }
            catch (Exception ex)
            {
                token.Status = new SecurityStatusPal(
                    SecurityStatusPalErrorCode.InternalError, ex);
            }

            return token;
        }

        public static SecurityStatusPal DecryptMessage(
            SafeDeleteSslContext securityContext,
            Span<byte> encrypted,
            Span<byte> destination,
            out int bytesWritten,
            out int leftoverOffset,
            out int leftoverLength)
        {
            bytesWritten = 0;
            leftoverOffset = 0;
            leftoverLength = 0;

            try
            {
                RinSslHandle handle = GetHandle(securityContext);
                int result = Interop.RinTls.Decrypt(handle, encrypted, destination,
                                                    out _, out bytesWritten);
                return MapNativeError(result, handle);
            }
            catch (Exception ex)
            {
                return new SecurityStatusPal(
                    SecurityStatusPalErrorCode.InternalError, ex);
            }
        }

        public static ChannelBinding? QueryContextChannelBinding(
            SafeDeleteSslContext securityContext, ChannelBindingKind attribute)
        {
            if (attribute != ChannelBindingKind.Endpoint)
            {
                return null;
            }

            ChannelBinding? binding = EndpointChannelBindingToken.Build(securityContext);
            if (binding is null)
            {
                throw new AuthenticationException(
                    "RinTLS could not construct the endpoint channel binding.");
            }

            return binding;
        }

        public static ProtocolToken Renegotiate(
            ref SafeFreeCredentials? _, ref SafeDeleteSslContext context,
            SslAuthenticationOptions __)
            => Unsupported("RinTLS does not implement TLS renegotiation.");

        public static void QueryContextStreamSizes(
            SafeDeleteContext? _, out StreamSizes streamSizes)
        {
            // RinTLS emits at most one 16 KiB TLS record per send operation.
            streamSizes = new StreamSizes { MaximumMessage = 16 * 1024 };
        }

        public static void QueryContextConnectionInfo(
            SafeDeleteSslContext securityContext,
            ref SslConnectionInfo connectionInfo)
        {
            connectionInfo.UpdateSslConnectionInfo(GetHandle(securityContext));
        }

        public static bool TryUpdateClintCertificate(
            SafeFreeCredentials? _, SafeDeleteSslContext? context,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            if (context is not RinSslHandle handle)
            {
                return false;
            }

            if (handle.ClientCertificateConfigured)
            {
                return true;
            }

            SslStreamCertificateContext? certificateContext =
                sslAuthenticationOptions.CertificateContext;
            if (certificateContext is null)
            {
                int declined = Interop.RinTls.SetClientCertificate(
                    handle, ReadOnlySpan<byte>.Empty, IntPtr.Zero, IntPtr.Zero);
                if (declined != 0)
                {
                    throw new RinTlsException(
                        declined, "RinTLS rejected declining the client certificate request.");
                }

                handle.MarkClientCertificateConfigured();
                return true;
            }

            byte[] certificateList = BuildClientCertificateList(certificateContext);
            RinClientCertificateState state =
                new RinClientCertificateState(certificateContext.TargetCertificate);
            IntPtr stateHandle = handle.AttachClientCertificateState(state);
            int result = Interop.RinTls.SetClientCertificate(
                handle, certificateList,
                Marshal.GetFunctionPointerForDelegate(s_clientCertificateSignCallback),
                stateHandle);
            if (result != 0)
            {
                throw new RinTlsException(
                    result, "RinTLS rejected the managed client certificate.");
            }

            handle.MarkClientCertificateConfigured();
            return true;
        }

        private const int MaxClientCertificateChain = 16 * 1024;

        private static byte[] BuildClientCertificateList(
            SslStreamCertificateContext certificateContext)
        {
            byte[][] certificates = new byte[
                1 + certificateContext.IntermediateCertificates.Count][];
            certificates[0] = certificateContext.TargetCertificate.RawData;
            for (int i = 0; i < certificateContext.IntermediateCertificates.Count; i++)
            {
                certificates[i + 1] =
                    certificateContext.IntermediateCertificates[i].RawData;
            }

            int listLength = 0;
            foreach (byte[] certificate in certificates)
            {
                if (certificate.Length == 0 || certificate.Length > 0xFFFFFF)
                {
                    throw new AuthenticationException(
                        "RinTLS received an invalid client certificate.");
                }

                listLength = checked(listLength + 3 + certificate.Length + 2);
            }

            if (listLength > MaxClientCertificateChain - 3)
            {
                throw new AuthenticationException(
                    "The RinTLS client certificate chain exceeds 16 KiB.");
            }

            byte[] result = new byte[listLength + 3];
            WriteUInt24(result, 0, listLength);
            int offset = 3;
            foreach (byte[] certificate in certificates)
            {
                WriteUInt24(result, offset, certificate.Length);
                offset += 3;
                certificate.AsSpan().CopyTo(result.AsSpan(offset));
                offset += certificate.Length;
                result[offset++] = 0;
                result[offset++] = 0;
            }

            return result;
        }

        private static void WriteUInt24(Span<byte> destination, int offset, int value)
        {
            destination[offset] = (byte)(value >> 16);
            destination[offset + 1] = (byte)(value >> 8);
            destination[offset + 2] = (byte)value;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private unsafe delegate int ClientCertificateSignCallback(
            IntPtr opaque, ushort signatureScheme, byte* message,
            nuint messageLength, byte* signature, nuint signatureCapacity,
            nuint* signatureLength);

        private static readonly unsafe ClientCertificateSignCallback
            s_clientCertificateSignCallback = SignClientCertificate;

        private static unsafe int SignClientCertificate(
            IntPtr opaque, ushort signatureScheme, byte* message,
            nuint messageLength, byte* signature, nuint signatureCapacity,
            nuint* signatureLength)
        {
            if (signatureLength is null || messageLength > int.MaxValue ||
                signatureCapacity > int.MaxValue ||
                (message is null && messageLength != 0u))
            {
                return -1;
            }

            *signatureLength = 0u;
            try
            {
                if (opaque == IntPtr.Zero || signature is null)
                {
                    return -1;
                }

                object? target = GCHandle.FromIntPtr(opaque).Target;
                if (target is not RinClientCertificateState state)
                {
                    return -1;
                }

                byte[] signedData = new ReadOnlySpan<byte>(
                    message, checked((int)messageLength)).ToArray();
                byte[] signed = state.Sign(signatureScheme, signedData);
                if (signed.Length == 0 || signed.Length > (int)signatureCapacity)
                {
                    return -1;
                }

                signed.AsSpan().CopyTo(new Span<byte>(signature, signed.Length));
                *signatureLength = (nuint)signed.Length;
                return 0;
            }
            catch
            {
                return -1;
            }
        }

        private sealed class RinClientCertificateState
        {
            private readonly X509Certificate2 _certificate;

            internal RinClientCertificateState(X509Certificate2 certificate)
            {
                _certificate = certificate;
            }

            internal byte[] Sign(ushort signatureScheme, ReadOnlySpan<byte> message)
            {
                return signatureScheme switch
                {
                    0x0403 => SignEcdsa(message, HashAlgorithmName.SHA256, 256),
                    0x0503 => SignEcdsa(message, HashAlgorithmName.SHA384, 384),
                    0x0603 => SignEcdsa(message, HashAlgorithmName.SHA512, 521),
                    0x0804 => SignRsa(message, HashAlgorithmName.SHA256),
                    0x0805 => SignRsa(message, HashAlgorithmName.SHA384),
                    0x0806 => SignRsa(message, HashAlgorithmName.SHA512),
                    _ => throw new CryptographicException(
                        "RinTLS selected an unsupported client signature scheme."),
                };
            }

            private byte[] SignEcdsa(
                ReadOnlySpan<byte> message, HashAlgorithmName hashAlgorithm,
                int expectedKeySize)
            {
                using ECDsa? ecdsa = _certificate.GetECDsaPrivateKey();
                if (ecdsa is null || ecdsa.KeySize != expectedKeySize)
                {
                    throw new CryptographicException(
                        "The client certificate does not match the TLS signature scheme.");
                }

                byte[] hash = hashAlgorithm == HashAlgorithmName.SHA256
                    ? SHA256.HashData(message)
                    : hashAlgorithm == HashAlgorithmName.SHA384
                        ? SHA384.HashData(message)
                        : SHA512.HashData(message);
                return ecdsa.SignHash(hash);
            }

            private byte[] SignRsa(
                ReadOnlySpan<byte> message, HashAlgorithmName hashAlgorithm)
            {
                using RSA? rsa = _certificate.GetRSAPrivateKey();
                if (rsa is null)
                {
                    throw new CryptographicException(
                        "The client certificate does not contain an RSA private key.");
                }

                byte[] hash = hashAlgorithm == HashAlgorithmName.SHA256
                    ? SHA256.HashData(message)
                    : hashAlgorithm == HashAlgorithmName.SHA384
                        ? SHA384.HashData(message)
                        : SHA512.HashData(message);
                return rsa.SignHash(hash, hashAlgorithm, RSASignaturePadding.Pss);
            }
        }

        private static ProtocolToken HandshakeInternal(
            ref SafeDeleteSslContext? context,
            ReadOnlySpan<byte> inputBuffer,
            out int consumed,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            ProtocolToken token = default;
            token.RentBuffer = true;
            consumed = 0;

            try
            {
                if (sslAuthenticationOptions.IsServer)
                {
                    return Unsupported("RinTLS currently exposes a client-only TLS API.");
                }

                bool created = false;
                if (context is null || context.IsInvalid)
                {
                    context = CreateHandle(sslAuthenticationOptions);
                    created = true;
                }

                RinSslHandle handle = GetHandle(context);
                if (!handle.ClientCertificateConfigured &&
                    ((created && sslAuthenticationOptions.CertificateContext is not null) ||
                     Interop.RinTls.ClientCertificateRequested(handle)))
                {
                    TryUpdateClintCertificate(null, handle, sslAuthenticationOptions);
                }
                int result;
                if (Interop.RinTls.IsClosed(handle))
                {
                    result = Interop.RinTls.PendingOutputLength(handle) != 0
                        ? 0 : -6;
                }
                else
                {
                    result = Interop.RinTls.Handshake(handle, inputBuffer,
                                                      out consumed);
                }

                consumed = Math.Clamp(consumed, 0, inputBuffer.Length);
                DrainOutput(handle, ref token);
                token.Status = MapNativeError(result, handle);
            }
            catch (Exception ex) when (ex is not ArgumentException)
            {
                token.Status = new SecurityStatusPal(
                    SecurityStatusPalErrorCode.InternalError, ex);
            }

            return token;
        }

        public static SecurityStatusPal ApplyAlertToken(
            SafeDeleteContext? _, TlsAlertType __, TlsAlertMessage ___)
            => new SecurityStatusPal(SecurityStatusPalErrorCode.OK);

        public static SecurityStatusPal ApplyShutdownToken(
            SafeDeleteSslContext securityContext)
        {
            try
            {
                RinSslHandle handle = GetHandle(securityContext);
                int result = Interop.RinTls.Shutdown(handle);
                return MapNativeError(result, handle);
            }
            catch (Exception ex)
            {
                return new SecurityStatusPal(
                    SecurityStatusPalErrorCode.InternalError, ex);
            }
        }

        private static RinSslHandle CreateHandle(
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            X509ChainPolicy? chainPolicy =
                sslAuthenticationOptions.CertificateChainPolicy;
            if (string.IsNullOrEmpty(sslAuthenticationOptions.TargetHost))
            {
                throw new AuthenticationException(
                    "RinTLS requires a target host for certificate verification.");
            }
            if (!sslAuthenticationOptions.CheckCertName)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS does not support disabling hostname verification.");
            }
            if (sslAuthenticationOptions.CipherSuitesPolicy is not null)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS does not expose a managed cipher-suite policy yet.");
            }
            if (sslAuthenticationOptions.CertificateRevocationCheckMode != X509RevocationMode.NoCheck)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS certificate revocation checking is not available yet.");
            }
            if (sslAuthenticationOptions.ApplicationProtocols is { Count: > 0 } protocols)
            {
                foreach (SslApplicationProtocol protocol in protocols)
                {
                    if (protocol != SslApplicationProtocol.Http11)
                    {
                        throw new PlatformNotSupportedException(
                            "RinTLS supports only the HTTP/1.1 ALPN protocol.");
                    }
                }
            }

            uint options = GetRinTlsOptions(sslAuthenticationOptions.EnabledSslProtocols);
            ulong trustedTime = GetTrustedUnixTime(chainPolicy);
            IntPtr raw = Interop.RinTls.Create(
                TargetHostNameHelper.NormalizeHostName(sslAuthenticationOptions.TargetHost),
                options, trustedTime,
                out int error);
            if (raw == IntPtr.Zero)
            {
                throw new RinTlsException(error);
            }

            RinSslHandle handle = new RinSslHandle(raw);
            try
            {
                bool useCustomTrust = chainPolicy?.TrustMode ==
                    X509ChainTrustMode.CustomRootTrust;
                byte[] trust = useCustomTrust
                    ? BuildCustomTrustBundle(chainPolicy!.CustomTrustStore)
                    : File.ReadAllBytes(TrustStorePath);
                try
                {
                    if (trust.Length > MaxTrustStoreBytes)
                    {
                        throw new AuthenticationException("RinTLS trust bundle is too large.");
                    }

                    int result = Interop.RinTls.LoadTrustStore(handle, trust);
                    if (result != 0)
                    {
                        throw new RinTlsException(result);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(trust);
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        private static ulong GetTrustedUnixTime(X509ChainPolicy? chainPolicy)
        {
            DateTime verificationTime = chainPolicy?.VerificationTime ?? DateTime.UtcNow;
            long unixTime = new DateTimeOffset(
                verificationTime.ToUniversalTime()).ToUnixTimeSeconds();
            if (unixTime <= 0 || unixTime > MaxTrustedUnixTime)
            {
                throw new AuthenticationException(
                    "RinTLS certificate verification time is outside the supported range.");
            }

            return (ulong)unixTime;
        }

        private static byte[] BuildCustomTrustBundle(
            X509Certificate2Collection certificates)
        {
            if (certificates.Count == 0)
            {
                throw new AuthenticationException(
                    "RinTLS CustomRootTrust requires at least one trust anchor.");
            }
            if (certificates.Count > MaxCustomTrustAnchors)
            {
                throw new AuthenticationException(
                    "RinTLS CustomRootTrust exceeds the trust-anchor limit.");
            }

            byte[][] rawCertificates = new byte[certificates.Count][];
            int bundleLength = 8;
            for (int i = 0; i < rawCertificates.Length; i++)
            {
                byte[] raw = certificates[i].RawData;
                if (raw.Length == 0 || raw.Length > ushort.MaxValue)
                {
                    throw new AuthenticationException(
                        "RinTLS received an invalid custom trust anchor.");
                }

                rawCertificates[i] = raw;
                bundleLength = checked(bundleLength + 4 + raw.Length);
                if (bundleLength > MaxTrustStoreBytes)
                {
                    throw new AuthenticationException(
                        "RinTLS custom trust bundle is too large.");
                }
            }

            byte[] bundle = new byte[bundleLength];
            bundle[0] = (byte)'R';
            bundle[1] = (byte)'C';
            bundle[2] = (byte)'A';
            bundle[3] = (byte)'1';
            WriteUInt32LittleEndian(bundle, 4, rawCertificates.Length);

            int offset = 8;
            foreach (byte[] raw in rawCertificates)
            {
                WriteUInt32LittleEndian(bundle, offset, raw.Length);
                offset += 4;
                raw.AsSpan().CopyTo(bundle.AsSpan(offset));
                offset += raw.Length;
            }

            return bundle;
        }

        private static void WriteUInt32LittleEndian(
            Span<byte> destination, int offset, int value)
        {
            destination[offset] = (byte)value;
            destination[offset + 1] = (byte)(value >> 8);
            destination[offset + 2] = (byte)(value >> 16);
            destination[offset + 3] = (byte)(value >> 24);
        }

        private static uint GetRinTlsOptions(SslProtocols protocols)
        {
            if (protocols == SslProtocols.None)
            {
                return 0;
            }

            const SslProtocols supported = SslProtocols.Tls12 | SslProtocols.Tls13;
            if ((protocols & ~supported) != 0)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS supports only TLS 1.2 and TLS 1.3.");
            }

            bool tls12 = (protocols & SslProtocols.Tls12) != 0;
            bool tls13 = (protocols & SslProtocols.Tls13) != 0;
            return tls12 == tls13 ? 0 : tls12 ? 0x0002u : 0x0004u;
        }

        private static void DrainOutput(RinSslHandle handle, ref ProtocolToken token)
        {
            int pending = Interop.RinTls.PendingOutputLength(handle);
            if (pending <= 0)
            {
                return;
            }

            token.EnsureAvailableSpace(pending);
            int read = Interop.RinTls.ReadOutput(handle,
                                                  token.AvailableSpan.Slice(0, pending));
            if (read < 0)
            {
                throw new RinTlsException(read);
            }
            token.Size += read;
        }

        private static RinSslHandle GetHandle(SafeDeleteSslContext context)
            => context as RinSslHandle ?? throw new InvalidHandleException();

        private static SecurityStatusPal MapNativeError(int error,
                                                         RinSslHandle handle)
        {
            return error switch
            {
                0 => new SecurityStatusPal(SecurityStatusPalErrorCode.OK),
                -10 or -11 => new SecurityStatusPal(SecurityStatusPalErrorCode.ContinueNeeded),
                -13 => new SecurityStatusPal(SecurityStatusPalErrorCode.CredentialsNeeded),
                -6 => new SecurityStatusPal(SecurityStatusPalErrorCode.ContextExpired),
                -4 or -12 => new SecurityStatusPal(
                    SecurityStatusPalErrorCode.UntrustedRoot,
                    new RinTlsException(error)),
                -5 => new SecurityStatusPal(
                    SecurityStatusPalErrorCode.WrongPrincipal,
                    new RinTlsException(error)),
                -8 => new SecurityStatusPal(
                    SecurityStatusPalErrorCode.DecryptFailure,
                    new RinTlsException(error)),
                _ => new SecurityStatusPal(
                    SecurityStatusPalErrorCode.InternalError,
                    new RinTlsException(Interop.RinTls.GetError(handle)))
            };
        }

        private static ProtocolToken Unsupported(string message)
            => new ProtocolToken
            {
                Status = new SecurityStatusPal(
                    SecurityStatusPalErrorCode.Unsupported,
                    new PlatformNotSupportedException(message))
            };

        private sealed class InvalidHandleException : Exception
        {
            internal InvalidHandleException()
                : base("The TLS context is not a RinTLS context.")
            {
            }
        }

        private sealed class RinTlsException : AuthenticationException
        {
            internal RinTlsException(int errorCode)
                : this(errorCode, $"RinTLS error {errorCode}.")
            {
            }

            internal RinTlsException(int errorCode, string message)
                : base(message)
            {
                ErrorCode = errorCode;
            }

            internal int ErrorCode { get; }
        }
#pragma warning restore IDE0060
    }
}
