// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Authentication.ExtendedProtection;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    internal static class SslStreamPal
    {
        private const string TrustStorePath = "/System/Trust/roots.rinca";
        private const int MaxTrustStoreBytes = 4 * 1024 * 1024;

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
            SafeFreeCredentials? _, SafeDeleteSslContext? __,
            SslAuthenticationOptions sslAuthenticationOptions)
        {
            if (sslAuthenticationOptions.CertificateContext is not null ||
                (sslAuthenticationOptions.ClientCertificates?.Count ?? 0) != 0 ||
                sslAuthenticationOptions.CertSelectionDelegate is not null)
            {
                throw new PlatformNotSupportedException(
                    "RinTLS client-certificate callbacks are not connected to SslStream.");
            }

            return false;
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

                if (context is null || context.IsInvalid)
                {
                    context = CreateHandle(sslAuthenticationOptions);
                }

                RinSslHandle handle = GetHandle(context);
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
            if (sslAuthenticationOptions.CertificateChainPolicy is not null &&
                (sslAuthenticationOptions.CertificateChainPolicy.CustomTrustStore.Count != 0 ||
                 sslAuthenticationOptions.CertificateChainPolicy.TrustMode == X509ChainTrustMode.CustomRootTrust))
            {
                throw new PlatformNotSupportedException(
                    "RinTLS uses the product trust bundle; custom managed roots are not connected yet.");
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
            IntPtr raw = Interop.RinTls.Create(
                TargetHostNameHelper.NormalizeHostName(sslAuthenticationOptions.TargetHost),
                options, checked((ulong)DateTimeOffset.UtcNow.ToUnixTimeSeconds()),
                out int error);
            if (raw == IntPtr.Zero)
            {
                throw new RinTlsException(error);
            }

            RinSslHandle handle = new RinSslHandle(raw);
            try
            {
                byte[] trust = File.ReadAllBytes(TrustStorePath);
                if (trust.Length > MaxTrustStoreBytes)
                {
                    throw new AuthenticationException("RinTLS trust bundle is too large.");
                }

                int result = Interop.RinTls.LoadTrustStore(handle, trust);
                if (result != 0)
                {
                    throw new RinTlsException(result);
                }
                return handle;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
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
