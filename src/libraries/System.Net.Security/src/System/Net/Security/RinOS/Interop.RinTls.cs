// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal static partial class Interop
    {
        internal static partial class RinTls
        {
            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsCreate",
                StringMarshalling = StringMarshalling.Utf8)]
            private static partial IntPtr CreateNative(
                int isServer, string hostname, uint options, ulong trustedTime,
                out int error);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsDestroy")]
            private static partial void DestroyNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsSetCipherSuites")]
            private static partial unsafe int SetCipherSuitesNative(
                IntPtr handle, ushort* cipherSuites, int cipherSuiteCount);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsLoadTrustStore")]
            private static partial unsafe int LoadTrustStoreNative(
                IntPtr handle, byte* bundle, int bundleLength);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsHandshake")]
            private static partial unsafe int HandshakeNative(
                IntPtr handle, byte* input, int inputLength, out int consumed);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsSetClientCertificate")]
            private static partial unsafe int SetClientCertificateNative(
                IntPtr handle, byte* certificateList, int certificateListLength,
                IntPtr signer, IntPtr signerOpaque);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsClientCertificateRequested")]
            private static partial int ClientCertificateRequestedNative(
                IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsPendingOutputLength")]
            private static partial int PendingOutputLengthNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsReadOutput")]
            private static partial unsafe int ReadOutputNative(
                IntPtr handle, byte* destination, int capacity);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsEncrypt")]
            private static partial unsafe int EncryptNative(
                IntPtr handle, byte* plaintext, int plaintextLength,
                out int consumed);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsDecrypt")]
            private static partial unsafe int DecryptNative(
                IntPtr handle, byte* encrypted, int encryptedLength,
                byte* plaintext, int plaintextCapacity, out int consumed,
                out int written);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsShutdown")]
            private static partial int ShutdownNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsIsClosed")]
            private static partial int IsClosedNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetVersion")]
            private static partial int GetVersionNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetCipherSuite")]
            private static partial int GetCipherSuiteNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetApplicationProtocolLength")]
            private static partial int GetApplicationProtocolLengthNative(
                IntPtr handle, out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsCopyApplicationProtocol")]
            private static partial unsafe int CopyApplicationProtocolNative(
                IntPtr handle, byte* destination, int capacity);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetError")]
            private static partial int GetErrorNative(IntPtr handle);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetPeerCertificateLength")]
            private static partial int GetPeerCertificateLengthNative(
                IntPtr handle, out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsCopyPeerCertificate")]
            private static partial unsafe int CopyPeerCertificateNative(
                IntPtr handle, byte* destination, int capacity);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetPeerCertificateChainLength")]
            private static partial int GetPeerCertificateChainLengthNative(
                IntPtr handle, out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsCopyPeerCertificateChain")]
            private static partial unsafe int CopyPeerCertificateChainNative(
                IntPtr handle, byte* destination, int capacity);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetPeerRevocationEndpoint")]
            private static partial unsafe int GetPeerRevocationEndpointNative(
                IntPtr handle, int source, byte* destination, int capacity,
                out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsGetPeerRevocationEndpointAt")]
            private static partial unsafe int GetPeerRevocationEndpointAtNative(
                IntPtr handle, int certificateIndex, int source,
                byte* destination, int capacity, out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsVerifyPeerRevocation")]
            private static partial unsafe int VerifyPeerRevocationNative(
                IntPtr handle, int source, byte* response, int responseLength,
                ulong sequence, ulong trustedUnixTime, out int status);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsVerifyPeerRevocationAt")]
            private static partial unsafe int VerifyPeerRevocationAtNative(
                IntPtr handle, int certificateIndex, int source,
                byte* response, int responseLength, ulong sequence,
                ulong trustedUnixTime, out int status);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinOSX509GetRevocationEndpoint")]
            private static partial unsafe int GetCertificateRevocationEndpointNative(
                byte* certificateDer, int certificateLength, int source,
                byte* destination, int capacity, out int length);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinOSX509VerifyRevocation")]
            private static partial unsafe int VerifyCertificateRevocationNative(
                byte* certificateDer, int certificateLength,
                byte* issuerDer, int issuerLength, int source,
                byte* response, int responseLength, ulong trustedUnixTime,
                ulong sequence, out int status);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinOSX509LookupRevocation")]
            private static partial unsafe int LookupCachedRevocationNative(
                byte* certificateDer, int certificateLength,
                byte* issuerDer, int issuerLength, ulong trustedUnixTime,
                out int status);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinOSX509VerifySignature")]
            private static partial unsafe int VerifyCertificateSignatureNative(
                byte* certificateDer, int certificateLength,
                byte* issuerDer, int issuerLength);

            internal static IntPtr Create(string hostname, uint options,
                                          ulong trustedTime, out int error)
                => CreateNative(0, hostname, options, trustedTime, out error);

            internal static void Destroy(RinSslHandle handle)
                => DestroyNative(handle.DangerousGetHandle());

            internal static unsafe int SetCipherSuites(
                RinSslHandle handle, ReadOnlySpan<ushort> cipherSuites)
            {
                fixed (ushort* cipherSuitesPtr = cipherSuites)
                {
                    return SetCipherSuitesNative(handle.DangerousGetHandle(),
                                                 cipherSuitesPtr,
                                                 cipherSuites.Length);
                }
            }

            internal static unsafe int LoadTrustStore(RinSslHandle handle,
                                                       ReadOnlySpan<byte> bundle)
            {
                fixed (byte* bundlePtr = bundle)
                {
                    return LoadTrustStoreNative(handle.DangerousGetHandle(),
                                                bundlePtr, bundle.Length);
                }
            }

            internal static unsafe int Handshake(RinSslHandle handle,
                                                 ReadOnlySpan<byte> input,
                                                 out int consumed)
            {
                fixed (byte* inputPtr = input)
                {
                    return HandshakeNative(handle.DangerousGetHandle(), inputPtr,
                                           input.Length, out consumed);
                }
            }

            internal static unsafe int SetClientCertificate(
                RinSslHandle handle, ReadOnlySpan<byte> certificateList,
                IntPtr signer, IntPtr signerOpaque)
            {
                fixed (byte* listPtr = certificateList)
                {
                    return SetClientCertificateNative(
                        handle.DangerousGetHandle(),
                        certificateList.IsEmpty ? null : listPtr,
                        certificateList.Length, signer, signerOpaque);
                }
            }

            internal static bool ClientCertificateRequested(RinSslHandle handle)
                => ClientCertificateRequestedNative(handle.DangerousGetHandle()) != 0;

            internal static int PendingOutputLength(RinSslHandle handle)
                => PendingOutputLengthNative(handle.DangerousGetHandle());

            internal static unsafe int ReadOutput(RinSslHandle handle,
                                                  Span<byte> destination)
            {
                fixed (byte* destinationPtr = destination)
                {
                    return ReadOutputNative(handle.DangerousGetHandle(),
                                            destinationPtr, destination.Length);
                }
            }

            internal static unsafe int Encrypt(RinSslHandle handle,
                                               ReadOnlySpan<byte> plaintext,
                                               out int consumed)
            {
                fixed (byte* plaintextPtr = plaintext)
                {
                    return EncryptNative(handle.DangerousGetHandle(), plaintextPtr,
                                         plaintext.Length, out consumed);
                }
            }

            internal static unsafe int Decrypt(RinSslHandle handle,
                                               ReadOnlySpan<byte> encrypted,
                                               Span<byte> plaintext,
                                               out int consumed, out int written)
            {
                fixed (byte* encryptedPtr = encrypted)
                fixed (byte* plaintextPtr = plaintext)
                {
                    return DecryptNative(handle.DangerousGetHandle(), encryptedPtr,
                                         encrypted.Length, plaintextPtr,
                                         plaintext.Length, out consumed, out written);
                }
            }

            internal static int Shutdown(RinSslHandle handle)
                => ShutdownNative(handle.DangerousGetHandle());

            internal static bool IsClosed(RinSslHandle handle)
                => IsClosedNative(handle.DangerousGetHandle()) != 0;

            internal static int GetVersion(RinSslHandle handle)
                => GetVersionNative(handle.DangerousGetHandle());

            internal static int GetCipherSuite(RinSslHandle handle)
                => GetCipherSuiteNative(handle.DangerousGetHandle());

            internal static int GetApplicationProtocolLength(RinSslHandle handle,
                                                              out int length)
                => GetApplicationProtocolLengthNative(handle.DangerousGetHandle(),
                                                       out length);

            internal static unsafe int CopyApplicationProtocol(
                RinSslHandle handle, Span<byte> destination)
            {
                fixed (byte* destinationPtr = destination)
                {
                    return CopyApplicationProtocolNative(handle.DangerousGetHandle(),
                                                         destinationPtr,
                                                         destination.Length);
                }
            }

            internal static int GetError(RinSslHandle handle)
                => GetErrorNative(handle.DangerousGetHandle());

            internal static int GetPeerCertificateLength(RinSslHandle handle,
                                                         out int length)
                => GetPeerCertificateLengthNative(handle.DangerousGetHandle(),
                                                  out length);

            internal static unsafe int CopyPeerCertificate(RinSslHandle handle,
                                                            Span<byte> destination)
            {
                fixed (byte* destinationPtr = destination)
                {
                    return CopyPeerCertificateNative(handle.DangerousGetHandle(),
                                                     destinationPtr,
                                                     destination.Length);
                }
            }

            internal static int GetPeerCertificateChainLength(RinSslHandle handle,
                                                               out int length)
                => GetPeerCertificateChainLengthNative(handle.DangerousGetHandle(),
                                                       out length);

            internal static unsafe int CopyPeerCertificateChain(
                RinSslHandle handle, Span<byte> destination)
            {
                fixed (byte* destinationPtr = destination)
                {
                    return CopyPeerCertificateChainNative(
                        handle.DangerousGetHandle(), destinationPtr,
                        destination.Length);
                }
            }

            internal static unsafe string? GetPeerRevocationEndpoint(
                RinSslHandle handle, int source)
            {
                Span<byte> endpoint = stackalloc byte[256];
                fixed (byte* endpointPtr = endpoint)
                {
                    int result = GetPeerRevocationEndpointNative(
                        handle.DangerousGetHandle(), source, endpointPtr,
                        endpoint.Length, out int length);
                    if (result != 0)
                    {
                        throw new AuthenticationException(
                            "RinTLS could not expose the peer revocation endpoint.");
                    }

                    if (length == 0)
                    {
                        return null;
                    }

                    if ((uint)length >= (uint)endpoint.Length)
                    {
                        throw new AuthenticationException(
                            "RinTLS returned an invalid revocation endpoint length.");
                    }

                    return System.Text.Encoding.ASCII.GetString(
                        endpoint.Slice(0, length));
                }
            }

            internal static unsafe string? GetPeerRevocationEndpoint(
                RinSslHandle handle, int certificateIndex, int source)
            {
                Span<byte> endpoint = stackalloc byte[256];
                fixed (byte* endpointPtr = endpoint)
                {
                    int result = GetPeerRevocationEndpointAtNative(
                        handle.DangerousGetHandle(), certificateIndex, source,
                        endpointPtr, endpoint.Length, out int length);
                    if (result != 0)
                    {
                        throw new AuthenticationException(
                            "RinTLS could not expose the peer revocation endpoint.");
                    }

                    if (length == 0)
                    {
                        return null;
                    }

                    if ((uint)length >= (uint)endpoint.Length)
                    {
                        throw new AuthenticationException(
                            "RinTLS returned an invalid revocation endpoint length.");
                    }

                    return System.Text.Encoding.ASCII.GetString(
                        endpoint.Slice(0, length));
                }
            }

            internal static unsafe int VerifyPeerRevocation(
                RinSslHandle handle, int source, ReadOnlySpan<byte> response,
                ulong sequence, ulong trustedUnixTime, out int status)
            {
                fixed (byte* responsePtr = response)
                {
                    return VerifyPeerRevocationNative(
                        handle.DangerousGetHandle(), source,
                        response.IsEmpty ? null : responsePtr, response.Length,
                        sequence, trustedUnixTime, out status);
                }
            }

            internal static unsafe int VerifyPeerRevocation(
                RinSslHandle handle, int certificateIndex, int source,
                ReadOnlySpan<byte> response, ulong sequence,
                ulong trustedUnixTime, out int status)
            {
                fixed (byte* responsePtr = response)
                {
                    return VerifyPeerRevocationAtNative(
                        handle.DangerousGetHandle(), certificateIndex, source,
                        response.IsEmpty ? null : responsePtr, response.Length,
                        sequence, trustedUnixTime, out status);
                }
            }

            internal static unsafe string? GetCertificateRevocationEndpoint(
                X509Certificate2 certificate, int source)
            {
                ArgumentNullException.ThrowIfNull(certificate);
                byte[] der = certificate.RawData;
                if (der.Length == 0 || der.Length > 8 * 1024)
                {
                    throw new AuthenticationException(
                        "RinTLS certificate exceeds the revocation size limit.");
                }

                Span<byte> endpoint = stackalloc byte[256];
                fixed (byte* derPtr = der)
                fixed (byte* endpointPtr = endpoint)
                {
                    int result = GetCertificateRevocationEndpointNative(
                        derPtr, der.Length, source, endpointPtr,
                        endpoint.Length, out int length);
                    if (result != 0)
                    {
                        throw new AuthenticationException(
                            "RinTLS could not expose the certificate revocation endpoint.");
                    }

                    if (length == 0)
                    {
                        return null;
                    }

                    if ((uint)length >= (uint)endpoint.Length)
                    {
                        throw new AuthenticationException(
                            "RinTLS returned an invalid certificate revocation endpoint length.");
                    }

                    return System.Text.Encoding.ASCII.GetString(
                        endpoint.Slice(0, length));
                }
            }

            internal static unsafe int VerifyCertificateRevocation(
                X509Certificate2 certificate, X509Certificate2 issuer,
                int source, ReadOnlySpan<byte> response, ulong trustedUnixTime,
                ulong sequence, out int status)
            {
                ArgumentNullException.ThrowIfNull(certificate);
                ArgumentNullException.ThrowIfNull(issuer);
                byte[] certificateDer = certificate.RawData;
                byte[] issuerDer = issuer.RawData;
                if (certificateDer.Length == 0 || certificateDer.Length > 8 * 1024 ||
                    issuerDer.Length == 0 || issuerDer.Length > 8 * 1024)
                {
                    status = 0;
                    return -1;
                }
                fixed (byte* certificatePtr = certificateDer)
                fixed (byte* issuerPtr = issuerDer)
                fixed (byte* responsePtr = response)
                {
                    return VerifyCertificateRevocationNative(
                        certificatePtr, certificateDer.Length, issuerPtr,
                        issuerDer.Length, source,
                        response.IsEmpty ? null : responsePtr, response.Length,
                        trustedUnixTime, sequence, out status);
                }
            }

            internal static unsafe int LookupCachedRevocation(
                X509Certificate2 certificate, X509Certificate2 issuer,
                ulong trustedUnixTime, out int status)
            {
                ArgumentNullException.ThrowIfNull(certificate);
                ArgumentNullException.ThrowIfNull(issuer);
                byte[] certificateDer = certificate.RawData;
                byte[] issuerDer = issuer.RawData;
                if (certificateDer.Length == 0 || certificateDer.Length > 8 * 1024 ||
                    issuerDer.Length == 0 || issuerDer.Length > 8 * 1024)
                {
                    status = 0;
                    return -1;
                }

                fixed (byte* certificatePtr = certificateDer)
                fixed (byte* issuerPtr = issuerDer)
                {
                    return LookupCachedRevocationNative(
                        certificatePtr, certificateDer.Length, issuerPtr,
                        issuerDer.Length, trustedUnixTime, out status);
                }
            }

            internal static unsafe bool IsSelfSigned(X509Certificate2 certificate)
            {
                ArgumentNullException.ThrowIfNull(certificate);
                byte[] der = certificate.RawData;
                if (der.Length == 0 || der.Length > 8 * 1024)
                {
                    return false;
                }

                fixed (byte* derPtr = der)
                {
                    return VerifyCertificateSignatureNative(
                        derPtr, der.Length, derPtr, der.Length) != 0;
                }
            }
        }
    }
}
