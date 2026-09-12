// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
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
                EntryPoint = "CryptoNative_RinTlsLoadTrustStore")]
            private static partial unsafe int LoadTrustStoreNative(
                IntPtr handle, byte* bundle, int bundleLength);

            [LibraryImport(Libraries.CryptoNative,
                EntryPoint = "CryptoNative_RinTlsHandshake")]
            private static partial unsafe int HandshakeNative(
                IntPtr handle, byte* input, int inputLength, out int consumed);

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

            internal static IntPtr Create(string hostname, uint options,
                                          ulong trustedTime, out int error)
                => CreateNative(0, hostname, options, trustedTime, out error);

            internal static void Destroy(RinSslHandle handle)
                => DestroyNative(handle.DangerousGetHandle());

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
        }
    }
}
