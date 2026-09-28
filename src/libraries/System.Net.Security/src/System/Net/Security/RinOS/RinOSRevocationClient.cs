// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace System.Net.Security
{
    internal enum RinOSRevocationStatus
    {
        Unknown = 0,
        Good = 1,
        Revoked = 2,
    }

    // The revocation URI is certificate-discovered input.  Only the dedicated
    // workerd command may retrieve it; SslStream never opens an arbitrary
    // HTTP client from inside certificate validation.
    internal static class RinOSRevocationClient
    {
        private const string WorkerdSocketPath = "/run/rin/workerd.sock";
        private const uint WorkerdMagic = 0x57525632u;
        private const uint WorkerdVersion = 3u;
        private const uint FetchRevocationCommand = 4u;
        private const uint OcspSource = 1u;
        private const uint CrlSource = 2u;
        private const int MaxUrlBytes = 256;
        private const int MaxResponseBytes = 256 * 1024;
        private const int DefaultTimeoutMilliseconds = 5000;
        private const int MaximumTimeoutMilliseconds = 30000;
        private static int s_nextRequestId;
        private static long s_nextEvidenceSequence;

        internal static RinOSRevocationStatus CheckPeer(
            RinSslHandle handle,
            X509Chain chain,
            X509RevocationMode mode,
            X509RevocationFlag flag,
            TimeSpan timeout)
        {
            if (mode == X509RevocationMode.NoCheck)
            {
                return RinOSRevocationStatus.Good;
            }

            if (mode != X509RevocationMode.Online ||
                (flag != X509RevocationFlag.ExcludeRoot &&
                 flag != X509RevocationFlag.EndCertificateOnly))
            {
                return RinOSRevocationStatus.Unknown;
            }

            int timeoutMilliseconds = GetTimeoutMilliseconds(timeout);
            int elementCount = chain.ChainElements.Count;
            if (elementCount == 0 || elementCount > 16)
            {
                return RinOSRevocationStatus.Unknown;
            }

            int[] certificateIndexes = new int[elementCount];
            int certificateCount = 0;
            if (flag == X509RevocationFlag.EndCertificateOnly)
            {
                certificateIndexes[certificateCount++] = 0;
            }
            else
            {
                for (int index = 0; index < elementCount; index++)
                {
                    // A self-signed final element is the managed trust anchor,
                    // not a certificate sent by the peer.  It has no adjacent
                    // issuer in the TLS Certificate message and is excluded
                    // by the ExcludeRoot policy.
                    if (index == elementCount - 1 &&
                        IsSelfSigned(chain.ChainElements[index].Certificate))
                    {
                        continue;
                    }

                    certificateIndexes[certificateCount++] = index;
                }
            }

            if (certificateCount == 0)
            {
                return RinOSRevocationStatus.Unknown;
            }

            for (int index = 0; index < certificateCount; index++)
            {
                RinOSRevocationStatus status = CheckCertificate(
                    handle, certificateIndexes[index], timeoutMilliseconds);
                if (status != RinOSRevocationStatus.Good)
                {
                    return status;
                }
            }

            return RinOSRevocationStatus.Good;
        }

        private static RinOSRevocationStatus CheckCertificate(
            RinSslHandle handle, int certificateIndex, int timeoutMilliseconds)
        {
            int[] sources = { checked((int)OcspSource), checked((int)CrlSource) };
            bool sawGood = false;
            foreach (int source in sources)
            {
                string? endpoint;
                try
                {
                    endpoint = Interop.RinTls.GetPeerRevocationEndpoint(
                        handle, certificateIndex, source);
                }
                catch (AuthenticationException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                catch (DllNotFoundException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                catch (EntryPointNotFoundException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                catch (BadImageFormatException)
                {
                    return RinOSRevocationStatus.Unknown;
                }

                if (endpoint is null ||
                    !TryFetch(endpoint, (uint)source, timeoutMilliseconds,
                              out byte[] response))
                {
                    continue;
                }

                try
                {
                    long sequence = Interlocked.Increment(
                        ref s_nextEvidenceSequence);
                    if (sequence <= 0)
                    {
                        return RinOSRevocationStatus.Unknown;
                    }

                    int verifyResult = Interop.RinTls.VerifyPeerRevocation(
                        handle, certificateIndex, source, response,
                        (ulong)sequence, out int nativeStatus);
                    if (verifyResult != 0)
                    {
                        continue;
                    }

                    if (nativeStatus == (int)RinOSRevocationStatus.Revoked)
                    {
                        return RinOSRevocationStatus.Revoked;
                    }

                    if (nativeStatus == (int)RinOSRevocationStatus.Good)
                    {
                        sawGood = true;
                    }
                }
                catch (DllNotFoundException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                catch (EntryPointNotFoundException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                catch (BadImageFormatException)
                {
                    return RinOSRevocationStatus.Unknown;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(response);
                }
            }

            return sawGood
                ? RinOSRevocationStatus.Good
                : RinOSRevocationStatus.Unknown;
        }

        private static bool IsSelfSigned(X509Certificate2 certificate)
        {
            // Matching issuer and subject names means only self-issued.  The
            // final element may be excluded from ExcludeRoot only after the
            // product verifier confirms the certificate signature with its
            // own key; otherwise a same-DN non-self-signed certificate could
            // bypass revocation by being mistaken for the trust anchor.
            if (!certificate.SubjectName.RawData.AsSpan().SequenceEqual(
                    certificate.IssuerName.RawData))
            {
                return false;
            }

            try
            {
                return Interop.RinTls.IsSelfSigned(certificate);
            }
            catch (AuthenticationException)
            {
                return false;
            }
            catch (CryptographicException)
            {
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                return false;
            }
            catch (DllNotFoundException)
            {
                // A missing product crypto library is not evidence that the
                // final certificate is self-signed.  Keep ExcludeRoot
                // fail-closed instead of allowing the anchor to be skipped.
                return false;
            }
            catch (EntryPointNotFoundException)
            {
                // The verifier export is part of the RinOS managed/native
                // contract.  A stale or partial native deployment must not
                // turn a same-DN certificate into an unrevoked root.
                return false;
            }
            catch (BadImageFormatException)
            {
                // Treat an architecture/ABI mismatch like an unavailable
                // verifier and retain the revocation check.
                return false;
            }
        }

        private static int GetTimeoutMilliseconds(TimeSpan timeout)
        {
            if (timeout == TimeSpan.Zero)
            {
                return DefaultTimeoutMilliseconds;
            }

            if (timeout < TimeSpan.Zero ||
                timeout > TimeSpan.FromMilliseconds(MaximumTimeoutMilliseconds))
            {
                return DefaultTimeoutMilliseconds;
            }

            long milliseconds = timeout.Ticks / TimeSpan.TicksPerMillisecond;
            return (int)Math.Clamp(milliseconds, 1,
                                   MaximumTimeoutMilliseconds);
        }

        private static bool TryFetch(
            string url, uint source, int timeoutMilliseconds,
            out byte[] response)
        {
            response = Array.Empty<byte>();
            if (!TryEncodeUrl(url, out byte[] urlBytes) ||
                (source != OcspSource && source != CrlSource))
            {
                return false;
            }

            int requestId = Interlocked.Increment(ref s_nextRequestId);
            if (requestId == 0)
            {
                requestId = Interlocked.Increment(ref s_nextRequestId);
            }

            byte[] message = new byte[32 + 16 + urlBytes.Length];
            WriteUInt32(message, 0, WorkerdMagic);
            WriteUInt32(message, 4, WorkerdVersion);
            WriteUInt32(message, 8, FetchRevocationCommand);
            WriteInt32(message, 12, 0);
            WriteUInt32(message, 16, unchecked((uint)requestId));
            WriteUInt32(message, 20, checked((uint)(16 + urlBytes.Length)));
            WriteUInt32(message, 24, 0);
            WriteUInt32(message, 28, 0);
            WriteUInt32(message, 32, checked((uint)timeoutMilliseconds));
            WriteUInt32(message, 36, source);
            WriteUInt32(message, 40, checked((uint)urlBytes.Length));
            WriteUInt32(message, 44, 0);
            Buffer.BlockCopy(urlBytes, 0, message, 48, urlBytes.Length);

            byte[] payload = Array.Empty<byte>();
            bool responseComplete = false;
            try
            {
                using Socket socket = new Socket(
                    AddressFamily.Unix, SocketType.Stream,
                    ProtocolType.Unspecified);
                socket.SendTimeout = timeoutMilliseconds;
                socket.ReceiveTimeout = timeoutMilliseconds;
                using CancellationTokenSource operationCancellation =
                    new CancellationTokenSource(timeoutMilliseconds);
                socket.ConnectAsync(
                    new UnixDomainSocketEndPoint(WorkerdSocketPath),
                    operationCancellation.Token).GetAwaiter().GetResult();
                SendAll(socket, message, operationCancellation.Token);

                byte[] header = new byte[32];
                ReceiveExact(socket, header, operationCancellation.Token);
                if (ReadUInt32(header, 0) != WorkerdMagic ||
                    ReadUInt32(header, 4) != WorkerdVersion ||
                    ReadUInt32(header, 8) != FetchRevocationCommand ||
                    ReadInt32(header, 12) != 0 ||
                    ReadUInt32(header, 16) != unchecked((uint)requestId))
                {
                    return false;
                }

                uint payloadLength = ReadUInt32(header, 20);
                if (payloadLength < 16u ||
                    payloadLength > 16u + (uint)MaxResponseBytes)
                {
                    return false;
                }

                payload = new byte[checked((int)payloadLength)];
                ReceiveExact(socket, payload, operationCancellation.Token);
                int statusCode = ReadInt32(payload, 0);
                uint transferComplete = ReadUInt32(payload, 4);
                uint success = ReadUInt32(payload, 8);
                uint bodyLength = ReadUInt32(payload, 12);
                if (statusCode < 200 || statusCode >= 300 ||
                    transferComplete != 1u || success != 1u ||
                    bodyLength == 0u || bodyLength > (uint)MaxResponseBytes ||
                    payloadLength != 16u + bodyLength)
                {
                    return false;
                }

                response = new byte[checked((int)bodyLength)];
                Buffer.BlockCopy(payload, 16, response, 0, response.Length);
                responseComplete = true;
                return true;
            }
            catch (Exception ex) when (
                ex is SocketException ||
                ex is IOException ||
                ex is ObjectDisposedException ||
                ex is InvalidOperationException ||
                ex is PlatformNotSupportedException ||
                ex is ArgumentException ||
                ex is OperationCanceledException)
            {
                return false;
            }
            finally
            {
                if (!responseComplete && response.Length != 0)
                {
                    CryptographicOperations.ZeroMemory(response);
                    response = Array.Empty<byte>();
                }
                CryptographicOperations.ZeroMemory(payload);
                CryptographicOperations.ZeroMemory(urlBytes);
                CryptographicOperations.ZeroMemory(message);
            }
        }

        private static bool TryEncodeUrl(string url, out byte[] bytes)
        {
            bytes = Array.Empty<byte>();
            if (string.IsNullOrEmpty(url) || url.Length > MaxUrlBytes)
            {
                return false;
            }

            foreach (char value in url)
            {
                if (value <= 0x20 || value >= 0x7f)
                {
                    return false;
                }
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed) ||
                (parsed.Scheme != Uri.UriSchemeHttp &&
                 parsed.Scheme != Uri.UriSchemeHttps) ||
                string.IsNullOrEmpty(parsed.Host))
            {
                return false;
            }

            bytes = Encoding.ASCII.GetBytes(url);
            return bytes.Length != 0 && bytes.Length <= MaxUrlBytes;
        }

        private static void SendAll(
            Socket socket, byte[] buffer, CancellationToken cancellationToken)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int sent = socket.SendAsync(
                    buffer.AsMemory(offset), SocketFlags.None,
                    cancellationToken).GetAwaiter().GetResult();
                if (sent <= 0)
                {
                    throw new IOException("workerd closed the revocation request.");
                }

                offset = checked(offset + sent);
            }
        }

        private static void ReceiveExact(
            Socket socket, byte[] buffer, CancellationToken cancellationToken)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int received = socket.ReceiveAsync(
                    buffer.AsMemory(offset), SocketFlags.None,
                    cancellationToken).GetAwaiter().GetResult();
                if (received <= 0)
                {
                    throw new IOException("workerd truncated the revocation response.");
                }

                offset = checked(offset + received);
            }
        }

        private static uint ReadUInt32(byte[] buffer, int offset)
            => (uint)(buffer[offset] |
                      (buffer[offset + 1] << 8) |
                      (buffer[offset + 2] << 16) |
                      (buffer[offset + 3] << 24));

        private static int ReadInt32(byte[] buffer, int offset)
            => unchecked((int)ReadUInt32(buffer, offset));

        private static void WriteUInt32(byte[] buffer, int offset, uint value)
        {
            buffer[offset] = (byte)value;
            buffer[offset + 1] = (byte)(value >> 8);
            buffer[offset + 2] = (byte)(value >> 16);
            buffer[offset + 3] = (byte)(value >> 24);
        }

        private static void WriteInt32(byte[] buffer, int offset, int value)
            => WriteUInt32(buffer, offset, unchecked((uint)value));
    }
}
