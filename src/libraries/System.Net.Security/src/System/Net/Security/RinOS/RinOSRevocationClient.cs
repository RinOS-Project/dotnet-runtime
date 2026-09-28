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
            X509RevocationMode mode,
            X509RevocationFlag flag,
            TimeSpan timeout)
        {
            if (mode == X509RevocationMode.NoCheck)
            {
                return RinOSRevocationStatus.Good;
            }

            // RinTLS currently exposes a leaf/issuer-bound evidence verifier.
            // Both ExcludeRoot and EndCertificateOnly select the peer leaf in
            // the supported path; the former also describes SslStream's
            // default policy.  Remain fail-closed for a scope that includes
            // an intermediate certificate or for an offline cache lookup.
            if (mode != X509RevocationMode.Online ||
                (flag != X509RevocationFlag.ExcludeRoot &&
                 flag != X509RevocationFlag.EndCertificateOnly))
            {
                return RinOSRevocationStatus.Unknown;
            }

            int timeoutMilliseconds = GetTimeoutMilliseconds(timeout);
            int[] sources = { checked((int)OcspSource), checked((int)CrlSource) };
            foreach (int source in sources)
            {
                string? endpoint = Interop.RinTls.GetPeerRevocationEndpoint(
                    handle, source);
                if (endpoint is null ||
                    !TryFetch(endpoint, (uint)source, timeoutMilliseconds,
                              out byte[] response))
                {
                    continue;
                }

                long sequence = Interlocked.Increment(ref s_nextEvidenceSequence);
                if (sequence <= 0)
                {
                    return RinOSRevocationStatus.Unknown;
                }

                int verifyResult = Interop.RinTls.VerifyPeerRevocation(
                    handle, source, response, (ulong)sequence,
                    out int nativeStatus);
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
                    return RinOSRevocationStatus.Good;
                }
            }

            return RinOSRevocationStatus.Unknown;
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

            try
            {
                using Socket socket = new Socket(
                    AddressFamily.Unix, SocketType.Stream,
                    ProtocolType.Unspecified);
                socket.SendTimeout = timeoutMilliseconds;
                socket.ReceiveTimeout = timeoutMilliseconds;
                socket.Connect(new UnixDomainSocketEndPoint(WorkerdSocketPath));
                SendAll(socket, message);

                byte[] header = new byte[32];
                ReceiveExact(socket, header);
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

                byte[] payload = new byte[checked((int)payloadLength)];
                ReceiveExact(socket, payload);
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
                return true;
            }
            catch (Exception ex) when (
                ex is SocketException ||
                ex is IOException ||
                ex is ObjectDisposedException ||
                ex is InvalidOperationException ||
                ex is PlatformNotSupportedException ||
                ex is ArgumentException)
            {
                return false;
            }
            finally
            {
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

        private static void SendAll(Socket socket, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int sent = socket.Send(buffer, offset, buffer.Length - offset,
                                       SocketFlags.None);
                if (sent <= 0)
                {
                    throw new IOException("workerd closed the revocation request.");
                }

                offset = checked(offset + sent);
            }
        }

        private static void ReceiveExact(Socket socket, byte[] buffer)
        {
            int offset = 0;
            while (offset < buffer.Length)
            {
                int received = socket.Receive(buffer, offset,
                                              buffer.Length - offset,
                                              SocketFlags.None);
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
