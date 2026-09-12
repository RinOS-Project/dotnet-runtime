// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Authentication;

namespace System.Net.Security
{
    internal partial struct SslConnectionInfo
    {
        public void UpdateSslConnectionInfo(RinSslHandle sslContext)
        {
            Protocol = Interop.RinTls.GetVersion(sslContext) switch
            {
                0x0303 => (int)SslProtocols.Tls12,
                0x0304 => (int)SslProtocols.Tls13,
                _ => (int)SslProtocols.None
            };

            MapCipherSuite((TlsCipherSuite)Interop.RinTls.GetCipherSuite(sslContext));

            int alpnResult = Interop.RinTls.GetApplicationProtocolLength(
                sslContext, out int alpnLength);
            if (alpnResult != 0 || alpnLength < 0)
            {
                throw new AuthenticationException(
                    "RinTLS could not read the negotiated application protocol.");
            }

            if (alpnLength != 0)
            {
                byte[] alpn = new byte[alpnLength];
                alpnResult = Interop.RinTls.CopyApplicationProtocol(sslContext,
                                                                      alpn);
                if (alpnResult != 0)
                {
                    throw new AuthenticationException(
                        "RinTLS could not copy the negotiated application protocol.");
                }
                ApplicationProtocol = alpn;
            }
        }
    }
}
