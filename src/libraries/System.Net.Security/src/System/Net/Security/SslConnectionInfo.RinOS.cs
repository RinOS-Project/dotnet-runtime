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
            // RinTLS currently has no ALPN or session-resumption API.  Keeping
            // ApplicationProtocol null accurately reports that limitation.
        }
    }
}
