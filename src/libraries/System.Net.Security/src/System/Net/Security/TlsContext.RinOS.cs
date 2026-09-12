// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.Security
{
    public sealed partial class TlsContext
    {
        partial void AttachSharedNativeContext(SslAuthenticationOptions sessionOptions)
        {
            // RinTLS contexts are per-session because the product API does not
            // expose a reusable SSL_CTX equivalent.
        }

        partial void DisposeNativeContext()
        {
        }
    }
}
