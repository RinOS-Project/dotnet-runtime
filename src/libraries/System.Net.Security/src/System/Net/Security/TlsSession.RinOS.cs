// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Microsoft.Win32.SafeHandles;

namespace System.Net.Security
{
    public partial class TlsSession
    {
        partial void EnableNativeSocketBinding(SafeSocketHandle socket,
                                                ref bool nativeBindingEnabled)
        {
            // RinTLS is deliberately driven through the buffered PAL. The
            // managed Socket remains the sole owner of transport I/O.
            nativeBindingEnabled = false;
        }

        partial void TryFastHandshake(ref TlsOperationStatus? result)
        {
        }

        partial void TryPeekClientHello(ref TlsOperationStatus? result)
        {
        }

        partial void TryFastRead(Span<byte> buffer, ref int bytesRead,
                                 ref TlsOperationStatus? result)
        {
        }

        partial void TryFastWrite(ReadOnlySpan<byte> buffer, ref int bytesWritten,
                                  ref TlsOperationStatus? result)
        {
        }

        partial void OnServerContextSet()
        {
        }

        partial void OnDispose()
        {
        }

        partial void TryGetNativeClientHelloBytes(ref ReadOnlySpan<byte> bytes)
        {
        }
    }
}
