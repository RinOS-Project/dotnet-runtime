// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Net.Security
{
    internal sealed class RinSslHandle : SafeDeleteSslContext
    {
        internal RinSslHandle(IntPtr handle)
            : base(handle, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle()
        {
            Interop.RinTls.Destroy(this);
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}
