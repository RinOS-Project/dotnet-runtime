// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal sealed class RinSslHandle : SafeDeleteSslContext
    {
        private GCHandle _clientCertificateState;
        private bool _clientCertificateConfigured;

        internal RinSslHandle(IntPtr handle)
            : base(handle, ownsHandle: true)
        {
        }

        internal bool ClientCertificateConfigured => _clientCertificateConfigured;

        internal IntPtr AttachClientCertificateState(object state)
        {
            if (_clientCertificateState.IsAllocated)
            {
                throw new InvalidOperationException(
                    "RinTLS client certificate state is already attached.");
            }

            _clientCertificateState = GCHandle.Alloc(state);
            return GCHandle.ToIntPtr(_clientCertificateState);
        }

        internal void MarkClientCertificateConfigured()
            => _clientCertificateConfigured = true;

        private void ReleaseClientCertificateState()
        {
            if (_clientCertificateState.IsAllocated)
            {
                _clientCertificateState.Free();
            }
        }

        protected override bool ReleaseHandle()
        {
            Interop.RinTls.Destroy(this);
            ReleaseClientCertificateState();
            SetHandle(IntPtr.Zero);
            return true;
        }
    }
}
