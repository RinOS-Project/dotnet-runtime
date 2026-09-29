// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;

namespace System.Net.Security
{
    internal sealed class RinSslHandle : SafeDeleteSslContext
    {
        private GCHandle _certificateSignerState;
        private bool _clientCertificateConfigured;
        private readonly ulong _trustedUnixTime;

        internal RinSslHandle(IntPtr handle, ulong trustedUnixTime)
            : base(handle, ownsHandle: true)
        {
            _trustedUnixTime = trustedUnixTime;
        }

        internal bool ClientCertificateConfigured => _clientCertificateConfigured;
        internal ulong TrustedUnixTime => _trustedUnixTime;

        internal IntPtr AttachCertificateSignerState(object state)
        {
            if (_certificateSignerState.IsAllocated)
            {
                throw new InvalidOperationException(
                    "RinTLS certificate signer state is already attached.");
            }

            _certificateSignerState = GCHandle.Alloc(state);
            return GCHandle.ToIntPtr(_certificateSignerState);
        }

        internal void MarkClientCertificateConfigured()
            => _clientCertificateConfigured = true;

        private void ReleaseClientCertificateState()
        {
            if (_certificateSignerState.IsAllocated)
            {
                _certificateSignerState.Free();
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
