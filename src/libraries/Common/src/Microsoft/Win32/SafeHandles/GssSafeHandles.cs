// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
    /// <summary>
    /// Wrapper around a gss_name_t_desc*
    /// </summary>
    internal sealed class SafeGssNameHandle : SafeHandle
    {
        public static SafeGssNameHandle CreateUser(string name)
        {
            Debug.Assert(!string.IsNullOrEmpty(name), "Invalid user name passed to SafeGssNameHandle create");
            SafeGssNameHandle retHandle;
            Interop.NetSecurityNative.Status minorStatus;
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.ImportUserName(
                out minorStatus, name, Encoding.UTF8.GetByteCount(name), out retHandle);

            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                retHandle.Dispose();
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        public static SafeGssNameHandle CreateTarget(string name)
        {
            Debug.Assert(!string.IsNullOrEmpty(name), "Invalid target name passed to SafeGssNameHandle create");
            SafeGssNameHandle retHandle;
            Interop.NetSecurityNative.Status minorStatus;
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.ImportPrincipalName(
                out minorStatus, name, Encoding.UTF8.GetByteCount(name), out retHandle);

            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                retHandle.Dispose();
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.ReleaseName(out _, ref handle);
            if (status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                SetHandle(IntPtr.Zero);
                return true;
            }

            // Keep a provider-owned name live when the native boundary could
            // not consume it.  This is the same retryable SafeHandle contract
            // used by credentials and security contexts; clearing the handle
            // here would orphan an opaque allocation after a transient PAL
            // or provider failure.
            return false;
        }

        public SafeGssNameHandle()
            : base(IntPtr.Zero, true)
        {
        }
    }

    /// <summary>
    /// Wrapper around a gss_cred_id_t_desc_struct*
    /// </summary>
    internal sealed class SafeGssCredHandle : SafeHandle
    {
        private static readonly Lazy<bool> s_IsNtlmInstalled = new Lazy<bool>(InitIsNtlmInstalled);

        public static SafeGssCredHandle CreateAcceptor()
        {
            SafeGssCredHandle? retHandle;
            Interop.NetSecurityNative.Status status;
            Interop.NetSecurityNative.Status minorStatus;

            status = Interop.NetSecurityNative.AcquireAcceptorCred(out minorStatus, out retHandle);
            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                // The native PAL may retain a provider handle when owner
                // cleanup failed transiently. Dispose it here so a failed
                // acquisition does not strand a retryable opaque handle.
                retHandle?.Dispose();
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        /// <summary>
        /// Acquires the provider's authenticated session-bound default
        /// initiator credential. This is the only path which may omit a
        /// desired name; the native provider resolves the live session owner.
        /// </summary>
        public static SafeGssCredHandle CreateDefault(Interop.NetSecurityNative.PackageType packageType)
        {
            if (packageType == Interop.NetSecurityNative.PackageType.NTLM && !s_IsNtlmInstalled.Value)
            {
                throw new Interop.NetSecurityNative.GssApiException(
                    Interop.NetSecurityNative.Status.GSS_S_BAD_MECH,
                    0,
                    SR.net_gssapi_ntlm_missing_plugin);
            }

            SafeGssCredHandle? retHandle;
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.InitiateCredSpNego(
                out Interop.NetSecurityNative.Status minorStatus, null, out retHandle);
            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                retHandle?.Dispose();
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        /// <summary>
        /// Returns the handle for explicitly supplied credentials. An empty
        /// name is not an alias for DefaultCredentials: callers must select
        /// the session-bound CreateDefault path explicitly.
        /// </summary>
        public static SafeGssCredHandle Create(string username, string password, Interop.NetSecurityNative.PackageType packageType)
        {
            if (packageType == Interop.NetSecurityNative.PackageType.NTLM && !s_IsNtlmInstalled.Value)
            {
                throw new Interop.NetSecurityNative.GssApiException(
                    Interop.NetSecurityNative.Status.GSS_S_BAD_MECH,
                    0,
                    SR.net_gssapi_ntlm_missing_plugin);
            }

            if (string.IsNullOrEmpty(username))
            {
                throw new Interop.NetSecurityNative.GssApiException(
                    Interop.NetSecurityNative.Status.GSS_S_BAD_NAME, 0);
            }

            SafeGssCredHandle? retHandle = null;
            Interop.NetSecurityNative.Status status;
            Interop.NetSecurityNative.Status minorStatus;

            using SafeGssNameHandle userHandle = SafeGssNameHandle.CreateUser(username);
            if (string.IsNullOrEmpty(password))
            {
                status = Interop.NetSecurityNative.InitiateCredSpNego(
                    out minorStatus, userHandle, out retHandle);
            }
            else
            {
                status = Interop.NetSecurityNative.InitiateCredWithPassword(
                    out minorStatus, packageType, userHandle, password,
                    Encoding.UTF8.GetByteCount(password), out retHandle);
            }

            if (status != Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                retHandle?.Dispose();
                throw new Interop.NetSecurityNative.GssApiException(status, minorStatus);
            }

            return retHandle;
        }

        public SafeGssCredHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override bool ReleaseHandle()
        {
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.ReleaseCred(out _, ref handle);
            if (status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                SetHandle(IntPtr.Zero);
                return true;
            }

            // A live opaque handle means the owner rejected cleanup without
            // consuming it. Keep the SafeHandle non-invalid so its retryable
            // release contract is not converted into a leak.
            return false;
        }

        private static bool InitIsNtlmInstalled()
        {
            return Interop.NetSecurityNative.IsNtlmInstalled();
        }
    }

    internal sealed class SafeGssContextHandle : SafeHandle
    {
        public SafeGssContextHandle()
            : base(IntPtr.Zero, true)
        {
        }

        public override bool IsInvalid
        {
            get { return handle == IntPtr.Zero; }
        }

        protected override unsafe bool ReleaseHandle()
        {
            Interop.NetSecurityNative.Status status = Interop.NetSecurityNative.DeleteSecContext(out _, ref handle);
            if (status == Interop.NetSecurityNative.Status.GSS_S_COMPLETE)
            {
                SetHandle(IntPtr.Zero);
                return true;
            }

            // The RinOS owner keeps a failed-delete context retryable. Do not
            // erase the handle before SafeHandle retry/finalization can call
            // DeleteSecContext again.
            return false;
        }
    }
}
