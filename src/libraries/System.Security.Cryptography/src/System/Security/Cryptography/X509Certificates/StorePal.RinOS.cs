// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography.X509Certificates
{
    // RinOS owns one immutable, authenticated system trust bundle.  Expose it
    // as the Root store without introducing an OpenSSL or native-store
    // dependency into the target build.
    internal sealed class RinOSStorePal : IStorePal
    {
        private const string SystemRootStorePath = "/System/Trust/roots.rinca";
        private const int HeaderSize = 8;
        private const int RecordHeaderSize = 4;
        private const int MaximumBundleBytes = 4 * 1024 * 1024;
        private const int MaximumCertificates = 256;
        private const int MaximumCertificateBytes = 65535;

        private readonly X509Certificate2Collection _certificates;

        private RinOSStorePal(ReadOnlySpan<byte> bundle)
        {
            _certificates = LoadBundle(bundle);
        }

        internal static IStorePal OpenSystemRoot(OpenFlags openFlags)
        {
            OpenFlags writeFlags = openFlags & (OpenFlags.ReadWrite | OpenFlags.MaxAllowed);
            if (writeFlags != OpenFlags.ReadOnly)
            {
                throw new CryptographicException(SR.Cryptography_Unix_X509_MachineStoresReadOnly);
            }

            byte[] bundle;
            try
            {
                bundle = File.ReadAllBytes(SystemRootStorePath);
            }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException)
            {
                throw new CryptographicException(SR.Cryptography_X509_StoreNotFound, e);
            }

            return new RinOSStorePal(bundle);
        }

        public void CloneTo(X509Certificate2Collection collection)
        {
            ArgumentNullException.ThrowIfNull(collection);

            foreach (X509Certificate2 certificate in _certificates)
            {
                collection.Add(new X509Certificate2(certificate));
            }
        }

        public void Add(ICertificatePal cert)
        {
            throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
        }

        public void Remove(ICertificatePal cert)
        {
            throw new CryptographicException(SR.Cryptography_X509_StoreReadOnly);
        }

        SafeHandle? IStorePal.SafeHandle => null;

        public void Dispose()
        {
            foreach (X509Certificate2 certificate in _certificates)
            {
                certificate.Dispose();
            }
        }

        private static X509Certificate2Collection LoadBundle(ReadOnlySpan<byte> bundle)
        {
            if (bundle.Length < HeaderSize || bundle.Length > MaximumBundleBytes ||
                !bundle[..4].SequenceEqual("RCA1"u8))
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int count = ReadLittleEndianInt32(bundle[4..]);
            if (count <= 0 || count > MaximumCertificates)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            X509Certificate2Collection certificates = new X509Certificate2Collection();
            int offset = HeaderSize;
            try
            {
                for (int index = 0; index < count; index++)
                {
                    if (bundle.Length - offset < RecordHeaderSize)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    int certificateLength = ReadLittleEndianInt32(bundle[offset..]);
                    offset += RecordHeaderSize;
                    if (certificateLength <= 0 || certificateLength > MaximumCertificateBytes ||
                        certificateLength > bundle.Length - offset)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    certificates.Add(new X509Certificate2(
                        RinOSCertificatePal.FromBlob(
                            bundle.Slice(offset, certificateLength),
                            SafePasswordHandle.InvalidHandle,
                            X509KeyStorageFlags.EphemeralKeySet)));
                    offset += certificateLength;
                }

                if (offset != bundle.Length)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return certificates;
            }
            catch
            {
                foreach (X509Certificate2 certificate in certificates)
                {
                    certificate.Dispose();
                }
                throw;
            }
        }

        private static int ReadLittleEndianInt32(ReadOnlySpan<byte> value)
        {
            return value[0] |
                   (value[1] << 8) |
                   (value[2] << 16) |
                   (value[3] << 24);
        }
    }

    internal static partial class StorePal
    {
        internal static partial IStorePal FromHandle(IntPtr storeHandle) =>
            throw new PlatformNotSupportedException("RinOS certificate stores do not expose native handles.");

        internal static partial IStorePal FromSystemStore(
            string storeName,
            StoreLocation storeLocation,
            OpenFlags openFlags)
        {
            ArgumentException.ThrowIfNullOrEmpty(storeName);
            if (storeLocation != StoreLocation.CurrentUser &&
                storeLocation != StoreLocation.LocalMachine)
            {
                throw new ArgumentException(SR.Format(SR.Arg_EnumIllegalVal, nameof(storeLocation)));
            }

            if (!X509Store.RootStoreName.Equals(storeName, StringComparison.OrdinalIgnoreCase))
            {
                throw new CryptographicException(
                    SR.Cryptography_Unix_X509_MachineStoresRootOnly,
                    new PlatformNotSupportedException("RinOS exposes only the product Root trust store."));
            }

            return RinOSStorePal.OpenSystemRoot(openFlags);
        }
    }
}

#endif
