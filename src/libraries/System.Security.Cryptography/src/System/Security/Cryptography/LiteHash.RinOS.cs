// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;

namespace System.Security.Cryptography
{
    internal static partial class LiteHashProvider
    {
        private static LiteHash CreateHash(string hashAlgorithmId) =>
            new LiteHash(HashProviderDispenser.CreateHashProvider(hashAlgorithmId));

        private static LiteHmac CreateHmac(string hashAlgorithmId, ReadOnlySpan<byte> key) =>
            new LiteHmac(HashProviderDispenser.CreateMacProvider(hashAlgorithmId, key));

        internal static LiteXof CreateXof(string hashAlgorithmId)
        {
            int algorithm = hashAlgorithmId switch
            {
                HashAlgorithmNames.SHAKE128 => 7,
                HashAlgorithmNames.SHAKE256 => 8,
                _ => throw new CryptographicException($"RinOS does not provide the {hashAlgorithmId} XOF.")
            };

            return new LiteXof(algorithm);
        }

        internal static LiteKmac CreateKmac(
            string algorithmId,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> customizationString,
            bool xof)
        {
            int algorithm = algorithmId switch
            {
                HashAlgorithmNames.KMAC128 => 1,
                HashAlgorithmNames.KMAC256 => 2,
                _ => throw new CryptographicException($"Unknown RinOS KMAC algorithm: {algorithmId}")
            };

            return new LiteKmac(algorithm, key, customizationString, xof);
        }
    }

    internal readonly struct LiteHash : ILiteHash
    {
        private readonly HashProvider _provider;

        internal LiteHash(HashProvider provider)
        {
            _provider = provider;
        }

        public int HashSizeInBytes => _provider.HashSizeInBytes;
        public void Append(ReadOnlySpan<byte> data) => _provider.AppendHashData(data);
        public int Finalize(Span<byte> destination) => _provider.FinalizeHashAndReset(destination);
        public void Dispose() => _provider.Dispose();
    }

    internal readonly struct LiteHmac : ILiteHash
    {
        private readonly HashProvider _provider;

        internal LiteHmac(HashProvider provider)
        {
            _provider = provider;
        }

        public int HashSizeInBytes => _provider.HashSizeInBytes;
        public void Append(ReadOnlySpan<byte> data) => _provider.AppendHashData(data);
        public int Finalize(Span<byte> destination) => _provider.FinalizeHashAndReset(destination);
        public void Dispose() => _provider.Dispose();
    }

    internal readonly struct LiteXof : ILiteHash
    {
        private readonly IntPtr _context;
        private readonly int _algorithm;

        internal LiteXof(int algorithm)
        {
            _algorithm = algorithm;
            _context = Interop.Crypto.RinOSXofCreate(algorithm);
            if (_context == IntPtr.Zero)
                throw new CryptographicException("RinOS XOF context allocation failed.");
        }

        private LiteXof(IntPtr context, int algorithm)
        {
            _context = context;
            _algorithm = algorithm;
        }

        public int HashSizeInBytes => throw new NotSupportedException();

        public void Append(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) return;
            unsafe
            {
                fixed (byte* pData = data)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSXofUpdate(_context, pData, data.Length));
                }
            }
        }

        public int Finalize(Span<byte> destination)
        {
            unsafe
            {
                fixed (byte* pDestination = destination)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSXofFinal(_context, pDestination, destination.Length));
                }
            }
            return destination.Length;
        }

        public int FinalizeAndReset(Span<byte> destination)
        {
            int written = Finalize(destination);
            Reset();
            return written;
        }

        public void Current(Span<byte> destination)
        {
            unsafe
            {
                fixed (byte* pDestination = destination)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSXofCurrent(_context, pDestination, destination.Length));
                }
            }
        }

        public void Reset() => ThrowIfFailed(Interop.Crypto.RinOSXofReset(_context));

        public LiteXof Clone()
        {
            IntPtr clone = Interop.Crypto.RinOSXofClone(_context);
            if (clone == IntPtr.Zero)
                throw new CryptographicException("RinOS XOF context clone failed.");
            return new LiteXof(clone, _algorithm);
        }

        public void Read(Span<byte> destination)
        {
            unsafe
            {
                fixed (byte* pDestination = destination)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSXofRead(_context, pDestination, destination.Length));
                }
            }
        }

        public void Dispose() => Interop.Crypto.RinOSXofDestroy(_context);

        private static void ThrowIfFailed(int result)
        {
            if (result == 0)
                throw new CryptographicException("RinOS XOF operation failed.");
        }
    }

    internal readonly struct LiteKmac : ILiteHash
    {
        private readonly IntPtr _context;
        private readonly int _algorithm;

        internal LiteKmac(
            int algorithm,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> customizationString,
            bool xof)
        {
            _algorithm = algorithm;
            unsafe
            {
                fixed (byte* pKey = key)
                fixed (byte* pCustomization = customizationString)
                {
                    _context = Interop.Crypto.RinOSKmacCreate(
                        algorithm,
                        pKey,
                        key.Length,
                        pCustomization,
                        customizationString.Length,
                        xof ? 1 : 0);
                }
            }

            if (_context == IntPtr.Zero)
                throw new CryptographicException("RinOS KMAC context allocation failed.");
        }

        private LiteKmac(IntPtr context, int algorithm)
        {
            _context = context;
            _algorithm = algorithm;
        }

        public int HashSizeInBytes => throw new NotSupportedException();

        public void Append(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty) return;
            unsafe
            {
                fixed (byte* pData = data)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSKmacUpdate(_context, pData, data.Length));
                }
            }
        }

        public int Finalize(Span<byte> destination)
        {
            unsafe
            {
                fixed (byte* pDestination = destination)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSKmacFinal(_context, pDestination, destination.Length));
                }
            }
            return destination.Length;
        }

        public void Current(Span<byte> destination)
        {
            unsafe
            {
                fixed (byte* pDestination = destination)
                {
                    ThrowIfFailed(Interop.Crypto.RinOSKmacCurrent(_context, pDestination, destination.Length));
                }
            }
        }

        public void Reset() => ThrowIfFailed(Interop.Crypto.RinOSKmacReset(_context));

        public LiteKmac Clone()
        {
            IntPtr clone = Interop.Crypto.RinOSKmacClone(_context);
            if (clone == IntPtr.Zero)
                throw new CryptographicException("RinOS KMAC context clone failed.");
            return new LiteKmac(clone, _algorithm);
        }

        public void Dispose() => Interop.Crypto.RinOSKmacDestroy(_context);

        private static void ThrowIfFailed(int result)
        {
            if (result == 0)
                throw new CryptographicException("RinOS KMAC operation failed.");
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofCreate")]
        internal static partial IntPtr RinOSXofCreate(int algorithm);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofClone")]
        internal static partial IntPtr RinOSXofClone(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofUpdate")]
        internal static unsafe partial int RinOSXofUpdate(IntPtr context, byte* data, int length);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofFinal")]
        internal static unsafe partial int RinOSXofFinal(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofCurrent")]
        internal static unsafe partial int RinOSXofCurrent(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofReset")]
        internal static partial int RinOSXofReset(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofRead")]
        internal static unsafe partial int RinOSXofRead(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSXofDestroy")]
        internal static partial void RinOSXofDestroy(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacCreate")]
        internal static unsafe partial IntPtr RinOSKmacCreate(
            int algorithm, byte* key, int keyLength, byte* customization,
            int customizationLength, int xof);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacClone")]
        internal static partial IntPtr RinOSKmacClone(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacUpdate")]
        internal static unsafe partial int RinOSKmacUpdate(IntPtr context, byte* data, int length);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacFinal")]
        internal static unsafe partial int RinOSKmacFinal(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacCurrent")]
        internal static unsafe partial int RinOSKmacCurrent(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacReset")]
        internal static partial int RinOSKmacReset(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSKmacDestroy")]
        internal static partial void RinOSKmacDestroy(IntPtr context);
    }
}

#endif
