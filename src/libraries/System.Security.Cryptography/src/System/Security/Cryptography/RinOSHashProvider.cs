// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        private static class RinOSAlgorithms
        {
            internal const int Sha256 = 1;
            internal const int Sha384 = 2;
            internal const int Sha512 = 3;

            internal static int GetHashAlgorithm(string id)
            {
                return id switch
                {
                    HashAlgorithmNames.SHA256 => Sha256,
                    HashAlgorithmNames.SHA384 => Sha384,
                    HashAlgorithmNames.SHA512 => Sha512,
                    HashAlgorithmNames.SHA1 => throw Unsupported(id),
                    HashAlgorithmNames.MD5 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_256 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_384 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_512 => throw Unsupported(id),
                    HashAlgorithmNames.SHAKE128 => throw Unsupported(id),
                    HashAlgorithmNames.SHAKE256 => throw Unsupported(id),
                    _ => throw Unknown(id),
                };
            }

            internal static int GetMacAlgorithm(string id)
            {
                return id switch
                {
                    HashAlgorithmNames.SHA256 => Sha256,
                    HashAlgorithmNames.SHA384 => Sha384,
                    HashAlgorithmNames.SHA1 => throw Unsupported(id),
                    HashAlgorithmNames.MD5 => throw Unsupported(id),
                    HashAlgorithmNames.SHA512 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_256 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_384 => throw Unsupported(id),
                    HashAlgorithmNames.SHA3_512 => throw Unsupported(id),
                    _ => throw Unknown(id),
                };
            }

            internal static bool IsHashSupported(string id)
            {
                return id switch
                {
                    HashAlgorithmNames.SHA256 or HashAlgorithmNames.SHA384 or HashAlgorithmNames.SHA512 => true,
                    HashAlgorithmNames.SHA1 or HashAlgorithmNames.MD5 or
                    HashAlgorithmNames.SHA3_256 or HashAlgorithmNames.SHA3_384 or
                    HashAlgorithmNames.SHA3_512 or HashAlgorithmNames.SHAKE128 or
                    HashAlgorithmNames.SHAKE256 => false,
                    _ => throw Unknown(id),
                };
            }

            internal static bool IsMacSupported(string id)
            {
                return id switch
                {
                    HashAlgorithmNames.SHA256 or HashAlgorithmNames.SHA384 => true,
                    HashAlgorithmNames.SHA1 or HashAlgorithmNames.MD5 or
                    HashAlgorithmNames.SHA512 or HashAlgorithmNames.SHA3_256 or
                    HashAlgorithmNames.SHA3_384 or HashAlgorithmNames.SHA3_512 => false,
                    _ => throw Unknown(id),
                };
            }

            private static Exception Unsupported(string id) =>
                new PlatformNotSupportedException($"RinOS does not provide the {id} cryptographic provider.");

            private static Exception Unknown(string id) =>
                new CryptographicException(SR.Format(SR.Cryptography_UnknownHashAlgorithm, id));
        }

        private sealed unsafe class RinOSHashProvider : HashProvider
        {
            private readonly int _algorithm;
            private readonly int _hashSize;
            private IntPtr _context;
            private bool _running;
            private ConcurrencyBlock _block;

            internal RinOSHashProvider(string hashAlgorithmId)
            {
                _algorithm = RinOSAlgorithms.GetHashAlgorithm(hashAlgorithmId);
                _hashSize = _algorithm switch
                {
                    RinOSAlgorithms.Sha256 => 32,
                    RinOSAlgorithms.Sha384 => 48,
                    _ => 64,
                };
                _context = Interop.Crypto.RinOSHashCreate(_algorithm);
                if (_context == IntPtr.Zero)
                    throw new CryptographicException("RinOS hash context allocation failed.");
            }

            private RinOSHashProvider(RinOSHashProvider source)
            {
                _algorithm = source._algorithm;
                _hashSize = source._hashSize;
                _context = Interop.Crypto.RinOSHashClone(source._context);
                if (_context == IntPtr.Zero)
                    throw new CryptographicException("RinOS hash context clone failed.");
                _running = source._running;
            }

            internal static int OneShot(string hashAlgorithmId, ReadOnlySpan<byte> source, Span<byte> destination)
            {
                using RinOSHashProvider provider = new(hashAlgorithmId);
                provider.AppendHashData(source);
                return provider.FinalizeHashAndReset(destination);
            }

            public override RinOSHashProvider Clone()
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    return new RinOSHashProvider(this);
                }
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    fixed (byte* pData = data)
                    {
                        ThrowIfFailed(Interop.Crypto.RinOSHashUpdate(_context, pData, data.Length));
                    }
                    _running = true;
                }
            }

            public override int FinalizeHashAndReset(Span<byte> destination)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    EnsureDestination(destination);
                    fixed (byte* pDestination = destination)
                    {
                        int written = Interop.Crypto.RinOSHashFinal(_context, pDestination, destination.Length);
                        ThrowIfFailed(written);
                        ThrowIfFailed(Interop.Crypto.RinOSHashReset(_context));
                        _running = false;
                        return written;
                    }
                }
            }

            public override int GetCurrentHash(Span<byte> destination)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    EnsureDestination(destination);
                    fixed (byte* pDestination = destination)
                    {
                        int written = Interop.Crypto.RinOSHashCurrent(_context, pDestination, destination.Length);
                        ThrowIfFailed(written);
                        return written;
                    }
                }
            }

            public override int HashSizeInBytes => _hashSize;

            public override void Dispose(bool disposing)
            {
                if (disposing && _context != IntPtr.Zero)
                {
                    Interop.Crypto.RinOSHashDestroy(_context);
                    _context = IntPtr.Zero;
                }
            }

            public override void Reset()
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    if (_running)
                    {
                        ThrowIfFailed(Interop.Crypto.RinOSHashReset(_context));
                        _running = false;
                    }
                }
            }

            private void EnsureDestination(Span<byte> destination)
            {
                if (destination.Length < _hashSize)
                    throw new ArgumentException("Destination is too small.", nameof(destination));
            }

            private static void ThrowIfFailed(int result)
            {
                if (result == 0)
                    throw new CryptographicException("RinOS cryptographic operation failed.");
            }
        }

        private sealed unsafe class RinOSHmacProvider : HashProvider
        {
            private readonly int _algorithm;
            private readonly int _hashSize;
            private IntPtr _context;
            private bool _running;
            private ConcurrencyBlock _block;

            internal RinOSHmacProvider(string hashAlgorithmId, ReadOnlySpan<byte> key)
            {
                _algorithm = RinOSAlgorithms.GetMacAlgorithm(hashAlgorithmId);
                _hashSize = _algorithm == RinOSAlgorithms.Sha256 ? 32 : 48;
                fixed (byte* pKey = key)
                {
                    _context = Interop.Crypto.RinOSHmacCreate(_algorithm, pKey, key.Length);
                }
                if (_context == IntPtr.Zero)
                    throw new CryptographicException("RinOS HMAC context allocation failed.");
            }

            private RinOSHmacProvider(RinOSHmacProvider source)
            {
                _algorithm = source._algorithm;
                _hashSize = source._hashSize;
                _context = Interop.Crypto.RinOSHmacClone(source._context);
                if (_context == IntPtr.Zero)
                    throw new CryptographicException("RinOS HMAC context clone failed.");
                _running = source._running;
            }

            internal static int OneShot(string hashAlgorithmId, ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
            {
                using RinOSHmacProvider provider = new(hashAlgorithmId, key);
                provider.AppendHashData(source);
                return provider.FinalizeHashAndReset(destination);
            }

            public override RinOSHmacProvider Clone()
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    return new RinOSHmacProvider(this);
                }
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    fixed (byte* pData = data)
                    {
                        ThrowIfFailed(Interop.Crypto.RinOSHmacUpdate(_context, pData, data.Length));
                    }
                    _running = true;
                }
            }

            public override int FinalizeHashAndReset(Span<byte> destination)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    EnsureDestination(destination);
                    fixed (byte* pDestination = destination)
                    {
                        int written = Interop.Crypto.RinOSHmacFinal(_context, pDestination, destination.Length);
                        ThrowIfFailed(written);
                        ThrowIfFailed(Interop.Crypto.RinOSHmacReset(_context));
                        _running = false;
                        return written;
                    }
                }
            }

            public override int GetCurrentHash(Span<byte> destination)
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    EnsureDestination(destination);
                    fixed (byte* pDestination = destination)
                    {
                        int written = Interop.Crypto.RinOSHmacCurrent(_context, pDestination, destination.Length);
                        ThrowIfFailed(written);
                        return written;
                    }
                }
            }

            public override int HashSizeInBytes => _hashSize;

            public override void Dispose(bool disposing)
            {
                if (disposing && _context != IntPtr.Zero)
                {
                    Interop.Crypto.RinOSHmacDestroy(_context);
                    _context = IntPtr.Zero;
                }
            }

            public override void Reset()
            {
                using (ConcurrencyBlock.Enter(ref _block))
                {
                    if (_running)
                    {
                        ThrowIfFailed(Interop.Crypto.RinOSHmacReset(_context));
                        _running = false;
                    }
                }
            }

            private void EnsureDestination(Span<byte> destination)
            {
                if (destination.Length < _hashSize)
                    throw new ArgumentException("Destination is too small.", nameof(destination));
            }

            private static void ThrowIfFailed(int result)
            {
                if (result == 0)
                    throw new CryptographicException("RinOS cryptographic operation failed.");
            }
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashCreate")]
        internal static partial IntPtr RinOSHashCreate(int algorithm);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashClone")]
        internal static partial IntPtr RinOSHashClone(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashUpdate")]
        internal static unsafe partial int RinOSHashUpdate(IntPtr context, byte* data, int length);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashFinal")]
        internal static unsafe partial int RinOSHashFinal(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashCurrent")]
        internal static unsafe partial int RinOSHashCurrent(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashReset")]
        internal static partial int RinOSHashReset(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHashDestroy")]
        internal static partial void RinOSHashDestroy(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacCreate")]
        internal static unsafe partial IntPtr RinOSHmacCreate(int algorithm, byte* key, int keyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacClone")]
        internal static partial IntPtr RinOSHmacClone(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacUpdate")]
        internal static unsafe partial int RinOSHmacUpdate(IntPtr context, byte* data, int length);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacFinal")]
        internal static unsafe partial int RinOSHmacFinal(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacCurrent")]
        internal static unsafe partial int RinOSHmacCurrent(IntPtr context, byte* destination, int destinationLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacReset")]
        internal static partial int RinOSHmacReset(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSHmacDestroy")]
        internal static partial void RinOSHmacDestroy(IntPtr context);
    }
}

#endif
