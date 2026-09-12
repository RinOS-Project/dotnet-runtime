// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Runtime.InteropServices;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    internal sealed partial class AesImplementation
    {
        private static UniversalCryptoTransform CreateTransformCore(
            CipherMode cipherMode,
            PaddingMode paddingMode,
            ReadOnlySpan<byte> key,
            byte[]? iv,
            int blockSize,
            int paddingSize,
            int feedback,
            bool encrypting)
        {
            ReadOnlySpan<byte> ivSpan = iv is null ? ReadOnlySpan<byte>.Empty : iv.AsSpan();
            BasicSymmetricCipher cipher = new RinOSAesCipher(
                cipherMode,
                blockSize,
                paddingSize,
                key,
                ivSpan,
                feedback,
                encrypting);

            return UniversalCryptoTransform.Create(paddingMode, cipher, encrypting);
        }

        private static ILiteSymmetricCipher CreateLiteCipher(
            CipherMode cipherMode,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv,
            int blockSize,
            int paddingSize,
            int feedback,
            bool encrypting)
        {
            return new RinOSAesCipher(
                cipherMode,
                blockSize,
                paddingSize,
                key,
                iv,
                feedback,
                encrypting);
        }
    }

    internal sealed class RinOSAesCipher : BasicSymmetricCipher, ILiteSymmetricCipher
    {
        private const int NativeModeEcb = 0;
        private const int NativeModeCbc = 1;
        private const int NativeModeCfb = 2;

        private IntPtr _context;

        internal RinOSAesCipher(
            CipherMode cipherMode,
            int blockSizeInBytes,
            int paddingSizeInBytes,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv,
            int feedbackSizeInBytes,
            bool encrypting)
            : base(GetCipherIv(cipherMode, iv), blockSizeInBytes, paddingSizeInBytes)
        {
            int nativeMode = cipherMode switch
            {
                CipherMode.ECB => NativeModeEcb,
                CipherMode.CBC => NativeModeCbc,
                CipherMode.CFB => NativeModeCfb,
                _ => throw new NotSupportedException(),
            };

            unsafe
            {
                fixed (byte* pKey = key)
                fixed (byte* pIv = iv)
                {
                    _context = Interop.Crypto.RinOSAesCreate(
                        pKey,
                        key.Length,
                        nativeMode,
                        cipherMode == CipherMode.CFB ? feedbackSizeInBytes : 0,
                        pIv,
                        iv.Length,
                        encrypting ? 1 : 0);
                }
            }

            if (_context == IntPtr.Zero)
            {
                throw new CryptographicException("RinOS AES cipher creation failed.");
            }
        }

        public override int Transform(ReadOnlySpan<byte> input, Span<byte> output)
        {
            return TransformCore(input, output);
        }

        public override int TransformFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int written = TransformCore(input, output);
            ReadOnlySpan<byte> initialIv = IV is null ? ReadOnlySpan<byte>.Empty : IV.AsSpan();
            Reset(initialIv);
            return written;
        }

        public void Reset(ReadOnlySpan<byte> iv)
        {
            unsafe
            {
                fixed (byte* pIv = iv)
                {
                    if (Interop.Crypto.RinOSAesReset(_context, pIv, iv.Length) == 0)
                    {
                        throw new CryptographicException("RinOS AES cipher reset failed.");
                    }
                }
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && _context != IntPtr.Zero)
            {
                Interop.Crypto.RinOSAesDestroy(_context);
                _context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        private int TransformCore(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (input.Length > output.Length)
            {
                throw new ArgumentException(SR.Argument_DestinationTooShort, nameof(output));
            }

            // The product adapter supports exact in-place operation, but not partial overlap.
            if (input.Overlaps(output, out int overlapOffset) && overlapOffset != 0)
            {
                byte[] rented = CryptoPool.Rent(input.Length);
                int written = 0;

                try
                {
                    written = TransformNative(input, rented);
                    rented.AsSpan(0, written).CopyTo(output);
                    return written;
                }
                finally
                {
                    CryptoPool.Return(rented, written);
                }
            }

            return TransformNative(input, output);
        }

        private unsafe int TransformNative(ReadOnlySpan<byte> input, Span<byte> output)
        {
            fixed (byte* pInput = input)
            fixed (byte* pOutput = output)
            {
                int written = Interop.Crypto.RinOSAesTransform(
                    _context,
                    pInput,
                    input.Length,
                    pOutput,
                    output.Length);

                if (written < 0)
                {
                    throw new CryptographicException("RinOS AES transformation failed.");
                }

                return written;
            }
        }

        private static byte[]? GetCipherIv(CipherMode cipherMode, ReadOnlySpan<byte> iv)
        {
            if (cipherMode is not (CipherMode.ECB or CipherMode.CBC or CipherMode.CFB))
            {
                throw new NotSupportedException();
            }

            return cipherMode.GetCipherIv(iv.ToArray());
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesCreate")]
        internal static unsafe partial IntPtr RinOSAesCreate(
            byte* key,
            int keyLength,
            int mode,
            int feedbackSize,
            byte* iv,
            int ivLength,
            int encrypting);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesTransform")]
        internal static unsafe partial int RinOSAesTransform(
            IntPtr context,
            byte* input,
            int inputLength,
            byte* output,
            int outputLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesReset")]
        internal static unsafe partial int RinOSAesReset(IntPtr context, byte* iv, int ivLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesDestroy")]
        internal static partial void RinOSAesDestroy(IntPtr context);
    }
}
