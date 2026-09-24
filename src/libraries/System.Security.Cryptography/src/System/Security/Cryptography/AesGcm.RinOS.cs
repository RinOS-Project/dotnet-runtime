// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    public sealed partial class AesGcm
    {
        private IntPtr _context;
        private static readonly KeySizes s_tagByteSizes = new KeySizes(12, 16, 1);

        public static partial bool IsSupported => true;
        public static partial KeySizes TagByteSizes => s_tagByteSizes;

        [MemberNotNull(nameof(_context))]
        private partial void ImportKey(ReadOnlySpan<byte> key)
        {
            unsafe
            {
                fixed (byte* pKey = key)
                {
                    _context = Interop.Crypto.RinOSAesGcmCreate(pKey, key.Length);
                }
            }

            if (_context == IntPtr.Zero)
            {
                throw new CryptographicException("RinOS AES-GCM key import failed.");
            }
        }

        private partial void EncryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData)
        {
            try
            {
                unsafe
                {
                    fixed (byte* pNonce = nonce)
                    fixed (byte* pAssociatedData = associatedData)
                    fixed (byte* pPlaintext = plaintext)
                    fixed (byte* pCiphertext = ciphertext)
                    fixed (byte* pTag = tag)
                    {
                        if (Interop.Crypto.RinOSAesGcmEncrypt(
                            _context,
                            pNonce,
                            nonce.Length,
                            pAssociatedData,
                            associatedData.Length,
                            pPlaintext,
                            plaintext.Length,
                            pCiphertext,
                            ciphertext.Length,
                            pTag,
                            tag.Length) == 0)
                        {
                            throw new CryptographicException("RinOS AES-GCM encryption failed.");
                        }
                    }
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(ciphertext);
                CryptographicOperations.ZeroMemory(tag);
                throw;
            }
        }

        private partial void DecryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData)
        {
            try
            {
                unsafe
                {
                    fixed (byte* pNonce = nonce)
                    fixed (byte* pAssociatedData = associatedData)
                    fixed (byte* pCiphertext = ciphertext)
                    fixed (byte* pTag = tag)
                    fixed (byte* pPlaintext = plaintext)
                    {
                        if (Interop.Crypto.RinOSAesGcmDecrypt(
                            _context,
                            pNonce,
                            nonce.Length,
                            pAssociatedData,
                            associatedData.Length,
                            pCiphertext,
                            ciphertext.Length,
                            pTag,
                            tag.Length,
                            pPlaintext,
                            plaintext.Length) == 0)
                        {
                            throw new AuthenticationTagMismatchException();
                        }
                    }
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
        }

        public partial void Dispose()
        {
            if (_context != IntPtr.Zero)
            {
                Interop.Crypto.RinOSAesGcmDestroy(_context);
                _context = IntPtr.Zero;
            }
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesGcmCreate")]
        internal static unsafe partial IntPtr RinOSAesGcmCreate(byte* key, int keyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesGcmEncrypt")]
        internal static unsafe partial int RinOSAesGcmEncrypt(
            IntPtr context,
            byte* nonce,
            int nonceLength,
            byte* associatedData,
            int associatedDataLength,
            byte* plaintext,
            int plaintextLength,
            byte* ciphertext,
            int ciphertextLength,
            byte* tag,
            int tagLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesGcmDecrypt")]
        internal static unsafe partial int RinOSAesGcmDecrypt(
            IntPtr context,
            byte* nonce,
            int nonceLength,
            byte* associatedData,
            int associatedDataLength,
            byte* ciphertext,
            int ciphertextLength,
            byte* tag,
            int tagLength,
            byte* plaintext,
            int plaintextLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSAesGcmDestroy")]
        internal static partial void RinOSAesGcmDestroy(IntPtr context);
    }
}
