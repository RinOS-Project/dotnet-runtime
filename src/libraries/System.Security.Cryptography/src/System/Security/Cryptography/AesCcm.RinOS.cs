// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

namespace System.Security.Cryptography
{
    public sealed partial class AesCcm
    {
        private FixedMemoryKeyBox _keyBox;

        public static bool IsSupported => true;

        private void ImportKey(ReadOnlySpan<byte> key)
        {
            _keyBox = new FixedMemoryKeyBox(key);
        }

        private void EncryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext,
            Span<byte> tag,
            ReadOnlySpan<byte> associatedData = default)
        {
            ValidateMessageLength(plaintext.Length, nonce.Length, nameof(plaintext));
            bool addedRef = false;

            try
            {
                _keyBox.DangerousAddRef(ref addedRef);
                ReadOnlySpan<byte> key = _keyBox.DangerousKeySpan;

                using Aes aes = CreateEcb(key);
                Span<byte> mac = stackalloc byte[16];
                Span<byte> s0 = stackalloc byte[16];

                ComputeMac(aes, nonce, plaintext, associatedData, tag.Length, mac);
                EncryptCounterBlock(aes, nonce, nonce.Length, 0, s0);
                for (int i = 0; i < tag.Length; i++)
                {
                    tag[i] = (byte)(mac[i] ^ s0[i]);
                }

                CtrCrypt(aes, nonce, plaintext, ciphertext, 1);
                CryptographicOperations.ZeroMemory(mac);
                CryptographicOperations.ZeroMemory(s0);
            }
            finally
            {
                if (addedRef)
                {
                    _keyBox.DangerousRelease();
                }
            }
        }

        private void DecryptCore(
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            ReadOnlySpan<byte> tag,
            Span<byte> plaintext,
            ReadOnlySpan<byte> associatedData)
        {
            ValidateMessageLength(ciphertext.Length, nonce.Length, nameof(ciphertext));
            bool addedRef = false;

            try
            {
                _keyBox.DangerousAddRef(ref addedRef);
                ReadOnlySpan<byte> key = _keyBox.DangerousKeySpan;

                using Aes aes = CreateEcb(key);
                Span<byte> mac = stackalloc byte[16];
                Span<byte> expectedTag = stackalloc byte[16];
                Span<byte> s0 = stackalloc byte[16];

                CtrCrypt(aes, nonce, ciphertext, plaintext, 1);
                ComputeMac(aes, nonce, plaintext, associatedData, tag.Length, mac);
                EncryptCounterBlock(aes, nonce, nonce.Length, 0, s0);
                for (int i = 0; i < tag.Length; i++)
                {
                    expectedTag[i] = (byte)(mac[i] ^ s0[i]);
                }

                if (!CryptographicOperations.FixedTimeEquals(tag, expectedTag.Slice(0, tag.Length)))
                {
                    CryptographicOperations.ZeroMemory(plaintext);
                    throw new AuthenticationTagMismatchException();
                }

                CryptographicOperations.ZeroMemory(mac);
                CryptographicOperations.ZeroMemory(expectedTag);
                CryptographicOperations.ZeroMemory(s0);
            }
            catch
            {
                CryptographicOperations.ZeroMemory(plaintext);
                throw;
            }
            finally
            {
                if (addedRef)
                {
                    _keyBox.DangerousRelease();
                }
            }
        }

        public void Dispose() => _keyBox.Dispose();

        private static Aes CreateEcb(ReadOnlySpan<byte> key)
        {
            Aes aes = Aes.Create();
            try
            {
                aes.Key = key.ToArray();
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                return aes;
            }
            catch
            {
                aes.Dispose();
                throw;
            }
        }

        private static void ComputeMac(
            Aes aes,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            ReadOnlySpan<byte> associatedData,
            int tagLength,
            Span<byte> mac)
        {
            int lengthBytes = 15 - nonce.Length;
            Span<byte> block = stackalloc byte[16];
            Span<byte> encrypted = stackalloc byte[16];
            int blockLength = 0;
            mac.Clear();

            block[0] = (byte)((associatedData.Length == 0 ? 0 : 0x40) |
                              (((tagLength - 2) / 2) << 3) |
                              (lengthBytes - 1));
            nonce.CopyTo(block.Slice(1));
            WriteBigEndianLength(block.Slice(16 - lengthBytes), plaintext.Length, lengthBytes);
            ProcessMacBlock(aes, block, mac, encrypted);

            block.Clear();
            if (associatedData.Length != 0)
            {
                Span<byte> encodedLength = stackalloc byte[10];
                int encodedLengthBytes = EncodeAssociatedDataLength(associatedData.Length, encodedLength);
                AppendMacBytes(aes, encodedLength.Slice(0, encodedLengthBytes), block, ref blockLength, mac, encrypted);
                AppendMacBytes(aes, associatedData, block, ref blockLength, mac, encrypted);
                FinishMacBlock(aes, block, ref blockLength, mac, encrypted);
            }

            AppendMacBytes(aes, plaintext, block, ref blockLength, mac, encrypted);
            FinishMacBlock(aes, block, ref blockLength, mac, encrypted);

            CryptographicOperations.ZeroMemory(block);
            CryptographicOperations.ZeroMemory(encrypted);
        }

        private static void AppendMacBytes(
            Aes aes,
            ReadOnlySpan<byte> source,
            Span<byte> block,
            ref int blockLength,
            Span<byte> mac,
            Span<byte> encrypted)
        {
            while (!source.IsEmpty)
            {
                int count = Math.Min(source.Length, block.Length - blockLength);
                source.Slice(0, count).CopyTo(block.Slice(blockLength));
                source = source.Slice(count);
                blockLength += count;

                if (blockLength == block.Length)
                {
                    ProcessMacBlock(aes, block, mac, encrypted);
                    block.Clear();
                    blockLength = 0;
                }
            }
        }

        private static void FinishMacBlock(
            Aes aes,
            Span<byte> block,
            ref int blockLength,
            Span<byte> mac,
            Span<byte> encrypted)
        {
            if (blockLength != 0)
            {
                block.Slice(blockLength).Clear();
                ProcessMacBlock(aes, block, mac, encrypted);
                block.Clear();
                blockLength = 0;
            }
        }

        private static void ProcessMacBlock(
            Aes aes,
            ReadOnlySpan<byte> block,
            Span<byte> mac,
            Span<byte> encrypted)
        {
            Span<byte> input = stackalloc byte[16];
            for (int i = 0; i < input.Length; i++)
            {
                input[i] = (byte)(mac[i] ^ block[i]);
            }

            aes.EncryptEcb(input, encrypted, PaddingMode.None);
            encrypted.CopyTo(mac);
            CryptographicOperations.ZeroMemory(input);
        }

        private static void CtrCrypt(
            Aes aes,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            int initialCounter)
        {
            Span<byte> stream = stackalloc byte[16];
            int counter = initialCounter;
            int offset = 0;

            while (offset < source.Length)
            {
                EncryptCounterBlock(aes, nonce, nonce.Length, counter, stream);
                int count = Math.Min(16, source.Length - offset);
                for (int i = 0; i < count; i++)
                {
                    destination[offset + i] = (byte)(source[offset + i] ^ stream[i]);
                }

                offset += count;
                counter++;
            }

            CryptographicOperations.ZeroMemory(stream);
        }

        private static void ValidateMessageLength(int length, int nonceLength, string parameterName)
        {
            int lengthBytes = 15 - nonceLength;
            if (lengthBytes < 4 && length > ((1 << (lengthBytes * 8)) - 1))
            {
                throw new ArgumentException(
                    "The message is too long for the selected nonce length.",
                    parameterName);
            }
        }

        private static void EncryptCounterBlock(
            Aes aes,
            ReadOnlySpan<byte> nonce,
            int nonceLength,
            int counter,
            Span<byte> destination)
        {
            int lengthBytes = 15 - nonceLength;
            Span<byte> input = stackalloc byte[16];
            input[0] = (byte)(lengthBytes - 1);
            nonce.CopyTo(input.Slice(1));
            WriteBigEndianLength(input.Slice(16 - lengthBytes), counter, lengthBytes);
            aes.EncryptEcb(input, destination, PaddingMode.None);
            CryptographicOperations.ZeroMemory(input);
        }

        private static int EncodeAssociatedDataLength(int length, Span<byte> destination)
        {
            if (length < 0xFF00)
            {
                destination[0] = (byte)(length >> 8);
                destination[1] = (byte)length;
                return 2;
            }

            destination[0] = 0xFF;
            destination[1] = 0xFE;
            destination[2] = (byte)(length >> 24);
            destination[3] = (byte)(length >> 16);
            destination[4] = (byte)(length >> 8);
            destination[5] = (byte)length;
            return 6;
        }

        private static void WriteBigEndianLength(Span<byte> destination, int value, int lengthBytes)
        {
            uint unsignedValue = (uint)value;
            destination.Clear();
            for (int i = 1; i <= lengthBytes; i++)
            {
                destination[lengthBytes - i] = (byte)unsignedValue;
                unsignedValue >>= 8;
            }
        }
    }
}
