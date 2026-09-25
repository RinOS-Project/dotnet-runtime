// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal sealed unsafe class RinOSRsa : RSA
    {
        private const int RsaPaddingPkcs1 = 1;
        private const int RsaPaddingOaep = 2;
        private const int RsaSignaturePkcs1 = 1;
        private const int RsaSignaturePss = 2;
        private const int RsaHashSha1 = 1;
        private const int RsaHashSha256 = 2;
        private const int RsaHashSha384 = 3;
        private const int RsaHashSha512 = 4;

        private static readonly KeySizes[] s_legalKeySizes =
        {
            new KeySizes(2048, 4096, 8),
        };

        private IntPtr _context;

        internal RinOSRsa()
        {
            LegalKeySizesValue = s_legalKeySizes;
            _context = Interop.Crypto.RinOSRsaCreate();
            if (_context == IntPtr.Zero)
            {
                throw new CryptographicException("RinOS RSA context allocation failed.");
            }

            if (Interop.Crypto.RinOSRsaGenerateKey(_context, 2048, 65537) == 0)
            {
                Interop.Crypto.RinOSRsaDestroy(_context);
                _context = IntPtr.Zero;
                throw new CryptographicException("RinOS RSA key generation failed.");
            }

            KeySizeValue = 2048;
        }

        public override int KeySize
        {
            get
            {
                ThrowIfDisposed();
                int keySize = Interop.Crypto.RinOSRsaGetKeySize(_context);
                return keySize != 0 ? keySize : throw new CryptographicException(SR.Cryptography_InvalidKeySize);
            }
            set
            {
                ThrowIfDisposed();
                if (!value.IsLegalSize(LegalKeySizesValue))
                {
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);
                }

                if (Interop.Crypto.RinOSRsaGenerateKey(_context, value, 65537) == 0)
                {
                    throw new CryptographicException("RinOS RSA key generation failed.");
                }

                KeySizeValue = value;
            }
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            ThrowIfDisposed();
            int modulusCapacity = (KeySize + 7) / 8;
            int factorCapacity = (modulusCapacity + 1) / 2;
            byte[] modulus = new byte[modulusCapacity];
            byte[] exponent = new byte[4];
            byte[] privateExponent = includePrivateParameters ? new byte[modulusCapacity] : Array.Empty<byte>();
            byte[] prime1 = includePrivateParameters ? new byte[factorCapacity] : Array.Empty<byte>();
            byte[] prime2 = includePrivateParameters ? new byte[factorCapacity] : Array.Empty<byte>();
            byte[] exponent1 = includePrivateParameters ? new byte[factorCapacity] : Array.Empty<byte>();
            byte[] exponent2 = includePrivateParameters ? new byte[factorCapacity] : Array.Empty<byte>();
            byte[] coefficient = includePrivateParameters ? new byte[factorCapacity] : Array.Empty<byte>();
            int modulusLength = 0;
            int exponentLength = 0;
            int privateExponentLength = 0;
            int prime1Length = 0;
            int prime2Length = 0;
            int exponent1Length = 0;
            int exponent2Length = 0;
            int coefficientLength = 0;

            fixed (byte* pModulus = modulus)
            fixed (byte* pExponent = exponent)
            fixed (byte* pPrivateExponent = privateExponent)
            fixed (byte* pPrime1 = prime1)
            fixed (byte* pPrime2 = prime2)
            fixed (byte* pExponent1 = exponent1)
            fixed (byte* pExponent2 = exponent2)
            fixed (byte* pCoefficient = coefficient)
            {
                if (Interop.Crypto.RinOSRsaExportParameters(
                        _context, includePrivateParameters ? 1 : 0,
                        pModulus, modulus.Length, &modulusLength,
                        pExponent, exponent.Length, &exponentLength,
                        pPrivateExponent, privateExponent.Length, &privateExponentLength,
                        pPrime1, prime1.Length, &prime1Length,
                        pPrime2, prime2.Length, &prime2Length,
                        pExponent1, exponent1.Length, &exponent1Length,
                        pExponent2, exponent2.Length, &exponent2Length,
                        pCoefficient, coefficient.Length, &coefficientLength) == 0)
                {
                    throw new CryptographicException("RinOS RSA key export failed.");
                }
            }

            return new RSAParameters
            {
                Modulus = TrimToLength(modulus, modulusLength),
                Exponent = TrimToLength(exponent, exponentLength),
                D = includePrivateParameters ? TrimToLength(privateExponent, privateExponentLength) : null,
                P = includePrivateParameters ? TrimToLength(prime1, prime1Length) : null,
                Q = includePrivateParameters ? TrimToLength(prime2, prime2Length) : null,
                DP = includePrivateParameters ? TrimToLength(exponent1, exponent1Length) : null,
                DQ = includePrivateParameters ? TrimToLength(exponent2, exponent2Length) : null,
                InverseQ = includePrivateParameters ? TrimToLength(coefficient, coefficientLength) : null,
            };
        }

        public override void ImportParameters(RSAParameters parameters)
        {
            ThrowIfDisposed();
            byte[] modulus = parameters.Modulus ?? Array.Empty<byte>();
            byte[] exponent = parameters.Exponent ?? Array.Empty<byte>();
            byte[] privateExponent = parameters.D ?? Array.Empty<byte>();
            byte[] prime1 = parameters.P ?? Array.Empty<byte>();
            byte[] prime2 = parameters.Q ?? Array.Empty<byte>();
            byte[] exponent1 = parameters.DP ?? Array.Empty<byte>();
            byte[] exponent2 = parameters.DQ ?? Array.Empty<byte>();
            byte[] coefficient = parameters.InverseQ ?? Array.Empty<byte>();

            fixed (byte* pModulus = modulus)
            fixed (byte* pExponent = exponent)
            fixed (byte* pPrivateExponent = privateExponent)
            fixed (byte* pPrime1 = prime1)
            fixed (byte* pPrime2 = prime2)
            fixed (byte* pExponent1 = exponent1)
            fixed (byte* pExponent2 = exponent2)
            fixed (byte* pCoefficient = coefficient)
            {
                if (Interop.Crypto.RinOSRsaImportParameters(
                        _context, pModulus, modulus.Length, pExponent, exponent.Length,
                        pPrivateExponent, privateExponent.Length, pPrime1, prime1.Length,
                        pPrime2, prime2.Length, pExponent1, exponent1.Length,
                        pExponent2, exponent2.Length, pCoefficient, coefficient.Length) == 0)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
                }
            }

            KeySizeValue = Interop.Crypto.RinOSRsaGetKeySize(_context);
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(padding);
            byte[] destination = new byte[GetMaxOutputSize()];
            if (!TryEncrypt(data, destination, padding, out int written))
            {
                throw new CryptographicException("RinOS RSA encryption failed.");
            }

            return TrimToLength(destination, written);
        }

        public override bool TryEncrypt(ReadOnlySpan<byte> data, Span<byte> destination,
                                        RSAEncryptionPadding padding, out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(padding);
            ThrowIfDisposed();
            int mode = GetEncryptionMode(padding, out int hashAlgorithm);
            fixed (byte* pData = data)
            fixed (byte* pDestination = destination)
            {
                return Interop.Crypto.RinOSRsaEncrypt(
                           _context, mode, hashAlgorithm, pData, data.Length,
                           pDestination, destination.Length, &bytesWritten) != 0;
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            ArgumentNullException.ThrowIfNull(data);
            ArgumentNullException.ThrowIfNull(padding);
            byte[] destination = new byte[GetMaxOutputSize()];
            if (!TryDecrypt(data, destination, padding, out int written))
            {
                throw new CryptographicException("RinOS RSA decryption failed.");
            }

            return TrimToLength(destination, written);
        }

        public override bool TryDecrypt(ReadOnlySpan<byte> data, Span<byte> destination,
                                        RSAEncryptionPadding padding, out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(padding);
            ThrowIfDisposed();
            int mode = GetEncryptionMode(padding, out int hashAlgorithm);
            fixed (byte* pData = data)
            fixed (byte* pDestination = destination)
            {
                return Interop.Crypto.RinOSRsaDecrypt(
                           _context, mode, hashAlgorithm, pData, data.Length,
                           pDestination, destination.Length, &bytesWritten) != 0;
            }
        }

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm,
                                        RSASignaturePadding padding)
        {
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(padding);
            byte[] destination = new byte[GetMaxOutputSize()];
            if (!TrySignHash(hash, destination, hashAlgorithm, padding, out int written))
            {
                throw new CryptographicException("RinOS RSA signing failed.");
            }

            return TrimToLength(destination, written);
        }

        public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination,
                                         HashAlgorithmName hashAlgorithm,
                                         RSASignaturePadding padding, out int bytesWritten)
        {
            ArgumentNullException.ThrowIfNull(padding);
            ThrowIfDisposed();
            int hashId = GetHashAlgorithm(hashAlgorithm, out int hashSize);
            int mode = padding.Mode switch
            {
                RSASignaturePaddingMode.Pkcs1 => RsaSignaturePkcs1,
                RSASignaturePaddingMode.Pss => RsaSignaturePss,
                _ => throw new CryptographicException("RinOS RSA signature padding is unsupported."),
            };
            int saltLength = mode == RsaSignaturePss ? hashSize : 0;
            fixed (byte* pHash = hash)
            fixed (byte* pDestination = destination)
            {
                return Interop.Crypto.RinOSRsaSignHash(
                           _context, mode, hashId, pHash, hash.Length, saltLength,
                           pDestination, Math.Min(destination.Length, GetMaxOutputSize()),
                           &bytesWritten) != 0;
            }
        }

        public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature,
                                        HashAlgorithmName hashAlgorithm,
                                        RSASignaturePadding padding)
        {
            ArgumentNullException.ThrowIfNull(padding);
            ThrowIfDisposed();
            int hashId = GetHashAlgorithm(hashAlgorithm, out int hashSize);
            int mode = padding.Mode switch
            {
                RSASignaturePaddingMode.Pkcs1 => RsaSignaturePkcs1,
                RSASignaturePaddingMode.Pss => RsaSignaturePss,
                _ => throw new CryptographicException("RinOS RSA signature padding is unsupported."),
            };
            int saltLength = mode == RsaSignaturePss ? hashSize : 0;
            fixed (byte* pHash = hash)
            fixed (byte* pSignature = signature)
            {
                return Interop.Crypto.RinOSRsaVerifyHash(
                           _context, mode, hashId, pHash, hash.Length, saltLength,
                           pSignature, signature.Length) != 0;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (_context != IntPtr.Zero)
            {
                Interop.Crypto.RinOSRsaDestroy(_context);
                _context = IntPtr.Zero;
            }

            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            if (_context == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(RinOSRsa));
            }
        }

        private static byte[] TrimToLength(byte[] source, int length)
        {
            if (length == source.Length)
                return source;
            byte[] result = new byte[length];
            source.AsSpan(0, length).CopyTo(result);
            CryptographicOperations.ZeroMemory(source);
            return result;
        }

        private static int GetEncryptionMode(RSAEncryptionPadding padding, out int hashAlgorithm)
        {
            hashAlgorithm = 0;
            return padding.Mode switch
            {
                RSAEncryptionPaddingMode.Pkcs1 => RsaPaddingPkcs1,
                RSAEncryptionPaddingMode.Oaep => GetOaepHash(padding.OaepHashAlgorithm, out hashAlgorithm),
                _ => throw new CryptographicException("RinOS RSA encryption padding is unsupported."),
            };
        }

        private static int GetOaepHash(HashAlgorithmName hashAlgorithm, out int hashId)
        {
            hashId = GetHashAlgorithm(hashAlgorithm, out _);
            return RsaPaddingOaep;
        }

        private static int GetHashAlgorithm(HashAlgorithmName hashAlgorithm, out int hashSize)
        {
            switch (hashAlgorithm.Name)
            {
                case "SHA1":
                    hashSize = 20;
                    return RsaHashSha1;
                case "SHA256":
                    hashSize = 32;
                    return RsaHashSha256;
                case "SHA384":
                    hashSize = 48;
                    return RsaHashSha384;
                case "SHA512":
                    hashSize = 64;
                    return RsaHashSha512;
                default:
                    throw new PlatformNotSupportedException("RinOS RSA supports SHA-1, SHA-256, SHA-384, and SHA-512.");
            }
        }

    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaCreate")]
                internal static partial IntPtr RinOSRsaCreate();

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaGenerateKey")]
                internal static partial int RinOSRsaGenerateKey(IntPtr context, int keySize, int publicExponent);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaImportParameters")]
                internal static unsafe partial int RinOSRsaImportParameters(
                    IntPtr context, byte* modulus, int modulusLength, byte* exponent,
                    int exponentLength, byte* privateExponent, int privateExponentLength,
                    byte* prime1, int prime1Length, byte* prime2, int prime2Length,
                    byte* exponent1, int exponent1Length, byte* exponent2, int exponent2Length,
                    byte* coefficient, int coefficientLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaGetKeySize")]
                internal static partial int RinOSRsaGetKeySize(IntPtr context);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaExportParameters")]
                internal static unsafe partial int RinOSRsaExportParameters(
                    IntPtr context, int includePrivateParameters, byte* modulus,
                    int modulusCapacity, int* modulusLength, byte* exponent,
                    int exponentCapacity, int* exponentLength, byte* privateExponent,
                    int privateExponentCapacity, int* privateExponentLength, byte* prime1,
                    int prime1Capacity, int* prime1Length, byte* prime2, int prime2Capacity,
                    int* prime2Length, byte* exponent1, int exponent1Capacity,
                    int* exponent1Length, byte* exponent2, int exponent2Capacity,
                    int* exponent2Length, byte* coefficient, int coefficientCapacity,
                    int* coefficientLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaEncrypt")]
                internal static unsafe partial int RinOSRsaEncrypt(
                    IntPtr context, int padding, int hashAlgorithm, byte* input,
                    int inputLength, byte* output, int outputCapacity, int* outputLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaDecrypt")]
                internal static unsafe partial int RinOSRsaDecrypt(
                    IntPtr context, int padding, int hashAlgorithm, byte* input,
                    int inputLength, byte* output, int outputCapacity, int* outputLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaSignHash")]
                internal static unsafe partial int RinOSRsaSignHash(
                    IntPtr context, int padding, int hashAlgorithm, byte* hash,
                    int hashLength, int saltLength, byte* signature,
                    int signatureCapacity, int* signatureLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaVerifyHash")]
                internal static unsafe partial int RinOSRsaVerifyHash(
                    IntPtr context, int padding, int hashAlgorithm, byte* hash,
                    int hashLength, int saltLength, byte* signature, int signatureLength);

                [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSRsaDestroy")]
                internal static partial void RinOSRsaDestroy(IntPtr context);
    }
}

#endif
