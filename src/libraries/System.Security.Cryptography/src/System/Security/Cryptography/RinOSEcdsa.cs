// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal sealed unsafe class RinOSEcdsa : ECDsa
    {
        private const int CurveP256 = 23;
        private const string P256Oid = "1.2.840.10045.3.1.7";
        private const int PrivateKeySize = 32;
        private const int PublicKeySize = 65;
        private const int SignatureSize = 64;
        private const int Sha256Size = 32;

        private static readonly KeySizes[] s_legalKeySizes =
        {
            new KeySizes(256, 256, 0),
        };

        private IntPtr _context;

        internal RinOSEcdsa()
        {
            LegalKeySizesValue = s_legalKeySizes;
            _context = Interop.Crypto.RinOSEcdsaCreate();
            if (_context == IntPtr.Zero)
                throw new CryptographicException("RinOS ECDSA context allocation failed.");

            try
            {
                GenerateKey(ECCurve.NamedCurves.nistP256);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        internal RinOSEcdsa(ECCurve curve) : this()
        {
            if (!IsP256(curve))
            {
                Dispose();
                throw new PlatformNotSupportedException("RinOS ECDSA supports only named P-256.");
            }
        }

        public override int KeySize
        {
            get
            {
                ThrowIfDisposed();
                int keySize = Interop.Crypto.RinOSEcdsaGetKeySize(_context);
                return keySize != 0 ? keySize : throw new CryptographicException(SR.Cryptography_InvalidKeySize);
            }
            set
            {
                ThrowIfDisposed();
                if (value != 256)
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);
                GenerateKey(ECCurve.NamedCurves.nistP256);
            }
        }

        public override byte[] SignHash(byte[] hash)
        {
            ArgumentNullException.ThrowIfNull(hash);
            ThrowIfDisposed();
            if (hash.Length != Sha256Size)
                throw new PlatformNotSupportedException("RinOS ECDSA currently supports SHA-256 hashes.");

            byte[] signature = new byte[SignatureSize];
            int signatureLength = 0;
            fixed (byte* pHash = hash)
            fixed (byte* pSignature = signature)
            {
                if (Interop.Crypto.RinOSEcdsaSignHash(
                        _context, pHash, hash.Length, pSignature, signature.Length,
                        &signatureLength) == 0 || signatureLength != SignatureSize)
                {
                    CryptographicOperations.ZeroMemory(signature);
                    throw new CryptographicException("RinOS ECDSA signing failed.");
                }
            }
            return signature;
        }

        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            ArgumentNullException.ThrowIfNull(hash);
            ArgumentNullException.ThrowIfNull(signature);
            ThrowIfDisposed();
            if (hash.Length != Sha256Size || signature.Length != SignatureSize)
                return false;

            fixed (byte* pHash = hash)
            fixed (byte* pSignature = signature)
            {
                return Interop.Crypto.RinOSEcdsaVerifyHash(
                           _context, pHash, hash.Length, pSignature, signature.Length) != 0;
            }
        }

        public override ECParameters ExportParameters(bool includePrivateParameters)
        {
            ThrowIfDisposed();
            byte[] privateKey = includePrivateParameters ? new byte[PrivateKeySize] : Array.Empty<byte>();
            byte[] publicKey = new byte[PublicKeySize];
            int privateKeyLength = 0;
            int publicKeyLength = 0;

            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pPublicKey = publicKey)
            {
                if (Interop.Crypto.RinOSEcdsaExportParameters(
                        _context, includePrivateParameters ? 1 : 0,
                        pPrivateKey, privateKey.Length, &privateKeyLength,
                        pPublicKey, publicKey.Length, &publicKeyLength) == 0 ||
                    publicKeyLength != PublicKeySize ||
                    (includePrivateParameters && privateKeyLength != PrivateKeySize))
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                    CryptographicOperations.ZeroMemory(publicKey);
                    throw new CryptographicException("RinOS ECDSA key export failed.");
                }
            }

            byte[]? exportedPrivateKey = includePrivateParameters ? privateKey : null;
            if (!includePrivateParameters)
                CryptographicOperations.ZeroMemory(privateKey);

            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = publicKey.AsSpan(1, PrivateKeySize).ToArray(),
                    Y = publicKey.AsSpan(1 + PrivateKeySize, PrivateKeySize).ToArray(),
                },
                D = exportedPrivateKey,
            };
        }

        public override void ImportParameters(ECParameters parameters)
        {
            ThrowIfDisposed();
            if (!IsP256(parameters.Curve))
                throw new PlatformNotSupportedException("RinOS ECDSA supports only named P-256.");

            byte[] x = parameters.Q.X ?? Array.Empty<byte>();
            byte[] y = parameters.Q.Y ?? Array.Empty<byte>();
            byte[] privateKey = parameters.D is { Length: > 0 }
                ? (byte[])parameters.D.Clone()
                : Array.Empty<byte>();
            if (x.Length != PrivateKeySize || y.Length != PrivateKeySize ||
                (privateKey.Length != 0 && privateKey.Length != PrivateKeySize))
            {
                CryptographicOperations.ZeroMemory(privateKey);
                throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters);
            }

            byte[] publicKey = new byte[PublicKeySize];
            publicKey[0] = 4;
            x.AsSpan().CopyTo(publicKey.AsSpan(1, PrivateKeySize));
            y.AsSpan().CopyTo(publicKey.AsSpan(1 + PrivateKeySize, PrivateKeySize));
            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pPublicKey = publicKey)
            {
                if (Interop.Crypto.RinOSEcdsaImportParameters(
                        _context, pPrivateKey, privateKey.Length,
                        pPublicKey, publicKey.Length) == 0)
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                    CryptographicOperations.ZeroMemory(publicKey);
                    throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters);
                }
            }
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
            KeySizeValue = 256;
        }

        public override void GenerateKey(ECCurve curve)
        {
            ThrowIfDisposed();
            if (!IsP256(curve))
                throw new PlatformNotSupportedException("RinOS ECDSA supports only named P-256.");
            if (Interop.Crypto.RinOSEcdsaGenerateKey(_context) == 0)
                throw new CryptographicException("RinOS ECDSA key generation failed.");
            KeySizeValue = 256;
        }

        protected override void Dispose(bool disposing)
        {
            if (_context != IntPtr.Zero)
            {
                Interop.Crypto.RinOSEcdsaDestroy(_context);
                _context = IntPtr.Zero;
            }
            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            if (_context == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(RinOSEcdsa));
        }

        private static bool IsP256(ECCurve curve)
        {
            return curve.IsNamed && curve.Oid.Value == P256Oid;
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaCreate")]
        internal static partial IntPtr RinOSEcdsaCreate();

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaGenerateKey")]
        internal static partial int RinOSEcdsaGenerateKey(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaImportParameters")]
        internal static unsafe partial int RinOSEcdsaImportParameters(
            IntPtr context, byte* privateKey, int privateKeyLength,
            byte* publicKey, int publicKeyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaGetKeySize")]
        internal static partial int RinOSEcdsaGetKeySize(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaExportParameters")]
        internal static unsafe partial int RinOSEcdsaExportParameters(
            IntPtr context, int includePrivate, byte* privateKey,
            int privateKeyCapacity, int* privateKeyLength, byte* publicKey,
            int publicKeyCapacity, int* publicKeyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaSignHash")]
        internal static unsafe partial int RinOSEcdsaSignHash(
            IntPtr context, byte* hash, int hashLength, byte* signature,
            int signatureCapacity, int* signatureLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaVerifyHash")]
        internal static unsafe partial int RinOSEcdsaVerifyHash(
            IntPtr context, byte* hash, int hashLength, byte* signature,
            int signatureLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaDestroy")]
        internal static partial void RinOSEcdsaDestroy(IntPtr context);
    }
}

#endif
