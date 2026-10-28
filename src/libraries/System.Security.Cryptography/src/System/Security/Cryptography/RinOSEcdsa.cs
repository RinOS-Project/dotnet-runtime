// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal sealed unsafe class RinOSEcdsa : ECDsa
    {
        private const string P256Oid = "1.2.840.10045.3.1.7";
        private const string P384Oid = "1.3.132.0.34";
        private const string P521Oid = "1.3.132.0.35";
        private const int CurveP256 = 23;
        private const int CurveP384 = 24;
        private const int CurveP521 = 25;

        private static readonly KeySizes[] s_legalKeySizes =
        {
            new KeySizes(256, 256, 0),
            new KeySizes(384, 384, 0),
            new KeySizes(521, 521, 0),
        };

        private IntPtr _context;
        private int _curve;

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
            try
            {
                GenerateKey(curve);
            }
            catch
            {
                Dispose();
                throw;
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
                int curve = value switch
                {
                    256 => CurveP256,
                    384 => CurveP384,
                    521 => CurveP521,
                    _ => 0,
                };
                if (curve == 0)
                    throw new CryptographicException(SR.Cryptography_InvalidKeySize);
                GenerateKey(GetCurve(curve));
            }
        }

        public override byte[] SignHash(byte[] hash)
        {
            ArgumentNullException.ThrowIfNull(hash);
            ThrowIfDisposed();
            int hashSize = GetHashSize(_curve);
            int signatureSize = GetCoordinateSize(_curve) * 2;
            if (hash.Length != hashSize)
                throw new CryptographicException(SR.Cryptography_InvalidHashSize);

            byte[] signature = new byte[signatureSize];
            int signatureLength = 0;
            fixed (byte* pHash = hash)
            fixed (byte* pSignature = signature)
            {
                if (Interop.Crypto.RinOSEcdsaSignHash(
                        _context, pHash, hash.Length, pSignature, signature.Length,
                        &signatureLength) == 0 || signatureLength != signatureSize)
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
            int coordinateSize = GetCoordinateSize(_curve);
            if (hash.Length != GetHashSize(_curve) || signature.Length != coordinateSize * 2)
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
            int coordinateSize = GetCoordinateSize(_curve);
            int privateKeySize = coordinateSize;
            int publicKeySize = 1 + coordinateSize * 2;
            byte[] privateKey = includePrivateParameters ? new byte[privateKeySize] : Array.Empty<byte>();
            byte[] publicKey = new byte[publicKeySize];
            int privateKeyLength = 0;
            int publicKeyLength = 0;

            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pPublicKey = publicKey)
            {
                if (Interop.Crypto.RinOSEcdsaExportParameters(
                        _context, includePrivateParameters ? 1 : 0,
                        pPrivateKey, privateKey.Length, &privateKeyLength,
                        pPublicKey, publicKey.Length, &publicKeyLength) == 0 ||
                    publicKeyLength != publicKeySize ||
                    (includePrivateParameters && privateKeyLength != privateKeySize))
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
                Curve = GetCurve(_curve),
                Q = new ECPoint
                {
                    X = publicKey.AsSpan(1, coordinateSize).ToArray(),
                    Y = publicKey.AsSpan(1 + coordinateSize, coordinateSize).ToArray(),
                },
                D = exportedPrivateKey,
            };
        }

        public override void ImportParameters(ECParameters parameters)
        {
            ThrowIfDisposed();
            int curve = GetCurveId(parameters.Curve);
            int coordinateSize = GetCoordinateSize(curve);

            byte[] x = parameters.Q.X ?? Array.Empty<byte>();
            byte[] y = parameters.Q.Y ?? Array.Empty<byte>();
            byte[] privateKey = parameters.D is { Length: > 0 }
                ? (byte[])parameters.D.Clone()
                : Array.Empty<byte>();
            if (x.Length != coordinateSize || y.Length != coordinateSize ||
                (privateKey.Length != 0 && privateKey.Length != coordinateSize))
            {
                CryptographicOperations.ZeroMemory(privateKey);
                throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters);
            }

            byte[] publicKey = new byte[1 + coordinateSize * 2];
            publicKey[0] = 4;
            x.AsSpan().CopyTo(publicKey.AsSpan(1, coordinateSize));
            y.AsSpan().CopyTo(publicKey.AsSpan(1 + coordinateSize, coordinateSize));
            fixed (byte* pPrivateKey = privateKey)
            fixed (byte* pPublicKey = publicKey)
            {
                if (Interop.Crypto.RinOSEcdsaImportParameters(
                        _context, curve, pPrivateKey, privateKey.Length,
                        pPublicKey, publicKey.Length) == 0)
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                    CryptographicOperations.ZeroMemory(publicKey);
                    throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters);
                }
            }
            CryptographicOperations.ZeroMemory(privateKey);
            CryptographicOperations.ZeroMemory(publicKey);
            _curve = curve;
            KeySizeValue = curve switch
            {
                CurveP256 => 256,
                CurveP384 => 384,
                CurveP521 => 521,
                _ => throw new CryptographicException(SR.Cryptography_InvalidCurveKeyParameters),
            };
        }

        public override void GenerateKey(ECCurve curve)
        {
            ThrowIfDisposed();
            int curveId = GetCurveId(curve);
            if (Interop.Crypto.RinOSEcdsaGenerateKey(_context, curveId) == 0)
                throw new CryptographicException("RinOS ECDSA key generation failed.");
            _curve = curveId;
            KeySizeValue = curveId switch
            {
                CurveP256 => 256,
                CurveP384 => 384,
                CurveP521 => 521,
                _ => throw new CryptographicException(SR.Cryptography_InvalidKeySize),
            };
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
            ObjectDisposedException.ThrowIf(_context == IntPtr.Zero, this);
        }

        private static int GetCurveId(ECCurve curve)
        {
            if (!curve.IsNamed)
                throw new PlatformNotSupportedException("RinOS ECDSA requires a named NIST curve.");
            return curve.Oid.Value switch
            {
                P256Oid => CurveP256,
                P384Oid => CurveP384,
                P521Oid => CurveP521,
                _ => throw new PlatformNotSupportedException("RinOS ECDSA supports only named P-256, P-384, and P-521."),
            };
        }

        private static int GetCoordinateSize(int curve)
        {
            return curve switch
            {
                CurveP256 => 32,
                CurveP384 => 48,
                CurveP521 => 66,
                _ => throw new CryptographicException(SR.Cryptography_InvalidKeySize),
            };
        }

        private static int GetHashSize(int curve)
        {
            return curve switch
            {
                CurveP256 => 32,
                CurveP384 => 48,
                CurveP521 => 64,
                _ => throw new CryptographicException(SR.Cryptography_InvalidKeySize),
            };
        }

        private static ECCurve GetCurve(int curve)
        {
            return curve switch
            {
                CurveP256 => ECCurve.NamedCurves.nistP256,
                CurveP384 => ECCurve.NamedCurves.nistP384,
                CurveP521 => ECCurve.NamedCurves.nistP521,
                _ => throw new CryptographicException(SR.Cryptography_InvalidKeySize),
            };
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
        internal static partial int RinOSEcdsaGenerateKey(IntPtr context, int curve);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdsaImportParameters")]
        internal static unsafe partial int RinOSEcdsaImportParameters(
            IntPtr context, int curve, byte* privateKey, int privateKeyLength,
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
