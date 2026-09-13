// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal sealed unsafe class RinOSEcdh : ECDiffieHellman
    {
        private const string P256Oid = "1.2.840.10045.3.1.7";
        private const int PrivateKeySize = 32;
        private const int PublicKeySize = 65;
        private const int SecretSize = 32;

        private static readonly KeySizes[] s_legalKeySizes =
        {
            new KeySizes(256, 256, 0),
        };

        private IntPtr _context;

        internal RinOSEcdh()
        {
            LegalKeySizesValue = s_legalKeySizes;
            _context = Interop.Crypto.RinOSEcdhCreate();
            if (_context == IntPtr.Zero)
                throw new CryptographicException("RinOS ECDH context allocation failed.");

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

        internal RinOSEcdh(ECCurve curve) : this()
        {
            if (!IsP256(curve))
            {
                Dispose();
                throw new PlatformNotSupportedException("RinOS ECDH supports only named P-256.");
            }
        }

        public override ECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                ThrowIfDisposed();
                ECParameters parameters = ExportParameters(false);
                byte[] publicKey = new byte[PublicKeySize];
                publicKey[0] = 4;
                parameters.Q.X!.AsSpan().CopyTo(publicKey.AsSpan(1, PrivateKeySize));
                parameters.Q.Y!.AsSpan().CopyTo(publicKey.AsSpan(1 + PrivateKeySize, PrivateKeySize));
                return new RinOSEcdhPublicKey(publicKey);
            }
        }

        public override int KeySize
        {
            get
            {
                ThrowIfDisposed();
                int keySize = Interop.Crypto.RinOSEcdhGetKeySize(_context);
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

        public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
        {
            return DeriveRawSecretAgreement(otherPartyPublicKey);
        }

        public override byte[] DeriveRawSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey)
        {
            ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
            ThrowIfDisposed();
            byte[] peerPublicKey = GetRawPublicKey(otherPartyPublicKey);
            byte[] secret = new byte[SecretSize];
            int secretLength = 0;
            try
            {
                fixed (byte* pPeerPublicKey = peerPublicKey)
                fixed (byte* pSecret = secret)
                {
                    if (Interop.Crypto.RinOSEcdhDeriveRawSecret(
                            _context, pPeerPublicKey, peerPublicKey.Length,
                            pSecret, secret.Length, &secretLength) == 0 ||
                        secretLength != SecretSize)
                    {
                        CryptographicOperations.ZeroMemory(secret);
                        throw new CryptographicException("RinOS ECDH derivation failed.");
                    }
                }
                return secret;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(peerPublicKey);
            }
        }

        public override byte[] DeriveKeyFromHash(
            ECDiffieHellmanPublicKey otherPartyPublicKey,
            HashAlgorithmName hashAlgorithm,
            byte[]? secretPrepend,
            byte[]? secretAppend)
        {
            ArgumentNullException.ThrowIfNull(otherPartyPublicKey);
            ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm.Name, nameof(hashAlgorithm));
            byte[] secret = DeriveRawSecretAgreement(otherPartyPublicKey);
            byte[] prepend = secretPrepend ?? Array.Empty<byte>();
            byte[] append = secretAppend ?? Array.Empty<byte>();
            byte[] input = new byte[prepend.Length + secret.Length + append.Length];
            try
            {
                prepend.AsSpan().CopyTo(input);
                secret.AsSpan().CopyTo(input.AsSpan(prepend.Length));
                append.AsSpan().CopyTo(input.AsSpan(prepend.Length + secret.Length));
                return HashData(hashAlgorithm, input);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(secret);
                CryptographicOperations.ZeroMemory(input);
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
                if (Interop.Crypto.RinOSEcdhExportParameters(
                        _context, includePrivateParameters ? 1 : 0,
                        pPrivateKey, privateKey.Length, &privateKeyLength,
                        pPublicKey, publicKey.Length, &publicKeyLength) == 0 ||
                    publicKeyLength != PublicKeySize ||
                    (includePrivateParameters && privateKeyLength != PrivateKeySize))
                {
                    CryptographicOperations.ZeroMemory(privateKey);
                    CryptographicOperations.ZeroMemory(publicKey);
                    throw new CryptographicException("RinOS ECDH key export failed.");
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
                throw new PlatformNotSupportedException("RinOS ECDH supports only named P-256.");

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
                if (Interop.Crypto.RinOSEcdhImportParameters(
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
                throw new PlatformNotSupportedException("RinOS ECDH supports only named P-256.");
            if (Interop.Crypto.RinOSEcdhGenerateKey(_context) == 0)
                throw new CryptographicException("RinOS ECDH key generation failed.");
            KeySizeValue = 256;
        }

        protected override void Dispose(bool disposing)
        {
            if (_context != IntPtr.Zero)
            {
                Interop.Crypto.RinOSEcdhDestroy(_context);
                _context = IntPtr.Zero;
            }
            base.Dispose(disposing);
        }

        private static byte[] GetRawPublicKey(ECDiffieHellmanPublicKey publicKey)
        {
            if (publicKey is RinOSEcdhPublicKey rinosKey)
                return rinosKey.CloneRawPublicKey();

            ECParameters parameters = publicKey.ExportParameters();
            if (!IsP256(parameters.Curve) || parameters.Q.X is not { Length: PrivateKeySize } x ||
                parameters.Q.Y is not { Length: PrivateKeySize } y)
                throw new PlatformNotSupportedException("RinOS ECDH requires a named P-256 public key.");

            byte[] raw = new byte[PublicKeySize];
            raw[0] = 4;
            x.AsSpan().CopyTo(raw.AsSpan(1, PrivateKeySize));
            y.AsSpan().CopyTo(raw.AsSpan(1 + PrivateKeySize, PrivateKeySize));
            return raw;
        }

        private void ThrowIfDisposed()
        {
            if (_context == IntPtr.Zero)
                throw new ObjectDisposedException(nameof(RinOSEcdh));
        }

        private static bool IsP256(ECCurve curve)
        {
            return curve.IsNamed && curve.Oid.Value == P256Oid;
        }

        private static byte[] HashData(HashAlgorithmName hashAlgorithm, ReadOnlySpan<byte> input)
        {
            return hashAlgorithm.Name switch
            {
                "SHA256" => SHA256.HashData(input),
                "SHA384" => SHA384.HashData(input),
                "SHA512" => SHA512.HashData(input),
                _ => throw new PlatformNotSupportedException("RinOS ECDH key derivation supports SHA-256, SHA-384, and SHA-512."),
            };
        }
    }

    internal sealed class RinOSEcdhPublicKey : ECDiffieHellmanPublicKey
    {
        private byte[] _publicKey;
        private bool _disposed;

        internal RinOSEcdhPublicKey(byte[] publicKey)
        {
            _publicKey = publicKey;
        }

        internal byte[] CloneRawPublicKey()
        {
            ThrowIfDisposed();
            return (byte[])_publicKey.Clone();
        }

        public override ECParameters ExportParameters()
        {
            ThrowIfDisposed();
            return new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint
                {
                    X = _publicKey.AsSpan(1, 32).ToArray(),
                    Y = _publicKey.AsSpan(33, 32).ToArray(),
                },
            };
        }

#pragma warning disable 0672, SYSLIB0043
        public override byte[] ToByteArray()
        {
            return CloneRawPublicKey();
        }
#pragma warning restore 0672, SYSLIB0043

        protected override void Dispose(bool disposing)
        {
            if (_disposed)
                return;
            _disposed = true;
            CryptographicOperations.ZeroMemory(_publicKey);
            _publicKey = Array.Empty<byte>();
            base.Dispose(disposing);
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(RinOSEcdhPublicKey));
        }
    }
}

internal static partial class Interop
{
    internal static partial class Crypto
    {
        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhCreate")]
        internal static partial IntPtr RinOSEcdhCreate();

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhGenerateKey")]
        internal static partial int RinOSEcdhGenerateKey(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhImportParameters")]
        internal static unsafe partial int RinOSEcdhImportParameters(
            IntPtr context, byte* privateKey, int privateKeyLength,
            byte* publicKey, int publicKeyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhGetKeySize")]
        internal static partial int RinOSEcdhGetKeySize(IntPtr context);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhExportParameters")]
        internal static unsafe partial int RinOSEcdhExportParameters(
            IntPtr context, int includePrivate, byte* privateKey,
            int privateKeyCapacity, int* privateKeyLength, byte* publicKey,
            int publicKeyCapacity, int* publicKeyLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhDeriveRawSecret")]
        internal static unsafe partial int RinOSEcdhDeriveRawSecret(
            IntPtr context, byte* peerPublicKey, int peerPublicKeyLength,
            byte* secret, int secretCapacity, int* secretLength);

        [LibraryImport(Libraries.CryptoNative, EntryPoint = "CryptoNative_RinOSEcdhDestroy")]
        internal static partial void RinOSEcdhDestroy(IntPtr context);
    }
}

#endif
