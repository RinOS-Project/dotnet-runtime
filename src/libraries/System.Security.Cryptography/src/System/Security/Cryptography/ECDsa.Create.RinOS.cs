// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS

namespace System.Security.Cryptography
{
    public partial class ECDsa : ECAlgorithm
    {
        public static new partial ECDsa Create()
        {
            return new RinOSEcdsa();
        }

        public static partial ECDsa Create(ECCurve curve)
        {
            return new RinOSEcdsa(curve);
        }

        public static partial ECDsa Create(ECParameters parameters)
        {
            var ecdsa = new RinOSEcdsa();
            try
            {
                ecdsa.ImportParameters(parameters);
                return ecdsa;
            }
            catch
            {
                ecdsa.Dispose();
                throw;
            }
        }
    }
}

#endif
