// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#if TARGET_RINOS
namespace System.Security.Cryptography
{
    public abstract partial class RSA
    {
        public static new partial RSA Create() => new RinOSRsa();
    }
}
#endif
