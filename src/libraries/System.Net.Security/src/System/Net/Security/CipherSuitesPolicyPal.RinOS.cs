// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;

namespace System.Net.Security
{
    internal sealed class CipherSuitesPolicyPal
    {
        private readonly List<TlsCipherSuite> _cipherSuites = new();

        internal CipherSuitesPolicyPal(IEnumerable<TlsCipherSuite> allowedCipherSuites)
        {
            foreach (TlsCipherSuite cipherSuite in allowedCipherSuites)
            {
                _cipherSuites.Add(cipherSuite);
            }
        }

        internal IEnumerable<TlsCipherSuite> GetCipherSuites() => _cipherSuites;
    }
}
