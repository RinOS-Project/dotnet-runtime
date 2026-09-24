// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NetworkInformation
{
    internal sealed class RinOSIPv6InterfaceProperties : UnixIPv6InterfaceProperties
    {
        private readonly RinOSNetworkInterface _networkInterface;

        internal RinOSIPv6InterfaceProperties(RinOSNetworkInterface networkInterface)
            : base(networkInterface)
        {
            _networkInterface = networkInterface;
        }

        public override int Mtu => _networkInterface.Mtu;

        public override long GetScopeId(ScopeLevel scopeLevel)
        {
            if (scopeLevel == ScopeLevel.None || scopeLevel == ScopeLevel.Interface ||
                scopeLevel == ScopeLevel.Link || scopeLevel == ScopeLevel.Subnet)
            {
                return _networkInterface.Index;
            }

            return 0;
        }
    }
}
