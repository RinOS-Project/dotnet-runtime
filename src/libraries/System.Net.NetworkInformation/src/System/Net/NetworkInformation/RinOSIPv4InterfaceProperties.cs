// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NetworkInformation
{
    internal sealed class RinOSIPv4InterfaceProperties : UnixIPv4InterfaceProperties
    {
        private readonly RinOSNetworkInterface _networkInterface;

        internal RinOSIPv4InterfaceProperties(RinOSNetworkInterface networkInterface)
            : base(networkInterface)
        {
            _networkInterface = networkInterface;
        }

        public override bool UsesWins => false;

        public override bool IsDhcpEnabled => false;

        public override bool IsAutomaticPrivateAddressingActive => false;

        public override bool IsAutomaticPrivateAddressingEnabled => false;

        public override bool IsForwardingEnabled => false;

        public override int Mtu => _networkInterface.Mtu;
    }
}
