// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NetworkInformation
{
    internal sealed class RinOSIPInterfaceProperties : UnixIPInterfaceProperties
    {
        private readonly RinOSIPv4InterfaceProperties _ipv4Properties;
        private readonly RinOSIPv6InterfaceProperties _ipv6Properties;
        private readonly GatewayIPAddressInformationCollection _gatewayAddresses = new GatewayIPAddressInformationCollection();
        private readonly InternalIPAddressCollection _emptyAddresses = new InternalIPAddressCollection();

        internal RinOSIPInterfaceProperties(RinOSNetworkInterface networkInterface)
            : base(networkInterface, globalConfig: true)
        {
            _ipv4Properties = new RinOSIPv4InterfaceProperties(networkInterface);
            _ipv6Properties = new RinOSIPv6InterfaceProperties(networkInterface);
        }

        public override bool IsDynamicDnsEnabled => false;

        public override IPAddressInformationCollection AnycastAddresses => new IPAddressInformationCollection();

        public override GatewayIPAddressInformationCollection GatewayAddresses => _gatewayAddresses;

        public override IPAddressCollection DhcpServerAddresses => _emptyAddresses;

        public override IPAddressCollection WinsServersAddresses => _emptyAddresses;

        public override IPv4InterfaceProperties GetIPv4Properties() => _ipv4Properties;

        public override IPv6InterfaceProperties GetIPv6Properties() => _ipv6Properties;
    }
}
