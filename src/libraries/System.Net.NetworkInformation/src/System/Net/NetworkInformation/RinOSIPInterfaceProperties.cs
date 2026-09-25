// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

namespace System.Net.NetworkInformation
{
    internal sealed class RinOSIPInterfaceProperties : UnixIPInterfaceProperties
    {
        private readonly RinOSIPv4InterfaceProperties _ipv4Properties;
        private readonly RinOSIPv6InterfaceProperties _ipv6Properties;
        private readonly GatewayIPAddressInformationCollection _gatewayAddresses;
        private readonly InternalIPAddressCollection _dnsAddresses;
        private readonly InternalIPAddressCollection _emptyAddresses = new InternalIPAddressCollection();

        internal RinOSIPInterfaceProperties(
            RinOSNetworkInterface networkInterface,
            Interop.Sys.RinOSNetworkPrimaryInfo? primaryInfo)
            : base(networkInterface, globalConfig: true)
        {
            _ipv4Properties = new RinOSIPv4InterfaceProperties(networkInterface);
            _ipv6Properties = new RinOSIPv6InterfaceProperties(networkInterface);
            _gatewayAddresses = CreateGatewayAddresses(primaryInfo);
            _dnsAddresses = CreateDnsAddresses(primaryInfo);
        }

        public override bool IsDynamicDnsEnabled => false;

        public override IPAddressInformationCollection AnycastAddresses => new IPAddressInformationCollection();

        public override GatewayIPAddressInformationCollection GatewayAddresses => _gatewayAddresses;

        public override IPAddressCollection DhcpServerAddresses => _emptyAddresses;

        public override IPAddressCollection WinsServersAddresses => _emptyAddresses;

        public override bool IsDnsEnabled => _dnsAddresses.Count != 0;

        public override IPAddressCollection DnsAddresses => _dnsAddresses;

        public override IPv4InterfaceProperties GetIPv4Properties() => _ipv4Properties;

        public override IPv6InterfaceProperties GetIPv6Properties() => _ipv6Properties;

        private static IPAddress? ToConfiguredAddress(InlineArray4<byte> bytes)
        {
            ReadOnlySpan<byte> addressBytes = bytes;
            bool allZero = true;
            for (int i = 0; i < addressBytes.Length; i++)
            {
                if (addressBytes[i] != 0)
                {
                    allZero = false;
                    break;
                }
            }

            return allZero ? null : new IPAddress(addressBytes);
        }

        private static GatewayIPAddressInformationCollection CreateGatewayAddresses(
            Interop.Sys.RinOSNetworkPrimaryInfo? primaryInfo)
        {
            InternalIPAddressCollection gatewayAddresses = new InternalIPAddressCollection();
            if (primaryInfo.HasValue)
            {
                IPAddress? gateway = ToConfiguredAddress(primaryInfo.Value.GatewayBytes);
                if (gateway is not null)
                {
                    gatewayAddresses.InternalAdd(gateway);
                }
            }

            return SystemGatewayIPAddressInformation.ToGatewayIpAddressInformationCollection(gatewayAddresses);
        }

        private static InternalIPAddressCollection CreateDnsAddresses(
            Interop.Sys.RinOSNetworkPrimaryInfo? primaryInfo)
        {
            List<IPAddress> addresses = new List<IPAddress>();
            if (primaryInfo.HasValue)
            {
                IPAddress? dns = ToConfiguredAddress(primaryInfo.Value.DnsBytes);
                if (dns is not null)
                {
                    addresses.Add(dns);
                }
            }

            return new InternalIPAddressCollection(addresses);
        }
    }
}
