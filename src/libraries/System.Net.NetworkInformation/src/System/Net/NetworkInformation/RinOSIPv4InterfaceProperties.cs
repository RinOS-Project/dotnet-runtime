// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

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

        public override bool UsesWins =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override bool IsDhcpEnabled =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override bool IsAutomaticPrivateAddressingActive =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override bool IsAutomaticPrivateAddressingEnabled =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override bool IsForwardingEnabled =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override int Mtu => _networkInterface.Mtu;
    }
}
