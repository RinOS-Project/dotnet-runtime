// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NetworkInformation
{
    internal static class IPGlobalPropertiesPal
    {
        public static IPGlobalProperties GetIPGlobalProperties()
        {
            return new RinOSIPGlobalProperties();
        }
    }

    internal sealed class RinOSIPGlobalProperties : UnixIPGlobalProperties
    {
        public override IPEndPoint[] GetActiveUdpListeners() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IPEndPoint[] GetActiveTcpListeners() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override TcpConnectionInformation[] GetActiveTcpConnections() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override string DhcpScopeName =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override bool IsWinsProxy =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override TcpStatistics GetTcpIPv4Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override TcpStatistics GetTcpIPv6Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override UdpStatistics GetUdpIPv4Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override UdpStatistics GetUdpIPv6Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IcmpV4Statistics GetIcmpV4Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IcmpV6Statistics GetIcmpV6Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IPGlobalStatistics GetIPv4GlobalStatistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IPGlobalStatistics GetIPv6GlobalStatistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
    }
}
