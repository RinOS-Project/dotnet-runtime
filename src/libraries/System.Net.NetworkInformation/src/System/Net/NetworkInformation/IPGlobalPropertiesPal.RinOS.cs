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
            new RinOSTcpStatistics(System.Net.Sockets.AddressFamily.InterNetwork);

        public override TcpStatistics GetTcpIPv6Statistics() =>
            new RinOSTcpStatistics(System.Net.Sockets.AddressFamily.InterNetworkV6);

        public override UdpStatistics GetUdpIPv4Statistics() =>
            new RinOSUdpStatistics(System.Net.Sockets.AddressFamily.InterNetwork);

        public override UdpStatistics GetUdpIPv6Statistics() =>
            new RinOSUdpStatistics(System.Net.Sockets.AddressFamily.InterNetworkV6);

        public override IcmpV4Statistics GetIcmpV4Statistics() =>
            new RinOSIcmpV4Statistics();

        public override IcmpV6Statistics GetIcmpV6Statistics() =>
            new RinOSIcmpV6Statistics();

        public override IPGlobalStatistics GetIPv4GlobalStatistics() =>
            new RinOSIPGlobalStatistics(System.Net.Sockets.AddressFamily.InterNetwork);

        public override IPGlobalStatistics GetIPv6GlobalStatistics() =>
            new RinOSIPGlobalStatistics(System.Net.Sockets.AddressFamily.InterNetworkV6);
    }
}
