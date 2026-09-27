// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Sys
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct LinkLayerAddressInfo
        {
            public int InterfaceIndex;
            public InlineArray12<byte> AddressBytes;
            public byte NumAddressBytes;
            private byte __padding; // For native struct-size padding. Does not contain useful data.
            public ushort HardwareType;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IpAddressInfo
        {
            public int InterfaceIndex;
            public InlineArray16<byte> AddressBytes;
            public byte NumAddressBytes;
            public byte PrefixLength;
            private InlineArray2<byte> __padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct NetworkInterfaceInfo
        {
            public InlineArray16<byte> Name;
            public long Speed;
            public int InterfaceIndex;
            public int Mtu;
            public ushort HardwareType;
            public byte OperationalState;
            public byte NumAddressBytes;
            public InlineArray12<byte> AddressBytes;
            public byte SupportsMulticast;
            private InlineArray3<byte> __padding;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkPrimaryInfo
        {
            public InlineArray16<byte> Name;
            public InlineArray4<byte> AddressBytes;
            public InlineArray4<byte> NetmaskBytes;
            public InlineArray4<byte> GatewayBytes;
            public InlineArray4<byte> DnsBytes;
            public uint Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkInterfaceStatistics
        {
            public uint Version;
            public uint StructSize;
            public ulong DeviceGeneration;
            public ulong RxBytes;
            public ulong TxBytes;
            public ulong RxPackets;
            public ulong TxPackets;
            public ulong RxErrors;
            public ulong TxErrors;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkIpGlobalStatistics
        {
            public uint Version;
            public uint StructSize;
            public ulong DeviceGeneration;
            public uint AddressFamily;
            public uint SupportedFlags;
            public ulong OutputPacketRequests;
            public ulong ReceivedPackets;
            public ulong ReceivedPacketsDelivered;
            public ulong ReceivedPacketsForwarded;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkUdpGlobalStatistics
        {
            public uint Version;
            public uint StructSize;
            public ulong DeviceGeneration;
            public uint AddressFamily;
            public uint SupportedFlags;
            public ulong DatagramsSent;
            public ulong DatagramsReceived;
            public ulong IncomingDatagramsDiscarded;
            public ulong IncomingDatagramsWithErrors;
            public ulong UdpListeners;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkTcpGlobalStatistics
        {
            public uint Version;
            public uint StructSize;
            public ulong DeviceGeneration;
            public uint AddressFamily;
            public uint SupportedFlags;
            public ulong ConnectionsAccepted;
            public ulong ConnectionsInitiated;
            public ulong CumulativeConnections;
            public ulong CurrentConnections;
            public ulong ErrorsReceived;
            public ulong FailedConnectionAttempts;
            public ulong ResetConnections;
            public ulong SegmentsReceived;
            public ulong SegmentsResent;
            public ulong SegmentsSent;
            public ulong ResetsSent;
            public ulong MaximumConnections;
            public ulong MaximumTransmissionTimeout;
            public ulong MinimumTransmissionTimeout;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RinOSNetworkIcmpGlobalStatistics
        {
            public uint Version;
            public uint StructSize;
            public ulong DeviceGeneration;
            public uint AddressFamily;
            public uint SupportedFlags;
            public ulong MessagesReceived;
            public ulong MessagesSent;
            public ulong ErrorsReceived;
            public ulong ErrorsSent;
            public ulong DestinationUnreachableReceived;
            public ulong DestinationUnreachableSent;
            public ulong EchoRepliesReceived;
            public ulong EchoRepliesSent;
            public ulong EchoRequestsReceived;
            public ulong EchoRequestsSent;
            public ulong ParameterProblemsReceived;
            public ulong ParameterProblemsSent;
            public ulong TimeExceededReceived;
            public ulong TimeExceededSent;
            public ulong PacketTooBigReceived;
            public ulong PacketTooBigSent;
        }

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_EnumerateInterfaceAddresses")]
        public static unsafe partial int EnumerateInterfaceAddresses(
            void* context,
            delegate* unmanaged<void*, byte*, IpAddressInfo*, void> ipv4Found,
            delegate* unmanaged<void*, byte*, IpAddressInfo*, uint*, void> ipv6Found,
            delegate* unmanaged<void*, byte*, LinkLayerAddressInfo*, void> linkLayerFound);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_EnumerateGatewayAddressesForInterface")]
        public static unsafe partial int EnumerateGatewayAddressesForInterface(void* context, uint interfaceIndex, delegate* unmanaged<void*, IpAddressInfo*, void> onGatewayFound);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetNetworkInterfaces", SetLastError = true)]
        public static unsafe partial int GetNetworkInterfaces(int* count, NetworkInterfaceInfo** addrs, int* addressCount, IpAddressInfo** aa);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkPrimaryInfo", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkPrimaryInfo(RinOSNetworkPrimaryInfo* info);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkInterfaceStatistics", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkInterfaceStatistics(uint interfaceIndex, RinOSNetworkInterfaceStatistics* info);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkIpGlobalStatistics", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkIpGlobalStatistics(uint addressFamily, RinOSNetworkIpGlobalStatistics* info);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkUdpGlobalStatistics", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkUdpGlobalStatistics(uint addressFamily, RinOSNetworkUdpGlobalStatistics* info);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkTcpGlobalStatistics", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkTcpGlobalStatistics(uint addressFamily, RinOSNetworkTcpGlobalStatistics* info);

        [LibraryImport(Libraries.SystemNative, EntryPoint = "SystemNative_GetRinOSNetworkIcmpGlobalStatistics", SetLastError = true)]
        public static unsafe partial int GetRinOSNetworkIcmpGlobalStatistics(uint addressFamily, RinOSNetworkIcmpGlobalStatistics* info);

    }
}
