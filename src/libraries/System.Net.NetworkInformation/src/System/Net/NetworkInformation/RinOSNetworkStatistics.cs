// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Net.Sockets;

namespace System.Net.NetworkInformation
{
    internal readonly struct RinOSNetworkStatisticsSnapshot
    {
        internal readonly long BytesReceived;
        internal readonly long BytesSent;
        internal readonly long IncomingPacketsWithErrors;
        internal readonly long OutgoingPacketsWithErrors;
        internal readonly long UnicastPacketsReceived;
        internal readonly long UnicastPacketsSent;

        private RinOSNetworkStatisticsSnapshot(
            long bytesReceived,
            long bytesSent,
            long incomingPacketsWithErrors,
            long outgoingPacketsWithErrors,
            long unicastPacketsReceived,
            long unicastPacketsSent)
        {
            BytesReceived = bytesReceived;
            BytesSent = bytesSent;
            IncomingPacketsWithErrors = incomingPacketsWithErrors;
            OutgoingPacketsWithErrors = outgoingPacketsWithErrors;
            UnicastPacketsReceived = unicastPacketsReceived;
            UnicastPacketsSent = unicastPacketsSent;
        }

        internal static unsafe RinOSNetworkStatisticsSnapshot Read(int interfaceIndex)
        {
            if (interfaceIndex <= 0)
            {
                throw new NetworkInformationException(
                    "RinOS returned an invalid network-interface index.");
            }

            Interop.Sys.RinOSNetworkInterfaceStatistics native = default;
            if (Interop.Sys.GetRinOSNetworkInterfaceStatistics(
                    unchecked((uint)interfaceIndex), &native) != 0 ||
                native.Version != 1u ||
                native.StructSize != 64u ||
                native.DeviceGeneration != unchecked((uint)interfaceIndex))
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current network-statistics snapshot.");
            }

            return new RinOSNetworkStatisticsSnapshot(
                Clamp(native.RxBytes),
                Clamp(native.TxBytes),
                Clamp(native.RxErrors),
                Clamp(native.TxErrors),
                Clamp(native.RxPackets),
                Clamp(native.TxPackets));
        }

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        internal static long UnsupportedMetric() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        internal static int UnsupportedMetricInt() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        internal static bool UnsupportedMetricBool() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);
    }

    internal sealed class RinOSIPInterfaceStatistics : IPInterfaceStatistics
    {
        private readonly RinOSNetworkStatisticsSnapshot _snapshot;

        internal RinOSIPInterfaceStatistics(int interfaceIndex)
        {
            _snapshot = RinOSNetworkStatisticsSnapshot.Read(interfaceIndex);
        }

        public override long BytesReceived => _snapshot.BytesReceived;
        public override long BytesSent => _snapshot.BytesSent;
        public override long IncomingPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long IncomingPacketsWithErrors => _snapshot.IncomingPacketsWithErrors;
        public override long IncomingUnknownProtocolPackets => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long NonUnicastPacketsReceived => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long NonUnicastPacketsSent => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutgoingPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutgoingPacketsWithErrors => _snapshot.OutgoingPacketsWithErrors;
        public override long OutputQueueLength => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long UnicastPacketsReceived => _snapshot.UnicastPacketsReceived;
        public override long UnicastPacketsSent => _snapshot.UnicastPacketsSent;
    }

    internal sealed class RinOSIPv4InterfaceStatistics : IPv4InterfaceStatistics
    {
        private readonly RinOSNetworkStatisticsSnapshot _snapshot;

        internal RinOSIPv4InterfaceStatistics(int interfaceIndex)
        {
            _snapshot = RinOSNetworkStatisticsSnapshot.Read(interfaceIndex);
        }

        public override long BytesReceived => _snapshot.BytesReceived;
        public override long BytesSent => _snapshot.BytesSent;
        public override long IncomingPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long IncomingPacketsWithErrors => _snapshot.IncomingPacketsWithErrors;
        public override long IncomingUnknownProtocolPackets => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long NonUnicastPacketsReceived => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long NonUnicastPacketsSent => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutgoingPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutgoingPacketsWithErrors => _snapshot.OutgoingPacketsWithErrors;
        public override long OutputQueueLength => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long UnicastPacketsReceived => _snapshot.UnicastPacketsReceived;
        public override long UnicastPacketsSent => _snapshot.UnicastPacketsSent;
    }

    internal sealed class RinOSIPGlobalStatistics : IPGlobalStatistics
    {
        private const uint AddressFamilyIPv4 = 4u;
        private const uint AddressFamilyIPv6 = 6u;
        private const uint OutputPacketRequestsFlag = 0x00000001u;
        private const uint ReceivedPacketsFlag = 0x00000002u;
        private const uint ReceivedPacketsDeliveredFlag = 0x00000004u;
        private const uint ReceivedPacketsForwardedFlag = 0x00000008u;

        private readonly Interop.Sys.RinOSNetworkIpGlobalStatistics _snapshot;

        internal unsafe RinOSIPGlobalStatistics(AddressFamily family)
        {
            uint addressFamily = family == AddressFamily.InterNetwork
                ? AddressFamilyIPv4
                : family == AddressFamily.InterNetworkV6
                    ? AddressFamilyIPv6
                    : 0u;
            Interop.Sys.RinOSNetworkIpGlobalStatistics snapshot = default;
            if (addressFamily == 0u ||
                Interop.Sys.GetRinOSNetworkIpGlobalStatistics(
                    addressFamily, &snapshot) != 0 ||
                snapshot.Version != 1u ||
                snapshot.StructSize != 56u ||
                snapshot.DeviceGeneration == 0u ||
                snapshot.AddressFamily != addressFamily ||
                (snapshot.SupportedFlags & ~0x0000000Fu) != 0u)
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current IP-global-statistics snapshot.");
            }
            _snapshot = snapshot;
        }

        private long Read(ulong value, uint flag) =>
            (_snapshot.SupportedFlags & flag) != 0u
                ? Clamp(value)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        public override int DefaultTtl => RinOSNetworkStatisticsSnapshot.UnsupportedMetricInt();
        public override bool ForwardingEnabled => RinOSNetworkStatisticsSnapshot.UnsupportedMetricBool();
        public override int NumberOfInterfaces => RinOSNetworkStatisticsSnapshot.UnsupportedMetricInt();
        public override int NumberOfIPAddresses => RinOSNetworkStatisticsSnapshot.UnsupportedMetricInt();
        public override long OutputPacketRequests => Read(_snapshot.OutputPacketRequests, OutputPacketRequestsFlag);
        public override long OutputPacketRoutingDiscards => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutputPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long OutputPacketsWithNoRoute => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketFragmentFailures => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketReassembliesRequired => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketReassemblyFailures => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketReassemblyTimeout => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketsFragmented => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long PacketsReassembled => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long ReceivedPackets => Read(_snapshot.ReceivedPackets, ReceivedPacketsFlag);
        public override long ReceivedPacketsDelivered => Read(_snapshot.ReceivedPacketsDelivered, ReceivedPacketsDeliveredFlag);
        public override long ReceivedPacketsDiscarded => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long ReceivedPacketsForwarded => Read(_snapshot.ReceivedPacketsForwarded, ReceivedPacketsForwardedFlag);
        public override long ReceivedPacketsWithAddressErrors => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long ReceivedPacketsWithHeadersErrors => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override long ReceivedPacketsWithUnknownProtocol => RinOSNetworkStatisticsSnapshot.UnsupportedMetric();
        public override int NumberOfRoutes => RinOSNetworkStatisticsSnapshot.UnsupportedMetricInt();
    }
}
