// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

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
}
