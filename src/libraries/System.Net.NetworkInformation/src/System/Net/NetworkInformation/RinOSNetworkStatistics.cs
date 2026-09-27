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

    internal sealed class RinOSUdpStatistics : UdpStatistics
    {
        private const uint AddressFamilyIPv4 = 4u;
        private const uint AddressFamilyIPv6 = 6u;
        private const uint DatagramsSentFlag = 0x00000001u;
        private const uint DatagramsReceivedFlag = 0x00000002u;
        private const uint IncomingDiscardedFlag = 0x00000004u;
        private const uint IncomingErrorsFlag = 0x00000008u;
        private const uint ListenersFlag = 0x00000010u;

        private readonly Interop.Sys.RinOSNetworkUdpGlobalStatistics _snapshot;

        internal unsafe RinOSUdpStatistics(AddressFamily family)
        {
            uint addressFamily = family == AddressFamily.InterNetwork
                ? AddressFamilyIPv4
                : family == AddressFamily.InterNetworkV6
                    ? AddressFamilyIPv6
                    : 0u;
            Interop.Sys.RinOSNetworkUdpGlobalStatistics snapshot = default;
            if (addressFamily == 0u ||
                Interop.Sys.GetRinOSNetworkUdpGlobalStatistics(
                    addressFamily, &snapshot) != 0 ||
                snapshot.Version != 1u ||
                snapshot.StructSize != 64u ||
                snapshot.DeviceGeneration == 0u ||
                snapshot.AddressFamily != addressFamily ||
                (snapshot.SupportedFlags & ~0x0000001Fu) != 0u)
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current UDP-statistics snapshot.");
            }
            _snapshot = snapshot;
        }

        private long Read(ulong value, uint flag) =>
            (_snapshot.SupportedFlags & flag) != 0u
                ? Clamp(value)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        private int ReadListeners() =>
            (_snapshot.SupportedFlags & ListenersFlag) != 0u
                ? ClampToInt(_snapshot.UdpListeners)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetricInt();

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        private static int ClampToInt(ulong value) =>
            value > int.MaxValue ? int.MaxValue : (int)value;

        public override long DatagramsReceived =>
            Read(_snapshot.DatagramsReceived, DatagramsReceivedFlag);

        public override long DatagramsSent =>
            Read(_snapshot.DatagramsSent, DatagramsSentFlag);

        public override long IncomingDatagramsDiscarded =>
            Read(_snapshot.IncomingDatagramsDiscarded, IncomingDiscardedFlag);

        public override long IncomingDatagramsWithErrors =>
            Read(_snapshot.IncomingDatagramsWithErrors, IncomingErrorsFlag);

        public override int UdpListeners => ReadListeners();
    }

    internal sealed class RinOSTcpStatistics : TcpStatistics
    {
        private const uint AddressFamilyIPv4 = 4u;
        private const uint AddressFamilyIPv6 = 6u;
        private const uint ConnectionsAcceptedFlag = 0x00000001u;
        private const uint ConnectionsInitiatedFlag = 0x00000002u;
        private const uint CumulativeConnectionsFlag = 0x00000004u;
        private const uint CurrentConnectionsFlag = 0x00000008u;
        private const uint ErrorsReceivedFlag = 0x00000010u;
        private const uint FailedConnectionAttemptsFlag = 0x00000020u;
        private const uint ResetConnectionsFlag = 0x00000040u;
        private const uint SegmentsReceivedFlag = 0x00000080u;
        private const uint SegmentsResentFlag = 0x00000100u;
        private const uint SegmentsSentFlag = 0x00000200u;
        private const uint ResetsSentFlag = 0x00000400u;
        private const uint KnownFlags = 0x00003FFFu;

        private readonly Interop.Sys.RinOSNetworkTcpGlobalStatistics _snapshot;

        internal unsafe RinOSTcpStatistics(AddressFamily family)
        {
            uint addressFamily = family == AddressFamily.InterNetwork
                ? AddressFamilyIPv4
                : family == AddressFamily.InterNetworkV6
                    ? AddressFamilyIPv6
                    : 0u;
            Interop.Sys.RinOSNetworkTcpGlobalStatistics snapshot = default;
            if (addressFamily == 0u ||
                Interop.Sys.GetRinOSNetworkTcpGlobalStatistics(
                    addressFamily, &snapshot) != 0 ||
                snapshot.Version != 1u ||
                snapshot.StructSize != 136u ||
                snapshot.DeviceGeneration == 0u ||
                snapshot.AddressFamily != addressFamily ||
                (snapshot.SupportedFlags & ~KnownFlags) != 0u)
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current TCP-statistics snapshot.");
            }
            _snapshot = snapshot;
        }

        private long Read(ulong value, uint flag) =>
            (_snapshot.SupportedFlags & flag) != 0u
                ? Clamp(value)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        public override long ConnectionsAccepted =>
            Read(_snapshot.ConnectionsAccepted, ConnectionsAcceptedFlag);

        public override long ConnectionsInitiated =>
            Read(_snapshot.ConnectionsInitiated, ConnectionsInitiatedFlag);

        public override long CumulativeConnections =>
            Read(_snapshot.CumulativeConnections, CumulativeConnectionsFlag);

        public override long CurrentConnections =>
            Read(_snapshot.CurrentConnections, CurrentConnectionsFlag);

        public override long ErrorsReceived =>
            Read(_snapshot.ErrorsReceived, ErrorsReceivedFlag);

        public override long FailedConnectionAttempts =>
            Read(_snapshot.FailedConnectionAttempts, FailedConnectionAttemptsFlag);

        public override long MaximumConnections =>
            RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        public override long MaximumTransmissionTimeout =>
            RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        public override long MinimumTransmissionTimeout =>
            RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        public override long ResetConnections =>
            Read(_snapshot.ResetConnections, ResetConnectionsFlag);

        public override long SegmentsReceived =>
            Read(_snapshot.SegmentsReceived, SegmentsReceivedFlag);

        public override long SegmentsResent =>
            Read(_snapshot.SegmentsResent, SegmentsResentFlag);

        public override long SegmentsSent =>
            Read(_snapshot.SegmentsSent, SegmentsSentFlag);

        public override long ResetsSent =>
            Read(_snapshot.ResetsSent, ResetsSentFlag);
    }

    internal sealed class RinOSIcmpV4Statistics : IcmpV4Statistics
    {
        private const uint AddressFamily = 4u;
        private const uint MessagesReceivedFlag = 0x00000001u;
        private const uint MessagesSentFlag = 0x00000002u;
        private const uint ErrorsReceivedFlag = 0x00000004u;
        private const uint ErrorsSentFlag = 0x00000008u;
        private const uint DestinationUnreachableReceivedFlag = 0x00000010u;
        private const uint DestinationUnreachableSentFlag = 0x00000020u;
        private const uint EchoRepliesReceivedFlag = 0x00000040u;
        private const uint EchoRepliesSentFlag = 0x00000080u;
        private const uint EchoRequestsReceivedFlag = 0x00000100u;
        private const uint EchoRequestsSentFlag = 0x00000200u;
        private const uint ParameterProblemsReceivedFlag = 0x00000400u;
        private const uint ParameterProblemsSentFlag = 0x00000800u;
        private const uint TimeExceededReceivedFlag = 0x00001000u;
        private const uint TimeExceededSentFlag = 0x00002000u;
        private const uint AddressMaskFlag = 0x00010000u;
        private const uint AddressMaskRequestFlag = 0x00020000u;
        private const uint RedirectFlag = 0x00040000u;
        private const uint SourceQuenchFlag = 0x00080000u;
        private const uint TimestampReplyFlag = 0x00100000u;
        private const uint TimestampRequestFlag = 0x00200000u;
        private const uint KnownFlags = 0x003F3FFFu;

        private readonly Interop.Sys.RinOSNetworkIcmpGlobalStatisticsV2 _snapshot;

        internal unsafe RinOSIcmpV4Statistics()
        {
            Interop.Sys.RinOSNetworkIcmpGlobalStatisticsV2 snapshot = default;
            if (Interop.Sys.GetRinOSNetworkIcmpGlobalStatisticsV2(
                    AddressFamily, &snapshot) != 0 ||
                snapshot.Version != 2u ||
                snapshot.StructSize != 376u ||
                snapshot.DeviceGeneration == 0u ||
                snapshot.AddressFamily != AddressFamily ||
                (snapshot.SupportedFlags & ~KnownFlags) != 0u)
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current ICMPv4-statistics snapshot.");
            }
            _snapshot = snapshot;
        }

        private long Read(ulong value, uint flag) =>
            (_snapshot.SupportedFlags & flag) != 0u
                ? Clamp(value)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        private static long Unsupported() =>
            RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        public override long AddressMaskRepliesReceived =>
            Read(_snapshot.AddressMaskRepliesReceived, AddressMaskFlag);
        public override long AddressMaskRepliesSent =>
            Read(_snapshot.AddressMaskRepliesSent, AddressMaskFlag);
        public override long AddressMaskRequestsReceived =>
            Read(_snapshot.AddressMaskRequestsReceived, AddressMaskRequestFlag);
        public override long AddressMaskRequestsSent =>
            Read(_snapshot.AddressMaskRequestsSent, AddressMaskRequestFlag);
        public override long DestinationUnreachableMessagesReceived =>
            Read(_snapshot.DestinationUnreachableReceived, DestinationUnreachableReceivedFlag);
        public override long DestinationUnreachableMessagesSent =>
            Read(_snapshot.DestinationUnreachableSent, DestinationUnreachableSentFlag);
        public override long EchoRepliesReceived =>
            Read(_snapshot.EchoRepliesReceived, EchoRepliesReceivedFlag);
        public override long EchoRepliesSent =>
            Read(_snapshot.EchoRepliesSent, EchoRepliesSentFlag);
        public override long EchoRequestsReceived =>
            Read(_snapshot.EchoRequestsReceived, EchoRequestsReceivedFlag);
        public override long EchoRequestsSent =>
            Read(_snapshot.EchoRequestsSent, EchoRequestsSentFlag);
        public override long ErrorsReceived =>
            Read(_snapshot.ErrorsReceived, ErrorsReceivedFlag);
        public override long ErrorsSent =>
            Read(_snapshot.ErrorsSent, ErrorsSentFlag);
        public override long MessagesReceived =>
            Read(_snapshot.MessagesReceived, MessagesReceivedFlag);
        public override long MessagesSent =>
            Read(_snapshot.MessagesSent, MessagesSentFlag);
        public override long ParameterProblemsReceived =>
            Read(_snapshot.ParameterProblemsReceived, ParameterProblemsReceivedFlag);
        public override long ParameterProblemsSent =>
            Read(_snapshot.ParameterProblemsSent, ParameterProblemsSentFlag);
        public override long RedirectsReceived =>
            Read(_snapshot.RedirectsV4Received, RedirectFlag);
        public override long RedirectsSent =>
            Read(_snapshot.RedirectsV4Sent, RedirectFlag);
        public override long SourceQuenchesReceived =>
            Read(_snapshot.SourceQuenchesReceived, SourceQuenchFlag);
        public override long SourceQuenchesSent =>
            Read(_snapshot.SourceQuenchesSent, SourceQuenchFlag);
        public override long TimeExceededMessagesReceived =>
            Read(_snapshot.TimeExceededReceived, TimeExceededReceivedFlag);
        public override long TimeExceededMessagesSent =>
            Read(_snapshot.TimeExceededSent, TimeExceededSentFlag);
        public override long TimestampRepliesReceived =>
            Read(_snapshot.TimestampRepliesReceived, TimestampReplyFlag);
        public override long TimestampRepliesSent =>
            Read(_snapshot.TimestampRepliesSent, TimestampReplyFlag);
        public override long TimestampRequestsReceived =>
            Read(_snapshot.TimestampRequestsReceived, TimestampRequestFlag);
        public override long TimestampRequestsSent =>
            Read(_snapshot.TimestampRequestsSent, TimestampRequestFlag);
    }

    internal sealed class RinOSIcmpV6Statistics : IcmpV6Statistics
    {
        private const uint AddressFamily = 6u;
        private const uint MessagesReceivedFlag = 0x00000001u;
        private const uint MessagesSentFlag = 0x00000002u;
        private const uint ErrorsReceivedFlag = 0x00000004u;
        private const uint ErrorsSentFlag = 0x00000008u;
        private const uint DestinationUnreachableReceivedFlag = 0x00000010u;
        private const uint DestinationUnreachableSentFlag = 0x00000020u;
        private const uint EchoRepliesReceivedFlag = 0x00000040u;
        private const uint EchoRepliesSentFlag = 0x00000080u;
        private const uint EchoRequestsReceivedFlag = 0x00000100u;
        private const uint EchoRequestsSentFlag = 0x00000200u;
        private const uint ParameterProblemsReceivedFlag = 0x00000400u;
        private const uint ParameterProblemsSentFlag = 0x00000800u;
        private const uint TimeExceededReceivedFlag = 0x00001000u;
        private const uint TimeExceededSentFlag = 0x00002000u;
        private const uint PacketTooBigReceivedFlag = 0x00004000u;
        private const uint PacketTooBigSentFlag = 0x00008000u;
        private const uint MembershipQueryFlag = 0x00400000u;
        private const uint MembershipReductionFlag = 0x00800000u;
        private const uint MembershipReportFlag = 0x01000000u;
        private const uint NeighborAdvertisementFlag = 0x02000000u;
        private const uint NeighborSolicitFlag = 0x04000000u;
        private const uint RedirectFlag = 0x08000000u;
        private const uint RouterAdvertisementFlag = 0x10000000u;
        private const uint RouterSolicitFlag = 0x20000000u;
        private const uint KnownFlags = 0x3FC0FFFFu;

        private readonly Interop.Sys.RinOSNetworkIcmpGlobalStatisticsV2 _snapshot;

        internal unsafe RinOSIcmpV6Statistics()
        {
            Interop.Sys.RinOSNetworkIcmpGlobalStatisticsV2 snapshot = default;
            if (Interop.Sys.GetRinOSNetworkIcmpGlobalStatisticsV2(
                    AddressFamily, &snapshot) != 0 ||
                snapshot.Version != 2u ||
                snapshot.StructSize != 376u ||
                snapshot.DeviceGeneration == 0u ||
                snapshot.AddressFamily != AddressFamily ||
                (snapshot.SupportedFlags & ~KnownFlags) != 0u)
            {
                throw new NetworkInformationException(
                    "RinOS did not provide a current ICMPv6-statistics snapshot.");
            }
            _snapshot = snapshot;
        }

        private long Read(ulong value, uint flag) =>
            (_snapshot.SupportedFlags & flag) != 0u
                ? Clamp(value)
                : RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        private static long Clamp(ulong value) =>
            value > long.MaxValue ? long.MaxValue : (long)value;

        private static long Unsupported() =>
            RinOSNetworkStatisticsSnapshot.UnsupportedMetric();

        public override long DestinationUnreachableMessagesReceived =>
            Read(_snapshot.DestinationUnreachableReceived, DestinationUnreachableReceivedFlag);
        public override long DestinationUnreachableMessagesSent =>
            Read(_snapshot.DestinationUnreachableSent, DestinationUnreachableSentFlag);
        public override long EchoRepliesReceived =>
            Read(_snapshot.EchoRepliesReceived, EchoRepliesReceivedFlag);
        public override long EchoRepliesSent =>
            Read(_snapshot.EchoRepliesSent, EchoRepliesSentFlag);
        public override long EchoRequestsReceived =>
            Read(_snapshot.EchoRequestsReceived, EchoRequestsReceivedFlag);
        public override long EchoRequestsSent =>
            Read(_snapshot.EchoRequestsSent, EchoRequestsSentFlag);
        public override long ErrorsReceived =>
            Read(_snapshot.ErrorsReceived, ErrorsReceivedFlag);
        public override long ErrorsSent =>
            Read(_snapshot.ErrorsSent, ErrorsSentFlag);
        public override long MembershipQueriesReceived =>
            Read(_snapshot.MembershipQueriesReceived, MembershipQueryFlag);
        public override long MembershipQueriesSent =>
            Read(_snapshot.MembershipQueriesSent, MembershipQueryFlag);
        public override long MembershipReductionsReceived =>
            Read(_snapshot.MembershipReductionsReceived, MembershipReductionFlag);
        public override long MembershipReductionsSent =>
            Read(_snapshot.MembershipReductionsSent, MembershipReductionFlag);
        public override long MembershipReportsReceived =>
            Read(_snapshot.MembershipReportsReceived, MembershipReportFlag);
        public override long MembershipReportsSent =>
            Read(_snapshot.MembershipReportsSent, MembershipReportFlag);
        public override long MessagesReceived =>
            Read(_snapshot.MessagesReceived, MessagesReceivedFlag);
        public override long MessagesSent =>
            Read(_snapshot.MessagesSent, MessagesSentFlag);
        public override long NeighborAdvertisementsReceived =>
            Read(_snapshot.NeighborAdvertisementsReceived, NeighborAdvertisementFlag);
        public override long NeighborAdvertisementsSent =>
            Read(_snapshot.NeighborAdvertisementsSent, NeighborAdvertisementFlag);
        public override long NeighborSolicitsReceived =>
            Read(_snapshot.NeighborSolicitsReceived, NeighborSolicitFlag);
        public override long NeighborSolicitsSent =>
            Read(_snapshot.NeighborSolicitsSent, NeighborSolicitFlag);
        public override long PacketTooBigMessagesReceived =>
            Read(_snapshot.PacketTooBigReceived, PacketTooBigReceivedFlag);
        public override long PacketTooBigMessagesSent =>
            Read(_snapshot.PacketTooBigSent, PacketTooBigSentFlag);
        public override long ParameterProblemsReceived =>
            Read(_snapshot.ParameterProblemsReceived, ParameterProblemsReceivedFlag);
        public override long ParameterProblemsSent =>
            Read(_snapshot.ParameterProblemsSent, ParameterProblemsSentFlag);
        public override long RedirectsReceived =>
            Read(_snapshot.RedirectsV6Received, RedirectFlag);
        public override long RedirectsSent =>
            Read(_snapshot.RedirectsV6Sent, RedirectFlag);
        public override long RouterAdvertisementsReceived =>
            Read(_snapshot.RouterAdvertisementsReceived, RouterAdvertisementFlag);
        public override long RouterAdvertisementsSent =>
            Read(_snapshot.RouterAdvertisementsSent, RouterAdvertisementFlag);
        public override long RouterSolicitsReceived =>
            Read(_snapshot.RouterSolicitsReceived, RouterSolicitFlag);
        public override long RouterSolicitsSent =>
            Read(_snapshot.RouterSolicitsSent, RouterSolicitFlag);
        public override long TimeExceededMessagesReceived =>
            Read(_snapshot.TimeExceededReceived, TimeExceededReceivedFlag);
        public override long TimeExceededMessagesSent =>
            Read(_snapshot.TimeExceededSent, TimeExceededSentFlag);
    }
}
