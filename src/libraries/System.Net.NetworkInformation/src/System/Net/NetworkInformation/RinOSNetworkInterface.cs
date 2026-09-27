// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;

namespace System.Net.NetworkInformation
{
    /// <summary>
    /// Implements a NetworkInterface from the RinOS product interface ABI.
    /// </summary>
    internal sealed class RinOSNetworkInterface : UnixNetworkInterface
    {
        private const int InterfaceNameCapacity = 16;
        private const int HardwareAddressCapacity = 12;

        private readonly RinOSIPInterfaceProperties _ipProperties;
        private readonly OperationalStatus _operationalStatus;
        private readonly bool _supportsMulticast;
        private readonly long _speed;
        private readonly int _mtu;

        private RinOSNetworkInterface(
            string name,
            int index,
            long speed,
            int mtu,
            NetworkInterfaceType interfaceType,
            OperationalStatus operationalStatus,
            bool supportsMulticast,
            Interop.Sys.RinOSNetworkPrimaryInfo? primaryInfo)
            : base(name)
        {
            _index = index;
            _speed = speed;
            _mtu = mtu;
            _networkInterfaceType = interfaceType;
            _operationalStatus = operationalStatus;
            _supportsMulticast = supportsMulticast;
            _ipProperties = new RinOSIPInterfaceProperties(this, primaryInfo);
        }

        internal static unsafe NetworkInterface[] GetRinOSNetworkInterfaces()
        {
            int interfaceCount = 0;
            int addressCount = 0;
            Interop.Sys.NetworkInterfaceInfo* interfaceList = null;
            Interop.Sys.IpAddressInfo* addressList = null;
            IntPtr globalMemory = IntPtr.Zero;
            Interop.Sys.RinOSNetworkPrimaryInfo primaryInfo = default;
            bool hasPrimaryInfo = Interop.Sys.GetRinOSNetworkPrimaryInfo(&primaryInfo) == 0;

            if (Interop.Sys.GetNetworkInterfaces(&interfaceCount, &interfaceList, &addressCount, &addressList) != 0)
            {
                throw new NetworkInformationException(Interop.Sys.GetLastErrorInfo().GetErrorMessage());
            }

            globalMemory = (IntPtr)interfaceList;
            try
            {
                if (interfaceCount < 0 || addressCount < 0 ||
                    (interfaceCount != 0 && interfaceList == null) ||
                    (addressCount != 0 && addressList == null))
                {
                    throw new NetworkInformationException(
                        "RinOS returned an invalid network-interface snapshot.");
                }

                string? primaryName = hasPrimaryInfo
                    ? ReadFixedUtf8Name((byte*)&primaryInfo.Name)
                    : null;

                NetworkInterface[] result = new NetworkInterface[interfaceCount];
                Dictionary<int, RinOSNetworkInterface> byIndex = new Dictionary<int, RinOSNetworkInterface>(interfaceCount);

                for (int i = 0; i < interfaceCount; i++)
                {
                    string name = ReadFixedUtf8Name((byte*)&interfaceList->Name);
                    int interfaceIndex = GetInterfaceIndex(
                        unchecked((uint)interfaceList->InterfaceIndex));
                    RinOSNetworkInterface networkInterface = new RinOSNetworkInterface(
                        name,
                        interfaceIndex,
                        interfaceList->Speed,
                        interfaceList->Mtu,
                        (NetworkInterfaceType)interfaceList->HardwareType,
                        (OperationalStatus)interfaceList->OperationalState,
                        interfaceList->SupportsMulticast != 0,
                        hasPrimaryInfo && string.Equals(
                            name,
                            primaryName,
                            StringComparison.Ordinal)
                            ? primaryInfo
                            : null);

                    if (interfaceList->NumAddressBytes > HardwareAddressCapacity)
                    {
                        throw new NetworkInformationException(
                            "RinOS returned an oversized hardware address.");
                    }

                    if (interfaceList->NumAddressBytes > 0)
                    {
                        networkInterface._physicalAddress = new PhysicalAddress(
                            ((ReadOnlySpan<byte>)interfaceList->AddressBytes)[..interfaceList->NumAddressBytes].ToArray());
                    }

                    result[i] = networkInterface;
                    if (!byIndex.TryAdd(networkInterface.Index, networkInterface))
                    {
                        throw new NetworkInformationException(
                            "RinOS returned duplicate network-interface indices.");
                    }
                    interfaceList++;
                }

                for (int i = 0; i < addressCount; i++)
                {
                    Interop.Sys.IpAddressInfo addressInfo = *addressList;
                    int addressLength = GetAddressLength(addressInfo.NumAddressBytes);
                    ValidatePrefixLength(addressLength, addressInfo.PrefixLength);
                    int interfaceIndex = GetInterfaceIndex(
                        unchecked((uint)addressInfo.InterfaceIndex));
                    if (byIndex.TryGetValue(interfaceIndex, out RinOSNetworkInterface? networkInterface))
                    {
                        IPAddress address = new IPAddress(((ReadOnlySpan<byte>)addressInfo.AddressBytes)[..addressLength]);
                        if (addressLength == 16 && address.IsIPv6LinkLocal)
                        {
                            address.ScopeId = (uint)interfaceIndex;
                        }

                        networkInterface.AddAddress(address, addressInfo.PrefixLength);
                    }

                    addressList++;
                }

                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(globalMemory);
            }
        }

        private static unsafe string ReadFixedUtf8Name(byte* name)
        {
            int terminator = new ReadOnlySpan<byte>(name, InterfaceNameCapacity).IndexOf((byte)0);
            if (terminator <= 0)
            {
                throw new NetworkInformationException(
                    "RinOS returned an invalid network-interface name.");
            }

            return Utf8StringMarshaller.ConvertToManaged(name)!;
        }

        private static int GetAddressLength(byte length)
        {
            if (length is not (4 or 16))
            {
                throw new NetworkInformationException(
                    "RinOS returned an unsupported network address length.");
            }

            return length;
        }

        private static int GetInterfaceIndex(uint index)
        {
            if (index == 0 || index > int.MaxValue)
            {
                throw new NetworkInformationException(
                    "RinOS returned an invalid network-interface index.");
            }

            return (int)index;
        }

        private static void ValidatePrefixLength(int addressLength, byte prefixLength)
        {
            int maximum = addressLength * 8;
            if (prefixLength > maximum)
            {
                throw new NetworkInformationException(
                    "RinOS returned an invalid network prefix length.");
            }
        }

        public override bool SupportsMulticast => _supportsMulticast;

        public override IPInterfaceProperties GetIPProperties() => _ipProperties;

        public override IPInterfaceStatistics GetIPStatistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override IPv4InterfaceStatistics GetIPv4Statistics() =>
            throw new PlatformNotSupportedException(SR.net_InformationUnavailableOnPlatform);

        public override OperationalStatus OperationalStatus => _operationalStatus;

        public override NetworkInterfaceType NetworkInterfaceType => _networkInterfaceType;

        public override long Speed => _speed;

        public override bool IsReceiveOnly => false;

        internal int Mtu => _mtu;
    }
}
