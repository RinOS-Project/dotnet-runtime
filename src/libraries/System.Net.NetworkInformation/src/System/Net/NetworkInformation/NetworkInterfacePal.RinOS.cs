// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net.NetworkInformation
{
    internal static class NetworkInterfacePal
    {
        public static NetworkInterface[] GetAllNetworkInterfaces()
        {
            return RinOSNetworkInterface.GetRinOSNetworkInterfaces();
        }

        public static bool GetIsNetworkAvailable()
        {
            foreach (NetworkInterface networkInterface in GetAllNetworkInterfaces())
            {
                if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                    networkInterface.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
                {
                    continue;
                }

                if (networkInterface.OperationalStatus == OperationalStatus.Up)
                {
                    return true;
                }
            }

            return false;
        }

        public static int IPv6LoopbackInterfaceIndex => LoopbackInterfaceIndex;

        public static int LoopbackInterfaceIndex
        {
            get
            {
                foreach (NetworkInterface networkInterface in GetAllNetworkInterfaces())
                {
                    if (networkInterface.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                    {
                        return ((RinOSNetworkInterface)networkInterface).Index;
                    }
                }

                throw new NetworkInformationException(SR.net_NoLoopback);
            }
        }
    }
}
