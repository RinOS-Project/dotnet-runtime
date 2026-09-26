// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_config.h"

#include "pal_errno.h"
#include "pal_networkchange.h"
#include "pal_types.h"
#include "pal_utilities.h"

#include <errno.h>
#include <net/if.h>
#if defined(TARGET_RINOS)
#include <pthread.h>
#include <rin/net/netif_abi.h>
#include <string.h>
#include <time.h>
#endif
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#if HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#elif HAVE_RT_MSGHDR
#if HAVE_IOS_NET_ROUTE_H
#include "ios/net/route.h"
#else
#include <net/route.h>
#endif
#endif

#pragma clang diagnostic ignored "-Wcast-align" // NLMSG_* macros trigger this

#if defined(TARGET_RINOS)
/*
 * RinOS deliberately does not expose a Linux netlink or BSD route socket.
 * Keep the managed NetworkChange contract live by observing the same
 * generation-bound primary snapshot used by getifaddrs().  The monitor owns
 * the write side of a socketpair; closing the managed Socket closes the peer,
 * and the next write terminates the detached monitor without a process-wide
 * signal or a product-specific event-thread ABI.
 */
typedef struct RinOSNetworkChangeMonitor
{
    int writeFd;
    RinNetPrimaryInfo previous;
} RinOSNetworkChangeMonitor;

extern int rin_net_get_primary_info(RinNetPrimaryInfo* out);

static int RinOSPrimaryIsReady(const RinNetPrimaryInfo* primary)
{
    return primary != NULL &&
        (primary->flags & RIN_NETINFO_FLAG_DEVICE_READY) != 0u &&
        primary->device_generation != 0u;
}

static int RinOSPrimaryAddressChanged(const RinNetPrimaryInfo* previous,
                                      const RinNetPrimaryInfo* current)
{
    const uint32_t addressFlags =
        RIN_NETINFO_FLAG_IPV4_CONFIGURED | RIN_NETINFO_FLAG_IPV6_CONFIGURED;
    return previous->device_generation != current->device_generation ||
        memcmp(previous->ifname, current->ifname, sizeof(previous->ifname)) != 0 ||
        memcmp(previous->ip, current->ip, sizeof(previous->ip)) != 0 ||
        memcmp(previous->netmask, current->netmask, sizeof(previous->netmask)) != 0 ||
        (previous->flags & addressFlags) != (current->flags & addressFlags);
}

static int RinOSWriteNetworkChangeEvent(int writeFd, NetworkChangeKind kind)
{
    unsigned char event = (unsigned char)kind;
    ssize_t written;

    do
    {
        written = send(writeFd, &event, sizeof(event), MSG_NOSIGNAL);
    }
    while (written < 0 && errno == EINTR);

    return written == (ssize_t)sizeof(event) ? 0 : -1;
}

static void* RinOSNetworkChangeMonitorMain(void* arg)
{
    RinOSNetworkChangeMonitor* monitor = (RinOSNetworkChangeMonitor*)arg;
    const struct timespec interval = {0, 250000000L};

    for (;;)
    {
        RinNetPrimaryInfo current;
        int sleepResult;

        do
        {
            sleepResult = nanosleep(&interval, NULL);
        }
        while (sleepResult < 0 && errno == EINTR);

        memset(&current, 0, sizeof(current));
        if (rin_net_get_primary_info(&current) != 0)
        {
            /* A revoked interface is represented by an empty snapshot. */
            memset(&current, 0, sizeof(current));
        }

        if (memcmp(&monitor->previous, &current, sizeof(current)) != 0)
        {
            int previousReady = RinOSPrimaryIsReady(&monitor->previous);
            int currentReady = RinOSPrimaryIsReady(&current);

            if (RinOSPrimaryAddressChanged(&monitor->previous, &current))
            {
                NetworkChangeKind kind = currentReady && !previousReady
                    ? AddressAdded
                    : !currentReady && previousReady
                        ? AddressRemoved
                        : AddressAdded;
                if (RinOSWriteNetworkChangeEvent(monitor->writeFd, kind) != 0)
                    break;
            }

            if (RinOSWriteNetworkChangeEvent(monitor->writeFd,
                                              AvailabilityChanged) != 0)
                break;

            monitor->previous = current;
        }
    }

    close(monitor->writeFd);
    free(monitor);
    return NULL;
}

static Error CreateRinOSNetworkChangeListenerSocket(intptr_t* retSocket)
{
    int sockets[2];
    RinOSNetworkChangeMonitor* monitor;
    RinNetPrimaryInfo initial;
    pthread_t thread;
    int threadError;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0)
    {
        *retSocket = -1;
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    monitor = (RinOSNetworkChangeMonitor*)calloc(1, sizeof(*monitor));
    if (monitor == NULL)
    {
        close(sockets[0]);
        close(sockets[1]);
        *retSocket = -1;
        errno = ENOMEM;
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    monitor->writeFd = sockets[1];
    memset(&initial, 0, sizeof(initial));
    if (rin_net_get_primary_info(&initial) == 0)
        monitor->previous = initial;
    threadError = pthread_create(&thread, NULL, RinOSNetworkChangeMonitorMain, monitor);
    if (threadError != 0)
    {
        close(sockets[0]);
        close(sockets[1]);
        free(monitor);
        *retSocket = -1;
        errno = threadError;
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    threadError = pthread_detach(thread);
    if (threadError != 0)
    {
        close(sockets[0]);
        (void)pthread_join(thread, NULL);
        *retSocket = -1;
        errno = threadError;
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    *retSocket = sockets[0];
    return Error_SUCCESS;
}

static Error ReadRinOSNetworkChangeEvents(intptr_t sock, NetworkChangeEvent onNetworkChange)
{
    unsigned char buffer[32];
    ssize_t count;
    int fd = ToFileDescriptor(sock);

    do
    {
        count = read(fd, buffer, sizeof(buffer));
    }
    while (count < 0 && errno == EINTR);

    if (count == 0)
        return Error_ECONNABORTED;
    if (count < 0)
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));

    for (ssize_t index = 0; index < count; ++index)
    {
        NetworkChangeKind kind = (NetworkChangeKind)buffer[index];
        if (kind == AddressAdded || kind == AddressRemoved ||
            kind == AvailabilityChanged)
            onNetworkChange(sock, kind);
    }

    return Error_SUCCESS;
}
#endif

Error SystemNative_CreateNetworkChangeListenerSocket(intptr_t* retSocket)
{
#if defined(TARGET_RINOS)
    return CreateRinOSNetworkChangeListenerSocket(retSocket);
#else
#if HAVE_LINUX_RTNETLINK_H
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(struct sockaddr_nl));

    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;
    int32_t sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

#elif HAVE_RT_MSGHDR
    int32_t sock = socket(PF_ROUTE, SOCK_RAW, 0);
#else
    int32_t sock = -1;
    errno = EAFNOSUPPORT;
#endif
    if (sock == -1)
    {
        *retSocket = -1;
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

#if HAVE_LINUX_RTNETLINK_H
    if (bind(sock, (struct sockaddr*)(&sa), sizeof(sa)) != 0)
    {
        *retSocket = -1;
        Error palError = (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
        close(sock);
        return palError;
    }
#endif

    *retSocket = sock;
    return Error_SUCCESS;
#endif
}

#if defined(TARGET_RINOS)
Error SystemNative_ReadEvents(intptr_t sock, NetworkChangeEvent onNetworkChange)
{
    return ReadRinOSNetworkChangeEvents(sock, onNetworkChange);
}
#elif HAVE_LINUX_RTNETLINK_H
static NetworkChangeKind ReadNewLinkMessage(struct nlmsghdr* hdr)
{
    assert(hdr != NULL);
    struct ifinfomsg* ifimsg;
    ifimsg = (struct ifinfomsg*)NLMSG_DATA(hdr);
    if (ifimsg->ifi_family == AF_UNSPEC)
    {
        return AvailabilityChanged;
    }

    return None;
}

Error SystemNative_ReadEvents(intptr_t sock, NetworkChangeEvent onNetworkChange)
{
    char buffer[4096];
    struct iovec iov = {buffer, sizeof(buffer)};
    struct sockaddr_nl sanl;
    int fd = ToFileDescriptor(sock);
    struct msghdr msg = { .msg_name = (void*)(&sanl), .msg_namelen = sizeof(struct sockaddr_nl), .msg_iov = &iov, .msg_iovlen = 1 };
    ssize_t len;
    while (CheckInterrupted(len = recvmsg(fd, &msg, 0)));
    if (len == 0)
    {
        return Error_ECONNABORTED; // EOF.
    }
    if (len == -1)
    {
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    assert(len >= 0);
    for (struct nlmsghdr* hdr = (struct nlmsghdr*)buffer; NLMSG_OK(hdr, (size_t)len); NLMSG_NEXT(hdr, len))
    {
        switch (hdr->nlmsg_type)
        {
            case NLMSG_DONE:
                return Error_SUCCESS; // End of a multi-part message; stop reading.
            case NLMSG_ERROR:
                return Error_SUCCESS;
            case RTM_NEWADDR:
                onNetworkChange(sock, AddressAdded);
                break;
            case RTM_DELADDR:
                onNetworkChange(sock, AddressRemoved);
                break;
            case RTM_NEWLINK:
                onNetworkChange(sock, ReadNewLinkMessage(hdr));
                break;
            case RTM_NEWROUTE:
            case RTM_DELROUTE:
            {
                struct rtmsg* dataAsRtMsg = (struct rtmsg*)NLMSG_DATA(hdr);
                if (dataAsRtMsg->rtm_table == RT_TABLE_MAIN)
                {
                    onNetworkChange(sock, AvailabilityChanged);
                    return Error_SUCCESS;
                }
                break;
            }
            default:
                break;
        }
    }
    return Error_SUCCESS;
}
#elif HAVE_RT_MSGHDR
Error SystemNative_ReadEvents(intptr_t sock, NetworkChangeEvent onNetworkChange)
{
    char buffer[4096];
    int fd = ToFileDescriptor(sock);
    ssize_t count = CheckInterrupted(read(fd, buffer, sizeof(buffer)));
    if (count == 0)
    {
        return Error_ECONNABORTED; // EOF.
    }
    if (count == -1)
    {
        return (Error)(SystemNative_ConvertErrorPlatformToPal(errno));
    }

    struct rt_msghdr msghdr;
    for (char *ptr = buffer; (ptr + sizeof(struct rt_msghdr)) <= (buffer + count); ptr += msghdr.rtm_msglen)
    {
        memcpy(&msghdr, ptr, sizeof(msghdr));
        if (msghdr.rtm_version != RTM_VERSION)
        {
            // version mismatch
            return Error_SUCCESS;
        }

        switch (msghdr.rtm_type)
        {
            case RTM_NEWADDR:
                onNetworkChange(sock, AddressAdded);
                break;
            case RTM_DELADDR:
                onNetworkChange(sock, AddressRemoved);
                break;
            case RTM_ADD:
            case RTM_DELETE:
            case RTM_REDIRECT:
                onNetworkChange(sock, AvailabilityChanged);
                return Error_SUCCESS;
            default:
                break;
        }
    }
    return Error_SUCCESS;
}
#else
Error SystemNative_ReadEvents(intptr_t sock, NetworkChangeEvent onNetworkChange)
{
    (void)sock;
    (void)onNetworkChange;
    return Error_ENOTSUP;
}
#endif
