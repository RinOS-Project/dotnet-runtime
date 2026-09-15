// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "rinoscrashhandoff.h"
#include "pal.h"

#if defined(TARGET_RINOS)

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rin/crash_service.h>
#include <rin/net/socket_abi.h>
#include <rin/service.h>

namespace
{

struct CrashReportHandoffPacket
{
    RinCrashServiceMessageHeaderV1 header;
    RinCrashReportHandoffV1 payload;
};

static bool IsCrashdEndpoint(int fd, unsigned int expectedSlot)
{
    rin_unix_service_identity_v1 identity = {};
    socklen_t identitySize = sizeof(identity);
    return getsockopt(
               fd, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
               &identity, &identitySize) == 0 &&
           identitySize == sizeof(identity) &&
           identity.slot_id == expectedSlot &&
           identity.owner_uid == 0u &&
           identity.scope == RIN_SERVICE_SCOPE_SYSTEM &&
           identity.flags == RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED;
}

} // namespace

bool
RinOSCrashReportHandoff::Initialize()
{
    uint32_t slot = 0u;
    uint64_t processId;
    uint64_t processInstanceCookie = 0u;
    struct sockaddr_un address = {};
    size_t pathSize = sizeof(RIN_CRASH_SERVICE_SOCKET_PATH) - 1u;
    int fd;

    if (m_fd >= 0)
        return true;
    processId = static_cast<uint64_t>(GetCurrentProcessId());
    if (processId == 0u || processId > UINT32_MAX ||
        rin_service_find_system_slot(RIN_CRASH_SERVICE_ID, &slot) != 0 ||
        slot == 0u ||
        rin_process_instance_cookie(
            static_cast<uint32_t>(processId), &processInstanceCookie) != 0 ||
        processInstanceCookie == 0u || pathSize >= sizeof(address.sun_path))
        return false;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return false;
    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        close(fd);
        return false;
    }

    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RIN_CRASH_SERVICE_SOCKET_PATH, pathSize);
    if (connect(fd, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) != 0 || !IsCrashdEndpoint(fd, slot))
    {
        close(fd);
        return false;
    }

    int fileFlags = fcntl(fd, F_GETFL, 0);
    if (fileFlags < 0 || fcntl(fd, F_SETFL, fileFlags | O_NONBLOCK) < 0)
    {
        close(fd);
        return false;
    }

    m_processId = static_cast<unsigned long long>(processId);
    m_processInstanceCookie =
        static_cast<unsigned long long>(processInstanceCookie);
    m_fd = fd;
    return true;
}

bool
RinOSCrashReportHandoff::Notify(int signal, bool reportFileReady)
{
    CrashReportHandoffPacket packet = {};
    ssize_t written;

    if (m_fd < 0 || signal <= 0 || signal > 64 || m_processId == 0u ||
        m_processInstanceCookie == 0u)
        return false;

    packet.header.struct_size = sizeof(packet.header);
    packet.header.version = RIN_CRASH_SERVICE_ABI_VERSION;
    packet.header.opcode = RIN_CRASH_SERVICE_OP_HANDOFF_REPORT;
    packet.header.request_id = 1u;
    packet.header.payload_size = sizeof(packet.payload);
    packet.payload.struct_size = sizeof(packet.payload);
    packet.payload.version = RIN_CRASH_HANDOFF_VERSION;
    packet.payload.flags = RIN_CRASH_HANDOFF_FLAG_KERNEL_SUMMARY_EXPECTED |
        (reportFileReady ? RIN_CRASH_HANDOFF_FLAG_REPORT_FILE_READY : 0u);
    packet.payload.signal = static_cast<uint32_t>(signal);
    packet.payload.process_id = static_cast<uint64_t>(m_processId);
    packet.payload.process_instance_cookie =
        static_cast<uint64_t>(m_processInstanceCookie);

    // PAL has already ignored SIGPIPE during signal setup. This is one
    // non-blocking write only: retrying, polling, allocation, socket calls,
    // and waiting would violate the fatal-signal contract. A short write is
    // treated as a lost notice; the kernel-backed minidump remains local.
    written = write(m_fd, &packet, sizeof(packet));
    return written == static_cast<ssize_t>(sizeof(packet));
}

#else

bool
RinOSCrashReportHandoff::Initialize()
{
    return false;
}

bool
RinOSCrashReportHandoff::Notify(int, bool)
{
    return false;
}

#endif // TARGET_RINOS
