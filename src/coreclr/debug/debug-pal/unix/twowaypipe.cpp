// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include <pal.h>
#include "volatile.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(TARGET_RINOS)
#include <rin/abi.h>
#include <rin_account_compat.h>
#include <sys/socket.h>
#include <sys/un.h>
#endif
#include <limits.h>
#include <string.h>
#include <pal_assert.h>
#include "twowaypipe.h"

#ifdef TARGET_WASI
static inline int mkfifo(const char *path, mode_t mode) { (void)path; (void)mode; errno = ENOTSUP; return -1; }
#endif

// Pipe names stored for use in AbortPipeServerImpl().
static char s_serverInPipeName[MAX_DEBUGGER_TRANSPORT_PIPE_NAME_LENGTH];
static char s_serverOutPipeName[MAX_DEBUGGER_TRANSPORT_PIPE_NAME_LENGTH];

// Cleans up the named pipe connection so no tmp files are left behind. Does only
// the minimum and must be safe to call at any time. Called during PAL ExitProcess,
// TerminateProcess and for unhandled native exceptions and asserts.
static void AbortPipeServerImpl()
{
    // IMPORTANT NOTE: This function must not call any signal unsafe functions
    // since it is called from signal handlers.
    // That includes ASSERT and TRACE macros.
    unlink(s_serverInPipeName);
    unlink(s_serverOutPipeName);
}

// Defined here and extern-declared in dbgtransportsession.h for use by Debugger::CleanupTransportSocket().
void (*g_pfnAbortTransportCallback)(void) = nullptr;

#if defined(TARGET_RINOS)
// RinOS does not expose filesystem FIFOs.  Keep the existing TwoWayPipe
// abstraction, but back each half-duplex channel with a private pathname UDS.
// The path is owner-private and the process instance cookie is already part of
// PAL_GetTransportPipeName(), so a recycled PID cannot attach to an old target.
static bool RinOSDebugTransportAuthorized()
{
    __rin_credentials_v1 credentials = {};
    if (__rin_credentials_get(&credentials) != 0)
        return false;

    // The capability is checked in both the debuggee and debugger process.
    // Socket mode and the process-instance cookie prevent accidental cross-user
    // and stale-PID connections, while this product capability is the explicit
    // authorization boundary for managed runtime control.
    return (credentials.capabilities & RIN_CAP_DEBUGGING) != 0u;
}

static int CreateRinOSUnixServer(const char* path)
{
    if (path == nullptr || path[0] == '\0' ||
        strlen(path) >= sizeof(((struct sockaddr_un*)nullptr)->sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0)
        return -1;
    if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0)
    {
        close(descriptor);
        return -1;
    }

    struct sockaddr_un address = {};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1u);
    unlink(path);
    if (bind(descriptor, reinterpret_cast<const sockaddr*>(&address),
             sizeof(address)) != 0 ||
        chmod(path, S_IRUSR | S_IWUSR) != 0 || listen(descriptor, 1) != 0)
    {
        close(descriptor);
        unlink(path);
        return -1;
    }
    return descriptor;
}

static int ConnectRinOSUnix(const char* path)
{
    if (path == nullptr || path[0] == '\0' ||
        strlen(path) >= sizeof(((struct sockaddr_un*)nullptr)->sun_path))
    {
        errno = ENAMETOOLONG;
        return -1;
    }

    int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0)
        return -1;
    if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0)
    {
        close(descriptor);
        return -1;
    }

    struct sockaddr_un address = {};
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, strlen(path) + 1u);
    int result;
    do
    {
        result = connect(descriptor, reinterpret_cast<const sockaddr*>(&address),
                         sizeof(address));
    } while (result != 0 && errno == EINTR);
    if (result != 0)
    {
        close(descriptor);
        return -1;
    }
    return descriptor;
}
#endif // TARGET_RINOS

// Creates a server side of the pipe.
// Id is used to create pipes names and uniquely identify the pipe on the machine.
// true - success, false - failure (use GetLastError() for more details)
bool TwoWayPipe::CreateServer(const ProcessDescriptor& pd)
{
    _ASSERTE(m_state == NotInitialized);
    if (m_state != NotInitialized)
        return false;

    PAL_GetTransportPipeName(m_inPipeName, pd.m_Pid, pd.m_ApplicationGroupId, "in");
    PAL_GetTransportPipeName(m_outPipeName, pd.m_Pid, pd.m_ApplicationGroupId, "out");

    // Keep a static copy so AbortPipeServerImpl() can unlink them without going through
    // the TwoWayPipe instance, which may be concurrently updated by the worker thread.
    // Only do this the first time CreateServer() is called; subsequent calls recreate the
    // pipe with the same names, so the static buffers remain valid.
    if (g_pfnAbortTransportCallback == nullptr)
    {
        memcpy(s_serverInPipeName, m_inPipeName, sizeof(s_serverInPipeName));
        memcpy(s_serverOutPipeName, m_outPipeName, sizeof(s_serverOutPipeName));
        VolatileStore(&g_pfnAbortTransportCallback, static_cast<void(*)(void)>(AbortPipeServerImpl));
    }

#if defined(TARGET_RINOS)
    if (!RinOSDebugTransportAuthorized())
    {
        errno = EACCES;
        return false;
    }

    m_inboundPipe = CreateRinOSUnixServer(m_inPipeName);
    if (m_inboundPipe == INVALID_PIPE)
        return false;
    m_outboundPipe = CreateRinOSUnixServer(m_outPipeName);
    if (m_outboundPipe == INVALID_PIPE)
    {
        close(m_inboundPipe);
        m_inboundPipe = INVALID_PIPE;
        unlink(m_inPipeName);
        return false;
    }
#else
    unlink(m_inPipeName);
    if (mkfifo(m_inPipeName, S_IRWXU) == -1)
        return false;

    unlink(m_outPipeName);
    if (mkfifo(m_outPipeName, S_IRWXU) == -1)
    {
        unlink(m_inPipeName);
        return false;
    }
#endif

    m_state = Created;
    return true;
}

// Connects to a previously opened server side of the pipe.
// Id is used to locate the pipe on the machine.
// true - success, false - failure (use GetLastError() for more details)
bool TwoWayPipe::Connect(const ProcessDescriptor& pd)
{
    _ASSERTE(m_state == NotInitialized);
    if (m_state != NotInitialized)
        return false;

    //"in" and "out" are switched deliberately, because we're on the client
    PAL_GetTransportPipeName(m_inPipeName, pd.m_Pid, pd.m_ApplicationGroupId, "out");
    PAL_GetTransportPipeName(m_outPipeName, pd.m_Pid, pd.m_ApplicationGroupId, "in");

#if defined(TARGET_RINOS)
    if (!RinOSDebugTransportAuthorized())
    {
        errno = EACCES;
        return false;
    }

    // Connect the server's inbound channel first, matching the server's
    // accept order and avoiding a two-channel startup deadlock.
    m_outboundPipe = ConnectRinOSUnix(m_outPipeName);
    if (m_outboundPipe == INVALID_PIPE)
        return false;
    m_inboundPipe = ConnectRinOSUnix(m_inPipeName);
    if (m_inboundPipe == INVALID_PIPE)
    {
        close(m_outboundPipe);
        m_outboundPipe = INVALID_PIPE;
        return false;
    }
#else
    // Pipe opening order is reversed compared to WaitForConnection()
    // in order to avoid deadlock.
    m_outboundPipe = open(m_outPipeName, O_WRONLY);
    if (m_outboundPipe == INVALID_PIPE)
    {
        return false;
    }
    m_inboundPipe = open(m_inPipeName, O_RDONLY);
    if (m_inboundPipe == INVALID_PIPE)
    {
        close(m_outboundPipe);
        m_outboundPipe = INVALID_PIPE;
        return false;
    }
#endif

    m_state = ClientConnected;
    return true;

}

// Waits for incoming client connections, assumes GetState() == Created
// true - success, false - failure (use GetLastError() for more details)
bool TwoWayPipe::WaitForConnection()
{
    _ASSERTE(m_state == Created);
    if (m_state != Created)
        return false;

#if defined(TARGET_RINOS)
    int inbound;
    do
    {
        inbound = accept(m_inboundPipe, nullptr, nullptr);
    } while (inbound == -1 && errno == EINTR);
    if (inbound == INVALID_PIPE)
        return false;
    if (fcntl(inbound, F_SETFD, FD_CLOEXEC) != 0)
    {
        close(inbound);
        return false;
    }
    int outbound = accept(m_outboundPipe, nullptr, nullptr);
    if (outbound == INVALID_PIPE)
    {
        close(inbound);
        return false;
    }
    if (fcntl(outbound, F_SETFD, FD_CLOEXEC) != 0)
    {
        close(inbound);
        close(outbound);
        return false;
    }
    close(m_inboundPipe);
    close(m_outboundPipe);
    m_inboundPipe = inbound;
    m_outboundPipe = outbound;
#else
    m_inboundPipe = open(m_inPipeName, O_RDONLY);
    if (m_inboundPipe == INVALID_PIPE)
        return false;

    m_outboundPipe = open(m_outPipeName, O_WRONLY);
    if (m_outboundPipe == INVALID_PIPE)
    {
        close(m_inboundPipe);
        m_inboundPipe = INVALID_PIPE;
        return false;
    }
#endif

    m_state = ServerConnected;
    return true;
}

// Reads data from pipe. Returns number of bytes read or a negative number in case of an error.
// use GetLastError() for more details
// UNIXTODO - mjm 9/6/15 - does not set last error on failure
int TwoWayPipe::Read(void *buffer, DWORD bufferSize)
{
    _ASSERTE(m_state == ServerConnected || m_state == ClientConnected);

    if (bufferSize > static_cast<DWORD>(INT_MAX))
    {
        errno = EOVERFLOW;
        return -1;
    }

    int totalBytesRead = 0;
    int bytesRead;
    int cb = bufferSize;

    while (true)
    {
        bytesRead = (int)read(m_inboundPipe, buffer, cb);
        if (bytesRead == -1 && errno == EINTR)
            continue;
        if (bytesRead <= 0)
            break;

        totalBytesRead += bytesRead;
        _ASSERTE(totalBytesRead <= (int)bufferSize);
        if (totalBytesRead >= (int)bufferSize)
        {
            break;
        }

        buffer = (char*)buffer + bytesRead;
        cb -= bytesRead;
    }

    return bytesRead == -1 ? -1 : totalBytesRead;
}

// Writes data to pipe. Returns number of bytes written or a negative number in case of an error.
// use GetLastError() for more details
// UNIXTODO - mjm 9/6/15 - does not set last error on failure
int TwoWayPipe::Write(const void *data, DWORD dataSize)
{
    _ASSERTE(m_state == ServerConnected || m_state == ClientConnected);

    if (dataSize > static_cast<DWORD>(INT_MAX))
    {
        errno = EOVERFLOW;
        return -1;
    }

    int totalBytesWritten = 0;
    int bytesWritten;
    int cb = dataSize;

    while (true)
    {
#if defined(TARGET_RINOS)
        bytesWritten = (int)send(m_outboundPipe, data, cb, MSG_NOSIGNAL);
#else
        bytesWritten = (int)write(m_outboundPipe, data, cb);
#endif
        if (bytesWritten == -1 && errno == EINTR)
            continue;
        if (bytesWritten <= 0)
            break;

        totalBytesWritten += bytesWritten;
        _ASSERTE(totalBytesWritten <= (int)dataSize);
        if (totalBytesWritten >= (int)dataSize)
        {
            break;
        }

        data = (char*)data + bytesWritten;
        cb -= bytesWritten;
    }

    return bytesWritten == -1 ? -1 : totalBytesWritten;
}

// Disconnect server or client side of the pipe.
// true - success, false - failure (use GetLastError() for more details)
bool TwoWayPipe::Disconnect()
{
    // IMPORTANT NOTE: This function must not call any signal unsafe functions
    // since it is called from signal handlers.
    // That includes ASSERT and TRACE macros.

    if (m_inboundPipe != INVALID_PIPE)
    {
        close(m_inboundPipe);
        m_inboundPipe = INVALID_PIPE;
    }
    if (m_outboundPipe != INVALID_PIPE)
    {
        close(m_outboundPipe);
        m_outboundPipe = INVALID_PIPE;
    }

    if (m_state == ServerConnected || m_state == Created)
    {
        unlink(m_inPipeName);
        unlink(m_outPipeName);
    }

    m_state = NotInitialized;
    return true;
}

// Used by debugger side (RS) to cleanup the target (LS) named pipes
// and semaphores when the debugger detects the debuggee process  exited.
void TwoWayPipe::CleanupTargetProcess()
{
    unlink(m_inPipeName);
    unlink(m_outPipeName);
}
