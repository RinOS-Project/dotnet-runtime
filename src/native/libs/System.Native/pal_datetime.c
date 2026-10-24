// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#include "pal_config.h"
#include "pal_datetime.h"
#include "pal_utilities.h"
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#if defined(TARGET_ANDROID)
#include <sys/system_properties.h>
#endif
#include <time.h>
#if defined(TARGET_RINOS)
#include <rin/contract_abi.h>
#include <sys/syscall.h>
#endif

static const int64_t TICKS_PER_SECOND = 10000000; /* 10^7 */
#if HAVE_CLOCK_REALTIME
static const int64_t NANOSECONDS_PER_TICK = 100;
#else
static const int64_t TICKS_PER_MICROSECOND = 10; /* 1000 / 100 */
#endif

//
// SystemNative_GetSystemTimeAsTicks return the system time as ticks (100 nanoseconds) 
// since 00:00 01 January 1970 UTC (Unix epoch) 
//
int64_t SystemNative_GetSystemTimeAsTicks(void)
{
#if HAVE_CLOCK_REALTIME
    struct timespec time;
    if (clock_gettime(CLOCK_REALTIME, &time) == 0)
    {
        return (int64_t)(time.tv_sec) * TICKS_PER_SECOND + (time.tv_nsec / NANOSECONDS_PER_TICK); 
    }
#else
    struct timeval time;
    if (gettimeofday(&time, NULL) == 0)
    {
        return (int64_t)(time.tv_sec) * TICKS_PER_SECOND + (time.tv_usec * TICKS_PER_MICROSECOND); 
    }
#endif
    // in failure we return 00:00 01 January 1970 UTC (Unix epoch)
    return 0;
}

#if defined(TARGET_ANDROID)
char* SystemNative_GetDefaultTimeZone(void)
{
    char defaulttimezone[PROP_VALUE_MAX];
    if (__system_property_get("persist.sys.timezone", defaulttimezone))
    {
        return strdup(defaulttimezone);
    }
    else
    {
        return NULL;
    }
}
#elif defined(TARGET_RINOS)
/* The machine-wide timezone is owned by the RinOS kernel/runtime boundary.
 * Do not inspect host filesystem timezone files or inherit a host libc database. */

static int rin_timezone_info_is_valid(const RinTimeZoneInfoV1* info)
{
    size_t length = 0;
    size_t index;
    size_t component_length = 0;

    if (info == NULL || info->struct_size != sizeof(*info) ||
        info->version != RIN_TIME_ZONE_INFO_VERSION ||
        info->reserved0 != 0u || info->generation == 0u ||
        (info->flags & ~(RIN_TIME_ZONE_INFO_FLAG_SYSTEM_DEFAULT |
                         RIN_TIME_ZONE_INFO_FLAG_FALLBACK_UTC)) != 0u ||
        (info->flags & RIN_TIME_ZONE_INFO_FLAG_SYSTEM_DEFAULT) == 0u)
    {
        return 0;
    }

    for (index = 0; index < sizeof(info->reserved); ++index)
    {
        if (info->reserved[index] != 0u)
            return 0;
    }

    while (length < sizeof(info->id) && info->id[length] != '\0')
        ++length;
    if (length == 0 || length > RIN_TIME_ZONE_ID_MAX ||
        length == sizeof(info->id) || info->id[0] == '/' ||
        info->id[length - 1] == '/')
    {
        return 0;
    }

    for (index = length + 1; index < sizeof(info->id); ++index)
    {
        if (info->id[index] != 0u)
            return 0;
    }

    /* The kernel owns catalogue membership. PAL still rejects malformed
     * IANA-shaped IDs before converting the ABI byte array to a C string. */
    for (index = 0; index < length; ++index)
    {
        unsigned char value = info->id[index];
        int alpha = (value >= 'A' && value <= 'Z') ||
                    (value >= 'a' && value <= 'z');
        int digit = value >= '0' && value <= '9';
        if (value == '/')
        {
            if (component_length == 0)
                return 0;
            component_length = 0;
            continue;
        }
        if (!alpha && !digit && value != '_' && value != '+' && value != '-')
            return 0;
        ++component_length;
    }
    return component_length != 0;
}

static int rin_timezone_query(RinTimeZoneInfoV1* info)
{
    if (info == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    memset(info, 0, sizeof(*info));
    if (syscall(RIN_SYS_TIMEZONE_GET, info) != 0)
        return -1;
    if (!rin_timezone_info_is_valid(info))
    {
        memset(info, 0, sizeof(*info));
        errno = EPROTO;
        return -1;
    }
    return 0;
}

char* SystemNative_GetDefaultTimeZone(void)
{
    RinTimeZoneInfoV1 info;
    if (rin_timezone_query(&info) != 0)
        return NULL;
    return strdup((const char*)info.id);
}

uint32_t SystemNative_GetTimeZoneGeneration(void)
{
    RinTimeZoneInfoV1 info;
    if (rin_timezone_query(&info) != 0)
        return 0u;
    return info.generation;
}
#elif !defined(__APPLE__)
char* SystemNative_GetDefaultTimeZone(void)
{
    assert_err(false, "This function is not supported on this platform.", EINVAL);
    return NULL;
}
#endif

#if !defined(TARGET_RINOS)
uint32_t SystemNative_GetTimeZoneGeneration(void)
{
    return 0u;
}
#endif

#if !defined(TARGET_WASM)
const char* SystemNative_GetTimeZoneData(const char* name, int* length)
{
    assert_msg(false, "Not supported on this platform", 0);
    (void)name;
    (void)length;
    return NULL;
}
#endif
