// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef RINOS_AFFINITY_H
#define RINOS_AFFINITY_H

/*
 * The RinOS scheduler ABI exposes a fixed 128-byte cpu_set_t.  This is not
 * the Linux CPU_ALLOC ABI: the kernel accepts exactly the public fixed-size
 * object and currently executes at most 64 CPUs.  Keep this adapter target
 * only so host cross-component tools cannot accidentally bind to it.
 */
#if defined(TARGET_RINOS) && !defined(RINOS_CROSS_COMPONENTS_HOST)

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

static inline int rinos_affinity_get(pid_t pid, cpu_set_t* set)
{
    if (set == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    CPU_ZERO(set);
    return sched_getaffinity(pid, sizeof(*set), set);
}

static inline int rinos_affinity_set(pid_t pid, const cpu_set_t* set)
{
    if (set == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    return sched_setaffinity(pid, sizeof(*set), set);
}

/* Convert the managed intptr mask without accepting an empty mask. */
static inline int rinos_affinity_from_intptr(intptr_t value, cpu_set_t* set)
{
    uintptr_t bits = (uintptr_t)value;
    size_t cpu;

    if (set == NULL || bits == 0u)
    {
        errno = EINVAL;
        return -1;
    }

    CPU_ZERO(set);
    for (cpu = 0u; cpu < sizeof(bits) * CHAR_BIT; ++cpu)
    {
        if ((bits & ((uintptr_t)1u << cpu)) != 0u)
        {
            CPU_SET(cpu, set);
        }
    }

    return 0;
}

/* Do not silently truncate a kernel mask that cannot fit the managed ABI. */
static inline int rinos_affinity_to_intptr(const cpu_set_t* set, intptr_t* value)
{
    uintptr_t bits = 0u;
    size_t cpu;

    if (set == NULL || value == NULL)
    {
        errno = EINVAL;
        return -1;
    }

    *value = 0;
    for (cpu = 0u; cpu < CPU_SETSIZE; ++cpu)
    {
        if (!CPU_ISSET(cpu, set))
        {
            continue;
        }

        if (cpu >= sizeof(bits) * CHAR_BIT)
        {
            errno = EOVERFLOW;
            return -1;
        }

        bits |= (uintptr_t)1u << cpu;
    }

    *value = (intptr_t)bits;
    return 0;
}

#endif /* TARGET_RINOS && !RINOS_CROSS_COMPONENTS_HOST */

#endif /* RINOS_AFFINITY_H */
