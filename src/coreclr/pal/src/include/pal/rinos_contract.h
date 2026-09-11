// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef _PAL_RINOS_CONTRACT_H_
#define _PAL_RINOS_CONTRACT_H_

/*
 * RinOS is a native CoreCLR target, not a Linux personality.  Keep the
 * target-only ABI facts in one header so PAL sources do not grow ad-hoc
 * Linux-shaped conditionals.
 */
#if !defined(TARGET_RINOS)
#error "pal/rinos_contract.h is only valid for TARGET_RINOS"
#endif

#if !defined(HOST_AMD64)
#error "The initial RinOS CoreCLR PAL supports x86_64 only"
#endif

#define RINOS_PAL_TARGET_NAME "RinOS"
#define RINOS_PAL_TARGET_RID "rinos-x64"
#define RINOS_PAL_RUNTIME_ROOT "/System/Dotnet"
#define RINOS_PAL_NATIVE_EXECUTABLE_EXT ".rin"
#define RINOS_PAL_NATIVE_LIBRARY_EXT ".rll"
#define RINOS_PAL_TEMP_DIRECTORY "/tmp/"

/* Exclusive upper bound for user mappings.  This is the product address-space
 * contract, not a host Linux canonical-address guess.  Keep it in the PAL
 * contract so GetSystemInfo/VirtualQuery and the GC/JIT see the same limit as
 * the kernel's native x86_64 user-space policy. */
#define RINOS_PAL_USER_ADDRESS_LIMIT ((uintptr_t)0x00007FFFFFF00000ULL)

/* RinOS has no Linux /proc or ptrace contract.  Cross-process register
 * inspection stays explicitly unavailable until a RinOS debugger ABI exists;
 * current-thread signal and exception contexts use ucontext_t instead. */
#define RINOS_PAL_HAS_LINUX_PROCFS 0
#define RINOS_PAL_HAS_CROSS_PROCESS_CONTEXT 0

#if defined(__cplusplus)
static_assert(sizeof(void*) == 8, "RinOS x64 PAL requires 64-bit pointers");
#else
_Static_assert(sizeof(void*) == 8, "RinOS x64 PAL requires 64-bit pointers");
#endif

#endif // _PAL_RINOS_CONTRACT_H_
