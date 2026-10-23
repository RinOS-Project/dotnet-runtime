// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#ifndef __NATIVEAOT_COMWRAPPERS_DIAGNOSTICS_H__
#define __NATIVEAOT_COMWRAPPERS_DIAGNOSTICS_H__

// These layouts are shared by the NativeAOT managed ComWrappers implementation
// and the diagnostics/runtime code. Keep the field order in lockstep with
// System.Runtime.InteropServices.ComWrappers.cs.
struct NativeAotManagedObjectWrapperLayout
{
    intptr_t HolderHandle;
    uint64_t RefCount;
    int32_t Flags;
    int32_t UserDefinedCount;
    void* UserDefined;
    void* Dispatches;
};

static const int32_t NativeAotComInterfaceCallerDefinedIUnknown = 1;
static const int32_t NativeAotComInterfaceTrackerSupport = 2;
static const int32_t NativeAotComInterfaceIsPegged = (1 << 31);
static const uint64_t NativeAotComRefCountMask = 0x000000007fffffffULL;
static const uint64_t NativeAotTrackerRefCountMask = 0xffffffff00000000ULL;
static const uint32_t NativeAotTrackerRefShift = 32;

struct NativeAotComInterfaceEntryLayout
{
    uint8_t IID[16];
    void* Vtable;
};

#if defined(HOST_64BIT)
static const uintptr_t NativeAotComInterfaceDispatchAlignment = 64;
static const size_t NativeAotComInterfaceEntriesPerDispatch = 7;
#else
static const uintptr_t NativeAotComInterfaceDispatchAlignment = 16;
static const size_t NativeAotComInterfaceEntriesPerDispatch = 3;
#endif

struct NativeAotInternalComInterfaceDispatch
{
    NativeAotManagedObjectWrapperLayout* ThisPtr;
    void* Vtables[NativeAotComInterfaceEntriesPerDispatch];
};

// The holder is a managed object. The first field is the Object header's
// method-table pointer inherited from Object; the following fields mirror the
// managed declaration: _releaser, _wrappedObject, _wrapper.
struct NativeAotManagedObjectWrapperHolderLayout : public Object
{
    Object* Releaser;
    Object* WrappedObject;
    NativeAotManagedObjectWrapperLayout* Wrapper;
};

extern "C" MethodTable* RhGetManagedObjectWrapperHolderType();

#endif // __NATIVEAOT_COMWRAPPERS_DIAGNOSTICS_H__
