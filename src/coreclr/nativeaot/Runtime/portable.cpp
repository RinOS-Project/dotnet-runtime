// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#include "common.h"

#include "CommonTypes.h"
#include "CommonMacros.h"
#include "daccess.h"
#include "PalLimitedContext.h"
#include "CommonMacros.inl"
#include "volatile.h"
#include "Pal.h"
#include "rhassert.h"

#include "slist.h"
#include "shash.h"
#include "holder.h"
#include "rhbinder.h"
#include "Crst.h"
#include "RuntimeInstance.h"
#include "event.h"
#include "regdisplay.h"
#include "StackFrameIterator.h"
#include "thread.h"
#include "threadstore.h"
#include "threadstore.inl"

#include "MethodTable.h"
#include "TypeManager.h"
#include "MethodTable.inl"
#include "ObjectLayout.h"

#include "GCMemoryHelpers.inl"

#if defined(FEATURE_PORTABLE_HELPERS)
EXTERN_C void* RhpGcAlloc(MethodTable *pEEType, uint32_t uFlags, intptr_t numElements, void * pTransitionFrame);
EXTERN_C void RhExceptionHandling_FailedAllocation(MethodTable *pEEType, bool fIsOverflow);
EXTERN_C void FASTCALL RhpGcPoll2(PInvokeTransitionFrame* pFrame);

static bool TryComputeArraySize(MethodTable* pArrayEEType, intptr_t numElements, size_t* pSize)
{
    if (numElements < 0)
    {
        RhExceptionHandling_FailedAllocation(pArrayEEType, true /* fIsOverflow */);
        return false;
    }

    const size_t baseSize = (size_t)pArrayEEType->GetBaseSize();
    const size_t componentSize = (size_t)pArrayEEType->RawGetComponentSize();
    const size_t elementCount = (size_t)numElements;
    if (componentSize != 0 && elementCount > (SIZE_MAX - baseSize) / componentSize)
    {
        RhExceptionHandling_FailedAllocation(pArrayEEType, true /* fIsOverflow */);
        return false;
    }

    size_t size = baseSize + (elementCount * componentSize);
    const size_t alignmentMask = sizeof(uintptr_t) - 1;
    if (size > SIZE_MAX - alignmentMask)
    {
        RhExceptionHandling_FailedAllocation(pArrayEEType, true /* fIsOverflow */);
        return false;
    }

    *pSize = ALIGN_UP(size, sizeof(uintptr_t));
    return true;
}

static Object* AllocateObject(MethodTable* pEEType, uint32_t uFlags, intptr_t numElements)
{
    Object* pObject = (Object*)RhpGcAlloc(pEEType, uFlags, numElements, nullptr);
    if (pObject == nullptr)
    {
        RhExceptionHandling_FailedAllocation(pEEType, false /* fIsOverflow */);
    }

    return pObject;
}

struct gc_alloc_context
{
    uint8_t* alloc_ptr;
    uint8_t* alloc_limit;
};

//
// Allocations
//
FCIMPL1(Object *, RhpNewFast, MethodTable* pEEType)
{
    ASSERT(!pEEType->HasFinalizer());

    Thread * pCurThread = ThreadStore::GetCurrentThread();
    gc_alloc_context * acontext = pCurThread->GetAllocContext();
    size_t size = pEEType->GetBaseSize();

    uint8_t* alloc_ptr = acontext->alloc_ptr;
    uint8_t* combined_limit = pCurThread->GetEEAllocContext()->GetCombinedLimit();
    ASSERT(alloc_ptr <= combined_limit);
    if ((size_t)(combined_limit - alloc_ptr) >= size)
    {
        acontext->alloc_ptr = alloc_ptr + size;
        Object* pObject = (Object *)alloc_ptr;
        pObject->SetMethodTable(pEEType);
        return pObject;
    }

    return AllocateObject(pEEType, 0, 0);
}
FCIMPLEND

#define GC_ALLOC_FINALIZE    0x1 // TODO: Defined in gc.h
#define GC_ALLOC_ALIGN8_BIAS 0x4 // TODO: Defined in gc.h
#define GC_ALLOC_ALIGN8      0x8 // TODO: Defined in gc.h

FCIMPL1(Object *, RhpNewFinalizable, MethodTable* pEEType)
{
    ASSERT(pEEType->HasFinalizer());
    return AllocateObject(pEEType, GC_ALLOC_FINALIZE, 0);
}
FCIMPLEND

FCIMPL2(Array *, RhpNewArrayFast, MethodTable * pArrayEEType, intptr_t numElements)
{
    Thread * pCurThread = ThreadStore::GetCurrentThread();
    gc_alloc_context * acontext = pCurThread->GetAllocContext();

#ifndef HOST_64BIT
    // if the element count is <= 0x10000, no overflow is possible because the component size is
    // <= 0xffff, and thus the product is <= 0xffff0000, and the base size is only ~12 bytes
    if (numElements > 0x10000)
    {
        // Overflow here should result in an OOM. Let the slow path take care of it.
        return (Array*)AllocateObject(pArrayEEType, 0, numElements);
    }
#endif // !HOST_64BIT

    size_t size;
    if (!TryComputeArraySize(pArrayEEType, numElements, &size))
    {
        return nullptr;
    }

    uint8_t* alloc_ptr = acontext->alloc_ptr;
    uint8_t* combined_limit = pCurThread->GetEEAllocContext()->GetCombinedLimit();
    ASSERT(alloc_ptr <= combined_limit);
    if ((size_t)(combined_limit - alloc_ptr) >= size)
    {
        acontext->alloc_ptr = alloc_ptr + size;
        Array* pObject = (Array*)alloc_ptr;
        pObject->SetMethodTable(pArrayEEType);
        pObject->SetNumComponents((uint32_t)numElements);
        return pObject;
    }

    return (Array*)AllocateObject(pArrayEEType, 0, numElements);
}
FCIMPLEND

FCIMPL2(String *, RhNewString, MethodTable * pStringEEType, intptr_t numElements)
{
    // NativeAOT strings use the array-compatible length/component layout. Reuse the
    // bounded allocator so negative lengths, overflow, fast-path limits, and OOM
    // handling remain identical to other variable-sized allocations.
    return (String*)RhpNewArrayFast(pStringEEType, numElements);
}
FCIMPLEND

#if defined(FEATURE_64BIT_ALIGNMENT)

GPTR_DECL(MethodTable, g_pFreeObjectEEType);

FCIMPL1(Object *, RhpNewFinalizableAlign8, MethodTable* pEEType)
{
    return AllocateObject(pEEType, GC_ALLOC_FINALIZE | GC_ALLOC_ALIGN8, 0);
}
FCIMPLEND

#ifndef HOST_64BIT
FCIMPL1(Object*, RhpNewFastAlign8, MethodTable* pEEType)
{
    ASSERT(!pEEType->HasFinalizer());

    Thread* pCurThread = ThreadStore::GetCurrentThread();
    gc_alloc_context* acontext = pCurThread->GetAllocContext();

    size_t size = pEEType->GetBaseSize();
    size = (size + (sizeof(uintptr_t) - 1)) & ~(sizeof(uintptr_t) - 1);

    uint8_t* alloc_ptr = acontext->alloc_ptr;
    int requiresPadding = ((uint32_t)alloc_ptr) & 7;
    size_t paddedSize = size;
    if (requiresPadding)
    {
        paddedSize += 12;
    }

    uint8_t* combined_limit = pCurThread->GetEEAllocContext()->GetCombinedLimit();
    ASSERT(alloc_ptr <= combined_limit);
    if ((size_t)(combined_limit - alloc_ptr) >= paddedSize)
    {
        acontext->alloc_ptr = alloc_ptr + paddedSize;
        if (requiresPadding)
        {
            Object* dummy = (Object*)alloc_ptr;
            dummy->SetMethodTable(g_pFreeObjectEEType);
            alloc_ptr += 12;
        }
        Object* pObject = (Object *)alloc_ptr;
        pObject->SetMethodTable(pEEType);
        return pObject;
    }

    return AllocateObject(pEEType, GC_ALLOC_ALIGN8, 0);
}
FCIMPLEND

FCIMPL1(Object*, RhpNewFastMisalign, MethodTable* pEEType)
{
    Thread* pCurThread = ThreadStore::GetCurrentThread();
    gc_alloc_context* acontext = pCurThread->GetAllocContext();

    size_t size = pEEType->GetBaseSize();

    uint8_t* alloc_ptr = acontext->alloc_ptr;
    int requiresPadding = (((uint32_t)alloc_ptr) & 7) != 4;
    size_t paddedSize = size;
    if (requiresPadding)
    {
        paddedSize += 12;
    }

    uint8_t* combined_limit = pCurThread->GetEEAllocContext()->GetCombinedLimit();
    ASSERT(alloc_ptr <= combined_limit);
    if ((size_t)(combined_limit - alloc_ptr) >= paddedSize)
    {
        acontext->alloc_ptr = alloc_ptr + paddedSize;
        if (requiresPadding)
        {
            Object* dummy = (Object*)alloc_ptr;
            dummy->SetMethodTable(g_pFreeObjectEEType);
            alloc_ptr += 12;
        }
        Object* pObject = (Object *)alloc_ptr;
        pObject->SetMethodTable(pEEType);
        return pObject;
    }

    return AllocateObject(pEEType, GC_ALLOC_ALIGN8 | GC_ALLOC_ALIGN8_BIAS, 0);
}
FCIMPLEND

FCIMPL2(Array*, RhpNewArrayFastAlign8, MethodTable* pArrayEEType, intptr_t numElements)
{
    Thread* pCurThread = ThreadStore::GetCurrentThread();
    gc_alloc_context* acontext = pCurThread->GetAllocContext();

    // if the element count is <= 0x10000, no overflow is possible because the component size is
    // <= 0xffff, and thus the product is <= 0xffff0000, and the base size is only ~12 bytes
    if (numElements > 0x10000)
    {
        // Overflow here should result in an OOM. Let the slow path take care of it.
        return (Array*)AllocateObject(pArrayEEType, GC_ALLOC_ALIGN8, numElements);
    }

    size_t size;
    if (!TryComputeArraySize(pArrayEEType, numElements, &size))
    {
        return nullptr;
    }

    uint8_t* alloc_ptr = acontext->alloc_ptr;
    int requiresAlignObject = ((uint32_t)alloc_ptr) & 7;
    size_t paddedSize = size;
    if (requiresAlignObject)
    {
        paddedSize += 12;
    }

    uint8_t* combined_limit = pCurThread->GetEEAllocContext()->GetCombinedLimit();
    ASSERT(alloc_ptr <= combined_limit);
    if ((size_t)(combined_limit - alloc_ptr) >= paddedSize)
    {
        acontext->alloc_ptr = alloc_ptr + paddedSize;
        if (requiresAlignObject)
        {
            Object* dummy = (Object*)alloc_ptr;
            dummy->SetMethodTable(g_pFreeObjectEEType);
            alloc_ptr += 12;
        }
        Array* pObject = (Array*)alloc_ptr;
        pObject->SetMethodTable(pArrayEEType);
        pObject->SetNumComponents((uint32_t)numElements);
        return pObject;
    }

    return (Array*)AllocateObject(pArrayEEType, GC_ALLOC_ALIGN8, numElements);
}
FCIMPLEND
#endif // !HOST_64BIT
#endif // defined(HOST_ARM) || defined(HOST_WASM)

// PortableRuntime source boundary: UniversalTransitionTailCall is an ABI-level
// tail-call trampoline.  It must preserve the target-specific register and
// stack contract, so a C++ fallback cannot safely replace the assembly helper.
// Keep the return-address marker defined for stack-walker builds until a
// target-specific portable thunk owner supplies the trampoline.
EXTERN_C void * ReturnFromUniversalTransitionTailCall;
void * ReturnFromUniversalTransitionTailCall;

#if !defined (HOST_ARM64)
FCIMPL2(void, RhpAssignRef, Object ** dst, Object * ref)
{
    // A null destination is an invalid managed write-barrier call.  Preserve
    // the native fault instead of silently dropping the reference; exception
    // recovery for this corruption is not part of the portable helper ABI.
    *dst = ref;
    InlineWriteBarrier(dst, ref);
}
FCIMPLEND

FCIMPL2(void, RhpCheckedAssignRef, Object ** dst, Object * ref)
{
    // See RhpAssignRef: an invalid destination must remain a native fault.
    *dst = ref;
    InlineCheckedWriteBarrier(dst, ref);
}
FCIMPLEND
#endif

FCIMPL3(Object *, RhpCheckedLockCmpXchg, Object ** location, Object * value, Object * comparand)
{
    Object * ret = (Object *)PalInterlockedCompareExchangePointer((void * volatile *)location, value, comparand);
    InlineCheckedWriteBarrier(location, value);
    return ret;
}
FCIMPLEND

FCIMPL2(Object *, RhpCheckedXchg, Object ** location, Object * value)
{
    // See RhpAssignRef: an invalid destination must remain a native fault.
    Object * ret = (Object *)PalInterlockedExchangePointer((void * volatile *)location, value);
    InlineCheckedWriteBarrier(location, value);
    return ret;
}
FCIMPLEND

FCIMPL1(HRESULT, RhAllocateThunksMapping, void ** ppThunksSection)
{
    // PortableRuntime has no executable thunk template or writable/executable
    // mapping owner. Keep the unsupported boundary in the managed ThunkPool
    // caller, which translates any non-S_OK result to PlatformNotSupportedException.
    UNREFERENCED_PARAMETER(ppThunksSection);
    return E_NOTIMPL;
}
FCIMPLEND

FCIMPL0(void *, RhpGetThunksBase)
{
    // PortableRuntime does not expose executable thunk mappings.
    return NULL;
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunkBlocksPerMapping)
{
    // Keep Constants initialization safe so RhAllocateThunksMapping can report
    // the managed PlatformNotSupportedException boundary.
    return 0;
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunksPerBlock)
{
    return 0;
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkSize)
{
    return 0;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkDataBlockAddress, void* pThunkStubAddress)
{
    UNREFERENCED_PARAMETER(pThunkStubAddress);
    return NULL;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkStubsBlockAddress, void* pThunkDataAddress)
{
    UNREFERENCED_PARAMETER(pThunkDataAddress);
    return NULL;
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkBlockSize)
{
    return 0;
}
FCIMPLEND

FCIMPL0(void *, RhGetCommonStubAddress)
{
    // There is no portable executable common stub.
    return NULL;
}
FCIMPLEND

FCIMPL0(void *, RhGetCurrentThunkContext)
{
    // PortableRuntime has no active native interop thunk context.
    return NULL;
}
FCIMPLEND

FCIMPL0(void, RhpGcPoll)
{
    // WASM cannot walk its native stack. Its GC roots are published through the
    // shadow stack, so a local transition frame is sufficient to enter the
    // shared trap/wait path without claiming a native register snapshot.
    PInvokeTransitionFrame frame = {};
    frame.m_RIP = NULL;
    RhpGcPoll2(&frame);
}
FCIMPLEND

#endif
