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
#include "../../../../../../public-base/RinOS-SDK/include/rin/dotnet/nativeaot_thunk_abi.h"

#include "GCMemoryHelpers.inl"

#include <new>

#if defined(__GNUC__) || defined(__clang__)
#define RINOS_NATIVEAOT_THUNK_WEAK __attribute__((weak))
#else
#define RINOS_NATIVEAOT_THUNK_WEAK
#endif

extern "C" const RinNativeAotThunkProviderV1*
rin_nativeaot_thunk_provider_get_v1(void) RINOS_NATIVEAOT_THUNK_WEAK;

static bool IsValidRinNativeAotThunkGeometry(
    const RinNativeAotThunkProviderV1* provider);

static const RinNativeAotThunkProviderV1* GetRinNativeAotThunkProvider()
{
    if (rin_nativeaot_thunk_provider_get_v1 == nullptr)
        return nullptr;

    const RinNativeAotThunkProviderV1* provider =
        rin_nativeaot_thunk_provider_get_v1();
    if (provider == nullptr ||
        provider->struct_size < RIN_NATIVEAOT_THUNK_PROVIDER_V1_REQUIRED_SIZE ||
        provider->abi_version != RIN_NATIVEAOT_THUNK_ABI_VERSION ||
        provider->reserved0 != 0 ||
        (provider->capability_mask & ~RIN_NATIVEAOT_THUNK_KNOWN_CAPABILITIES) != 0 ||
        (provider->capability_mask & RIN_NATIVEAOT_THUNK_REQUIRED_CAPABILITIES) !=
            RIN_NATIVEAOT_THUNK_REQUIRED_CAPABILITIES ||
        provider->allocate_thunks_mapping == nullptr ||
        provider->get_thunks_base == nullptr ||
        provider->get_num_thunk_blocks_per_mapping == nullptr ||
        provider->get_num_thunks_per_block == nullptr ||
        provider->get_thunk_size == nullptr ||
        provider->get_thunk_data_block_address == nullptr ||
        provider->get_thunk_stubs_block_address == nullptr ||
        provider->get_thunk_block_size == nullptr ||
        provider->get_common_stub_address == nullptr ||
        provider->get_current_thunk_context == nullptr)
        return nullptr;

    if ((provider->capability_mask & RIN_NATIVEAOT_THUNK_CAP_MAPPING_RELEASE) != 0 &&
        (provider->struct_size < RIN_NATIVEAOT_THUNK_PROVIDER_V1_RELEASE_SIZE ||
         provider->free_thunks_mapping == nullptr))
        return nullptr;

    /* All geometry callbacks describe one immutable provider layout.  Do the
     * same validation at discovery time as at allocation time so the
     * individual RuntimeImports below cannot expose malformed values after a
     * valid schema/capability table has been advertised. */
    if (!IsValidRinNativeAotThunkGeometry(provider))
        return nullptr;

    return provider;
}

/* PortableRuntime receives its thunk geometry from the product provider.
 * Keep the same page/block relationship that the managed ThunkPool validates
 * at a native boundary too: a malformed provider must not reach an allocator
 * callback with a geometry that can make its code/data halves overlap. */
static bool IsValidRinNativeAotThunkGeometry(
    const RinNativeAotThunkProviderV1* provider)
{
    const int32_t blocksPerMapping =
        provider->get_num_thunk_blocks_per_mapping(provider->context);
    const int32_t thunksPerBlock =
        provider->get_num_thunks_per_block(provider->context);
    const int32_t thunkSize =
        provider->get_thunk_size(provider->context);
    const int32_t blockSize =
        provider->get_thunk_block_size(provider->context);
    const uint64_t codeBytes =
        (uint64_t)(uint32_t)thunkSize * (uint64_t)(uint32_t)thunksPerBlock;
    const uint64_t dataBytes =
        (uint64_t)(sizeof(void*) * 2u) * (uint64_t)(uint32_t)thunksPerBlock +
        (uint64_t)sizeof(void*);
    const uint64_t requiredBytes = codeBytes > dataBytes
        ? codeBytes : dataBytes;
    uint64_t pageSize = 1u;

    if (blocksPerMapping <= 0 || thunksPerBlock <= 0 || thunkSize <= 0 ||
        blockSize <= 0 || requiredBytes == 0u ||
        requiredBytes > (uint64_t)INT32_MAX)
        return false;

    while (pageSize < requiredBytes) {
        if (pageSize > UINT64_MAX / 2u) return false;
        pageSize <<= 1u;
    }
    if (pageSize != (uint64_t)(uint32_t)blockSize ||
        pageSize > (uint64_t)SIZE_MAX / (uint64_t)(uint32_t)blocksPerMapping)
        return false;

    return true;
}

/* A portable mapping must be released by the same provider that allocated it.
 * Capability discovery is allowed to fail closed while an existing mapping is
 * still live, so rediscovering a provider in RhpFreeThunksMapping would either
 * leak the mapping or call a different owner.  Keep the exact provider
 * association until the owner reports a successful release. */
struct RinOsPortableThunkMappingOwner
{
    void* mapping;
    const RinNativeAotThunkProviderV1* provider;
    bool releaseInProgress;
    bool pendingRelease;
    RinOsPortableThunkMappingOwner* next;
};

static RinOsPortableThunkMappingOwner* g_portableThunkMappingOwners = nullptr;
static volatile int32_t g_portableThunkMappingOwnerLock = 0;

static void LockPortableThunkMappingOwners()
{
    while (PalInterlockedCompareExchange(
               &g_portableThunkMappingOwnerLock, 1, 0) != 0)
    {
        PalSwitchToThread();
    }
}

static void UnlockPortableThunkMappingOwners()
{
    VolatileStore<volatile int32_t>(&g_portableThunkMappingOwnerLock, 0);
}

static RinOsPortableThunkMappingOwner* ReservePortableThunkMappingOwner()
{
    RinOsPortableThunkMappingOwner* owner =
        new (std::nothrow) RinOsPortableThunkMappingOwner{};
    if (owner == nullptr)
        return nullptr;

    owner->mapping = nullptr;
    owner->provider = nullptr;
    owner->releaseInProgress = false;
    owner->pendingRelease = false;
    owner->next = nullptr;
    return owner;
}

static HRESULT RegisterPortableThunkMapping(
    RinOsPortableThunkMappingOwner* owner,
    void* mapping,
    const RinNativeAotThunkProviderV1* provider)
{
    owner->mapping = mapping;
    owner->provider = provider;
    owner->pendingRelease = false;

    LockPortableThunkMappingOwners();
    for (RinOsPortableThunkMappingOwner* current =
             g_portableThunkMappingOwners;
         current != nullptr;
         current = current->next)
    {
        if (current->mapping == mapping)
        {
            UnlockPortableThunkMappingOwners();
            // The provider returned an address already owned by a live
            // mapping.  Do not release it from the allocation failure path:
            // doing so would tear down the first mapping while its owner is
            // still using it.  The caller must clear its output and fail
            // closed without handing this duplicate address back to the
            // provider.
            return E_INVALIDARG;
        }
    }
    owner->next = g_portableThunkMappingOwners;
    g_portableThunkMappingOwners = owner;
    UnlockPortableThunkMappingOwners();
    return S_OK;
}

static void QueuePendingPortableThunkMappingRelease(
    RinOsPortableThunkMappingOwner* owner)
{
    owner->pendingRelease = true;
    owner->releaseInProgress = false;

    LockPortableThunkMappingOwners();
    owner->next = g_portableThunkMappingOwners;
    g_portableThunkMappingOwners = owner;
    UnlockPortableThunkMappingOwners();
}

static bool TryReleasePortableThunkMapping(
    const RinNativeAotThunkProviderV1* provider,
    void* mapping)
{
    if (provider == nullptr || mapping == nullptr ||
        (provider->capability_mask & RIN_NATIVEAOT_THUNK_CAP_MAPPING_RELEASE) == 0 ||
        provider->struct_size < RIN_NATIVEAOT_THUNK_PROVIDER_V1_RELEASE_SIZE ||
        provider->free_thunks_mapping == nullptr)
    {
        return false;
    }

    return provider->free_thunks_mapping(provider->context, mapping) ==
        RIN_NATIVEAOT_THUNK_S_OK;
}

/* An allocation callback is allowed to return a non-null mapping together
 * with a failure.  If the provider cannot release that mapping immediately,
 * retain the exact provider/mapping pair and retry before publishing another
 * mapping.  Dropping the owner here would leak an executable mapping with no
 * caller-visible handle and would make a later provider replacement unsafe. */
static bool RetryPendingPortableThunkMappingReleases()
{
    for (;;)
    {
        RinOsPortableThunkMappingOwner* candidate = nullptr;

        LockPortableThunkMappingOwners();
        for (RinOsPortableThunkMappingOwner* owner =
                 g_portableThunkMappingOwners;
             owner != nullptr;
             owner = owner->next)
        {
            if (!owner->pendingRelease)
                continue;

            if (owner->releaseInProgress)
            {
                // Another retry is still invoking the provider.  Do not
                // allocate a new executable mapping concurrently with it.
                UnlockPortableThunkMappingOwners();
                return false;
            }

            owner->releaseInProgress = true;
            candidate = owner;
            break;
        }
        UnlockPortableThunkMappingOwners();

        if (candidate == nullptr)
            return true;

        const bool released = TryReleasePortableThunkMapping(
            candidate->provider, candidate->mapping);

        LockPortableThunkMappingOwners();
        if (!released)
        {
            candidate->releaseInProgress = false;
            UnlockPortableThunkMappingOwners();
            return false;
        }

        RinOsPortableThunkMappingOwner** ownerLink =
            &g_portableThunkMappingOwners;
        while (*ownerLink != nullptr && *ownerLink != candidate)
            ownerLink = &(*ownerLink)->next;
        if (*ownerLink != candidate)
        {
            // The registry must not lose a pending owner while its provider
            // callback is outside the lock.  Keep it retryable if that
            // invariant is ever violated rather than freeing unknown state.
            candidate->releaseInProgress = false;
            UnlockPortableThunkMappingOwners();
            return false;
        }

        *ownerLink = candidate->next;
        UnlockPortableThunkMappingOwners();
        delete candidate;
    }
}

static RinOsPortableThunkMappingOwner* BeginPortableThunkMappingRelease(
    void* mapping)
{
    LockPortableThunkMappingOwners();
    for (RinOsPortableThunkMappingOwner* owner =
             g_portableThunkMappingOwners;
         owner != nullptr;
         owner = owner->next)
    {
        if (owner->mapping == mapping)
        {
            if (owner->pendingRelease || owner->releaseInProgress)
            {
                UnlockPortableThunkMappingOwners();
                return nullptr;
            }
            owner->releaseInProgress = true;
            UnlockPortableThunkMappingOwners();
            return owner;
        }
    }
    UnlockPortableThunkMappingOwners();
    return nullptr;
}

static void FinishPortableThunkMappingRelease(
    RinOsPortableThunkMappingOwner* released, bool success)
{
    LockPortableThunkMappingOwners();
    if (!success)
    {
        released->releaseInProgress = false;
        UnlockPortableThunkMappingOwners();
        return;
    }

    RinOsPortableThunkMappingOwner** link = &g_portableThunkMappingOwners;
    while (*link != nullptr && *link != released)
        link = &(*link)->next;
    if (*link == released)
        *link = released->next;
    UnlockPortableThunkMappingOwners();
    delete released;
}

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

// Keep these private allocation flags synchronized with the definitions in
// Runtime/unix/unixasmmacros.inc and the architecture-specific assembly
// macro includes.  portable.cpp cannot include the GC implementation header:
// these values are part of the NativeAOT GC/assembly ABI, not a gc.h API.
#define GC_ALLOC_FINALIZE    0x1
#define GC_ALLOC_ALIGN8_BIAS 0x4
#define GC_ALLOC_ALIGN8      0x8

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

static bool ValidateWriteBarrierDestination(Object ** destination)
{
    if (destination != nullptr)
        return true;

    // A null destination is an invalid managed write-barrier call.  Fail fast
    // explicitly instead of relying on an incidental native null dereference;
    // exception recovery for this corruption is not part of the portable
    // helper ABI.
    RhFailFast();
    return false;
}

#if !defined (HOST_ARM64)
FCIMPL2(void, RhpAssignRef, Object ** dst, Object * ref)
{
    if (!ValidateWriteBarrierDestination(dst))
        return;

    *dst = ref;
    InlineWriteBarrier(dst, ref);
}
FCIMPLEND

FCIMPL2(void, RhpCheckedAssignRef, Object ** dst, Object * ref)
{
    if (!ValidateWriteBarrierDestination(dst))
        return;

    *dst = ref;
    InlineCheckedWriteBarrier(dst, ref);
}
FCIMPLEND
#endif

FCIMPL3(Object *, RhpCheckedLockCmpXchg, Object ** location, Object * value, Object * comparand)
{
    if (!ValidateWriteBarrierDestination(location))
        return nullptr;

    Object * ret = (Object *)PalInterlockedCompareExchangePointer((void * volatile *)location, value, comparand);
    InlineCheckedWriteBarrier(location, value);
    return ret;
}
FCIMPLEND

FCIMPL2(Object *, RhpCheckedXchg, Object ** location, Object * value)
{
    if (!ValidateWriteBarrierDestination(location))
        return nullptr;

    Object * ret = (Object *)PalInterlockedExchangePointer((void * volatile *)location, value);
    InlineCheckedWriteBarrier(location, value);
    return ret;
}
FCIMPLEND

FCIMPL1(HRESULT, RhAllocateThunksMapping, void ** ppThunksSection)
{
    if (ppThunksSection == nullptr)
        return E_INVALIDARG;

    *ppThunksSection = nullptr;

    if (!RetryPendingPortableThunkMappingReleases())
        return E_FAIL;

    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
    {
        if (!IsValidRinNativeAotThunkGeometry(provider))
            return E_FAIL;

        // Reserve the bookkeeping owner before invoking product code.  The
        // callback may return an executable mapping even when a later
        // registry allocation fails; reserving first keeps that mapping
        // attributable to this provider for every post-callback failure.
        RinOsPortableThunkMappingOwner* owner =
            ReservePortableThunkMappingOwner();
        if (owner == nullptr)
            return E_OUTOFMEMORY;

        HRESULT result = (HRESULT)provider->allocate_thunks_mapping(
            provider->context, ppThunksSection);
        if (result != S_OK || *ppThunksSection == nullptr)
        {
            void* failedMapping = *ppThunksSection;
            *ppThunksSection = nullptr;
            if (failedMapping != nullptr)
            {
                owner->mapping = failedMapping;
                owner->provider = provider;
                if (!TryReleasePortableThunkMapping(provider, failedMapping))
                {
                    QueuePendingPortableThunkMappingRelease(owner);
                    return result == S_OK ? E_FAIL : result;
                }
            }
            delete owner;
            return result == S_OK ? E_FAIL : result;
        }

        result = RegisterPortableThunkMapping(owner, *ppThunksSection, provider);
        if (result != S_OK)
        {
            // E_INVALIDARG means the provider returned an address already
            // owned by a live mapping.  Releasing that address here would
            // invalidate the earlier allocation.  The owner was reserved
            // before the callback, so no post-callback allocation failure
            // can leave an untracked mapping behind.
            if (result != E_INVALIDARG &&
                (provider->capability_mask &
                    RIN_NATIVEAOT_THUNK_CAP_MAPPING_RELEASE) != 0 &&
                provider->free_thunks_mapping != nullptr)
            {
                (void)provider->free_thunks_mapping(
                    provider->context, *ppThunksSection);
            }
            *ppThunksSection = nullptr;
            delete owner;
            return result;
        }

        return S_OK;
    }

    // Keep the unsupported boundary in the managed ThunkPool caller, which
    // translates any non-S_OK result to PlatformNotSupportedException.
    return E_NOTIMPL;
}
FCIMPLEND

FCIMPL1(HRESULT, RhFreeThunksMapping, void* pThunksSection)
{
    if (pThunksSection == nullptr)
        return E_INVALIDARG;

    RinOsPortableThunkMappingOwner* owner =
        BeginPortableThunkMappingRelease(pThunksSection);
    if (owner == nullptr)
        return E_INVALIDARG;

    const RinNativeAotThunkProviderV1* provider = owner->provider;
    if ((provider->capability_mask &
            RIN_NATIVEAOT_THUNK_CAP_MAPPING_RELEASE) != 0 &&
        provider->struct_size >= RIN_NATIVEAOT_THUNK_PROVIDER_V1_RELEASE_SIZE &&
        provider->free_thunks_mapping != nullptr)
    {
        HRESULT result = (HRESULT)provider->free_thunks_mapping(
            provider->context, pThunksSection);
        FinishPortableThunkMappingRelease(owner, result == S_OK);
        return result;
    }

    // A provider that only advertises allocation cannot safely release an
    // executable mapping. Keep its ownership record so the managed
    // retry/fail-closed boundary and a later ABI upgrade cannot accidentally
    // pass a foreign mapping to a new provider.
    FinishPortableThunkMappingRelease(owner, false);
    return E_NOTIMPL;
}
FCIMPLEND

FCIMPL0(void *, RhpGetThunksBase)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_thunks_base(provider->context);

    return NULL;
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunkBlocksPerMapping)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_num_thunk_blocks_per_mapping(provider->context);

    return 0;
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunksPerBlock)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_num_thunks_per_block(provider->context);

    return 0;
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkSize)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_thunk_size(provider->context);

    return 0;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkDataBlockAddress, void* pThunkStubAddress)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr && pThunkStubAddress != nullptr)
        return provider->get_thunk_data_block_address(
            provider->context, pThunkStubAddress);

    return NULL;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkStubsBlockAddress, void* pThunkDataAddress)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr && pThunkDataAddress != nullptr)
        return provider->get_thunk_stubs_block_address(
            provider->context, pThunkDataAddress);

    return NULL;
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkBlockSize)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_thunk_block_size(provider->context);

    return 0;
}
FCIMPLEND

FCIMPL0(void *, RhGetCommonStubAddress)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_common_stub_address(provider->context);

    return NULL;
}
FCIMPLEND

FCIMPL0(void *, RhGetCurrentThunkContext)
{
    const RinNativeAotThunkProviderV1* provider =
        GetRinNativeAotThunkProvider();
    if (provider != nullptr)
        return provider->get_current_thunk_context(provider->context);

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
