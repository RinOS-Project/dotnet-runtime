// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

#include <fcall.h>

#include "gchelpers.inl"
#include "gcheaputilities.h"
#include "jitinterface.h"

// The portable CoreCLR helper is used only when the target has no
// architecture-specific RhpAssignRef implementation.  Keep the write
// barrier state owned by the existing CoreCLR GC/EE contract: the GC publishes
// the card table and generation bounds through g_card_table/g_ephemeral_* and
// updates them through GCToEEInterface::StompWriteBarrier.  Do not create a
// second card-table owner here.
static bool ValidatePortableWriteBarrierDestination(Object **dst)
{
    if (dst != nullptr)
        return true;

    // A null destination is a corrupt helper call.  The portable helper has
    // no recoverable managed exception ABI, so fail through the same CoreCLR
    // fail-fast path used by the other raw JIT helpers instead of relying on
    // an incidental null dereference.
    DoJITFailFast();
    return false;
}

static void MarkPortableWriteBarrierCards(Object **dst)
{
    // The region table is already skewed by the GC owner.  Filter out stores
    // that cannot be observed by an ephemeral collection before touching the
    // card table.  In bitwise-region mode, a full dirty byte is a conservative
    // superset of the individual card bit and is safe for the GC's card scan;
    // it also avoids inventing a byte-sized atomic RMW ABI for portable
    // targets.  The existing GC owner accepts 0xff as the dirty value.
    if (g_region_to_generation_table != nullptr)
    {
        const size_t destinationRegion =
            reinterpret_cast<size_t>(dst) >> g_region_shr;
        const size_t referenceRegion =
            reinterpret_cast<size_t>(*dst) >> g_region_shr;
        const uint8_t destinationGeneration =
            g_region_to_generation_table[destinationRegion];
        const uint8_t referenceGeneration =
            g_region_to_generation_table[referenceRegion];

        if (destinationGeneration == 0 ||
            referenceGeneration >= destinationGeneration)
        {
            return;
        }
    }

    // g_card_table is a skewed table, so the address shift is the complete
    // index calculation used by the architecture-specific barriers too.
    BYTE *card = (BYTE *)VolatileLoadWithoutBarrier(&g_card_table) +
        (reinterpret_cast<size_t>(dst) >> card_byte_shift);
    if (*card != 0xFF)
    {
        *card = 0xFF;

#ifdef FEATURE_MANUALLY_MANAGED_CARD_BUNDLES
        BYTE *cardBundle =
            (BYTE *)VolatileLoadWithoutBarrier(&g_card_bundle_table) +
            (reinterpret_cast<size_t>(dst) >> card_bundle_byte_shift);
        if (*cardBundle != 0xFF)
        {
            *cardBundle = 0xFF;
        }
#endif
    }
}

static void PortableWriteBarrier(Object **dst, Object *ref, bool checked)
{
    if (!ValidatePortableWriteBarrierDestination(dst))
        return;

    // The reference store is deliberately first.  This matches the upstream
    // RhpAssignRef ABI and the existing CoreCLR JIT write barrier: a checked
    // helper may target a handle/stack slot outside the GC heap, but it still
    // must perform the requested store.
    VolatileStore(dst, ref);

    if (checked && (((BYTE *)dst < g_lowest_address) ||
                    ((BYTE *)dst >= g_highest_address)))
    {
        return;
    }

#ifdef WRITE_BARRIER_CHECK
    updateGCShadow(dst, ref);
#endif

#ifdef FEATURE_USE_SOFTWARE_WRITE_WATCH_FOR_GC_HEAP
    if (GCHeapUtilities::SoftwareWriteWatchIsEnabled())
    {
        GCHeapUtilities::SoftwareWriteWatchSetDirty(dst, sizeof(*dst));
    }
#endif

    if (((BYTE *)ref < g_ephemeral_low) ||
        ((BYTE *)ref >= g_ephemeral_high))
    {
        return;
    }

    // The CoreCLR GC publishes g_card_table before changing heap bounds, and
    // VolatileLoadWithoutBarrier preserves that publication ordering here.
    MarkPortableWriteBarrierCards(dst);
}

EXTERN_C FCDECL2_RAW(VOID, RhpAssignRef, Object **dst, Object *ref);
FCIMPL2_RAW(VOID, RhpAssignRef, Object **dst, Object *ref)
{
    PortableWriteBarrier(dst, ref, false);
}
FCIMPLEND

EXTERN_C FCDECL2_RAW(VOID, RhpCheckedAssignRef, Object **dst, Object *ref);
FCIMPL2_RAW(VOID, RhpCheckedAssignRef, Object **dst, Object *ref)
{
    PortableWriteBarrier(dst, ref, true);
}
FCIMPLEND
