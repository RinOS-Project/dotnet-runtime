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

#include <string.h>


#ifdef FEATURE_RX_THUNKS

#ifdef TARGET_AMD64
#define THUNK_SIZE  20
#elif TARGET_X86
#define THUNK_SIZE  12
#elif TARGET_ARM
#define THUNK_SIZE  12
#elif TARGET_ARM64
#define THUNK_SIZE  16
#elif TARGET_LOONGARCH64
#define THUNK_SIZE  16
#elif TARGET_RISCV64
#define THUNK_SIZE  20
#else
#define THUNK_SIZE  (2 * OS_PAGE_SIZE) // This will cause RhpGetNumThunksPerBlock to return 0
#endif

static_assert((THUNK_SIZE % 4) == 0, "Thunk stubs size not aligned correctly. This will cause runtime failures.");

// 32 K or OS page
#define THUNKS_MAP_SIZE (max((size_t)0x8000, OS_PAGE_SIZE))

/*
 * Several thunk encodings place an immediate after a one- or three-byte
 * opcode.  Do not write those fields through a typed pointer: the x64 thunk
 * stores an eight-byte address at offset 2 and a four-byte displacement at
 * offset 13, neither of which is naturally aligned.  memcpy is the portable
 * object-representation write and keeps the code generator valid under the
 * RinOS strict-alignment contract before the code half is published RX.
 */
template <typename T>
static void WriteThunkValue(uint8_t*& cursor, const T& value)
{
    memcpy(cursor, &value, sizeof(value));
    cursor += sizeof(value);
}

static void WriteThunkPointer(uint8_t*& cursor, void* value)
{
    memcpy(cursor, &value, sizeof(value));
    cursor += sizeof(value);
}

static void WriteThunkBytes(uint8_t*& cursor, const void* value, size_t size)
{
    memcpy(cursor, value, size);
    cursor += size;
}

#ifdef TARGET_ARM
//*****************************************************************************
//  Encode a 16-bit immediate mov/movt in ARM Thumb2 Instruction (format T2_N)
//*****************************************************************************
void EncodeThumb2Mov16(uint16_t * pCode, uint16_t value, uint8_t rDestination, bool topWord)
{
    pCode[0] = ((topWord ? 0xf2c0 : 0xf240) |
        ((value >> 12) & 0x000f) |
        ((value >> 1) & 0x0400));
    pCode[1] = (((value << 4) & 0x7000) |
        (value & 0x00ff) |
        (rDestination << 8));
}

//*****************************************************************************
//  Encode a 32-bit immediate mov in ARM Thumb2 Instruction (format T2_N)
//*****************************************************************************
void EncodeThumb2Mov32(uint16_t * pCode, uint32_t value, uint8_t rDestination)
{
    EncodeThumb2Mov16(pCode, (uint16_t)(value & 0x0000ffff), rDestination, false);
    EncodeThumb2Mov16(pCode + 2, (uint16_t)(value >> 16), rDestination, true);
}
#endif

FCIMPL0(int, RhpGetNumThunkBlocksPerMapping)
{
    ASSERT_MSG((THUNKS_MAP_SIZE % OS_PAGE_SIZE) == 0, "Thunks map size should be in multiples of pages");

    return (int)(THUNKS_MAP_SIZE / OS_PAGE_SIZE);
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunksPerBlock)
{
    return (int)min(
        OS_PAGE_SIZE / THUNK_SIZE,                              // Number of thunks that can fit in a page
        (OS_PAGE_SIZE - POINTER_SIZE) / (POINTER_SIZE * 2)      // Number of pointer pairs, minus the jump stub cell, that can fit in a page
    );
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkSize)
{
    return THUNK_SIZE;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkDataBlockAddress, void* pThunkStubAddress)
{
    if (pThunkStubAddress == NULL)
    {
        return NULL;
    }

    uintptr_t pageAddress = (uintptr_t)pThunkStubAddress &
        ~((uintptr_t)OS_PAGE_SIZE - 1u);
    if (pageAddress > UINTPTR_MAX - (uintptr_t)THUNKS_MAP_SIZE)
    {
        return NULL;
    }

    return (void*)(pageAddress + (uintptr_t)THUNKS_MAP_SIZE);
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkStubsBlockAddress, void* pThunkDataAddress)
{
    if (pThunkDataAddress == NULL)
    {
        return NULL;
    }

    uintptr_t pageAddress = (uintptr_t)pThunkDataAddress &
        ~((uintptr_t)OS_PAGE_SIZE - 1u);
    if (pageAddress < (uintptr_t)THUNKS_MAP_SIZE)
    {
        return NULL;
    }

    return (void*)(pageAddress - (uintptr_t)THUNKS_MAP_SIZE);
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkBlockSize)
{
    return (int)OS_PAGE_SIZE;
}
FCIMPLEND

EXTERN_C HRESULT QCALLTYPE RhAllocateThunksMapping(void** ppThunksSection)
{
    if (ppThunksSection == NULL)
    {
        return E_INVALIDARG;
    }
    *ppThunksSection = NULL;

    size_t thunksMapSize = THUNKS_MAP_SIZE;
    if (thunksMapSize == 0 || thunksMapSize > SIZE_MAX / 2)
    {
        return E_INVALIDARG;
    }
    const size_t mappingSize = thunksMapSize * 2;

#ifdef WIN32

    void * pNewMapping = PalVirtualAlloc(mappingSize, PAGE_READWRITE);
    if (pNewMapping == NULL)
    {
        return E_OUTOFMEMORY;
    }

    void * pThunksSection = pNewMapping;
    void * pDataSection = (uint8_t*)pNewMapping + thunksMapSize;

#else

    // Note: On secure linux systems, we can't add execute permissions to a mapped virtual memory if it was not created
    // with execute permissions in the first place. This is why we create the virtual section with RX permissions, then
    // reduce it to RW for the data section. For the stubs section we need to increase to RWX to generate the stubs
    // instructions. After this we go back to RX for the stubs section before the stubs are used and should not be
    // changed anymore.
#if defined(TARGET_RINOS)
    // RinOS enforces W^X in the kernel and rejects the temporary RWX
    // transition used by the upstream Unix allocator.  The target has no
    // executable-at-map requirement, so build both halves as RW, emit the
    // stubs, and publish only the code half as RX below.  The data half stays
    // RW for the thunk slots.
    void * pNewMapping = PalVirtualAlloc(mappingSize, PAGE_READWRITE);
    if (pNewMapping == NULL)
    {
        return E_OUTOFMEMORY;
    }

    void * pThunksSection = pNewMapping;
    void * pDataSection = (uint8_t*)pNewMapping + thunksMapSize;
#else
    void * pNewMapping = PalVirtualAlloc(mappingSize, PAGE_EXECUTE_READ);
    if (pNewMapping == NULL)
    {
        return E_OUTOFMEMORY;
    }

    void * pThunksSection = pNewMapping;
    void * pDataSection = (uint8_t*)pNewMapping + thunksMapSize;

    if (!PalVirtualProtect(pDataSection, thunksMapSize, PAGE_READWRITE) ||
        !PalVirtualProtect(pThunksSection, thunksMapSize, PAGE_EXECUTE_READWRITE))
    {
        PalVirtualFree(pNewMapping, mappingSize);
        return E_FAIL;
    }
#endif

#if defined(HOST_APPLE) && defined(HOST_ARM64)
#if defined(HOST_MACCATALYST) || defined(HOST_IOS) || defined(HOST_TVOS)
    RhFailFast(); // we don't expect to get here on these platforms
#elif defined(HOST_OSX)
    pthread_jit_write_protect_np(0);
#else
    #error "Unknown OS"
#endif
#endif
#endif

    int numBlocksPerMap = RhpGetNumThunkBlocksPerMapping();
    int numThunksPerBlock = RhpGetNumThunksPerBlock();

    // The geometry helpers are supplied by the platform assembly on the RX
    // thunk path.  Validate their contract before using the values in pointer
    // arithmetic.  In particular, a malformed block count would make the
    // two halves of the mapping overlap or run past the allocation, while a
    // malformed thunk count would make the code/data page writes overflow.
    const size_t thunkBlockCapacity = thunksMapSize / (size_t)OS_PAGE_SIZE;
    const size_t thunkCodeCapacity = (size_t)OS_PAGE_SIZE / (size_t)THUNK_SIZE;
    const size_t thunkDataCapacity = OS_PAGE_SIZE >= POINTER_SIZE
        ? ((size_t)OS_PAGE_SIZE - POINTER_SIZE) / (POINTER_SIZE * 2)
        : 0;
    const size_t thunkCapacity = min(thunkCodeCapacity, thunkDataCapacity);
    if (OS_PAGE_SIZE == 0 ||
        thunksMapSize % (size_t)OS_PAGE_SIZE != 0 ||
        numBlocksPerMap <= 0 ||
        (size_t)numBlocksPerMap > thunkBlockCapacity ||
        numThunksPerBlock <= 0 ||
        (size_t)numThunksPerBlock > thunkCapacity)
    {
        PalVirtualFree(pNewMapping, mappingSize);
        return E_FAIL;
    }

    for (int m = 0; m < numBlocksPerMap; m++)
    {
        uint8_t* pDataBlockAddress = (uint8_t*)pDataSection + (size_t)m * OS_PAGE_SIZE;
        uint8_t* pThunkBlockAddress = (uint8_t*)pThunksSection + (size_t)m * OS_PAGE_SIZE;

        for (int i = 0; i < numThunksPerBlock; i++)
        {
            const size_t thunkDataOffset = (size_t)i * POINTER_SIZE * 2;
            uint8_t* pCurrentThunkAddress = pThunkBlockAddress + (size_t)THUNK_SIZE * i;
            uint8_t* pCurrentDataAddress = pDataBlockAddress + thunkDataOffset;

#ifdef TARGET_AMD64

            // mov r10,<thunk data address>
            // jmp [r10 + <delta to get to last qword in data page]

            WriteThunkValue(pCurrentThunkAddress, (uint16_t)0xba49);
            WriteThunkPointer(pCurrentThunkAddress, (void*)pCurrentDataAddress);
            const uint32_t indirectJump = 0x00a2ff41;
            WriteThunkBytes(pCurrentThunkAddress, &indirectJump, 3);
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset));

            // nops for alignment
            *pCurrentThunkAddress++ = 0x90;
            *pCurrentThunkAddress++ = 0x90;
            *pCurrentThunkAddress++ = 0x90;

#elif TARGET_X86

            // mov eax,<thunk data address>
            // jmp [eax + <delta to get to last dword in data page]

            *pCurrentThunkAddress++ = 0xb8;
            WriteThunkPointer(pCurrentThunkAddress, (void*)pCurrentDataAddress);
            WriteThunkValue(pCurrentThunkAddress, (uint16_t)0xa0ff);
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset));

            // nops for alignment
            *pCurrentThunkAddress++ = 0x90;

#elif TARGET_ARM

            // mov r12,<thunk data address>
            // ldr pc,[r12, <delta to get to last dword in data page>]
            // r12 retains data address; RhCommonStub reads it directly without stack

            EncodeThumb2Mov32((uint16_t*)pCurrentThunkAddress, (uint32_t)pCurrentDataAddress, 12);
            pCurrentThunkAddress += 8;

            // ldr pc, [r12, #offset]
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0xf000f8dc |
                           ((OS_PAGE_SIZE - POINTER_SIZE -
                             thunkDataOffset) << 16)));

#elif TARGET_ARM64

            //adr      xip0, <delta PC to thunk data address>
            //ldr      xip1, [xip0, <delta to get to last qword in data page>]
            //br       xip1
            //brk      0xf000 //Stubs need to be 16 byte aligned therefore we fill with a break here

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x10000010 |
                           (((delta & 0x03) << 29) |
                            (((delta & 0x1FFFFC) >> 2) << 5))));

            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0xF9400211 |
                           (((uint32_t)((OS_PAGE_SIZE - POINTER_SIZE -
                                         thunkDataOffset) /
                                        8)
                             << 10))));
            WriteThunkValue(pCurrentThunkAddress, (uint32_t)0xD61F0220);
            WriteThunkValue(pCurrentThunkAddress, (uint32_t)0xD43E0000);

#elif TARGET_LOONGARCH64

            //pcaddi    $t7, <delta PC to thunk data address>
            //pcaddi    $t8, -
            //ld.d      $t8, $t8, <delta to get to last qword in data page>
            //jirl      $r0, $t8, 0

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            ASSERT((-0x200000 <= delta) && (delta < 0x200000));

            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x18000013 |
                           (((delta & 0x3FFFFC) >> 2) << 5)));

            delta += OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset - 4;
            ASSERT((-0x200000 <= delta) && (delta < 0x200000));

            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x18000014 |
                           (((delta & 0x3FFFFC) >> 2) << 5)));
            WriteThunkValue(pCurrentThunkAddress, (uint32_t)0x28C00294);
            WriteThunkValue(pCurrentThunkAddress, (uint32_t)0x4C000280);

#elif defined(TARGET_RISCV64)

            //auipc    t1, hi(<delta PC to thunk data address>)
            //addi     t1, t1, lo(<delta PC to thunk data address>)
            //auipc    t0, hi(<delta to get to last word in data page>)
            //ld       t0, (t0)
            //jalr     zero, t0, 0

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x00000317 |
                           ((((delta + 0x800) & 0xFFFFF000) >> 12) << 12)));  // auipc t1, delta[31:12]
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x00030313 | ((delta & 0xFFF) << 20)));  // addi t1, t1, delta[11:0]

            delta += OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset - 8;
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x00000297 |
                           ((((delta + 0x800) & 0xFFFFF000) >> 12) << 12)));  // auipc t0, delta[31:12]
            WriteThunkValue(
                pCurrentThunkAddress,
                (uint32_t)(0x0002b283 | ((delta & 0xFFF) << 20))); // ld t0, (delta[11:0])(t0)
            WriteThunkValue(pCurrentThunkAddress, (uint32_t)0x00008282);  // jalr zero, t0, 0
            pCurrentThunkAddress += 4;

#else
            UNREFERENCED_PARAMETER(pCurrentDataAddress);
            UNREFERENCED_PARAMETER(pCurrentThunkAddress);
            PORTABILITY_ASSERT("RhAllocateThunksMapping");
#endif
        }
    }

#if defined(HOST_APPLE) && defined(HOST_ARM64)
#if defined(HOST_MACCATALYST) || defined(HOST_IOS) || defined(HOST_TVOS)
    RhFailFast(); // we don't expect to get here on these platforms
#elif defined(HOST_OSX)
    pthread_jit_write_protect_np(1);
#else
    #error "Unknown OS"
#endif
#else
    if (!PalVirtualProtect(pThunksSection, thunksMapSize, PAGE_EXECUTE_READ))
    {
        PalVirtualFree(pNewMapping, thunksMapSize * 2);
        return E_FAIL;
    }
#endif

    PalFlushInstructionCache(pThunksSection, thunksMapSize);

    *ppThunksSection = pThunksSection;
    return S_OK;
}

// FEATURE_RX_THUNKS
#elif FEATURE_FIXED_POOL_THUNKS
// This is used by the thunk code to find the stub data for the called thunk slot
extern "C" uintptr_t g_pThunkStubData;
uintptr_t g_pThunkStubData = NULL;

FCDECL0(int, RhpGetThunkBlockCount);
FCDECL0(int, RhpGetNumThunkBlocksPerMapping);
FCDECL0(int, RhpGetThunkBlockSize);
FCDECL1(void*, RhpGetThunkDataBlockAddress, void* addr);
FCDECL1(void*, RhpGetThunkStubsBlockAddress, void* addr);

EXTERN_C HRESULT QCALLTYPE RhAllocateThunksMapping(void** ppThunksSection)
{
    if (ppThunksSection == NULL)
    {
        return E_INVALIDARG;
    }
    *ppThunksSection = NULL;

    static int nextThunkDataMapping = 0;

    int thunkBlocksPerMapping = RhpGetNumThunkBlocksPerMapping();
    int thunkBlockSize = RhpGetThunkBlockSize();
    int blockCount = RhpGetThunkBlockCount();

    // These values come from the platform-specific fixed thunk pool.  Treat
    // them as untrusted configuration at this boundary: the old code divided
    // by thunkBlocksPerMapping and multiplied into int before validating either
    // value, which could turn a malformed pool description into an invalid
    // VirtualAlloc/commit range.
    if (thunkBlocksPerMapping <= 0 || thunkBlockSize <= 0 || blockCount <= 0 ||
        blockCount % thunkBlocksPerMapping != 0)
    {
        return E_FAIL;
    }

    size_t thunkDataMappingSize = (size_t)thunkBlocksPerMapping;
    if (thunkDataMappingSize > SIZE_MAX / (size_t)thunkBlockSize)
    {
        return E_FAIL;
    }
    thunkDataMappingSize *= (size_t)thunkBlockSize;

    size_t thunkDataMappingCount =
        (size_t)(blockCount / thunkBlocksPerMapping);
    if (thunkDataMappingCount == 0 ||
        thunkDataMappingSize > SIZE_MAX / thunkDataMappingCount)
    {
        return E_FAIL;
    }

    size_t thunkDataSize = thunkDataMappingSize * thunkDataMappingCount;
    if (nextThunkDataMapping < 0 ||
        (size_t)nextThunkDataMapping >= thunkDataMappingCount)
    {
        return E_FAIL;
    }

    if (g_pThunkStubData == NULL)
    {
        g_pThunkStubData = (uintptr_t)VirtualAlloc(NULL, thunkDataSize, MEM_RESERVE, PAGE_READWRITE);

        if (g_pThunkStubData == NULL)
        {
            return E_OUTOFMEMORY;
        }
    }

    size_t blockOffset = thunkDataMappingSize * (size_t)nextThunkDataMapping;
    void* pThunkDataBlock = (int8_t*)g_pThunkStubData + blockOffset;

    if (VirtualAlloc(pThunkDataBlock, thunkDataMappingSize, MEM_COMMIT, PAGE_READWRITE) == NULL)
    {
        return E_OUTOFMEMORY;
    }

    void* pThunks = RhpGetThunkStubsBlockAddress(pThunkDataBlock);
    if (pThunks == NULL || RhpGetThunkDataBlockAddress(pThunks) != pThunkDataBlock)
    {
        VirtualFree(pThunkDataBlock, thunkDataMappingSize, MEM_DECOMMIT);
        return E_FAIL;
    }

    nextThunkDataMapping++;
    *ppThunksSection = pThunks;
    return S_OK;
}

#else // FEATURE_FIXED_POOL_THUNKS

FCDECL0(void*, RhpGetThunksBase);
FCDECL0(int, RhpGetNumThunkBlocksPerMapping);
FCDECL0(int, RhpGetNumThunksPerBlock);
FCDECL0(int, RhpGetThunkSize);
FCDECL0(int, RhpGetThunkBlockSize);

EXTERN_C HRESULT QCALLTYPE RhAllocateThunksMapping(void** ppThunksSection)
{
    if (ppThunksSection == NULL)
    {
        return E_INVALIDARG;
    }
    *ppThunksSection = NULL;

    static void* pThunksTemplateAddress = NULL;

    void *pThunkMap = NULL;

    int thunkBlocksPerMapping = RhpGetNumThunkBlocksPerMapping();
    int thunkBlockSize = RhpGetThunkBlockSize();
    if (thunkBlocksPerMapping <= 0 || thunkBlockSize <= 0 ||
        (size_t)thunkBlocksPerMapping > SIZE_MAX / (size_t)thunkBlockSize)
    {
        return E_FAIL;
    }
    size_t templateSize = (size_t)thunkBlocksPerMapping * (size_t)thunkBlockSize;

#ifndef TARGET_APPLE // Apple platforms cannot use the initial template
    if (pThunksTemplateAddress == NULL)
    {
        // First, we use the thunks directly from the thunks template sections in the module until all
        // thunks in that template are used up.
        pThunksTemplateAddress = RhpGetThunksBase();
        pThunkMap = pThunksTemplateAddress;
    }
    else
#endif
    {
        // We've already used the thunks template in the module for some previous thunks, and we
        // cannot reuse it here. Now we need to create a new mapping of the thunks section in order to have
        // more thunks

        uint8_t* pThunkTemplate = (uint8_t*)RhpGetThunksBase();
        if (pThunkTemplate == NULL)
        {
            return E_FAIL;
        }
        uint8_t* pModuleBase = (uint8_t*)PalGetModuleHandleFromPointer(pThunkTemplate);
        uintptr_t thunkAddress = (uintptr_t)pThunkTemplate;
        uintptr_t moduleAddress = (uintptr_t)pModuleBase;
        if (pModuleBase == NULL || thunkAddress < moduleAddress ||
            thunkAddress - moduleAddress > UINT32_MAX)
        {
            return E_FAIL;
        }
        uint32_t templateRva = (uint32_t)(thunkAddress - moduleAddress);

        if (!PalAllocateThunksFromTemplate((HANDLE)pModuleBase, templateRva, templateSize, &pThunkMap))
            return E_OUTOFMEMORY;
    }

    if (!PalMarkThunksAsValidCallTargets(
        pThunkMap,
        RhpGetThunkSize(),
        RhpGetNumThunksPerBlock(),
        thunkBlockSize,
        thunkBlocksPerMapping))
    {
        if (pThunkMap != pThunksTemplateAddress)
            PalFreeThunksFromTemplate(pThunkMap, templateSize);

        return E_FAIL;
    }

    *ppThunksSection = pThunkMap;
    return S_OK;
}

#endif // FEATURE_RX_THUNKS
