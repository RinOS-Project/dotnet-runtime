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

#include <limits.h>
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

static bool IsValidThunkPageGeometry()
{
    const size_t pageSize = (size_t)OS_PAGE_SIZE;
    const size_t mappingSize = (size_t)THUNKS_MAP_SIZE;

    return pageSize != 0 && (pageSize & (pageSize - 1)) == 0 &&
        mappingSize != 0 && mappingSize % pageSize == 0 &&
        mappingSize <= (size_t)UINTPTR_MAX;
}

/*
 * Several thunk encodings place an immediate after a one- or three-byte
 * opcode.  Do not write those fields through a typed pointer: the x64 thunk
 * stores an eight-byte address at offset 2 and a four-byte displacement at
 * offset 13, neither of which is naturally aligned.  memcpy is the portable
 * object-representation write and keeps the code generator valid under the
 * RinOS strict-alignment contract before the code half is published RX.
 */
static bool CanWriteThunkBytes(uint8_t* cursor, uint8_t* end, size_t size)
{
    if (cursor == nullptr || end == nullptr || cursor > end)
        return false;
    return size <= (size_t)(end - cursor);
}

template <typename T>
static bool WriteThunkValue(uint8_t*& cursor, uint8_t* end, const T& value)
{
    if (!CanWriteThunkBytes(cursor, end, sizeof(value)))
        return false;
    memcpy(cursor, &value, sizeof(value));
    cursor += sizeof(value);
    return true;
}

static bool WriteThunkPointer(uint8_t*& cursor, uint8_t* end, void* value)
{
    if (!CanWriteThunkBytes(cursor, end, sizeof(value)))
        return false;
    memcpy(cursor, &value, sizeof(value));
    cursor += sizeof(value);
    return true;
}

static bool WriteThunkBytes(uint8_t*& cursor, uint8_t* end,
                            const void* value, size_t size)
{
    if (!CanWriteThunkBytes(cursor, end, size))
        return false;
    memcpy(cursor, value, size);
    cursor += size;
    return true;
}

static bool WriteThunkByte(uint8_t*& cursor, uint8_t* end, uint8_t value)
{
    if (!CanWriteThunkBytes(cursor, end, sizeof(value)))
        return false;
    *cursor++ = value;
    return true;
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
    if (!IsValidThunkPageGeometry())
        return 0;

    ASSERT_MSG((THUNKS_MAP_SIZE % OS_PAGE_SIZE) == 0, "Thunks map size should be in multiples of pages");

    const size_t blockCount = THUNKS_MAP_SIZE / OS_PAGE_SIZE;
    return blockCount > (size_t)INT_MAX ? 0 : (int)blockCount;
}
FCIMPLEND

FCIMPL0(int, RhpGetNumThunksPerBlock)
{
    if (!IsValidThunkPageGeometry() || POINTER_SIZE == 0 || THUNK_SIZE == 0 ||
        OS_PAGE_SIZE < POINTER_SIZE || POINTER_SIZE > SIZE_MAX / 2)
        return 0;

    const size_t codeCapacity = OS_PAGE_SIZE / THUNK_SIZE;
    const size_t dataCapacity =
        (OS_PAGE_SIZE - POINTER_SIZE) / (POINTER_SIZE * 2);
    const size_t thunkCount = min(codeCapacity, dataCapacity);
    return thunkCount > (size_t)INT_MAX ? 0 : (int)thunkCount;
}
FCIMPLEND

FCIMPL0(int, RhpGetThunkSize)
{
    // RuntimeImports exposes this geometry as an int.  Keep the conversion
    // failure-closed so an unsupported architecture or malformed page-size
    // provider cannot wrap into a small positive thunk size.
    return (size_t)THUNK_SIZE > (size_t)INT_MAX ? 0 : (int)THUNK_SIZE;
}
FCIMPLEND

FCIMPL1(void*, RhpGetThunkDataBlockAddress, void* pThunkStubAddress)
{
    if (pThunkStubAddress == NULL || !IsValidThunkPageGeometry())
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
    if (pThunkDataAddress == NULL || !IsValidThunkPageGeometry())
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
    // The managed thunk pool consumes this through an int ABI.  Do not let a
    // provider page size wrap before the caller validates the geometry.
    if (!IsValidThunkPageGeometry())
        return 0;
    return (size_t)OS_PAGE_SIZE > (size_t)INT_MAX ? 0 : (int)OS_PAGE_SIZE;
}
FCIMPLEND

EXTERN_C HRESULT QCALLTYPE RhAllocateThunksMapping(void** ppThunksSection)
{
    if (ppThunksSection == NULL)
    {
        return E_INVALIDARG;
    }
    *ppThunksSection = NULL;

    if (!IsValidThunkPageGeometry())
        return E_FAIL;

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
            uint8_t* const thunkEndAddress = pCurrentThunkAddress + THUNK_SIZE;
            uint8_t* pCurrentDataAddress = pDataBlockAddress + thunkDataOffset;
            bool thunkWriteOk = true;

#ifdef TARGET_AMD64

            // mov r10,<thunk data address>
            // jmp [r10 + <delta to get to last qword in data page]

            thunkWriteOk = WriteThunkValue(
                pCurrentThunkAddress, thunkEndAddress, (uint16_t)0xba49);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkPointer(
                    pCurrentThunkAddress, thunkEndAddress,
                    (void*)pCurrentDataAddress);
            const uint32_t indirectJump = 0x00a2ff41;
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkBytes(
                    pCurrentThunkAddress, thunkEndAddress, &indirectJump, 3);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                    (uint32_t)(OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset));

            // nops for alignment
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkByte(
                    pCurrentThunkAddress, thunkEndAddress, 0x90);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkByte(
                    pCurrentThunkAddress, thunkEndAddress, 0x90);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkByte(
                    pCurrentThunkAddress, thunkEndAddress, 0x90);

#elif TARGET_X86

            // mov eax,<thunk data address>
            // jmp [eax + <delta to get to last dword in data page]

            thunkWriteOk = WriteThunkByte(
                pCurrentThunkAddress, thunkEndAddress, 0xb8);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkPointer(
                    pCurrentThunkAddress, thunkEndAddress,
                    (void*)pCurrentDataAddress);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress, (uint16_t)0xa0ff);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                    (uint32_t)(OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset));

            // nops for alignment
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkByte(
                    pCurrentThunkAddress, thunkEndAddress, 0x90);

#elif TARGET_ARM

            // mov r12,<thunk data address>
            // ldr pc,[r12, <delta to get to last dword in data page>]
            // r12 retains data address; RhCommonStub reads it directly without stack

            uint16_t movInstructions[4];
            EncodeThumb2Mov32(movInstructions, (uint32_t)pCurrentDataAddress, 12);
            thunkWriteOk = WriteThunkBytes(
                pCurrentThunkAddress, thunkEndAddress,
                movInstructions, sizeof(movInstructions));

            // ldr pc, [r12, #offset]
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                    (uint32_t)(0xf000f8dc |
                               ((OS_PAGE_SIZE - POINTER_SIZE -
                                 thunkDataOffset) << 16)));

#elif TARGET_ARM64

            //adr      xip0, <delta PC to thunk data address>
            //ldr      xip1, [xip0, <delta to get to last qword in data page>]
            //br       xip1
            //brk      0xf000 //Stubs need to be 16 byte aligned therefore we fill with a break here

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            thunkWriteOk = WriteThunkValue(
                pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x10000010 |
                           (((delta & 0x03) << 29) |
                            (((delta & 0x1FFFFC) >> 2) << 5))));

            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0xF9400211 |
                           (((uint32_t)((OS_PAGE_SIZE - POINTER_SIZE -
                                         thunkDataOffset) /
                                        8)
                             << 10))));
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress, (uint32_t)0xD61F0220);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress, (uint32_t)0xD43E0000);

#elif TARGET_LOONGARCH64

            //pcaddi    $t7, <delta PC to thunk data address>
            //pcaddi    $t8, -
            //ld.d      $t8, $t8, <delta to get to last qword in data page>
            //jirl      $r0, $t8, 0

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            ASSERT((-0x200000 <= delta) && (delta < 0x200000));

            thunkWriteOk = WriteThunkValue(
                pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x18000013 |
                           (((delta & 0x3FFFFC) >> 2) << 5)));

            delta += OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset - 4;
            ASSERT((-0x200000 <= delta) && (delta < 0x200000));

            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x18000014 |
                           (((delta & 0x3FFFFC) >> 2) << 5)));
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress, (uint32_t)0x28C00294);
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress, (uint32_t)0x4C000280);

#elif defined(TARGET_RISCV64)

            //auipc    t1, hi(<delta PC to thunk data address>)
            //addi     t1, t1, lo(<delta PC to thunk data address>)
            //auipc    t0, hi(<delta to get to last word in data page>)
            //ld       t0, (t0)
            //jalr     zero, t0, 0

            int delta = (int)(pCurrentDataAddress - pCurrentThunkAddress);
            thunkWriteOk = WriteThunkValue(
                pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x00000317 |
                           ((((delta + 0x800) & 0xFFFFF000) >> 12) << 12)));  // auipc t1, delta[31:12]
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x00030313 | ((delta & 0xFFF) << 20)));  // addi t1, t1, delta[11:0]

            delta += OS_PAGE_SIZE - POINTER_SIZE - thunkDataOffset - 8;
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x00000297 |
                           ((((delta + 0x800) & 0xFFFFF000) >> 12) << 12)));  // auipc t0, delta[31:12]
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                (uint32_t)(0x0002b283 | ((delta & 0xFFF) << 20))); // ld t0, (delta[11:0])(t0)
            if (thunkWriteOk)
                thunkWriteOk = WriteThunkValue(
                    pCurrentThunkAddress, thunkEndAddress,
                    (uint32_t)0x00008282);  // jalr zero, t0, 0

#else
            UNREFERENCED_PARAMETER(pCurrentDataAddress);
            UNREFERENCED_PARAMETER(pCurrentThunkAddress);
            PORTABILITY_ASSERT("RhAllocateThunksMapping");
#endif

            // Keep each generated entry inside its declared slot.  This is a
            // runtime guard against an architecture encoder drifting past
            // THUNK_SIZE and corrupting the adjacent thunk/data page.
            if (!thunkWriteOk || pCurrentThunkAddress != thunkEndAddress)
            {
                PalVirtualFree(pNewMapping, mappingSize);
                return E_FAIL;
            }
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
        PalVirtualFree(pNewMapping, mappingSize);
        return E_FAIL;
    }
#endif

    PalFlushInstructionCache(pThunksSection, thunksMapSize);

    *ppThunksSection = pThunksSection;
    return S_OK;
}

EXTERN_C HRESULT QCALLTYPE RhFreeThunksMapping(void* pThunksSection)
{
    if (pThunksSection == NULL || !IsValidThunkPageGeometry() ||
        ((uintptr_t)pThunksSection % (uintptr_t)OS_PAGE_SIZE) != 0 ||
        THUNKS_MAP_SIZE > SIZE_MAX / 2)
    {
        return E_INVALIDARG;
    }

    return PalVirtualFreeChecked(
        pThunksSection, (uintptr_t)THUNKS_MAP_SIZE * 2u) ? S_OK : E_FAIL;
}

// FEATURE_RX_THUNKS
#elif FEATURE_FIXED_POOL_THUNKS
// This is used by the thunk code to find the stub data for the called thunk slot
extern "C" uintptr_t g_pThunkStubData;
uintptr_t g_pThunkStubData = NULL;
static size_t g_thunkStubDataSize = 0;

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

        g_thunkStubDataSize = thunkDataSize;
    }
    else if (g_thunkStubDataSize != thunkDataSize)
    {
        // The fixed-pool geometry is process-wide.  A provider that changes
        // its block count or size after reservation cannot safely address the
        // existing pool with the new layout.
        return E_FAIL;
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

EXTERN_C HRESULT QCALLTYPE RhFreeThunksMapping(void* pThunksSection)
{
    if (pThunksSection == NULL)
    {
        return E_INVALIDARG;
    }

    int thunkBlocksPerMapping = RhpGetNumThunkBlocksPerMapping();
    int thunkBlockSize = RhpGetThunkBlockSize();
    int blockCount = RhpGetThunkBlockCount();
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

    void* pThunkDataBlock = RhpGetThunkDataBlockAddress(pThunksSection);
    if (pThunkDataBlock == NULL ||
        RhpGetThunkStubsBlockAddress(pThunkDataBlock) != pThunksSection)
    {
        return E_INVALIDARG;
    }

    // The address helpers only describe the fixed-pool layout; they do not
    // prove that the caller supplied a block from this process's reservation.
    // Validate the derived data page against the exact reserved range before
    // passing it to VirtualFree.  This prevents a foreign, page-aligned pair
    // that happens to satisfy the reversible helper relation from becoming a
    // decommit request against unrelated memory.
    if (g_pThunkStubData == 0 || g_thunkStubDataSize == 0 ||
        g_thunkStubDataSize != thunkDataSize)
    {
        return E_INVALIDARG;
    }

    const uintptr_t poolBegin = g_pThunkStubData;
    const uintptr_t dataBegin = (uintptr_t)pThunkDataBlock;
    if (dataBegin < poolBegin ||
        dataBegin - poolBegin >= g_thunkStubDataSize ||
        (dataBegin - poolBegin) % thunkDataMappingSize != 0 ||
        thunkDataMappingSize > g_thunkStubDataSize - (dataBegin - poolBegin))
    {
        return E_INVALIDARG;
    }

    // The fixed pool reserves the complete address range once, then commits
    // each data mapping independently.  Release exactly that committed data
    // range; the process-wide reservation remains available for the pool's
    // monotonic allocator and is not accidentally torn down here.
    return VirtualFree(pThunkDataBlock, thunkDataMappingSize, MEM_DECOMMIT)
               ? S_OK
               : E_FAIL;
}

#else // FEATURE_FIXED_POOL_THUNKS

FCDECL0(void*, RhpGetThunksBase);
FCDECL0(int, RhpGetNumThunkBlocksPerMapping);
FCDECL0(int, RhpGetNumThunksPerBlock);
FCDECL0(int, RhpGetThunkSize);
FCDECL0(int, RhpGetThunkBlockSize);

static void* g_pThunksTemplateAddress = NULL;

EXTERN_C HRESULT QCALLTYPE RhAllocateThunksMapping(void** ppThunksSection)
{
    if (ppThunksSection == NULL)
    {
        return E_INVALIDARG;
    }
    *ppThunksSection = NULL;

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
    if (g_pThunksTemplateAddress == NULL)
    {
        // First, we use the thunks directly from the thunks template sections in the module until all
        // thunks in that template are used up.
        g_pThunksTemplateAddress = RhpGetThunksBase();
        pThunkMap = g_pThunksTemplateAddress;
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
        if (pThunkMap != g_pThunksTemplateAddress)
            PalFreeThunksFromTemplate(pThunkMap, templateSize);

        return E_FAIL;
    }

    *ppThunksSection = pThunkMap;
    return S_OK;
}

EXTERN_C HRESULT QCALLTYPE RhFreeThunksMapping(void* pThunksSection)
{
    if (pThunksSection == NULL)
    {
        return E_INVALIDARG;
    }

    int thunkBlocksPerMapping = RhpGetNumThunkBlocksPerMapping();
    int thunkBlockSize = RhpGetThunkBlockSize();
    if (thunkBlocksPerMapping <= 0 || thunkBlockSize <= 0 ||
        (size_t)thunkBlocksPerMapping > SIZE_MAX / (size_t)thunkBlockSize ||
        OS_PAGE_SIZE == 0)
    {
        return E_FAIL;
    }
    size_t templateSize = (size_t)thunkBlocksPerMapping *
                          (size_t)thunkBlockSize;
    if (templateSize == 0 || templateSize % OS_PAGE_SIZE != 0 ||
        ((uintptr_t)pThunksSection % OS_PAGE_SIZE) != 0)
    {
        return E_INVALIDARG;
    }

    // The first mapping is the image-owned template and must remain live for
    // the module lifetime.  Dynamically copied mappings are independent and
    // can use the same PAL release operation as allocation failure cleanup.
    if (pThunksSection == g_pThunksTemplateAddress)
    {
        return E_NOTIMPL;
    }

    return PalFreeThunksFromTemplate(pThunksSection, templateSize)
               ? S_OK
               : E_FAIL;
}

#endif // FEATURE_RX_THUNKS
