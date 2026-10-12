// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

//
// This is an implementation of a general purpose thunk pool manager. Each thunk consists of:
//      1- A thunk stub, typically consisting of a lea + jmp instructions (slightly different
//         on ARM, but semantically equivalent)
//      2- A thunk common stub: the implementation of the common stub depends on
//         the usage scenario of the thunk
//      3- Thunk data: each thunk has two pointer-sized data values that can be stored.
//         The first data value is called the thunk's 'context', and the second value is
//         the thunk's jump target typically.
//
// Without FEATURE_RX_THUNKS, thunks are allocated by mapping a thunks template into memory. The template
// consists of a number of pairs of sections called thunk blocks (typically 8 pairs per mapping). Each pair
// has 2 page-long sections (4096 bytes):
//      1- The first section has RX permissions, and contains the thunk stubs (lea's + jmp's),
//         and the thunk common stubs.
//      2- The second section has RW permissions and contains the thunks data (context + target).
//         The last pointer-sized block in this section is special: it stores the address of
//         the common stub that each thunk stub will jump to (the jump instruction in each thunk
//         jumps to the address stored in that block). Therefore, whenever a new thunks template
//         gets mapped into memory, the value of that last pointer cell in the data section is updated
//         to the common stub address passed in by the caller
//
// With FEATURE_RX_THUNKS, thunks are created by allocating new virtual memory space, where the first half of
// that space is filled with thunk stubs, and gets RX permissions, and the second half is for the thunks data,
// and gets RW permissions. The thunk stubs and data blocks are not grouped in pairs:
// all the thunk stubs blocks are groupped at the beginning of the allocated virtual memory space, and all the
// thunk data blocks are groupped in the second half of the virtual space.
//
// Available thunks are tracked using a linked list. The first cell in the data block of each thunk is
// used as the nodes of the linked list. The cell will point to the data block of the next available thunk,
// if one is available, or point to null. When thunks are freed, they are added to the beginning of the list.
//

using System.Diagnostics;
using System.Numerics;
using System.Threading;

namespace System.Runtime
{
    internal static class Constants
    {
        private static int RequirePositive(int value)
        {
            if (value <= 0)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return value;
        }

        private static uint ComputePageSize()
        {
            ulong codeBytes = (ulong)ThunkCodeSize * (ulong)NumThunksPerBlock;
            ulong dataBytes = (ulong)ThunkDataSize * (ulong)NumThunksPerBlock + (ulong)IntPtr.Size;
            ulong required = Math.Max(codeBytes, dataBytes);
            if (required == 0 || required > int.MaxValue)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            uint pageSize = BitOperations.RoundUpToPowerOf2((uint)required);
            if (pageSize == 0)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return pageSize;
        }

        private static nuint ComputeSpan(int elementSize, int elementCount, int extra)
        {
            ulong span = (ulong)elementSize * (ulong)elementCount + (ulong)extra;
            if (span == 0 || span > (ulong)nuint.MaxValue)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return (nuint)span;
        }

        private static uint ValidatePageAndBlockSize(uint pageSize)
        {
            // The native address helpers use the same page boundary for the
            // code/data halves and the managed pool uses ThunkBlockSize to
            // walk blocks in a mapping.  A provider that reports different
            // values would make those two address calculations disagree.
            if (pageSize == 0 || (uint)ThunkBlockSize != pageSize)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return pageSize;
        }

        internal static IntPtr AddOffsetChecked(IntPtr address, nuint offset)
        {
            nuint value = (nuint)(nint)address;
            if (value > nuint.MaxValue - offset)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return (IntPtr)(nint)(value + offset);
        }

        public static readonly int ThunkDataSize = 2 * IntPtr.Size;
        public static readonly int ThunkCodeSize = RequirePositive(RuntimeImports.RhpGetThunkSize());
        public static readonly int NumThunksPerBlock = RequirePositive(RuntimeImports.RhpGetNumThunksPerBlock());
        public static readonly int NumThunkBlocksPerMapping = RequirePositive(RuntimeImports.RhpGetNumThunkBlocksPerMapping());
        public static readonly int ThunkBlockSize = RequirePositive(RuntimeImports.RhpGetThunkBlockSize());
        public static readonly uint PageSize = ValidatePageAndBlockSize(ComputePageSize());
        public static readonly nuint PageSizeMask = PageSize - 1;
        public static readonly nuint ThunkCodeSpan = ComputeSpan(ThunkCodeSize, NumThunksPerBlock, 0);
        public static readonly nuint ThunkDataSpan = ComputeSpan(ThunkDataSize, NumThunksPerBlock, 0);
        public static readonly nuint MappingSpan = ComputeSpan(ThunkBlockSize, NumThunkBlocksPerMapping, 0);
    }

    internal class ThunksHeap
    {
        private class AllocatedBlock
        {
            internal IntPtr _blockBaseAddress;
            internal IntPtr _dataBlockAddress;
            internal AllocatedBlock _nextBlock;
        }

        private IntPtr _commonStubAddress;
        private IntPtr _nextAvailableThunkPtr;
        // Every free thunk stores its list link in the first data cell. Keep
        // a bounded count so stale-list validation cannot loop forever.
        private nuint _freeThunkCount;

        private AllocatedBlock _allocatedBlocks;

        // Helper functions to set/clear the lowest bit for ARM instruction pointers
        private static IntPtr ClearThumbBit(IntPtr value)
        {
#if TARGET_ARM
            Debug.Assert(((nint)value & 1) == 1);
            value = (IntPtr)((nint)value - 1);
#endif
            return value;
        }
        private static IntPtr SetThumbBit(IntPtr value)
        {
#if TARGET_ARM
            Debug.Assert(((nint)value & 1) == 0);
            value = (IntPtr)((nint)value + 1);
#endif
            return value;
        }

        private static IntPtr GetValidatedThunkDataBlockAddress(IntPtr thunkStubsBlock)
        {
            IntPtr thunkDataBlock = RuntimeImports.RhpGetThunkDataBlockAddress(thunkStubsBlock);
            if (thunkDataBlock == IntPtr.Zero ||
                ((nuint)(nint)thunkDataBlock & Constants.PageSizeMask) != 0 ||
                RuntimeImports.RhpGetThunkStubsBlockAddress(thunkDataBlock) != thunkStubsBlock)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            return thunkDataBlock;
        }

        private unsafe ThunksHeap(IntPtr commonStubAddress)
        {
            if (commonStubAddress == IntPtr.Zero)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            _commonStubAddress = commonStubAddress;

            _allocatedBlocks = new AllocatedBlock();

            IntPtr thunkStubsBlock = ThunkBlocks.GetNewThunksBlock();
            IntPtr thunkDataBlock = GetValidatedThunkDataBlockAddress(thunkStubsBlock);

            // Address of the first thunk data cell should be at the beginning of the thunks data block (page-aligned)
            Debug.Assert(((nuint)(nint)thunkDataBlock % Constants.PageSize) == 0);

            // Update the last pointer value in the thunks data section with the value of the common stub address
            *(IntPtr*)(thunkDataBlock + (int)(Constants.PageSize - IntPtr.Size)) = commonStubAddress;
            Debug.Assert(*(IntPtr*)(thunkDataBlock + (int)(Constants.PageSize - IntPtr.Size)) == commonStubAddress);

            // Set the head and end of the linked list
            _nextAvailableThunkPtr = thunkDataBlock;
            _freeThunkCount = (nuint)Constants.NumThunksPerBlock;

            _allocatedBlocks._blockBaseAddress = thunkStubsBlock;
            _allocatedBlocks._dataBlockAddress = thunkDataBlock;
        }

        public static unsafe ThunksHeap CreateThunksHeap(IntPtr commonStubAddress)
        {
            return new ThunksHeap(commonStubAddress);
        }

        // TODO: Feature
        // public static ThunksHeap DestroyThunksHeap(ThunksHeap heapToDestroy)
        // {
        // }

        //
        // Note: Expected to be called under lock
        //
        private unsafe void ExpandHeap(IntPtr freeListTail)
        {
            nuint addedFreeThunks = (nuint)Constants.NumThunksPerBlock;
            if (_freeThunkCount > nuint.MaxValue - addedFreeThunks)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            // The mapping's physical last cell is not necessarily the free-list
            // tail: an earlier cell can be the only remaining free thunk after
            // later cells have been allocated.  Link through the actual free
            // tail, otherwise an expansion can overwrite an allocated thunk's
            // context field.
            if (freeListTail == IntPtr.Zero ||
                !IsThunkDataInHeap(freeListTail) ||
                *((IntPtr*)freeListTail) != IntPtr.Zero)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            AllocatedBlock newBlockInfo = new AllocatedBlock();

            IntPtr thunkStubsBlock = ThunkBlocks.GetNewThunksBlock();
            IntPtr thunkDataBlock = GetValidatedThunkDataBlockAddress(thunkStubsBlock);

            // Address of the first thunk data cell should be at the beginning of the thunks data block (page-aligned)
            Debug.Assert(((nuint)(nint)thunkDataBlock % Constants.PageSize) == 0);

            // Update the last pointer value in the thunks data section with the value of the common stub address
            *(IntPtr*)(thunkDataBlock + (int)(Constants.PageSize - IntPtr.Size)) = _commonStubAddress;
            Debug.Assert(*(IntPtr*)(thunkDataBlock + (int)(Constants.PageSize - IntPtr.Size)) == _commonStubAddress);

            // Link the actual free-list tail to the first entry in the new list.
            // Do not write through the physical last cell of the old mapping:
            // that cell may already hold an allocated thunk's context.
            *((IntPtr*)freeListTail) = thunkDataBlock;

            newBlockInfo._blockBaseAddress = thunkStubsBlock;
            newBlockInfo._dataBlockAddress = thunkDataBlock;
            newBlockInfo._nextBlock = _allocatedBlocks;

            _allocatedBlocks = newBlockInfo;
            _freeThunkCount += addedFreeThunks;
        }

        public unsafe IntPtr AllocateThunk()
        {
            // TODO: optimize the implementation and make it lock-free
            // or at least change it to a per-heap lock instead of a global lock.

            Debug.Assert(_nextAvailableThunkPtr != IntPtr.Zero);

            IntPtr nextAvailableThunkPtr;
            IntPtr thunkAddress;
            lock (this)
            {
                if (_nextAvailableThunkPtr == IntPtr.Zero ||
                    _freeThunkCount == 0)
                {
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
                }

                // The free-list links live in writable thunk data. Validate
                // the current node before dereferencing it and validate the
                // successor before publishing the mutation. A malformed
                // provider mapping or corrupted link must not consume a
                // free-list entry and leave the heap partially advanced.
                if (!IsThunkDataInHeap(_nextAvailableThunkPtr))
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

                nextAvailableThunkPtr = _nextAvailableThunkPtr;
                // Resolve the executable address before ExpandHeap can map a
                // new section. A malformed current node must not allocate a
                // section and then fail with a half-advanced heap.
                thunkAddress = GetThunkAddressFromDataAddress(nextAvailableThunkPtr);
                IntPtr nextNextAvailableThunkPtr = *((IntPtr*)(nextAvailableThunkPtr));

                if (nextNextAvailableThunkPtr == IntPtr.Zero)
                {
                    ExpandHeap(nextAvailableThunkPtr);

                    nextAvailableThunkPtr = _nextAvailableThunkPtr;
                    nextNextAvailableThunkPtr = *((IntPtr*)(nextAvailableThunkPtr));
                    Debug.Assert(nextNextAvailableThunkPtr != IntPtr.Zero);
                }

                if (!IsThunkDataInHeap(nextNextAvailableThunkPtr))
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

                _nextAvailableThunkPtr = nextNextAvailableThunkPtr;
                --_freeThunkCount;
            }
            Debug.Assert(nextAvailableThunkPtr != IntPtr.Zero);

#if DEBUG
            // Reset debug flag indicating the thunk is now in use
            *((IntPtr*)(nextAvailableThunkPtr + IntPtr.Size)) = IntPtr.Zero;
#endif

            return SetThumbBit(thunkAddress);
        }

        public unsafe void FreeThunk(IntPtr thunkAddress)
        {
            // TODO: optimize the implementation and make it lock-free
            // or at least change it to a per-heap lock instead of a global lock.

            lock (this)
            {
                // Keep address derivation and ownership validation under the
                // same lock as the free-list mutation.  Otherwise a stale
                // caller can race with free-then-reallocate and release a
                // newly allocated thunk at the same address (an ABA window).
                IntPtr dataAddress = TryGetThunkDataAddress(thunkAddress);
                if (dataAddress == IntPtr.Zero || !IsThunkInHeap(thunkAddress))
                {
                    // FreeThunk is an internal runtime primitive.  A malformed or
                    // stale address must not let the release build write a linked
                    // list pointer into an unrelated writable page.
                    return;
                }

                // Cleanup paths can call FreeThunk more than once. Do not
                // put an already-free cell back at the head: that would make
                // the free list self-loop and return one executable thunk
                // repeatedly from later allocations.
                if (IsFreeThunkDataAddress(dataAddress))
                    return;
                if (_freeThunkCount == nuint.MaxValue)
                    return;

#if DEBUG
                Debug.Assert(IsThunkInHeap(thunkAddress));

                // Debug flag indicating the thunk is no longer used
                *((IntPtr*)(dataAddress + IntPtr.Size)) = new IntPtr(-1);
#endif

                *((IntPtr*)(dataAddress)) = _nextAvailableThunkPtr;
                _nextAvailableThunkPtr = dataAddress;
                ++_freeThunkCount;
            }
        }

        // Must be called while holding this heap's lock. The traversal is
        // bounded by _freeThunkCount, so a malformed link cannot turn stale
        // input into an unbounded loop.
        private unsafe bool IsFreeThunkDataAddress(IntPtr dataAddress)
        {
            IntPtr current = _nextAvailableThunkPtr;
            nuint remaining = _freeThunkCount;
            while (remaining != 0)
            {
                if (current == IntPtr.Zero)
                    return false;
                if (current == dataAddress)
                    return true;
                current = *((IntPtr*)current);
                --remaining;
            }

            return false;
        }

        private AllocatedBlock GetAllocatedBlockForThunkAddress(IntPtr thunkAddress)
        {
            nuint thunkAddressValue = (nuint)(nint)ClearThumbBit(thunkAddress);

            AllocatedBlock currentBlock = _allocatedBlocks;

            while (currentBlock != null)
            {
                nuint blockBaseAddress = (nuint)(nint)currentBlock._blockBaseAddress;
                if (blockBaseAddress <= nuint.MaxValue - Constants.ThunkCodeSpan &&
                    thunkAddressValue >= blockBaseAddress &&
                    thunkAddressValue < blockBaseAddress + Constants.ThunkCodeSpan)
                {
                    return currentBlock;
                }

                currentBlock = currentBlock._nextBlock;
            }

            return null;
        }

        private bool IsThunkInHeap(IntPtr thunkAddress)
        {
            return GetAllocatedBlockForThunkAddress(thunkAddress) != null;
        }

        private AllocatedBlock GetAllocatedBlockForThunkDataAddress(IntPtr dataAddress)
        {
            nuint dataAddressValue = (nuint)(nint)dataAddress;
            if (dataAddressValue == 0)
                return null;

            AllocatedBlock currentBlock = _allocatedBlocks;
            while (currentBlock != null)
            {
                nuint dataBlockAddress = (nuint)(nint)currentBlock._dataBlockAddress;
                if (dataBlockAddress != 0 &&
                    dataBlockAddress % Constants.PageSize == 0 &&
                    dataBlockAddress <= nuint.MaxValue - Constants.ThunkDataSpan &&
                    dataAddressValue >= dataBlockAddress &&
                    dataAddressValue < dataBlockAddress + Constants.ThunkDataSpan &&
                    (dataAddressValue - dataBlockAddress) %
                        (nuint)Constants.ThunkDataSize == 0)
                {
                    return currentBlock;
                }

                currentBlock = currentBlock._nextBlock;
            }

            return null;
        }

        private bool IsThunkDataInHeap(IntPtr dataAddress)
        {
            return GetAllocatedBlockForThunkDataAddress(dataAddress) != null;
        }

        private unsafe IntPtr GetThunkAddressFromDataAddress(IntPtr dataAddress)
        {
            AllocatedBlock block = GetAllocatedBlockForThunkDataAddress(dataAddress);
            if (block == null)
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

            nuint dataAddressValue = (nuint)(nint)dataAddress;
            nuint dataBlockAddress = (nuint)(nint)block._dataBlockAddress;
            nuint dataPageOffset = dataAddressValue - dataBlockAddress;
            if (dataPageOffset % (nuint)Constants.ThunkDataSize != 0)
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            nuint thunkIndexValue = dataPageOffset / (nuint)Constants.ThunkDataSize;
            if (thunkIndexValue >= (nuint)Constants.NumThunksPerBlock)
            {
                // The final cell in a data page stores the common stub address;
                // it is not an allocatable thunk node.  Do not turn a malformed
                // free-list value into an executable thunk address.
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            nuint codeOffset = thunkIndexValue * (nuint)Constants.ThunkCodeSize;
            nuint thunkStubsBlockAddress = (nuint)(nint)block._blockBaseAddress;
            if (thunkStubsBlockAddress == 0 ||
                thunkStubsBlockAddress > nuint.MaxValue - codeOffset)
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

            IntPtr thunkAddress = (IntPtr)(nint)(thunkStubsBlockAddress + codeOffset);
            if (thunkAddress == IntPtr.Zero)
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

            return thunkAddress;
        }

        private IntPtr TryGetThunkDataAddress(IntPtr thunkAddress)
        {
            nuint thunkAddressValue = (nuint)(nint)ClearThumbBit(thunkAddress);

            // Compute the base address of the thunk's mapping
            nuint currentThunksBlockAddress = thunkAddressValue & ~Constants.PageSizeMask;

            AllocatedBlock block = GetAllocatedBlockForThunkAddress(
                (IntPtr)(nint)thunkAddressValue);
            if (block == null)
                return IntPtr.Zero;

            // Make sure the thunk address is valid by checking alignment
            if ((thunkAddressValue - currentThunksBlockAddress) % (nuint)Constants.ThunkCodeSize != 0)
                return IntPtr.Zero;

            // Compute the thunk's index
            nuint codePageOffset = thunkAddressValue - currentThunksBlockAddress;
            nuint thunkIndexValue = codePageOffset / (nuint)Constants.ThunkCodeSize;
            if (thunkIndexValue >= (nuint)Constants.NumThunksPerBlock)
                return IntPtr.Zero;
            int thunkIndex = (int)thunkIndexValue;

            // Compute the address of the data block that corresponds to the current thunk
            IntPtr thunkDataBlockAddress = RuntimeImports.RhpGetThunkDataBlockAddress((IntPtr)((nint)thunkAddressValue));

            if (thunkDataBlockAddress == IntPtr.Zero)
                return IntPtr.Zero;

            nuint dataBlockValue = (nuint)(nint)thunkDataBlockAddress;
            if (dataBlockValue != (nuint)(nint)block._dataBlockAddress)
                return IntPtr.Zero;

            nuint dataOffset = (nuint)thunkIndex * (nuint)Constants.ThunkDataSize;
            if (dataBlockValue > nuint.MaxValue - dataOffset)
                return IntPtr.Zero;

            IntPtr dataAddress = (IntPtr)(nint)(dataBlockValue + dataOffset);
            if (!IsThunkDataInHeap(dataAddress))
                return IntPtr.Zero;

            return dataAddress;
        }

        /// <summary>
        /// This method retrieves the two data fields for a thunk.
        /// Invalid, foreign, and previously freed thunk addresses return false.
        /// </summary>
        /// <returns>True if the thunk's data was successfully retrieved.</returns>
        public unsafe bool TryGetThunkData(IntPtr thunkAddress, out IntPtr context, out IntPtr target)
        {
            context = IntPtr.Zero;
            target = IntPtr.Zero;

            lock (this)
            {
                // Derive and validate the data address while holding the heap
                // lock so a concurrent free/reallocate cannot turn a stale thunk handle
                // into an observation of a different allocation.
                IntPtr dataAddress = TryGetThunkDataAddress(thunkAddress);
                if (dataAddress == IntPtr.Zero ||
                    !IsThunkInHeap(thunkAddress) ||
                    IsFreeThunkDataAddress(dataAddress))
                    return false;

                // Do not interpret the first cell as context after the thunk
                // has been returned to the free list. The lock also keeps a
                // concurrent FreeThunk from changing that cell while reading.
                context = *((IntPtr*)(dataAddress));
                target = *((IntPtr*)(dataAddress + IntPtr.Size));
            }

            return true;
        }

        /// <summary>
        /// This method sets the two data fields for a thunk.
        /// Invalid, foreign, and previously freed thunk addresses fail closed
        /// with PlatformNotSupportedException.
        /// </summary>
        public unsafe void SetThunkData(IntPtr thunkAddress, IntPtr context, IntPtr target)
        {
            lock (this)
            {
                // Keep address derivation, ownership validation, and the write
                // atomic with respect to FreeThunk and AllocateThunk.  This prevents
                // an ABA reuse from redirecting a stale write.
                IntPtr dataAddress = TryGetThunkDataAddress(thunkAddress);
                if (dataAddress == IntPtr.Zero ||
                    !IsThunkInHeap(thunkAddress) ||
                    IsFreeThunkDataAddress(dataAddress))
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

                // Update the data that will be used by the thunk that was
                // allocated.
                *((IntPtr*)(dataAddress)) = context;
                *((IntPtr*)(dataAddress + IntPtr.Size)) = target;
            }
        }
    }

    internal static class ThunkBlocks
    {
        private static IntPtr[] s_currentlyMappedThunkBlocks = new IntPtr[Constants.NumThunkBlocksPerMapping];
        private static int s_currentlyMappedThunkBlocksIndex = Constants.NumThunkBlocksPerMapping;
        private static Lock s_lock = new Lock(useTrivialWaits: true);

        private static void ValidateThunkBlockPair(IntPtr thunksBlock, out IntPtr dataAddress)
        {
            // Validate the provider result before publishing the block into
            // the managed mapping cache. A malformed result must not leave a
            // bad block available to a later allocation attempt.
            if (thunksBlock == IntPtr.Zero ||
                ((nuint)(nint)thunksBlock & Constants.PageSizeMask) != 0)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }

            dataAddress = RuntimeImports.RhpGetThunkDataBlockAddress(thunksBlock);
            if (dataAddress == IntPtr.Zero ||
                ((nuint)(nint)dataAddress & Constants.PageSizeMask) != 0 ||
                RuntimeImports.RhpGetThunkStubsBlockAddress(dataAddress) != thunksBlock)
            {
                throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);
            }
        }

        public static unsafe IntPtr GetNewThunksBlock()
        {
            using Lock.Scope scope = s_lock.EnterScope();

            IntPtr nextThunksBlock;
            IntPtr dataAddress;

            // Check the most recently mapped thunks block. Each mapping consists of multiple
            // thunk stubs pages, and multiple thunk data pages (typically 8 pages of each in a single mapping)
            if (s_currentlyMappedThunkBlocksIndex < Constants.NumThunkBlocksPerMapping)
            {
                nextThunksBlock = s_currentlyMappedThunkBlocks[s_currentlyMappedThunkBlocksIndex];
                ValidateThunkBlockPair(nextThunksBlock, out dataAddress);
                s_currentlyMappedThunkBlocksIndex++;
#if DEBUG
                s_currentlyMappedThunkBlocks[s_currentlyMappedThunkBlocksIndex - 1] = IntPtr.Zero;
                Debug.Assert(nextThunksBlock != IntPtr.Zero);
#endif
            }
            else
            {
                nextThunksBlock = IntPtr.Zero;
                int result = RuntimeImports.RhAllocateThunksMapping(&nextThunksBlock);
                if (result == HResults.E_OUTOFMEMORY)
                    throw new OutOfMemoryException();
                else if (result != HResults.S_OK)
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_DynamicEntrypoint);

                ValidateThunkBlockPair(nextThunksBlock, out dataAddress);

                // Each mapping consists of multiple blocks of thunk stubs/data pairs. Keep track of those
                // so that we do not create a new mapping until all blocks in the sections we just mapped are consumed
                IntPtr currentThunksBlock = nextThunksBlock;
                for (int i = 0; i < Constants.NumThunkBlocksPerMapping; i++)
                {
                    s_currentlyMappedThunkBlocks[i] = currentThunksBlock;
                    currentThunksBlock = Constants.AddOffsetChecked(
                        currentThunksBlock, (nuint)Constants.ThunkBlockSize);
                }
                s_currentlyMappedThunkBlocksIndex = 1;
            }

            // Setup the thunks in the new block as a linked list of thunks.
            // Use the first data field of the thunk to build the linked list.

            for (int i = 0; i < Constants.NumThunksPerBlock; i++)
            {
                IntPtr nextDataAddress = Constants.AddOffsetChecked(
                    dataAddress, (nuint)Constants.ThunkDataSize);
                if (i == (Constants.NumThunksPerBlock - 1))
                    *((IntPtr*)(dataAddress)) = IntPtr.Zero;
                else
                    *((IntPtr*)(dataAddress)) = nextDataAddress;

#if DEBUG
                // Debug flag in the second data cell indicating the thunk is not used
                *((IntPtr*)(dataAddress + IntPtr.Size)) = new IntPtr(-1);
#endif

                dataAddress = nextDataAddress;
            }

            return nextThunksBlock;
        }

        // TODO: [Feature] Keep track of mapped sections and free them if we need to.
        // public static unsafe void FreeThunksBlock()
        // {
        // }
    }
}
