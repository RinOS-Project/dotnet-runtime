// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Runtime
{
    public sealed partial class MemoryFailPoint
    {
        private static ulong GetTopOfMemory()
        {
            // These values are optimistic assumptions. In reality the value will
            // often be lower.
            return IntPtr.Size == 4 ? uint.MaxValue : ulong.MaxValue;
        }

        private static bool CheckForAvailableMemory(out ulong availPageFile, out ulong totalAddressSpaceFree)
        {
#if TARGET_RINOS
            Interop.Sys.RinOSMemoryAvailability availability;
            if (Interop.Sys.GetRinOSMemoryAvailability(out availability) != 0 ||
                (availability.Flags & Interop.Sys.RinOSMemoryAvailabilityVmValid) == 0u ||
                (availability.Flags & Interop.Sys.RinOSMemoryAvailabilityVirtualValid) == 0u)
            {
                availPageFile = 0;
                totalAddressSpaceFree = 0;
                // A broken or unavailable product memory snapshot must not
                // become a successful gate.
                return false;
            }

            availPageFile = availability.AvailableVmBytes;
            totalAddressSpaceFree = availability.TotalFreeVirtualBytes;
            return true;
#else
            // Unix PALs that do not expose a page-file/VMA availability
            // snapshot use the physical-memory SysConf value as a lower bound.
            long pageSize = Interop.Sys.SysConf(Interop.Sys.SysConfName._SC_PAGESIZE);
            long availablePages = Interop.Sys.SysConf(Interop.Sys.SysConfName._SC_AVPHYS_PAGES);
            if (pageSize <= 0 || availablePages < 0)
            {
                availPageFile = 0;
                totalAddressSpaceFree = 0;
                return false;
            }

            ulong pageSizeUnsigned = (ulong)pageSize;
            ulong availablePagesUnsigned = (ulong)availablePages;
            if (availablePagesUnsigned > ulong.MaxValue / pageSizeUnsigned)
            {
                availPageFile = 0;
                totalAddressSpaceFree = 0;
                return false;
            }

            availPageFile = availablePagesUnsigned * pageSizeUnsigned;

            // Unix does not provide the Windows-style total free virtual-address
            // extent query through this PAL.  Use the product VMM's anonymous
            // mapping probe for the contiguous segment check below instead of
            // synthesizing a host /proc or platform-specific map scan.
            totalAddressSpaceFree = GetTopOfMemory();
            return true;
#endif
        }

#pragma warning disable IDE0060
        // Based on the shouldThrow parameter, this will throw an exception, or
        // returns whether there is enough space.  In all cases, we update
        // our last known free address space, hopefully avoiding needing to
        // probe again.
        private static void CheckForFreeAddressSpace(ulong size, bool shouldThrow)
        {
            IntPtr address = Interop.Sys.MMap(
                IntPtr.Zero,
                size,
                Interop.Sys.MemoryMappedProtections.PROT_NONE,
                Interop.Sys.MemoryMappedFlags.MAP_PRIVATE |
                    Interop.Sys.MemoryMappedFlags.MAP_ANONYMOUS,
                new IntPtr(-1),
                0);
            bool hasSpace = address != IntPtr.Zero;
            if (hasSpace)
                hasSpace = Interop.Sys.MUnmap(address, size) == 0;

            LastKnownFreeAddressSpace = hasSpace
                ? (long)Math.Min(size, (ulong)long.MaxValue)
                : 0;
            LastTimeCheckingAddressSpace = Environment.TickCount;

            if (!hasSpace && shouldThrow)
                throw new InsufficientMemoryException(SR.InsufficientMemory_MemFailPoint_VAFrag);
        }

        // Allocate a specified number of bytes, commit them and free them. This should enlarge
        // page file if necessary and possible.
        private static void GrowPageFileIfNecessaryAndPossible(UIntPtr numBytes)
        {
            // RinOS has no page-file growth ABI.  The next availability sample
            // will observe the product memory owner instead of pretending that
            // a host swap file can be enlarged.
        }
#pragma warning restore IDE0060
    }
}
