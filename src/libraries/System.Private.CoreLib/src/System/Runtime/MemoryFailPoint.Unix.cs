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
            // RinOS and the other Unix PALs expose the physical-memory snapshot
            // through SysConf.  It is intentionally used as a lower bound for
            // available VM: the product does not expose a page-file accounting
            // ABI, so claiming swap capacity here would make MemoryFailPoint
            // report success without an owned source of truth.
            long pageSize = Interop.Sys.SysConf(Interop.Sys.SysConfName._SC_PAGESIZE);
            long availablePages = Interop.Sys.SysConf(Interop.Sys.SysConfName._SC_AVPHYS_PAGES);
            if (pageSize <= 0 || availablePages <= 0)
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

            // Unix does not provide the Windows-style free virtual-address
            // extent query through this PAL.  The GC owns virtual reservations,
            // so keep the address-space side conservative and do not synthesize
            // a host /proc or platform-specific map scan.
            totalAddressSpaceFree = GetTopOfMemory();
            return true;
        }

#pragma warning disable IDE0060
        // Based on the shouldThrow parameter, this will throw an exception, or
        // returns whether there is enough space.  In all cases, we update
        // our last known free address space, hopefully avoiding needing to
        // probe again.
        private static void CheckForFreeAddressSpace(ulong size, bool shouldThrow)
        {
            // The current product ABI has no address-space extent enumeration.
            // Physical availability is checked above; the GC's own reserve and
            // commit path remains authoritative for virtual address space.
            LastKnownFreeAddressSpace = long.MaxValue;
            LastTimeCheckingAddressSpace = Environment.TickCount;
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
