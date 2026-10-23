// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Runtime.InteropServices
{
    public enum GCHandleType
    {
        Weak = 0,
        WeakTrackResurrection = 1,
        Normal = 2,
        // NativeAOT maps this value to the GC handle table's HNDTYPE_PINNED
        // entry.  GCHandle.cs owns the managed pin tag and address checks.
        Pinned = 3
    }
}
