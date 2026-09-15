// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System
{
    public static partial class Environment
    {
        // The product kernel exposes an authenticated, self-only resident
        // page-accounting snapshot. A failed/unsupported query remains zero,
        // matching the existing Browser/iOS fallback without fabricating RSS.
        public static long WorkingSet => Interop.Sys.GetWorkingSet();
    }
}
