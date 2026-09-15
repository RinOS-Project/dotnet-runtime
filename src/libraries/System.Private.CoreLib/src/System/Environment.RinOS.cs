// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System
{
    public static partial class Environment
    {
        // RinOS does not expose an unauthenticated process-RSS query to the
        // runtime PAL. Keep the public contract deterministic until a
        // capability-gated process telemetry ABI is available; reporting a
        // fabricated value would make RuntimeEventSource misleading.
        public static long WorkingSet => 0;
    }
}
