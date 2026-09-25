// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Reflection
{
    public abstract partial class ConstructorInfo : MethodBase
    {
        // Constructors have a void signature. Runtime-backed and emitted constructors
        // override this when they can obtain the return type from their metadata.
        internal virtual Type GetReturnType() => typeof(void);
    }
}
