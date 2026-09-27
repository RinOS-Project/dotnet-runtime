// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.


using System;

using Internal.Runtime.CompilerServices;

namespace Internal.TypeSystem
{
    public partial class ArrayMethod : MethodDesc
    {
        public override MethodNameAndSignature NameAndSignature
        {
            get
            {
                // Array methods are synthetic runtime methods and have no
                // metadata MethodHandle from which MethodNameAndSignature can
                // be constructed. Callers that need metadata identity must use
                // the owning array method's Name and Signature instead.
                throw new NotSupportedException(
                    "Array methods do not expose a metadata MethodNameAndSignature.");
            }
        }
    }
}
