// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace System.Net
{
    internal partial struct StreamSizes
    {
        public static StreamSizes Default => new StreamSizes
        {
            MaximumMessage = 16 * 1024
        };
    }
}
