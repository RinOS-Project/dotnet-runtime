// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;

using ILCompiler.DependencyAnalysis.Wasm;

namespace ILCompiler.DependencyAnalysis
{
    public partial class ReadyToRunGenericHelperNode
    {
        protected override void EmitCode(NodeFactory factory, ref WasmEmitter encoder, bool relocsOnly)
        {
            throw new NotSupportedException(
                "NativeAOT WASM ReadyToRun generic helper emission requires the WASM function-body/object-writer ABI");
        }

        protected virtual void EmitLoadGenericContext(NodeFactory factory, ref WasmEmitter encoder, bool relocsOnly)
        {
            throw new NotSupportedException(
                "NativeAOT WASM generic context loading requires the WASM function-body/object-writer ABI");
        }
    }

    public partial class ReadyToRunGenericLookupFromTypeNode
    {
        protected override void EmitLoadGenericContext(NodeFactory factory, ref WasmEmitter encoder, bool relocsOnly)
        {
            throw new NotSupportedException(
                "NativeAOT WASM generic type lookup requires the WASM function-body/object-writer ABI");
        }
    }
}
