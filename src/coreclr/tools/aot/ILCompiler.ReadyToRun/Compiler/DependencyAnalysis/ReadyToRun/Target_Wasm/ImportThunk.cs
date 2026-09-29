// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Diagnostics;

using ILCompiler.DependencyAnalysis.Wasm;

namespace ILCompiler.DependencyAnalysis.ReadyToRun
{
    /// <summary>
    /// This node emits a thunk calling DelayLoad_Helper with a given instance signature
    /// to populate its indirection cell.
    /// </summary>
    public partial class ImportThunk
    {
        protected override void EmitCode(NodeFactory factory, ref WasmEmitter instructionEncoder, bool relocsOnly)
        {
            // WASM import thunks need a signature-aware body.  All current WASM
            // delay-load paths use WasmImportThunk, which owns that signature
            // and emits the transition-block/indirect-call sequence.  Do not
            // silently emit an empty function if a generic ImportThunk reaches
            // this target-specific implementation before that ABI is defined.
            throw new NotSupportedException(
                "Generic ReadyToRun ImportThunk emission is not supported on WASM; use WasmImportThunk");
        }
    }
}
