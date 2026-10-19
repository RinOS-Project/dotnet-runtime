// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace System.Threading
{
    // Runs native EventPipe jobs that cannot be scheduled by a WASI host event
    // loop. Jobs run only while WasiEventLoop is pumped.
    internal static partial class WasiEventPipeJobs
    {
        private const int PumpIntervalMs = 100;
        private static bool s_pumpRunning;

        [ErrorHandler(typeof(QCallExceptionStatusMarshaller), ErrorLocation.HiddenLastParameter)]
        [LibraryImport(RuntimeHelpers.QCall, EntryPoint = "EventPipeInternal_WasiRunJobs")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool RunJobs();

        internal static void Pump()
        {
            if (s_pumpRunning)
                return;

            s_pumpRunning = true;
            _ = PumpAsync();
        }

        private static async Task PumpAsync()
        {
            try
            {
                while (RunJobs())
                    await Task.Delay(PumpIntervalMs).ConfigureAwait(false);
            }
            finally
            {
                s_pumpRunning = false;
            }
        }
    }
}
