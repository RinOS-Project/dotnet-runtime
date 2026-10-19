// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Generic;
using System.Threading.Tasks;
using WasiPollWorld.wit.Imports.wasi.io.v0_2_8;
using Pollable = WasiPollWorld.wit.Imports.wasi.io.v0_2_8.IPollImports.Pollable;
using MonotonicClockInterop = WasiPollWorld.wit.Imports.wasi.clocks.v0_2_8.IMonotonicClockImports;

namespace System.Threading
{
    internal static class WasiEventLoop
    {
        // A poll is otherwise unbounded. Keep a bounded wake-up so an abandoned Task can
        // be noticed even when its pollable never becomes ready.
        private const ulong AbandonedTaskSweepNanoseconds = 1_000_000_000;
        private static readonly List<PollableHolder> s_pollables = new();
        private static readonly List<PollHook> s_hooks = new();
        private static bool s_checkScheduled;
        private static Pollable? s_resolvedPollable;
        private static Task? s_mainTask;

        internal static Task RegisterWasiPollableHandle(int handle, bool ownsPollable, CancellationToken cancellationToken)
        {
            // note that this is duplicate of the original Pollable
            // the original should have been neutralized without disposing the handle
            var pollableCpy = new Pollable(new Pollable.THandle(handle));
            return RegisterWasiPollable(pollableCpy, ownsPollable, cancellationToken);
        }

        internal static Task RegisterWasiPollable(Pollable pollable, bool ownsPollable, CancellationToken cancellationToken)
        {
            // this will register the pollable holder into s_pollables
            var holder = new PollableHolder(pollable, ownsPollable, cancellationToken, out Task task);
            s_pollables.Add(holder);

            ScheduleCheck();

            return task;
        }

        internal static void RegisterWasiPollHook(object? state, Func<object?, IList<int>> beforePollHook, Action<object?> onResolveCallback, CancellationToken cancellationToken)
        {
            // this will register the poll hook into s_hooks
            var holder = new PollHook(state, beforePollHook, onResolveCallback, cancellationToken);
            s_hooks.Add(holder);

            ScheduleCheck();
        }


        internal static T PollWasiEventLoopUntilResolved<T>(Task<T> mainTask)
        {
            try
            {
                s_mainTask = mainTask;
                while (!mainTask.IsCompleted)
                {
#if FEATURE_PERFTRACING && CORECLR && !FEATURE_MULTITHREADING
                    // Register the pump before Dispatch, which may block in wasi:io/poll.
                    WasiEventPipeJobs.Pump();
#endif
                    ThreadPoolWorkQueue.Dispatch();
                    WasiFinalizerScheduler.DrainIfPending();
                }
            }
            finally
            {
                s_mainTask = null;
            }

            // The pump loop above guarantees the task is completed, so GetResult() never
            // reaches the blocking (PNSE-throwing) wait. It propagates with await semantics:
            // the original exception for faults and TaskCanceledException for cancellation.
            return mainTask.GetAwaiter().GetResult();
        }

        internal static void PollWasiEventLoopUntilResolvedVoid(Task mainTask)
        {
            try
            {
                s_mainTask = mainTask;
                while (!mainTask.IsCompleted)
                {
#if FEATURE_PERFTRACING && CORECLR && !FEATURE_MULTITHREADING
                    WasiEventPipeJobs.Pump();
#endif
                    ThreadPoolWorkQueue.Dispatch();
                    WasiFinalizerScheduler.DrainIfPending();
                }
            }
            finally
            {
                s_mainTask = null;
            }

            // The pump loop above guarantees the task is completed, so GetResult() never
            // reaches the blocking (PNSE-throwing) wait. It propagates with await semantics:
            // the original exception for faults and TaskCanceledException for cancellation.
            mainTask.GetAwaiter().GetResult();
        }

        internal static void ScheduleCheck()
        {
            if (!s_checkScheduled && (s_pollables.Count > 0 || s_hooks.Count > 0))
            {
                s_checkScheduled = true;
                ThreadPool.UnsafeQueueUserWorkItem(CheckPollables, null);
            }
        }

        internal static void CheckPollables(object? _)
        {
            s_checkScheduled = false;

            var holders = new List<PollableHolder>(s_pollables.Count);
            var hooks = new List<PollHook>(s_pollables.Count);
            var pending = new List<Pollable>(s_pollables.Count);
            for (int i = 0; i < s_pollables.Count; i++)
            {
                var holder = s_pollables[i];
                if (!holder.isDisposed && holder.HasLiveTask)
                {
                    holders.Add(holder);
                    pending.Add(holder.pollable);
                }
                else
                {
                    holder.DisposeAbandoned();
                }
            }
            for (int i = 0; i < s_hooks.Count; i++)
            {
                var hook = s_hooks[i];
                if (!hook.isDisposed)
                {
                    var handles = hook.BeforePollHook(hook.State);
                    for (int h = 0; h < handles.Count; h++)
                    {
                        var handle = handles[h];
                        var pollableCpy = new Pollable(new Pollable.THandle(handle));
                        hooks.Add(hook);
                        pending.Add(pollableCpy);
                    }
                }
            }

            s_pollables.Clear();
            s_hooks.Clear();

            if (pending.Count > 0)
            {
                // The WASI poll operation has no timeout. Add a short-lived timer so
                // dead Task/CompletionState cycles are collected from s_pollables even
                // when the application pollable itself never resolves.
                int abandonedTaskSweepIndex = pending.Count;
                Pollable abandonedTaskSweepPollable = MonotonicClockInterop.SubscribeDuration(AbandonedTaskSweepNanoseconds);
                pending.Add(abandonedTaskSweepPollable);

                var resolvedPollableIndex = -1;
                // if there is CPU-bound work to do, we should not block on PollInterop.Poll below
                // so we will append pollable resolved in 0ms
                // in effect, the PollInterop.Poll would not block us
                if (ThreadPool.PendingWorkItemCount > 0 || (s_mainTask != null && s_mainTask.IsCompleted))
                {
                    s_resolvedPollable ??= MonotonicClockInterop.SubscribeDuration(0);
                    resolvedPollableIndex = pending.Count;
                    pending.Add(s_resolvedPollable);
                }

                // this could block, this is blocking WASI API call
                // FIXME: this will also block soft-debugger ability to pause the execution. Solutions: A) upgrade to WASIp3 B) register debugger connection's pollable
                uint[] readyIndexes;
                try
                {
                    readyIndexes = IPollImports.Poll(pending);
                }
                finally
                {
                    abandonedTaskSweepPollable.Dispose();
                }

                var holdersCount = holders.Count;
                var hooksCount = hooks.Count;
                for (int i = 0; i < readyIndexes.Length; i++)
                {
                    uint readyIndex = readyIndexes[i];
                    if (readyIndex < holdersCount)
                    {
                        var holder = holders[(int)readyIndex];
                        holder.ResolveAndDispose();
                    }
                    else if (readyIndex < holdersCount + hooksCount)
                    {
                        var hook = hooks[(int)readyIndex-holdersCount];
                        hook.Resolve();
                    }
                    else if (readyIndex == (uint)abandonedTaskSweepIndex || readyIndex == (uint)resolvedPollableIndex)
                    {
                        // Internal wake-up pollables have no user callback.
                    }
                }

                for (int i = 0; i < holders.Count; i++)
                {
                    PollableHolder holder = holders[i];
                    if (!holder.isDisposed)
                    {
                        s_pollables.Add(holder);
                    }
                }
            }

            for (int i = 0; i < hooks.Count; i++)
            {
                PollHook hook = hooks[i];
                if (!hook.isDisposed)
                {
                    s_hooks.Add(hook);
                }
            }

            ScheduleCheck();
        }

        private sealed class PollableHolder
        {
            public bool isDisposed;
            public bool ownsPollable;
            public readonly Pollable pollable;
            public readonly CancellationTokenRegistration cancellationTokenRegistration;
            public readonly CancellationToken cancellationToken;
            private readonly WeakReference<CompletionState> completionState;

            public PollableHolder(Pollable pollable, bool ownsPollable, CancellationToken cancellationToken, out Task task)
            {
                this.pollable = pollable;
                this.ownsPollable = ownsPollable;
                this.cancellationToken = cancellationToken;

                // Keep the completion source in the Task's state cycle, not in this
                // holder. That lets the holder observe that the caller dropped the
                // Task instead of keeping the abandoned Task alive forever.
                var state = new CompletionState();
                completionState = new WeakReference<CompletionState>(state);
                task = state.taskCompletionSource.Task;

                // static method is used to avoid allocating a delegate
                cancellationTokenRegistration = cancellationToken.Register(CancelAndDispose, this);
            }

            public bool HasLiveTask => completionState.TryGetTarget(out _);

            public void ResolveAndDispose()
            {
                if (isDisposed)
                {
                    return;
                }

                // no need to unregister the holder from s_pollables, when this is called
                isDisposed = true;
                if (ownsPollable){
                    pollable.Dispose();
                }
                cancellationTokenRegistration.Dispose();
                if (completionState.TryGetTarget(out CompletionState? state))
                {
                    state.taskCompletionSource.TrySetResult(null);
                }
            }

            public void DisposeAbandoned()
            {
                if (isDisposed)
                {
                    return;
                }

                isDisposed = true;
                if (ownsPollable){
                    pollable.Dispose();
                }
                cancellationTokenRegistration.Dispose();
            }

            // for GC of abandoned Tasks or for cancellation
            public static void CancelAndDispose(object? s)
            {
                PollableHolder self = (PollableHolder)s!;
                if (self.isDisposed)
                {
                    return;
                }

                // it will be removed from s_pollables on the next run
                self.isDisposed = true;
                if (self.ownsPollable){
                    self.pollable.Dispose();
                }
                self.cancellationTokenRegistration.Dispose();
                if (self.completionState.TryGetTarget(out CompletionState? state))
                {
                    state.taskCompletionSource.TrySetCanceled(self.cancellationToken);
                }
            }
        }

        private sealed class CompletionState
        {
            public readonly TaskCompletionSource<object?> taskCompletionSource;

            public CompletionState()
            {
                taskCompletionSource = new TaskCompletionSource<object?>(this, TaskCreationOptions.RunContinuationsAsynchronously);
            }
        }

        private sealed class PollHook
        {
            public bool isDisposed;
            public readonly object? State;
            public readonly Func<object?, IList<int>> BeforePollHook;
            public readonly Action<object?> OnResolveCallback;
            public readonly CancellationTokenRegistration cancellationTokenRegistration;

            public PollHook(object? state, Func<object?, IList<int>> beforePollHook, Action<object?> onResolveCallback, CancellationToken cancellationToken)
            {
                this.State = state;
                this.BeforePollHook = beforePollHook;
                this.OnResolveCallback = onResolveCallback;

                // static method is used to avoid allocating a delegate
                cancellationTokenRegistration = cancellationToken.Register(Dispose, this);
            }

            public void Resolve()
            {
                OnResolveCallback(State);
            }

            public static void Dispose(object? s)
            {
                PollHook self = (PollHook)s!;
                if (self.isDisposed)
                {
                    return;
                }

                // it will be removed from s_hooks on the next run
                self.isDisposed = true;
                self.cancellationTokenRegistration.Dispose();
            }
        }
    }
}
