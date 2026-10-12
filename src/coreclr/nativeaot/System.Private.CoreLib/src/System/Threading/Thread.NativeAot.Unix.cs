// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.Runtime;
using System.Runtime.InteropServices;

using Microsoft.Win32.SafeHandles;

namespace System.Threading
{
    public sealed partial class Thread
    {
        // Event signaling that the thread has stopped
        private ManualResetEvent _stopped;

        private SafeWaitHandle GetJoinHandle() => _stopped.SafeWaitHandle;

        private WaitSubsystem.ThreadWaitInfo _waitInfo;

        internal WaitSubsystem.ThreadWaitInfo WaitInfo => _waitInfo;

        private void PlatformSpecificInitialize()
        {
            _waitInfo = new WaitSubsystem.ThreadWaitInfo(this);
        }

        // Platform-specific initialization of foreign threads, i.e. threads not created by Thread.Start
        private void PlatformSpecificInitializeExistingThread()
        {
            _stopped = new ManualResetEvent(false);
        }

        private ThreadPriority GetPriorityLive()
        {
#if TARGET_RINOS
            if (Interop.Sys.GetThreadScheduling(_osThreadId, out int policy, out int priority) == 0)
            {
                return MapFromRinOSScheduling(policy, priority);
            }

            // A scheduler query failure must not expose stale or guessed
            // priority state to managed code.
            return ThreadPriority.Normal;
#else
            return ThreadPriority.Normal;
#endif
        }

        private bool SetPriorityLive(ThreadPriority priority)
        {
#if TARGET_RINOS
            MapToRinOSScheduling(priority, out int policy, out int schedulerPriority);
            return Interop.Sys.SetThreadScheduling(_osThreadId, policy, schedulerPriority) == 0;
#else
            return true;
#endif
        }


#if TARGET_RINOS
        private const int RinOSSchedOther = 0;
        private const int RinOSSchedFifo = 1;
        private const int RinOSSchedRoundRobin = 2;
        private const int RinOSSchedBatch = 3;
        private const int RinOSSchedIdle = 5;

        private static ThreadPriority MapFromRinOSScheduling(int policy, int priority)
        {
            return policy switch
            {
                RinOSSchedIdle => ThreadPriority.Lowest,
                RinOSSchedBatch => ThreadPriority.BelowNormal,
                RinOSSchedOther => ThreadPriority.Normal,
                RinOSSchedFifo or RinOSSchedRoundRobin when priority >= 50 => ThreadPriority.Highest,
                RinOSSchedFifo or RinOSSchedRoundRobin => ThreadPriority.AboveNormal,
                _ => ThreadPriority.Normal,
            };
        }

        private static void MapToRinOSScheduling(ThreadPriority priority, out int policy, out int schedulerPriority)
        {
            switch (priority)
            {
                case ThreadPriority.Lowest:
                    policy = RinOSSchedIdle;
                    schedulerPriority = 0;
                    break;
                case ThreadPriority.BelowNormal:
                    policy = RinOSSchedBatch;
                    schedulerPriority = 0;
                    break;
                case ThreadPriority.Normal:
                    policy = RinOSSchedOther;
                    schedulerPriority = 0;
                    break;
                case ThreadPriority.AboveNormal:
                    policy = RinOSSchedRoundRobin;
                    schedulerPriority = 25;
                    break;
                case ThreadPriority.Highest:
                    policy = RinOSSchedRoundRobin;
                    schedulerPriority = 50;
                    break;
                default:
                    policy = RinOSSchedOther;
                    schedulerPriority = 0;
                    break;
            }
        }
#endif

        [UnmanagedCallersOnly]
        private static void OnThreadExit()
        {
            Thread? currentThread = t_currentThread;
            if (currentThread != null)
            {
                // Inform the wait subsystem that the thread is exiting. For instance, this would abandon any mutexes locked by
                // the thread.
                currentThread._waitInfo.OnThreadExiting();
                StopThread(currentThread);
                currentThread.SetJoinHandle();
            }
        }

        private unsafe bool CreateThread(GCHandle<Thread> thisThreadHandle)
        {
            // Create the Stop event before starting the thread to make sure
            // it is ready to be signaled at thread shutdown time.
            // This also avoids OOM after creating the thread.
            _stopped = new ManualResetEvent(false);

            nint stackSize = _startHelper!._maxStackSize;

            if (stackSize <= 0)
            {
                stackSize = RuntimeImports.RhGetDefaultStackSize();
            }

            if (!Interop.Sys.CreateThread(stackSize, RuntimeImports.RhGetThreadEntryPointAddress(), GCHandle<Thread>.ToIntPtr(thisThreadHandle)))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// This is an entry point for managed threads created by application
        /// </summary>
        [UnmanagedCallersOnly(EntryPoint = "ThreadEntryPoint")]
        private static IntPtr ThreadEntryPoint(IntPtr parameter)
        {
            StartThread(parameter);
            return IntPtr.Zero;
        }

        public ApartmentState GetApartmentState()
        {
            return ApartmentState.Unknown;
        }

        private static bool SetApartmentStateUnchecked(ApartmentState state, bool throwOnError)
        {
            if (state != ApartmentState.Unknown)
            {
                if (throwOnError)
                {
                    throw new PlatformNotSupportedException(SR.PlatformNotSupported_ComInterop);
                }

                return false;
            }

            return true;
        }

        partial void InitializeComOnNewThread();

        public void DisableComObjectEagerCleanup() { }

        public void Interrupt() => WaitSubsystem.Interrupt(this);

        internal const bool ReentrantWaitsEnabled = false;

        internal static void SuppressReentrantWaits()
        {
            throw new PlatformNotSupportedException();
        }

        internal static void RestoreReentrantWaits()
        {
            throw new PlatformNotSupportedException();
        }
    }
}
