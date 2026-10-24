// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace System
{
    public static partial class Environment
    {
        public static string[] GetLogicalDrives() => Interop.Sys.GetAllMountPoints();

        public static string MachineName
        {
            get
            {
                string hostName = Interop.Sys.GetHostName();
                int dotPos = hostName.IndexOf('.');
                return dotPos < 0 ? hostName : hostName.Substring(0, dotPos);
            }
        }

        public static string UserName => Interop.Sys.GetUserNameFromPasswd(Interop.Sys.GetEUid());

        private static bool IsPrivilegedProcessCore() => Interop.Sys.GetEUid() == 0;

        [MethodImplAttribute(MethodImplOptions.NoInlining)] // Avoid inlining PInvoke frame into the hot path
        private static int GetProcessId() => Interop.Sys.GetPid();

        [MethodImplAttribute(MethodImplOptions.NoInlining)] // Avoid inlining PInvoke frame into the hot path
        private static string? GetProcessPath() => Interop.Sys.GetProcessPath();

        private static string[] GetCommandLineArgsNative()
        {
            // This is only used for delegate created from native host

#if TARGET_RINOS
            // The RinOS crt0 records the process argv before invoking the native
            // host.  Hosted CoreCLR normally initializes s_commandLineArgs from
            // the host API, but a delegate loaded by a native host does not take
            // that path.  Read the product startup ABI instead of assuming a
            // Linux procfs exists or returning a fabricated argument list.
            int count = Interop.Sys.GetRinOSCommandLineArgCount();
            if (count <= 0)
            {
                return [];
            }

            string[] commandLineArgs = new string[count];
            for (int i = 0; i < commandLineArgs.Length; i++)
            {
                if (!Interop.Sys.TryGetRinOSCommandLineArg(i, out string? argument))
                {
                    // A stale or malformed startup context must not produce a
                    // partial command line that callers could mistake for the
                    // real process arguments.
                    return [];
                }

                commandLineArgs[i] = argument!;
            }

            return commandLineArgs;
#else
            return [];
#endif
        }
    }
}
