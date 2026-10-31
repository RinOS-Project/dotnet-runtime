// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Reflection;
using System.Resources;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: CLSCompliant(true)]
[assembly: ComVisible(false)]

// Number.Formatting.Common.cs is compiled into System.Runtime.Numerics as
// well as CoreLib.  RinOS supplies CLDR minimumGroupingDigits through the
// internal NumberFormatInfo state, so the shared formatter needs the same
// narrow friend access as the CoreLib copy without making that compatibility
// detail public API.
[assembly: InternalsVisibleTo("System.Runtime.Numerics, PublicKey=00240000048000009400000006020000002400005253413100040000010001004b86c4cb78549b34bab61a3b1800e23bfeb5b3ec390074041536a7e3cbd97f5f04cf0f857155a8928eaa29ebfd11cfbbad3ba70efea7bda3226c6a8d370a4cd303f714486b6ebc225985a638471e6ef571cc92a4613c00b8fa65d61ccee0cbe5f36330c9a01f4183559f1bef24cc2917c6d913e3a541333a1d05d9bed22b38cb")]

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]

[assembly: AssemblyMetadata("Serviceable", "True")]
[assembly: AssemblyMetadata("IsTrimmable", "True")]

[assembly: NeutralResourcesLanguage("en-US")]
