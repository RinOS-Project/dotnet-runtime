// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

//
// ===========================================================================
// File: winerror.h
//
// ===========================================================================
// dummy winerror.h for PAL

#if defined(MIDL_PASS)
// MIDL supplies the Windows ABI types through its standard IDL imports. Do
// not include palrt.h here: that header intentionally exposes the native PAL
// typedefs and would collide with the Windows SDK definitions while parsing
// an IDL such as corsym.idl.
#ifndef FACILITY_ITF
#define FACILITY_ITF 4
#endif
#ifndef MAKE_HRESULT
#define MAKE_HRESULT(severity, facility, code) \
    (((severity) << 31) | ((facility) << 16) | (code))
#endif
#else
#include "palrt.h"
#endif
