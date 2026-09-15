// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
//

//
// ===========================================================================
// File: guiddef.h
//
// ===========================================================================
// simplified guiddef.h for PAL

#ifndef _RINOS_GUIDDEF_H_
#define _RINOS_GUIDDEF_H_

#if !defined(MIDL_PASS)
#include "palrt.h"
#else
// MIDL consumes the Windows SDK IDL imports while generating the debugger
// contracts. It must not pull in the target PAL's inline Unix headers: those
// headers are for the native RinOS build and contain implementation details
// (syscalls, atomics, and C++ helpers) that MIDL cannot parse. Keep the
// declaration-only GUID surface here for that host-side generation pass.
#ifndef GUID_DEFINED
#define GUID_DEFINED
typedef struct _GUID {
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
} GUID;
#endif

#ifndef FAR
#define FAR
#endif

#ifndef EXTERN_C
#define EXTERN_C extern
#endif

#ifndef DLLEXPORT
#define DLLEXPORT
#endif

#ifndef __LPGUID_DEFINED__
#define __LPGUID_DEFINED__
typedef GUID *LPGUID;
#endif

#ifndef __LPCGUID_DEFINED__
#define __LPCGUID_DEFINED__
typedef const GUID FAR *LPCGUID;
#endif

#ifndef REFGUID
#define REFGUID const GUID *
#endif

#ifndef __IID_DEFINED__
#define __IID_DEFINED__
#ifdef __cplusplus
EXTERN_C const GUID GUID_NULL;
#else
extern const GUID GUID_NULL;
#endif
typedef GUID IID;
typedef GUID CLSID;
typedef CLSID *LPCLSID;
typedef GUID FMTID;
#ifndef __LPFMTID_DEFINED__
#define __LPFMTID_DEFINED__
typedef FMTID *LPFMTID;
#endif
#define CLSID_DEFINED
#define IID_NULL GUID_NULL
#define CLSID_NULL GUID_NULL
#define FMTID_NULL GUID_NULL
#endif

#ifndef REFIID
#define REFIID const IID *
#endif

#ifndef REFCLSID
#define REFCLSID const CLSID *
#endif

#ifndef REFFMTID
#define REFFMTID const FMTID *
#endif
#endif

#ifdef DEFINE_GUID
#undef DEFINE_GUID
#endif

#if defined(MIDL_PASS)
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    EXTERN_C const GUID FAR name
#elif defined(INITGUID)
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
        EXTERN_C DLLEXPORT constexpr GUID name \
                = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    EXTERN_C const GUID FAR name
#endif // INITGUID

#endif // _RINOS_GUIDDEF_H_
