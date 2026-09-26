// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Threading;
using Microsoft.Diagnostics.DataContractReader.Contracts;

namespace Microsoft.Diagnostics.DataContractReader.Legacy;

[GeneratedComClass]
public sealed unsafe partial class ClrDataAssembly : IXCLRDataAssembly
{
    private const uint ClrDataAssemblyDefault = 0;

    private readonly Lock _apiLock;
    private readonly Target _target;
    private readonly TargetPointer _assembly;
    private readonly IXCLRDataAssembly? _legacyImpl;

    private sealed class ModuleEnum : IEnum<Contracts.ModuleHandle>
    {
        public IEnumerator<Contracts.ModuleHandle> Enumerator { get; }
        public nuint LegacyHandle { get; set; }

        public ModuleEnum(Contracts.ModuleHandle module, nuint legacyHandle)
        {
            Enumerator = ((IEnumerable<Contracts.ModuleHandle>)new[] { module }).GetEnumerator();
            LegacyHandle = legacyHandle;
        }
    }

    internal TargetPointer Address => _assembly;

    public ClrDataAssembly(Target target, TargetPointer assembly, IXCLRDataAssembly? legacyImpl, Lock apiLock)
    {
        _target = target;
        _assembly = assembly;
        _legacyImpl = legacyImpl;
        _apiLock = apiLock;
    }

    int IXCLRDataAssembly.StartEnumModules(ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        ulong legacyHandle = 0;

        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));

            *handle = 0;
            if (_legacyImpl is not null)
                hrLocal = _legacyImpl.StartEnumModules(&legacyHandle);

            ILoader loader = _target.Contracts.Loader;
            Contracts.ModuleHandle module = loader.GetModuleHandleFromAssemblyPtr(_assembly);
            ModuleEnum modules = new(module, (nuint)legacyHandle);
            *handle = (ulong)((IEnum<Contracts.ModuleHandle>)modules).GetHandle();
            legacyHandle = 0;
        }
        catch (Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
                _legacyImpl.EndEnumModules(legacyHandle);
        }

#if DEBUG
        if (_legacyImpl is not null)
            DebugValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    int IXCLRDataAssembly.EnumModule(ulong* handle, DacComNullableByRef<IXCLRDataModule> mod)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));
            if (*handle == 0)
                return HResults.S_FALSE;
            if (mod.IsNullRef)
                throw new NullReferenceException();

            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not ModuleEnum modules)
                throw new ArgumentException();

            IXCLRDataModule? legacyModule = null;
            if (_legacyImpl is not null)
            {
                ulong legacyHandle = (ulong)modules.LegacyHandle;
                DacComNullableByRef<IXCLRDataModule> legacyModuleOut = new(isNullRef: false);
                hrLocal = _legacyImpl.EnumModule(&legacyHandle, legacyModuleOut);
                legacyModule = legacyModuleOut.Interface;
                modules.LegacyHandle = (nuint)legacyHandle;
            }

            if (modules.Enumerator.MoveNext())
            {
                ILoader loader = _target.Contracts.Loader;
                mod.Interface = new ClrDataModule(loader.GetModule(modules.Enumerator.Current), _target, legacyModule, _apiLock);
            }
            else
            {
                hr = HResults.S_FALSE;
            }
        }
        catch (Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
            DebugValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    int IXCLRDataAssembly.EndEnumModules(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (handle == 0)
            return HResults.S_OK;

        ModuleEnum modules;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not ModuleEnum modulesLocal)
                throw new ArgumentException();

            modules = modulesLocal;
            ((IEnum<Contracts.ModuleHandle>)modules).Dispose();
            gcHandle.Free();
        }
        catch (Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && modules.LegacyHandle != 0)
            return _legacyImpl.EndEnumModules((ulong)modules.LegacyHandle);

        return HResults.S_OK;
    }

    int IXCLRDataAssembly.GetName(uint bufLen, uint* nameLen, char* name)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        try
        {
            ILoader loader = _target.Contracts.Loader;
            Contracts.ModuleHandle module = loader.GetModuleHandleFromAssemblyPtr(_assembly);
            OutputBufferHelpers.CopyStringToBuffer(name, bufLen, nameLen, loader.GetSimpleName(module));
            return HResults.S_OK;
        }
        catch (Exception ex)
        {
            return ex.HResult;
        }
    }

    int IXCLRDataAssembly.GetFileName(uint bufLen, uint* nameLen, char* name)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        try
        {
            ILoader loader = _target.Contracts.Loader;
            Contracts.ModuleHandle module = loader.GetModuleHandleFromAssemblyPtr(_assembly);
            string path = loader.GetPath(module);
            if (string.IsNullOrEmpty(path))
                path = loader.GetFileName(module);
            if (string.IsNullOrEmpty(path))
                return HResults.E_FAIL;

            OutputBufferHelpers.CopyStringToBuffer(name, bufLen, nameLen, path);
            return HResults.S_OK;
        }
        catch (Exception ex)
        {
            return ex.HResult;
        }
    }

    int IXCLRDataAssembly.GetFlags(uint* flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        try
        {
            if (flags is null)
                throw new ArgumentNullException(nameof(flags));

            *flags = ClrDataAssemblyDefault;
            return HResults.S_OK;
        }
        catch (Exception ex)
        {
            return ex.HResult;
        }
    }

    int IXCLRDataAssembly.IsSameObject(IXCLRDataAssembly? assembly)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return assembly is ClrDataAssembly other && _assembly == other._assembly
            ? HResults.S_OK
            : HResults.S_FALSE;
    }

    int IXCLRDataAssembly.Request(uint reqCode, uint inBufferSize, byte* inBuffer, uint outBufferSize, byte* outBuffer)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        try
        {
            if (reqCode != (uint)CLRDataGeneralRequest.CLRDATA_REQUEST_REVISION
                || inBufferSize != 0
                || inBuffer is not null
                || outBufferSize != sizeof(uint))
            {
                throw new ArgumentException("Invalid request parameters.");
            }

            if (outBuffer is null)
                throw new NullReferenceException("The output buffer is null.");

            *(uint*)outBuffer = 2;
            return HResults.S_OK;
        }
        catch (Exception ex)
        {
            return ex.HResult;
        }
    }

    int IXCLRDataAssembly.StartEnumAppDomains(ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return HResults.E_NOTIMPL;
    }

    int IXCLRDataAssembly.EnumAppDomain(ulong* handle, void** appDomain)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return HResults.E_NOTIMPL;
    }

    int IXCLRDataAssembly.EndEnumAppDomains(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return HResults.E_NOTIMPL;
    }

    int IXCLRDataAssembly.GetDisplayName(uint bufLen, uint* nameLen, char* name)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return HResults.E_NOTIMPL;
    }

#if DEBUG
    private static void DebugValidateHResult(int actual, int expected)
    {
        Debug.Assert(actual == expected, $"cDAC: {actual:x}, DAC: {expected:x}");
    }
#endif
}
