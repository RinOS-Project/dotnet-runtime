// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Threading;
using Microsoft.Diagnostics.DataContractReader.Contracts;

namespace Microsoft.Diagnostics.DataContractReader.Legacy;

[GeneratedComClass]
public sealed unsafe partial class ClrDataTypeDefinition : IXCLRDataTypeDefinition
{
    private sealed class EnumMethodDefinitions : IEnum<uint>
    {
        public IEnumerator<uint> Enumerator { get; set; } = Enumerable.Empty<uint>().GetEnumerator();
        public nuint LegacyHandle { get; set; }

        private readonly MetadataReader _reader;
        private readonly uint _token;
        private readonly uint _flags;

        public bool UseNameApi { get; }

        public EnumMethodDefinitions(MetadataReader reader, uint token, uint flags, bool useNameApi, nuint legacyHandle)
        {
            _reader = reader;
            _token = token;
            _flags = flags;
            UseNameApi = useNameApi;
            LegacyHandle = legacyHandle;
        }

        public void Start()
        {
            TypeDefinitionHandle typeDefinition = MetadataTokens.TypeDefinitionHandle(
                checked((int)EcmaMetadataUtils.GetRowId(_token)));
            TypeDefinition definition = _reader.GetTypeDefinition(typeDefinition);
            StringComparison comparison = (_flags & (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE) != 0
                ? StringComparison.OrdinalIgnoreCase
                : StringComparison.Ordinal;

            Enumerator = definition.GetMethods()
                .Where(method => _flags == 0 || string.Equals(
                    _reader.GetString(_reader.GetMethodDefinition(method).Name),
                    _methodName,
                    comparison))
                .Select(method => (uint)MetadataTokens.GetToken(method))
                .GetEnumerator();
        }

        private string? _methodName;

        public void Start(string? methodName)
        {
            _methodName = methodName;
            Start();
        }
    }

    private readonly record struct FieldEntry(TargetPointer FieldDesc, ITypeHandle EnclosingType, bool IsInherited);

    private sealed class EnumFields : IEnum<FieldEntry>
    {
        public IEnumerator<FieldEntry> Enumerator { get; }
        public nuint LegacyHandle { get; set; }
        public bool ByName { get; }

        public EnumFields(IEnumerable<FieldEntry> fields, bool byName, nuint legacyHandle)
        {
            Enumerator = fields.GetEnumerator();
            ByName = byName;
            LegacyHandle = legacyHandle;
        }
    }

    private readonly Lock _apiLock;
    private readonly Target _target;
    private readonly TargetPointer _module;
    private readonly uint _token;
    private readonly ITypeHandle? _typeHandle;
    private readonly IXCLRDataTypeDefinition? _legacyImpl;

    public ClrDataTypeDefinition(
        Target target,
        TargetPointer module,
        uint token,
        ITypeHandle? typeHandle,
        IXCLRDataTypeDefinition? legacyImpl,
        Lock apiLock)
    {
        _apiLock = apiLock;
        _target = target;
        _module = module;
        _token = token;
        _typeHandle = typeHandle;
        _legacyImpl = legacyImpl;
    }

    int IXCLRDataTypeDefinition.GetModule(DacComNullableByRef<IXCLRDataModule> mod)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        IXCLRDataModule? legacyModule = null;

        if (_legacyImpl is not null && !mod.IsNullRef)
        {
            DacComNullableByRef<IXCLRDataModule> legacyModuleOut = new(isNullRef: false);
            hrLocal = _legacyImpl.GetModule(legacyModuleOut);
            legacyModule = legacyModuleOut.Interface;
        }

        try
        {
            if (mod.IsNullRef)
                return HResults.S_OK;

            mod.Interface = new ClrDataModule(_target, _module, legacyModule, _apiLock);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null && !mod.IsNullRef)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.StartEnumMethodDefinitions(ulong* handle)
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
                hrLocal = _legacyImpl.StartEnumMethodDefinitions(&legacyHandle);

            if ((_token & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtTypeDef)
                return HResults.E_INVALIDARG;

            Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(_module);
            MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
                ?? throw new InvalidOperationException("Module metadata is unavailable.");
            EnumMethodDefinitions methods = new(reader, _token, flags: 0, useNameApi: false, legacyHandle: (nuint)legacyHandle);
            methods.Start();
            *handle = (ulong)((IEnum<uint>)methods).GetHandle();
            legacyHandle = 0;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
                _legacyImpl.EndEnumMethodDefinitions(legacyHandle);
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.EnumMethodDefinition(ulong* handle, DacComNullableByRef<IXCLRDataMethodDefinition> methodDefinition)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        EnumMethodDefinitions methods;
        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));
            if (*handle == 0)
                return HResults.S_FALSE;
            if (methodDefinition.IsNullRef)
                throw new NullReferenceException();

            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not EnumMethodDefinitions methodsLocal)
                throw new ArgumentException();
            methods = methodsLocal;
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        IXCLRDataMethodDefinition? legacyMethod = null;
        if (_legacyImpl is not null)
        {
            ulong legacyHandle = methods.LegacyHandle;
            DacComNullableByRef<IXCLRDataMethodDefinition> legacyMethodOut = new(isNullRef: false);
            hrLocal = methods.UseNameApi
                ? _legacyImpl.EnumMethodDefinitionByName(&legacyHandle, legacyMethodOut)
                : _legacyImpl.EnumMethodDefinition(&legacyHandle, legacyMethodOut);
            legacyMethod = legacyMethodOut.Interface;
            methods.LegacyHandle = (nuint)legacyHandle;
        }

        try
        {
            if (methods.Enumerator.MoveNext())
            {
                methodDefinition.Interface = new ClrDataMethodDefinition(
                    _target,
                    _module,
                    methods.Enumerator.Current,
                    legacyMethod,
                    _apiLock);
            }
            else
            {
                hr = HResults.S_FALSE;
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.EndEnumMethodDefinitions(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (handle == 0)
            return HResults.S_OK;

        EnumMethodDefinitions methods;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not EnumMethodDefinitions methodsLocal)
                throw new ArgumentException();
            methods = methodsLocal;
            ((IEnum<uint>)methods).Dispose();
            gcHandle.Free();
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && methods.LegacyHandle != 0)
            return methods.UseNameApi
                ? _legacyImpl.EndEnumMethodDefinitionsByName(methods.LegacyHandle)
                : _legacyImpl.EndEnumMethodDefinitions(methods.LegacyHandle);
        return HResults.S_OK;
    }

    int IXCLRDataTypeDefinition.StartEnumMethodDefinitionsByName(char* name, uint flags, ulong* handle)
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
                hrLocal = _legacyImpl.StartEnumMethodDefinitionsByName(name, flags, &legacyHandle);
            if (name is null || *name == '\0')
                throw new ArgumentException();
            if ((flags & ~((uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_SENSITIVE | (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE)) != 0)
                throw new ArgumentException();
            if ((_token & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtTypeDef)
                return HResults.E_INVALIDARG;

            Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(_module);
            MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
                ?? throw new InvalidOperationException("Module metadata is unavailable.");
            EnumMethodDefinitions methods = new(reader, _token, flags, useNameApi: true, legacyHandle: (nuint)legacyHandle);
            methods.Start(new string(name));
            *handle = (ulong)((IEnum<uint>)methods).GetHandle();
            legacyHandle = 0;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
                _legacyImpl.EndEnumMethodDefinitionsByName(legacyHandle);
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.EnumMethodDefinitionByName(ulong* handle, DacComNullableByRef<IXCLRDataMethodDefinition> method)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return ((IXCLRDataTypeDefinition)this).EnumMethodDefinition(handle, method);
    }

    int IXCLRDataTypeDefinition.EndEnumMethodDefinitionsByName(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return ((IXCLRDataTypeDefinition)this).EndEnumMethodDefinitions(handle);
    }

    int IXCLRDataTypeDefinition.GetMethodDefinitionByToken(uint token, DacComNullableByRef<IXCLRDataMethodDefinition> methodDefinition)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if ((token & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtMethodDef)
            return HResults.E_INVALIDARG;

        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        IXCLRDataMethodDefinition? legacyMethod = null;
        try
        {
            if (_legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataMethodDefinition> legacyMethodOut = new(isNullRef: methodDefinition.IsNullRef);
                hrLocal = _legacyImpl.GetMethodDefinitionByToken(token, legacyMethodOut);
                legacyMethod = legacyMethodOut.Interface;
            }

            if (!methodDefinition.IsNullRef)
            {
                methodDefinition.Interface = new ClrDataMethodDefinition(
                    _target,
                    _module,
                    token,
                    legacyMethod,
                    _apiLock);
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.StartEnumInstances(IXCLRDataAppDomain? appDomain, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.StartEnumInstances(appDomain, handle) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.EnumInstance(ulong* handle, DacComNullableByRef<IXCLRDataTypeInstance> instance)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.EnumInstance(handle, instance) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.EndEnumInstances(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.EndEnumInstances(handle) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.GetName(uint flags, uint bufLen, uint* nameLen, char* nameBuf)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        try
        {
            if (flags != 0)
                throw new ArgumentException();

            string name;
            if (_typeHandle is null)
            {
                Contracts.ModuleHandle module = _target.Contracts.Loader.GetModuleHandleFromModulePtr(_module);
                MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(module) ?? throw new InvalidOperationException("Module metadata is unavailable.");
                TypeDefinitionHandle typeDefinitionHandle = MetadataTokens.TypeDefinitionHandle((int)EcmaMetadataUtils.GetRowId(_token));
                TypeDefinition typeDefinition = reader.GetTypeDefinition(typeDefinitionHandle);
                string typeName = reader.GetString(typeDefinition.Name);
                string typeNamespace = reader.GetString(typeDefinition.Namespace);
                name = string.IsNullOrEmpty(typeNamespace) ? typeName : $"{typeNamespace}.{typeName}";
            }
            else
            {
                name = _typeHandle.GetName(_target);
            }

            OutputBufferHelpers.CopyStringToBuffer(nameBuf, bufLen, nameLen, name, out bool truncated);
            if (nameBuf is not null && truncated)
                throw Marshal.GetExceptionForHR(CorDbgHResults.ERROR_INSUFFICIENT_BUFFER)!;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            uint nameLenLocal = 0;
            char[] nameBufLocal = new char[bufLen > 0 ? bufLen : 1];
            int hrLocal;
            fixed (char* pNameBufLocal = nameBufLocal)
            {
                hrLocal = _legacyImpl.GetName(flags, bufLen, &nameLenLocal, nameBuf is null ? null : pNameBufLocal);

                Debug.ValidateHResult(hr, hrLocal);
                if (hr >= 0)
                {
                    if (nameLen is not null)
                        Debug.Assert(nameLenLocal == *nameLen, $"cDAC: {*nameLen:x}, DAC: {nameLenLocal:x}");

                    if (nameBuf is not null)
                    {
                        string dacName = new(pNameBufLocal);
                        string cdacName = new(nameBuf);
                        Debug.Assert(dacName == cdacName, $"cDAC: {cdacName}, DAC: {dacName}");
                    }
                }
            }
        }
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.GetTokenAndScope(uint* token, DacComNullableByRef<IXCLRDataModule> mod)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        try
        {
            if (token is not null)
                *token = _token;

            if (!mod.IsNullRef)
            {
                IXCLRDataModule? legacyMod = null;
                if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null)
                {
                    DacComNullableByRef<IXCLRDataModule> legacyModOut = new(isNullRef: false);
                    int hrLegacy = _legacyImpl.GetTokenAndScope(null, legacyModOut);
                    Marshal.ThrowExceptionForHR(hrLegacy);
                    legacyMod = legacyModOut.Interface;
                }

                mod.Interface = new ClrDataModule(_module, _target, legacyMod, _apiLock);
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            bool validateToken = token is not null;
            uint tokenLocal = 0;
            DacComNullableByRef<IXCLRDataModule> legacyModOut = new(isNullRef: mod.IsNullRef);
            int hrLocal = _legacyImpl.GetTokenAndScope(validateToken ? &tokenLocal : null, legacyModOut);

            Debug.ValidateHResult(hr, hrLocal);
            if (validateToken && hr >= 0)
                Debug.Assert(tokenLocal == *token, $"cDAC: {*token:x}, DAC: {tokenLocal:x}");
        }
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.GetCorElementType(uint* type)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        try
        {
            if (type is null)
                throw new NullReferenceException();

            if (_typeHandle is null)
                throw new InvalidOperationException("Type handle is unavailable.");

            *type = (uint)_target.Contracts.RuntimeTypeSystem.GetInternalCorElementType(_typeHandle);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            uint typeLocal = 0;
            int hrLocal = _legacyImpl.GetCorElementType(type is null ? null : &typeLocal);

            Debug.ValidateHResult(hr, hrLocal);
            if (hr >= 0)
                Debug.Assert(typeLocal == *type, $"cDAC: {*type:x}, DAC: {typeLocal:x}");
        }
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.GetFlags(uint* flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (flags is null)
            return HResults.E_POINTER;

        *flags = 0; // CLRDATA_TYPE_DEFAULT

#if DEBUG
        if (_legacyImpl is not null)
        {
            uint flagsLocal = 0;
            int hrLocal = _legacyImpl.GetFlags(&flagsLocal);
            Debug.ValidateHResult(HResults.S_OK, hrLocal);
            Debug.Assert(flagsLocal == *flags, $"cDAC: {*flags}, DAC: {flagsLocal}");
        }
#endif

        return HResults.S_OK;
    }

    int IXCLRDataTypeDefinition.IsSameObject(IXCLRDataTypeDefinition? type)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_FALSE;
        try
        {
            if (type is ClrDataTypeDefinition other)
            {
                hr = _typeHandle is null
                    ? (_module == other._module && _token == other._token ? HResults.S_OK : HResults.S_FALSE)
                    : (other._typeHandle is not null && _typeHandle.Address == other._typeHandle.Address
                        ? HResults.S_OK
                        : HResults.S_FALSE);
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            int hrLocal = _legacyImpl.IsSameObject(type);
            Debug.Assert(hrLocal == hr, $"cDAC: {hr}, DAC: {hrLocal}");
        }
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.Request(uint reqCode, uint inBufferSize, byte* inBuffer, uint outBufferSize, byte* outBuffer)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.Request(reqCode, inBufferSize, inBuffer, outBufferSize, outBuffer) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.GetArrayRank(uint* rank)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (rank is null)
            return HResults.E_POINTER;
        if (_typeHandle is null)
            return HResults.E_NOTIMPL;

        try
        {
            if (!_target.Contracts.RuntimeTypeSystem.IsArray(_typeHandle, out uint arrayRank))
                return HResults.E_NOINTERFACE;

            *rank = arrayRank;
            return HResults.S_OK;
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }
    }

    int IXCLRDataTypeDefinition.GetBase(DacComNullableByRef<IXCLRDataTypeDefinition> @base)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        IXCLRDataTypeDefinition? legacyBase = null;

        try
        {
            if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataTypeDefinition> legacyBaseOut = new(isNullRef: @base.IsNullRef);
                hrLocal = _legacyImpl.GetBase(legacyBaseOut);
                legacyBase = legacyBaseOut.Interface;
            }

            if (@base.IsNullRef)
                return HResults.S_OK;

            uint baseToken;
            ITypeHandle? baseTypeHandle = null;
            if (_typeHandle is null)
            {
                Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(_module);
                MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
                    ?? throw new InvalidOperationException("Module metadata is unavailable.");
                TypeDefinitionHandle typeDefinition = MetadataTokens.TypeDefinitionHandle(
                    checked((int)EcmaMetadataUtils.GetRowId(_token)));
                EntityHandle extends = reader.GetTypeDefinition(typeDefinition).BaseType;
                baseToken = extends.IsNil ? 0u : (uint)MetadataTokens.GetToken(extends);
            }
            else
            {
                IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
                TargetPointer parentMethodTable = rts.GetParentMethodTable(_typeHandle);
                if (parentMethodTable == TargetPointer.Null)
                    return HResults.E_NOINTERFACE;

                baseTypeHandle = rts.GetTypeHandle(parentMethodTable);
                baseToken = rts.GetTypeDefToken(baseTypeHandle);
            }

            @base.Interface = new ClrDataTypeDefinition(
                _target,
                _module,
                baseToken,
                baseTypeHandle,
                legacyBase,
                _apiLock);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.GetNumFields(uint flags, uint* numFields)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (numFields is null)
            return HResults.E_POINTER;
        if (_typeHandle is null)
            return HResults.E_NOTIMPL;

        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        try
        {
            if (_legacyImpl is not null)
                hrLocal = _legacyImpl.GetNumFields(flags, numFields);

            *numFields = (uint)GetFields(flags).Count;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
        {
            Debug.ValidateHResult(hr, hrLocal);
            if (hr >= 0)
            {
                uint legacyCount = 0;
                _legacyImpl.GetNumFields(flags, &legacyCount);
                Debug.Assert(*numFields == legacyCount, $"cDAC: {*numFields}, DAC: {legacyCount}");
            }
        }
#endif

        return hr;
    }

    int IXCLRDataTypeDefinition.StartEnumFields(uint flags, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return StartEnumFieldsCore(null, 0, flags, handle);
    }

    int IXCLRDataTypeDefinition.EnumField(ulong* handle, uint nameBufLen, uint* nameLen, char* nameBuf, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EnumFieldCore(handle, nameBufLen, nameLen, nameBuf, type, flags, token, byName: false, null);
    }

    int IXCLRDataTypeDefinition.EndEnumFields(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EndEnumFieldsCore(handle);
    }

    int IXCLRDataTypeDefinition.StartEnumFieldsByName(char* name, uint nameFlags, uint fieldFlags, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (name is null)
            return HResults.E_POINTER;
        return StartEnumFieldsCore(new string(name), nameFlags, fieldFlags, handle);
    }

    int IXCLRDataTypeDefinition.EnumFieldByName(ulong* handle, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EnumFieldCore(handle, 0, null, null, type, flags, token, byName: true, null);
    }

    int IXCLRDataTypeDefinition.EndEnumFieldsByName(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EndEnumFieldsCore(handle);
    }

    int IXCLRDataTypeDefinition.GetFieldByToken(uint token, uint nameBufLen, uint* nameLen, char* nameBuf, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return GetFieldByTokenCore(null, token, nameBufLen, nameLen, nameBuf, type, flags);
    }

    int IXCLRDataTypeDefinition.GetTypeNotification(uint* flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.GetTypeNotification(flags) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.SetTypeNotification(uint flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.SetTypeNotification(flags) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeDefinition.EnumField2(ulong* handle, uint nameBufLen, uint* nameLen, char* nameBuf, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags, DacComNullableByRef<IXCLRDataModule> tokenScope, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EnumFieldCore(handle, nameBufLen, nameLen, nameBuf, type, flags, token, byName: false, tokenScope);
    }

    int IXCLRDataTypeDefinition.EnumFieldByName2(ulong* handle, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags, DacComNullableByRef<IXCLRDataModule> tokenScope, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return EnumFieldCore(handle, 0, null, null, type, flags, token, byName: true, tokenScope);
    }

    int IXCLRDataTypeDefinition.GetFieldByToken2(IXCLRDataModule? tokenScope, uint token, uint nameBufLen, uint* nameLen, char* nameBuf, DacComNullableByRef<IXCLRDataTypeDefinition> type, uint* flags)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        return GetFieldByTokenCore(tokenScope, token, nameBufLen, nameLen, nameBuf, type, flags);
    }

    private int StartEnumFieldsCore(string? name, uint nameFlags, uint fieldFlags, ulong* handle)
    {
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        ulong legacyHandle = 0;

        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));
            *handle = 0;

            if (_legacyImpl is not null)
            {
                if (name is null)
                {
                    hrLocal = _legacyImpl.StartEnumFields(fieldFlags, &legacyHandle);
                }
                else
                {
                    fixed (char* namePtr = name)
                        hrLocal = _legacyImpl.StartEnumFieldsByName(namePtr, nameFlags, fieldFlags, &legacyHandle);
                }
            }

            if (_typeHandle is null)
                return HResults.E_NOTIMPL;
            if (name is not null && (name.Length == 0 || nameFlags > (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE))
                throw new ArgumentException();

            List<FieldEntry> fields = GetFields(fieldFlags);
            if (name is not null)
            {
                int separatorIndex = name.LastIndexOf('.');
                string memberName = separatorIndex >= 0 ? name[(separatorIndex + 1)..] : name;
                StringComparison comparison = nameFlags == (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal;
                fields = fields
                    .Where(entry => string.Equals(GetFieldMetadata(entry).Name, memberName, comparison))
                    .ToList();
            }

            EnumFields enumeration = new(fields, name is not null, (nuint)legacyHandle);
            *handle = (ulong)((IEnum<FieldEntry>)enumeration).GetHandle();
            legacyHandle = 0;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
            {
                if (name is null)
                    _legacyImpl.EndEnumFields(legacyHandle);
                else
                    _legacyImpl.EndEnumFieldsByName(legacyHandle);
            }
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    private int EnumFieldCore(
        ulong* handle,
        uint nameBufLen,
        uint* nameLen,
        char* nameBuf,
        DacComNullableByRef<IXCLRDataTypeDefinition> type,
        uint* flags,
        uint* token,
        bool byName,
        DacComNullableByRef<IXCLRDataModule>? tokenScope)
    {
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        EnumFields? enumeration = null;
        IXCLRDataTypeDefinition? legacyType = null;
        IXCLRDataModule? legacyTokenScope = null;
        uint legacyNameLen = 0;
        uint legacyToken = 0;
        char[] legacyName = new char[nameBufLen > 0 ? nameBufLen : 1];

        try
        {
            if (handle is null || *handle == 0)
                throw new ArgumentException("Invalid field handle.", nameof(handle));
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not EnumFields fields)
                throw new ArgumentException("Invalid field handle.", nameof(handle));
            enumeration = fields;

            if (_legacyImpl is not null && enumeration.LegacyHandle != 0)
            {
                ulong legacyHandle = enumeration.LegacyHandle;
                DacComNullableByRef<IXCLRDataTypeDefinition> legacyTypeOut = new(isNullRef: type.IsNullRef);
                DacComNullableByRef<IXCLRDataModule>? legacyScopeOut = tokenScope is null
                    ? null
                    : new(isNullRef: tokenScope.Value.IsNullRef);
                fixed (char* legacyNamePtr = legacyName)
                {
                    if (tokenScope is null)
                    {
                        hrLocal = byName
                            ? _legacyImpl.EnumFieldByName(&legacyHandle, legacyTypeOut, &legacyToken)
                            : _legacyImpl.EnumField(&legacyHandle, nameBufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr, legacyTypeOut, flags, &legacyToken);
                    }
                    else
                    {
                        hrLocal = byName
                            ? _legacyImpl.EnumFieldByName2(&legacyHandle, legacyTypeOut, legacyScopeOut!.Value, &legacyToken)
                            : _legacyImpl.EnumField2(&legacyHandle, nameBufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr, legacyTypeOut, flags, legacyScopeOut!.Value, &legacyToken);
                    }
                }
                enumeration.LegacyHandle = (nuint)legacyHandle;
                if (hrLocal >= 0)
                {
                    legacyType = legacyTypeOut.Interface;
                    legacyTokenScope = legacyScopeOut?.Interface;
                }
            }

            if (!enumeration.Enumerator.MoveNext())
            {
                hr = HResults.S_FALSE;
            }
            else
            {
                FieldEntry entry = enumeration.Enumerator.Current;
                (string fieldName, uint fieldToken, FieldDefinition fieldDefinition) = GetFieldMetadata(entry);
                if (!byName)
                {
                    OutputBufferHelpers.CopyStringToBuffer(nameBuf, nameBufLen, nameLen, fieldName);
                    if (nameBuf is not null && nameBufLen != 0 && nameBufLen < fieldName.Length + 1)
                        hr = CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
                }

                if (hr >= 0)
                {
                    if (flags is not null)
                        *flags = GetFieldFlags(entry, fieldDefinition);
                    if (token is not null)
                        *token = fieldToken;
                    if (!type.IsNullRef)
                        type.Interface = CreateFieldType(entry, legacyType);
                    if (tokenScope is not null && !tokenScope.Value.IsNullRef)
                    {
                        TargetPointer fieldModule = _target.Contracts.RuntimeTypeSystem.GetModule(entry.EnclosingType);
                        tokenScope.Value.Interface = new ClrDataModule(fieldModule, _target, legacyTokenScope, _apiLock);
                    }
                }
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null && enumeration is not null)
        {
            Debug.ValidateHResult(hr, hrLocal, HResultValidationMode.AllowCdacSuccess);
            if (hr >= 0 && hrLocal >= 0)
            {
                Debug.Assert(token is null || *token == legacyToken);
                Debug.Assert(nameLen is null || *nameLen == legacyNameLen);
            }
        }
#endif
        return hr;
    }

    private int EndEnumFieldsCore(ulong handle)
    {
        if (handle == 0)
            return HResults.S_OK;

        EnumFields fields;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not EnumFields fieldsLocal)
                throw new ArgumentException("Invalid field handle.", nameof(handle));
            fields = fieldsLocal;
            ((IEnum<FieldEntry>)fields).Dispose();
            gcHandle.Free();
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && fields.LegacyHandle != 0)
            return fields.ByName
                ? _legacyImpl.EndEnumFieldsByName(fields.LegacyHandle)
                : _legacyImpl.EndEnumFields(fields.LegacyHandle);
        return HResults.S_OK;
    }

    private List<FieldEntry> GetFields(uint flags)
    {
        ValidateFieldFlags(flags);
        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        bool includeParents = (flags & (uint)ClrDataValueFlag.IS_INHERITED) != 0;
        bool includeInstanceFields = (flags & (uint)ClrDataValueFlag.FROM_INSTANCE) != 0;
        bool includeStaticFields = (flags & (uint)ClrDataValueFlag.FROM_STATIC) != 0;

        List<ITypeHandle> types = [];
        ITypeHandle current = _typeHandle ?? throw new InvalidOperationException("Type handle is unavailable.");
        do
        {
            types.Add(current);
            if (!includeParents)
                break;
            TargetPointer parent = rts.GetParentMethodTable(current);
            if (parent == TargetPointer.Null)
                break;
            current = rts.GetTypeHandle(parent);
        }
        while (true);

        types.Reverse();
        List<FieldEntry> fields = [];
        for (int i = 0; i < types.Count; i++)
        {
            bool inherited = i != types.Count - 1;
            foreach (TargetPointer fieldDesc in rts.GetFieldDescList(types[i]))
            {
                bool isStatic = rts.IsFieldDescStatic(fieldDesc) || rts.IsFieldDescThreadStatic(fieldDesc);
                if ((isStatic && includeStaticFields) || (!isStatic && includeInstanceFields))
                    fields.Add(new FieldEntry(fieldDesc, types[i], inherited));
            }
        }
        return fields;
    }

    private (string Name, uint Token, FieldDefinition Definition) GetFieldMetadata(FieldEntry entry)
    {
        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(
            rts.GetModule(entry.EnclosingType));
        MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
            ?? throw new InvalidOperationException("Module metadata is unavailable.");
        uint token = rts.GetFieldDescMemberDef(entry.FieldDesc);
        FieldDefinition definition = reader.GetFieldDefinition(
            MetadataTokens.FieldDefinitionHandle(checked((int)EcmaMetadataUtils.GetRowId(token))));
        return (reader.GetString(definition.Name), token, definition);
    }

    private ClrDataTypeDefinition CreateFieldType(FieldEntry entry, IXCLRDataTypeDefinition? legacyType)
    {
        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        ITypeHandle fieldType = rts.GetFieldDescApproxTypeHandle(entry.FieldDesc)
            ?? throw new InvalidOperationException("Field type handle is unavailable.");
        TargetPointer module = rts.GetModule(fieldType);
        uint token = rts.GetTypeDefToken(fieldType);
        return new ClrDataTypeDefinition(_target, module, token, fieldType, legacyType, _apiLock);
    }

    private uint GetFieldFlags(FieldEntry entry, FieldDefinition definition)
    {
        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        uint flags = entry.IsInherited ? (uint)ClrDataValueFlag.IS_INHERITED : 0;
        flags &= ~(uint)ClrDataValueFlag.ALL_KINDS;
        CorElementType elementType = rts.GetFieldDescType(entry.FieldDesc);

        if (rts.IsCorElementTypeObjRef(elementType))
            flags |= (uint)ClrDataValueFlag.IS_REFERENCE;
        else if (_typeHandle is not null && rts.IsEnum(_typeHandle))
            flags |= (uint)ClrDataValueFlag.IS_ENUM;
        else if (elementType == CorElementType.String)
            flags |= (uint)ClrDataValueFlag.IS_STRING;
        else if (elementType == CorElementType.Ptr)
            flags |= (uint)ClrDataValueFlag.IS_POINTER;
        else if (elementType is >= CorElementType.Void and <= CorElementType.R8 or CorElementType.I or CorElementType.U)
            flags |= (uint)ClrDataValueFlag.IS_PRIMITIVE;
        else if (_typeHandle is not null && rts.IsArray(_typeHandle, out _))
            flags |= (uint)ClrDataValueFlag.IS_ARRAY;
        else if (_typeHandle is not null && rts.IsValueType(_typeHandle))
            flags |= (uint)ClrDataValueFlag.IS_VALUE_TYPE;

        flags &= ~((uint)ClrDataValueFlag.IS_LITERAL
            | (uint)ClrDataValueFlag.FROM_INSTANCE
            | (uint)ClrDataValueFlag.FROM_TASK_LOCAL
            | (uint)ClrDataValueFlag.FROM_STATIC);
        if ((flags & (uint)ClrDataValueFlag.IS_REFERENCE) == 0
            && (definition.Attributes & FieldAttributes.Literal) != 0)
            flags |= (uint)ClrDataValueFlag.IS_LITERAL;

        if (rts.IsFieldDescStatic(entry.FieldDesc))
            flags |= (uint)ClrDataValueFlag.FROM_STATIC;
        else if (rts.IsFieldDescThreadStatic(entry.FieldDesc))
            flags |= (uint)ClrDataValueFlag.FROM_TASK_LOCAL;
        else
            flags |= (uint)ClrDataValueFlag.FROM_INSTANCE;
        return flags;
    }

    private static void ValidateFieldFlags(uint flags)
    {
        if ((flags & ~(uint)ClrDataValueFlag.ALL_FIELDS) != 0
            || (flags & (uint)ClrDataValueFlag.ALL_KINDS) != (uint)ClrDataValueFlag.ALL_KINDS
            || (flags & (uint)ClrDataValueFlag.ALL_LOCATIONS) == 0)
            throw new ArgumentException(nameof(flags));
    }

    private int GetFieldByTokenCore(
        IXCLRDataModule? tokenScope,
        uint token,
        uint nameBufLen,
        uint* nameLen,
        char* nameBuf,
        DacComNullableByRef<IXCLRDataTypeDefinition> type,
        uint* flags)
    {
        int hr = HResults.E_INVALIDARG;
        int hrLocal = HResults.S_OK;
        IXCLRDataTypeDefinition? legacyType = null;
        uint legacyNameLen = 0;
        char[] legacyName = new char[nameBufLen > 0 ? nameBufLen : 1];

        try
        {
            if (_legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataTypeDefinition> legacyTypeOut = new(isNullRef: type.IsNullRef);
                fixed (char* legacyNamePtr = legacyName)
                {
                    hrLocal = tokenScope is null
                        ? _legacyImpl.GetFieldByToken(token, nameBufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr, legacyTypeOut, flags)
                        : _legacyImpl.GetFieldByToken2(tokenScope, token, nameBufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr, legacyTypeOut, flags);
                }
                legacyType = legacyTypeOut.Interface;
            }

            if (_typeHandle is null)
                return HResults.E_NOTIMPL;

            TargetPointer tokenScopeAddress = TargetPointer.Null;
            if (tokenScope is not null)
            {
                if (tokenScope is not ClrDataModule module)
                    throw new ArgumentException(nameof(tokenScope));
                tokenScopeAddress = module.Address;
            }

            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
            foreach (FieldEntry entry in GetFields((uint)ClrDataValueFlag.ALL_FIELDS))
            {
                (string fieldName, uint fieldToken, FieldDefinition fieldDefinition) = GetFieldMetadata(entry);
                TargetPointer fieldModule = rts.GetModule(entry.EnclosingType);
                if (fieldToken != token || (tokenScope is not null && fieldModule != tokenScopeAddress))
                    continue;

                if (flags is not null)
                    *flags = GetFieldFlags(entry, fieldDefinition);
                OutputBufferHelpers.CopyStringToBuffer(nameBuf, nameBufLen, nameLen, fieldName);
                if (nameBuf is not null && nameBufLen != 0 && nameBufLen < fieldName.Length + 1)
                    return CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
                if (!type.IsNullRef)
                    type.Interface = CreateFieldType(entry, legacyType);
                return HResults.S_OK;
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal, HResultValidationMode.AllowCdacSuccess);
#endif
        return hr;
    }
}
