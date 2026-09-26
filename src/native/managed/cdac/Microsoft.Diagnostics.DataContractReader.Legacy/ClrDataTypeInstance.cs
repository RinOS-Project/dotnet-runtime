// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using System.Threading;
using Microsoft.Diagnostics.DataContractReader.Contracts;

namespace Microsoft.Diagnostics.DataContractReader.Legacy;

[GeneratedComClass]
public sealed unsafe partial class ClrDataTypeInstance : IXCLRDataTypeInstance
{
    private const uint InheritedStaticFieldFlags =
        (uint)ClrDataValueFlag.ALL_KINDS
        | (uint)ClrDataValueFlag.IS_INHERITED
        | (uint)ClrDataValueFlag.FROM_STATIC;

    private sealed class EnumMethodInstances : IEnum<uint>
    {
        public IEnumerator<uint> Enumerator { get; }
        public nuint LegacyHandle { get; set; }

        public EnumMethodInstances(IEnumerable<uint> tokens, nuint legacyHandle)
        {
            Enumerator = tokens.GetEnumerator();
            LegacyHandle = legacyHandle;
        }
    }

    private readonly record struct StaticFieldEntry(TargetPointer FieldDesc, bool IsInherited);

    private sealed class EnumStaticFields : IEnum<StaticFieldEntry>
    {
        public IEnumerator<StaticFieldEntry> Enumerator { get; }
        public nuint LegacyHandle { get; set; }
        public bool ByName { get; }
        public TargetPointer ThreadAddress { get; }

        public EnumStaticFields(
            IEnumerable<StaticFieldEntry> fields,
            bool byName,
            TargetPointer threadAddress,
            nuint legacyHandle)
        {
            Enumerator = fields.GetEnumerator();
            ByName = byName;
            ThreadAddress = threadAddress;
            LegacyHandle = legacyHandle;
        }
    }

    private readonly Lock _apiLock;
    private readonly Target _target;
    private readonly ITypeHandle _typeHandle;
    private readonly TargetPointer _appDomain;
    private readonly IXCLRDataTypeInstance? _legacyImpl;

    internal ITypeHandle TypeHandle => _typeHandle;
    internal IXCLRDataTypeInstance? LegacyImpl => _legacyImpl;

    public ClrDataTypeInstance(
        Target target,
        ITypeHandle typeHandle,
        IXCLRDataTypeInstance? legacyImpl,
        Lock apiLock,
        TargetPointer appDomain = default)
    {
        _apiLock = apiLock;
        _target = target;
        _typeHandle = typeHandle;
        _appDomain = appDomain;
        _legacyImpl = legacyImpl;
    }

    private IEnumerable<uint> GetMethodDefinitionTokens(string? methodName, uint flags)
    {
        if (flags > (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE)
            throw new ArgumentException("Invalid method name flags.", nameof(flags));

        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        uint typeToken = rts.GetTypeDefToken(_typeHandle);
        if ((typeToken & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtTypeDef)
            throw new InvalidOperationException("The type handle is not a method table.");

        Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(rts.GetModule(_typeHandle));
        MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
            ?? throw new InvalidOperationException("Module metadata is unavailable.");
        TypeDefinition definition = reader.GetTypeDefinition(
            MetadataTokens.TypeDefinitionHandle(checked((int)EcmaMetadataUtils.GetRowId(typeToken))));
        StringComparison comparison = flags == (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

        return definition.GetMethods()
            .Where(method => methodName is null || string.Equals(
                reader.GetString(reader.GetMethodDefinition(method).Name),
                methodName,
                comparison))
            .Select(method => (uint)MetadataTokens.GetToken(method))
            .ToArray();
    }

    int IXCLRDataTypeInstance.StartEnumMethodInstances(ulong* handle)
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
                hrLocal = _legacyImpl.StartEnumMethodInstances(&legacyHandle);

            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
            uint typeToken = rts.GetTypeDefToken(_typeHandle);
            if ((typeToken & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtTypeDef)
                return HResults.S_FALSE;

            EnumMethodInstances instances = new(GetMethodDefinitionTokens(null, 0), (nuint)legacyHandle);
            *handle = (ulong)((IEnum<uint>)instances).GetHandle();
            legacyHandle = 0;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
                _legacyImpl.EndEnumMethodInstances(legacyHandle);
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    int IXCLRDataTypeInstance.EnumMethodInstance(ulong* handle, DacComNullableByRef<IXCLRDataMethodInstance> methodInstance)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        EnumMethodInstances instances;
        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));
            if (*handle == 0)
                return HResults.S_FALSE;
            if (methodInstance.IsNullRef)
                throw new NullReferenceException();

            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not EnumMethodInstances instancesLocal)
                throw new ArgumentException();
            instances = instancesLocal;
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        IXCLRDataMethodInstance? legacyMethod = null;
        if (_legacyImpl is not null)
        {
            ulong legacyHandle = instances.LegacyHandle;
            DacComNullableByRef<IXCLRDataMethodInstance> legacyMethodOut = new(isNullRef: false);
            hrLocal = _legacyImpl.EnumMethodInstance(&legacyHandle, legacyMethodOut);
            legacyMethod = legacyMethodOut.Interface;
            instances.LegacyHandle = (nuint)legacyHandle;
        }

        try
        {
            ILoader loader = _target.Contracts.Loader;
            Contracts.ModuleHandle moduleHandle = loader.GetModuleHandleFromModulePtr(
                _target.Contracts.RuntimeTypeSystem.GetModule(_typeHandle));
            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;

            while (instances.Enumerator.MoveNext())
            {
                TargetPointer methodDescAddress = loader.GetModuleLookupMapElement(
                    moduleHandle,
                    ModuleLookupMapKind.MethodDefToDesc,
                    instances.Enumerator.Current,
                    out _);
                if (methodDescAddress == TargetPointer.Null)
                    continue;

                MethodDescHandle methodDesc = rts.GetMethodDescHandle(methodDescAddress);
                if (rts.GetNativeCode(methodDesc) == TargetCodePointer.Null)
                    continue;

                methodInstance.Interface = new ClrDataMethodInstance(
                    _target,
                    methodDesc,
                    _appDomain,
                    legacyMethod,
                    _apiLock);
                return HResults.S_OK;
            }

            hr = HResults.S_FALSE;
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

    int IXCLRDataTypeInstance.EndEnumMethodInstances(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (handle == 0)
            return HResults.S_OK;

        EnumMethodInstances instances;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not EnumMethodInstances instancesLocal)
                throw new ArgumentException();
            instances = instancesLocal;
            ((IEnum<uint>)instances).Dispose();
            gcHandle.Free();
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && instances.LegacyHandle != 0)
            return _legacyImpl.EndEnumMethodInstances(instances.LegacyHandle);
        return HResults.S_OK;
    }

    int IXCLRDataTypeInstance.StartEnumMethodInstancesByName(char* name, uint flags, ulong* handle)
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
                hrLocal = _legacyImpl.StartEnumMethodInstancesByName(name, flags, &legacyHandle);

            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
            uint typeToken = rts.GetTypeDefToken(_typeHandle);
            if ((typeToken & EcmaMetadataUtils.TokenTypeMask) != (uint)EcmaMetadataUtils.TokenType.mdtTypeDef)
                return HResults.S_FALSE;
            if (name is null || *name == '\0')
                throw new ArgumentException();

            EnumMethodInstances instances = new(
                GetMethodDefinitionTokens(new string(name), flags),
                (nuint)legacyHandle);
            *handle = (ulong)((IEnum<uint>)instances).GetHandle();
            legacyHandle = 0;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }
        finally
        {
            if (_legacyImpl is not null && legacyHandle != 0)
                _legacyImpl.EndEnumMethodInstancesByName(legacyHandle);
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    int IXCLRDataTypeInstance.EnumMethodInstanceByName(ulong* handle, DacComNullableByRef<IXCLRDataMethodInstance> method)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        EnumMethodInstances instances;
        try
        {
            if (handle is null)
                throw new ArgumentNullException(nameof(handle));
            if (*handle == 0)
                return HResults.S_FALSE;
            if (method.IsNullRef)
                throw new NullReferenceException();

            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not EnumMethodInstances instancesLocal)
                throw new ArgumentException();
            instances = instancesLocal;
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        IXCLRDataMethodInstance? legacyMethod = null;
        if (_legacyImpl is not null)
        {
            ulong legacyHandle = instances.LegacyHandle;
            DacComNullableByRef<IXCLRDataMethodInstance> legacyMethodOut = new(isNullRef: false);
            hrLocal = _legacyImpl.EnumMethodInstanceByName(&legacyHandle, legacyMethodOut);
            legacyMethod = legacyMethodOut.Interface;
            instances.LegacyHandle = (nuint)legacyHandle;
        }

        try
        {
            ILoader loader = _target.Contracts.Loader;
            Contracts.ModuleHandle moduleHandle = loader.GetModuleHandleFromModulePtr(
                _target.Contracts.RuntimeTypeSystem.GetModule(_typeHandle));
            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;

            while (instances.Enumerator.MoveNext())
            {
                TargetPointer methodDescAddress = loader.GetModuleLookupMapElement(
                    moduleHandle,
                    ModuleLookupMapKind.MethodDefToDesc,
                    instances.Enumerator.Current,
                    out _);
                if (methodDescAddress == TargetPointer.Null)
                    continue;

                MethodDescHandle methodDesc = rts.GetMethodDescHandle(methodDescAddress);
                if (rts.GetNativeCode(methodDesc) == TargetCodePointer.Null)
                    continue;

                method.Interface = new ClrDataMethodInstance(
                    _target,
                    methodDesc,
                    _appDomain,
                    legacyMethod,
                    _apiLock);
                return HResults.S_OK;
            }

            hr = HResults.S_FALSE;
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

    int IXCLRDataTypeInstance.EndEnumMethodInstancesByName(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        if (handle == 0)
            return HResults.S_OK;

        EnumMethodInstances instances;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not EnumMethodInstances instancesLocal)
                throw new ArgumentException();
            instances = instancesLocal;
            ((IEnum<uint>)instances).Dispose();
            gcHandle.Free();
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && instances.LegacyHandle != 0)
            return _legacyImpl.EndEnumMethodInstancesByName(instances.LegacyHandle);
        return HResults.S_OK;
    }

    private static TargetPointer GetThreadAddress(IXCLRDataTask? tlsTask)
        => tlsTask is ClrDataTask task ? task.Address : TargetPointer.Null;

    private List<StaticFieldEntry> GetStaticFields(uint flags)
    {
        ValidateStaticFieldFlags(flags);

        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        List<ITypeHandle> types = [];
        ITypeHandle current = _typeHandle;
        do
        {
            types.Add(current);
            if ((flags & (uint)ClrDataValueFlag.IS_INHERITED) == 0)
                break;

            TargetPointer parent = rts.GetParentMethodTable(current);
            if (parent == TargetPointer.Null)
                break;
            current = rts.GetTypeHandle(parent);
        }
        while (true);

        types.Reverse();
        List<StaticFieldEntry> fields = [];
        for (int i = 0; i < types.Count; i++)
        {
            bool inherited = i != types.Count - 1;
            foreach (TargetPointer fieldDesc in rts.GetFieldDescList(types[i]))
            {
                bool includeStatic = (flags & (uint)ClrDataValueFlag.FROM_STATIC) != 0;
                bool includeThreadStatic = (flags & (uint)ClrDataValueFlag.FROM_TASK_LOCAL) != 0;
                if ((rts.IsFieldDescStatic(fieldDesc) && includeStatic)
                    || (rts.IsFieldDescThreadStatic(fieldDesc) && (includeStatic || includeThreadStatic)))
                    fields.Add(new StaticFieldEntry(fieldDesc, inherited));
            }
        }

        return fields;
    }

    private static void ValidateStaticFieldFlags(uint flags)
    {
        if ((flags & ~(uint)ClrDataValueFlag.ALL_FIELDS) != 0
            || (flags & (uint)ClrDataValueFlag.ALL_KINDS) != (uint)ClrDataValueFlag.ALL_KINDS
            || (flags & (uint)ClrDataValueFlag.ALL_LOCATIONS) == 0)
        {
            throw new ArgumentException(nameof(flags));
        }
    }

    private (string Name, uint Token, ITypeHandle EnclosingType) GetStaticFieldMetadata(TargetPointer fieldDesc)
    {
        IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
        ITypeHandle enclosingType = rts.GetTypeHandle(rts.GetMTOfEnclosingClass(fieldDesc));
        Contracts.ModuleHandle moduleHandle = _target.Contracts.Loader.GetModuleHandleFromModulePtr(rts.GetModule(enclosingType));
        MetadataReader reader = _target.Contracts.EcmaMetadata.GetMetadata(moduleHandle)
            ?? throw new InvalidOperationException("Module metadata is unavailable.");
        uint token = rts.GetFieldDescMemberDef(fieldDesc);
        FieldDefinition definition = reader.GetFieldDefinition(
            MetadataTokens.FieldDefinitionHandle(checked((int)EcmaMetadataUtils.GetRowId(token))));
        return (reader.GetString(definition.Name), token, enclosingType);
    }

    private int StartEnumStaticFieldsCore(
        string? name,
        uint nameFlags,
        uint fieldFlags,
        IXCLRDataTask? tlsTask,
        ulong* handle,
        bool byName)
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
                if (byName)
                {
                    fixed (char* namePtr = name)
                        hrLocal = _legacyImpl.StartEnumStaticFieldsByName2(namePtr, nameFlags, fieldFlags, tlsTask, &legacyHandle);
                }
                else
                {
                    hrLocal = _legacyImpl.StartEnumStaticFields(fieldFlags, tlsTask, &legacyHandle);
                }
            }

            if (name is not null && name.Length == 0)
                throw new ArgumentException(nameof(name));
            if (nameFlags > (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE)
                throw new ArgumentException(nameof(nameFlags));

            List<StaticFieldEntry> fields = GetStaticFields(fieldFlags);
            if (name is not null)
            {
                int separatorIndex = name.LastIndexOf('.');
                string memberName = separatorIndex >= 0 ? name[(separatorIndex + 1)..] : name;
                StringComparison comparison = nameFlags == (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_INSENSITIVE
                    ? StringComparison.OrdinalIgnoreCase
                    : StringComparison.Ordinal;
                fields = fields.Where(entry => string.Equals(
                    GetStaticFieldMetadata(entry.FieldDesc).Name,
                    memberName,
                    comparison)).ToList();
            }

            EnumStaticFields enumeration = new(fields, byName, GetThreadAddress(tlsTask), (nuint)legacyHandle);
            *handle = (ulong)((IEnum<StaticFieldEntry>)enumeration).GetHandle();
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
                if (byName)
                    _legacyImpl.EndEnumStaticFieldsByName2(legacyHandle);
                else
                    _legacyImpl.EndEnumStaticFields(legacyHandle);
            }
        }

#if DEBUG
        if (_legacyImpl is not null)
            Debug.ValidateHResult(hr, hrLocal);
#endif
        return hr;
    }

    private int EnumStaticFieldCore(
        ulong* handle,
        DacComNullableByRef<IXCLRDataValue> field,
        uint bufLen,
        uint* nameLen,
        char* nameBuf,
        DacComNullableByRef<IXCLRDataModule>? tokenScope,
        uint* token)
    {
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        EnumStaticFields? enumeration = null;
        IXCLRDataValue? legacyField = null;
        IXCLRDataModule? legacyTokenScope = null;
        uint legacyNameLen = 0;
        uint legacyToken = 0;
        char[] legacyName = new char[bufLen > 0 ? bufLen : 1];

        try
        {
            if (handle is null || *handle == 0)
                throw new ArgumentException("Invalid static field handle.", nameof(handle));
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)(*handle));
            if (gcHandle.Target is not EnumStaticFields enumerationLocal)
                throw new ArgumentException("Invalid static field handle.", nameof(handle));
            enumeration = enumerationLocal;

            if (_legacyImpl is not null && enumeration.LegacyHandle != 0)
            {
                ulong legacyHandle = enumeration.LegacyHandle;
                DacComNullableByRef<IXCLRDataValue> legacyFieldOut = new(isNullRef: field.IsNullRef);
                DacComNullableByRef<IXCLRDataModule>? legacyScopeOut = tokenScope is null
                    ? null
                    : new(isNullRef: tokenScope.IsNullRef);
                fixed (char* legacyNamePtr = legacyName)
                {
                    if (tokenScope is null)
                    {
                        hrLocal = enumeration.ByName
                            ? _legacyImpl.EnumStaticFieldByName2(&legacyHandle, legacyFieldOut)
                            : _legacyImpl.EnumStaticField(&legacyHandle, legacyFieldOut);
                    }
                    else
                    {
                        hrLocal = enumeration.ByName
                            ? _legacyImpl.EnumStaticFieldByName3(&legacyHandle, legacyFieldOut, legacyScopeOut!, &legacyToken)
                            : _legacyImpl.EnumStaticField2(&legacyHandle, legacyFieldOut, bufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr, legacyScopeOut!, &legacyToken);
                    }
                }
                enumeration.LegacyHandle = (nuint)legacyHandle;
                if (hrLocal >= 0)
                {
                    legacyField = legacyFieldOut.Interface;
                    legacyTokenScope = legacyScopeOut?.Interface;
                }
            }

            if (!enumeration.Enumerator.MoveNext())
            {
                hr = HResults.S_FALSE;
            }
            else
            {
                StaticFieldEntry entry = enumeration.Enumerator.Current;
                (string fieldName, uint fieldToken, ITypeHandle enclosingType) = GetStaticFieldMetadata(entry.FieldDesc);
                OutputBufferHelpers.CopyStringToBuffer(nameBuf, bufLen, nameLen, fieldName);
                if (nameBuf is not null && bufLen != 0 && bufLen < fieldName.Length + 1)
                {
                    hr = CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
                }
                else
                {
                    if (token is not null)
                        *token = fieldToken;
                    if (!field.IsNullRef)
                    {
                        field.Interface = ClrDataValue.CreateStaticFieldValue(
                            _target,
                            enumeration.ThreadAddress,
                            entry.FieldDesc,
                            entry.IsInherited,
                            legacyField,
                            _apiLock);
                    }
                    if (tokenScope is not null && field.IsNullRef && !tokenScope.IsNullRef)
                    {
                        TargetPointer fieldModule = _target.Contracts.RuntimeTypeSystem.GetModule(enclosingType);
                        tokenScope.Interface = new ClrDataModule(fieldModule, _target, legacyTokenScope, _apiLock);
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
            Debug.ValidateHResult(hr, hrLocal, HResultValidationMode.AllowCdacSuccess);
#endif
        return hr;
    }

    private int EndEnumStaticFieldsCore(ulong handle, bool byName)
    {
        if (handle == 0)
            return HResults.S_OK;

        EnumStaticFields enumeration;
        nuint legacyHandle;
        try
        {
            GCHandle gcHandle = GCHandle.FromIntPtr((IntPtr)handle);
            if (gcHandle.Target is not EnumStaticFields enumerationLocal)
                throw new ArgumentException("Invalid static field handle.", nameof(handle));
            enumeration = enumerationLocal;
            legacyHandle = enumeration.LegacyHandle;
            ((IEnum<StaticFieldEntry>)enumeration).Dispose();
            gcHandle.Free();
        }
        catch (System.Exception ex)
        {
            return ex.HResult;
        }

        if (_legacyImpl is not null && legacyHandle != 0)
        {
            return byName
                ? _legacyImpl.EndEnumStaticFieldsByName2(legacyHandle)
                : _legacyImpl.EndEnumStaticFields(legacyHandle);
        }
        return HResults.S_OK;
    }

    private int GetStaticFieldByTokenCore(
        IXCLRDataModule? tokenScope,
        uint token,
        IXCLRDataTask? tlsTask,
        DacComNullableByRef<IXCLRDataValue> field,
        uint bufLen,
        uint* nameLen,
        char* nameBuf)
    {
        int hr = HResults.E_INVALIDARG;
        IXCLRDataValue? legacyField = null;
        uint legacyNameLen = 0;
        char[] legacyName = new char[bufLen > 0 ? bufLen : 1];

        try
        {
            if (_legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataValue> legacyFieldOut = new(isNullRef: field.IsNullRef);
                fixed (char* legacyNamePtr = legacyName)
                {
                    int hrLocal = tokenScope is null
                        ? _legacyImpl.GetStaticFieldByToken(token, tlsTask, legacyFieldOut, bufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr)
                        : _legacyImpl.GetStaticFieldByToken2(tokenScope, token, tlsTask, legacyFieldOut, bufLen, &legacyNameLen, nameBuf is null ? null : legacyNamePtr);
                    if (hrLocal >= 0)
                        legacyField = legacyFieldOut.Interface;
                }
            }

            TargetPointer tokenScopeAddress = TargetPointer.Null;
            if (tokenScope is not null)
            {
                if (tokenScope is not ClrDataModule module)
                    throw new ArgumentException(nameof(tokenScope));
                tokenScopeAddress = module.Address;
            }

            foreach (StaticFieldEntry entry in GetStaticFields(InheritedStaticFieldFlags))
            {
                (string fieldName, uint fieldToken, ITypeHandle enclosingType) = GetStaticFieldMetadata(entry.FieldDesc);
                TargetPointer fieldModule = _target.Contracts.RuntimeTypeSystem.GetModule(enclosingType);
                if (fieldToken != token || (tokenScope is not null && fieldModule != tokenScopeAddress))
                    continue;

                OutputBufferHelpers.CopyStringToBuffer(nameBuf, bufLen, nameLen, fieldName);
                if (nameBuf is not null && bufLen != 0 && bufLen < fieldName.Length + 1)
                    return CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
                if (!field.IsNullRef)
                {
                    field.Interface = ClrDataValue.CreateStaticFieldValue(
                        _target,
                        GetThreadAddress(tlsTask),
                        entry.FieldDesc,
                        entry.IsInherited,
                        legacyField,
                        _apiLock);
                }
                return HResults.S_OK;
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

        return hr;
    }

    int IXCLRDataTypeInstance.GetNumStaticFields(uint* numFields)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        try
        {
            if (_legacyImpl is not null)
                hrLocal = _legacyImpl.GetNumStaticFields(numFields);
            if (numFields is null)
                throw new ArgumentNullException(nameof(numFields));
            *numFields = (uint)GetStaticFields(InheritedStaticFieldFlags).Count;
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

    int IXCLRDataTypeInstance.GetStaticFieldByIndex(uint index, IXCLRDataTask? tlsTask, DacComNullableByRef<IXCLRDataValue> field, uint bufLen, uint* nameLen, char* nameBuf, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.E_INVALIDARG;
        try
        {
            IXCLRDataValue? legacyField = null;
            if (_legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataValue> legacyFieldOut = new(isNullRef: field.IsNullRef);
                uint legacyNameLen = 0;
                uint legacyToken = 0;
                char[] legacyName = new char[bufLen > 0 ? bufLen : 1];
                fixed (char* legacyNamePtr = legacyName)
                {
                    int hrLocal = _legacyImpl.GetStaticFieldByIndex(
                        index,
                        tlsTask,
                        legacyFieldOut,
                        bufLen,
                        &legacyNameLen,
                        nameBuf is null ? null : legacyNamePtr,
                        &legacyToken);
                    if (hrLocal >= 0)
                        legacyField = legacyFieldOut.Interface;
                }
            }

            List<StaticFieldEntry> fields = GetStaticFields(InheritedStaticFieldFlags);
            if (index >= fields.Count)
                return HResults.E_INVALIDARG;

            StaticFieldEntry entry = fields[(int)index];
            (string fieldName, uint fieldToken, _) = GetStaticFieldMetadata(entry.FieldDesc);
            OutputBufferHelpers.CopyStringToBuffer(nameBuf, bufLen, nameLen, fieldName);
            if (nameBuf is not null && bufLen != 0 && bufLen < fieldName.Length + 1)
                return CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
            if (token is not null)
                *token = fieldToken;
            if (!field.IsNullRef)
            {
                field.Interface = ClrDataValue.CreateStaticFieldValue(
                    _target,
                    GetThreadAddress(tlsTask),
                    entry.FieldDesc,
                    entry.IsInherited,
                    legacyField,
                    _apiLock);
            }
            hr = HResults.S_OK;
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

        return hr;
    }

    int IXCLRDataTypeInstance.StartEnumStaticFieldsByName(char* name, uint flags, IXCLRDataTask? tlsTask, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return StartEnumStaticFieldsCore(
            name is null ? null : new string(name),
            flags,
            InheritedStaticFieldFlags,
            tlsTask,
            handle,
            byName: true);
    }

    int IXCLRDataTypeInstance.EnumStaticFieldByName(ulong* handle, DacComNullableByRef<IXCLRDataValue> value)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EnumStaticFieldCore(handle, value, 0, null, null, tokenScope: null, token: null);
    }

    int IXCLRDataTypeInstance.EndEnumStaticFieldsByName(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EndEnumStaticFieldsCore(handle, byName: true);
    }

    int IXCLRDataTypeInstance.GetNumTypeArguments(uint* numTypeArgs)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.GetNumTypeArguments(numTypeArgs) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeInstance.GetTypeArgumentByIndex(uint index, DacComNullableByRef<IXCLRDataTypeInstance> typeArg)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.GetTypeArgumentByIndex(index, typeArg) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeInstance.GetName(uint flags, uint bufLen, uint* nameLen, char* nameBuf)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;

        try
        {
            if (flags != 0)
                throw new ArgumentException("GetName requires flags=0.", nameof(flags));

            string name = _typeHandle.GetName(_target);
            OutputBufferHelpers.CopyStringToBuffer(nameBuf, bufLen, nameLen, name, out bool truncated);
            if (truncated)
            {
                hr = CorDbgHResults.ERROR_INSUFFICIENT_BUFFER;
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null)
        {
            uint nameLenLocal = 0;
            char[] nameBufLocal = new char[bufLen > 0 ? bufLen : 1];
            int hrLocal;
            fixed (char* pNameBufLocal = nameBufLocal)
            {
                hrLocal = _legacyImpl.GetName(flags, bufLen, &nameLenLocal, nameBuf is null ? null : pNameBufLocal);
            }

            Debug.ValidateHResult(hr, hrLocal);
            if (hr >= 0)
            {
                string nameLenMessage = nameLen is null
                    ? $"cDAC: <null>, DAC: {nameLenLocal}"
                    : $"cDAC: {*nameLen}, DAC: {nameLenLocal}";
                Debug.Assert(nameLen is null || nameLenLocal == *nameLen, nameLenMessage);

                if (nameBuf is not null && nameLenLocal > 0)
                {
                    string dacName = new string(nameBufLocal, 0, (int)nameLenLocal - 1);
                    string cdacName = new string(nameBuf, 0, (int)nameLenLocal - 1);
                    Debug.Assert(dacName == cdacName, $"cDAC: {cdacName}, DAC: {dacName}");
                }
            }
        }
#endif

        return hr;
    }

    int IXCLRDataTypeInstance.GetModule(DacComNullableByRef<IXCLRDataModule> mod)
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

            TargetPointer module = _target.Contracts.RuntimeTypeSystem.GetModule(_typeHandle);
            mod.Interface = new ClrDataModule(module, _target, legacyModule, _apiLock);
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

    int IXCLRDataTypeInstance.GetDefinition(DacComNullableByRef<IXCLRDataTypeDefinition> typeDefinition)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        IXCLRDataTypeDefinition? legacyDefinition = null;
        if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null && !typeDefinition.IsNullRef)
        {
            DacComNullableByRef<IXCLRDataTypeDefinition> legacyDefinitionOut = new(isNullRef: false);
            hrLocal = _legacyImpl.GetDefinition(legacyDefinitionOut);
            legacyDefinition = legacyDefinitionOut.Interface;
        }

        try
        {
            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
            ITypeHandle? definitionType = null;
            TargetPointer module = default;
            uint token = 0;

            if (rts.IsArray(_typeHandle, out _) || rts.IsFunctionPointer(_typeHandle, out _, out _))
            {
                definitionType = _typeHandle;
                module = rts.GetModule(definitionType);
                token = rts.GetTypeDefToken(definitionType);
            }
            else if (rts.IsTypeDesc(_typeHandle) && rts.HasTypeParam(_typeHandle))
            {
                definitionType = rts.GetTypeParam(_typeHandle);
                module = rts.GetModule(definitionType);
                token = rts.GetTypeDefToken(definitionType);
            }
            else
            {
                module = rts.GetModule(_typeHandle);
                token = rts.GetTypeDefToken(_typeHandle);
                ILoader loader = _target.Contracts.Loader;
                Contracts.ModuleHandle moduleHandle = loader.GetModuleHandleFromModulePtr(module);
                TargetPointer definitionTypeAddress = loader.GetModuleLookupMapElement(
                    moduleHandle,
                    ModuleLookupMapKind.TypeDefToMethodTable,
                    token,
                    out _);
                definitionType = definitionTypeAddress == TargetPointer.Null ? null : rts.GetTypeHandle(definitionTypeAddress);
            }

            typeDefinition.Interface = new ClrDataTypeDefinition(
                _target,
                module,
                token,
                definitionType,
                legacyDefinition,
                _apiLock);
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

#if DEBUG
        if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null && !typeDefinition.IsNullRef)
        {
            Debug.ValidateHResult(hr, hrLocal);
        }
#endif

        return hr;
    }

    int IXCLRDataTypeInstance.GetFlags(uint* flags)
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

    int IXCLRDataTypeInstance.IsSameObject(IXCLRDataTypeInstance? type)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_FALSE;
        try
        {
            if (type is ClrDataTypeInstance other)
            {
                hr = _appDomain == other._appDomain && _typeHandle.Address == other._typeHandle.Address
                    ? HResults.S_OK
                    : HResults.S_FALSE;
            }
        }
        catch (System.Exception ex)
        {
            hr = ex.HResult;
        }

        return hr;
    }

    int IXCLRDataTypeInstance.Request(uint reqCode, uint inBufferSize, byte* inBuffer, uint outBufferSize, byte* outBuffer)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return LegacyFallbackHelper.CanFallback() && _legacyImpl is not null ? _legacyImpl.Request(reqCode, inBufferSize, inBuffer, outBufferSize, outBuffer) : HResults.E_NOTIMPL;
    }

    int IXCLRDataTypeInstance.GetNumStaticFields2(uint flags, uint* numFields)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        try
        {
            if (_legacyImpl is not null)
                hrLocal = _legacyImpl.GetNumStaticFields2(flags, numFields);
            if (numFields is null)
                throw new ArgumentNullException(nameof(numFields));
            *numFields = (uint)GetStaticFields(flags).Count;
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

    int IXCLRDataTypeInstance.StartEnumStaticFields(uint flags, IXCLRDataTask? tlsTask, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return StartEnumStaticFieldsCore(null, (uint)CLRDataByNameFlag.CLRDATA_BYNAME_CASE_SENSITIVE, flags, tlsTask, handle, byName: false);
    }

    int IXCLRDataTypeInstance.EnumStaticField(ulong* handle, DacComNullableByRef<IXCLRDataValue> value)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EnumStaticFieldCore(handle, value, 0, null, null, tokenScope: null, token: null);
    }

    int IXCLRDataTypeInstance.EndEnumStaticFields(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EndEnumStaticFieldsCore(handle, byName: false);
    }

    int IXCLRDataTypeInstance.StartEnumStaticFieldsByName2(char* name, uint nameFlags, uint fieldFlags, IXCLRDataTask? tlsTask, ulong* handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return StartEnumStaticFieldsCore(name is null ? null : new string(name), nameFlags, fieldFlags, tlsTask, handle, byName: true);
    }

    int IXCLRDataTypeInstance.EnumStaticFieldByName2(ulong* handle, DacComNullableByRef<IXCLRDataValue> value)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EnumStaticFieldCore(handle, value, 0, null, null, tokenScope: null, token: null);
    }

    int IXCLRDataTypeInstance.EndEnumStaticFieldsByName2(ulong handle)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EndEnumStaticFieldsCore(handle, byName: true);
    }

    int IXCLRDataTypeInstance.GetStaticFieldByToken(uint token, IXCLRDataTask? tlsTask, DacComNullableByRef<IXCLRDataValue> field, uint bufLen, uint* nameLen, char* nameBuf)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return GetStaticFieldByTokenCore(null, token, tlsTask, field, bufLen, nameLen, nameBuf);
    }

    int IXCLRDataTypeInstance.GetBase(DacComNullableByRef<IXCLRDataTypeInstance> @base)
    {
        using Lock.Scope scope = _apiLock.EnterScope();
        int hr = HResults.S_OK;
        int hrLocal = HResults.S_OK;
        IXCLRDataTypeInstance? legacyBase = null;

        try
        {
            if (LegacyFallbackHelper.CanFallback() && _legacyImpl is not null)
            {
                DacComNullableByRef<IXCLRDataTypeInstance> legacyBaseOut = new(isNullRef: @base.IsNullRef);
                hrLocal = _legacyImpl.GetBase(legacyBaseOut);
                legacyBase = legacyBaseOut.Interface;
            }

            if (@base.IsNullRef)
                return HResults.S_OK;

            IRuntimeTypeSystem rts = _target.Contracts.RuntimeTypeSystem;
            TargetPointer parentMethodTable = rts.GetParentMethodTable(_typeHandle);
            if (parentMethodTable == TargetPointer.Null)
                return HResults.E_NOINTERFACE;

            ITypeHandle parentTypeHandle = rts.GetTypeHandle(parentMethodTable);
            @base.Interface = new ClrDataTypeInstance(_target, parentTypeHandle, legacyBase, _apiLock, _appDomain);
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

    int IXCLRDataTypeInstance.EnumStaticField2(ulong* handle, DacComNullableByRef<IXCLRDataValue> value, uint bufLen, uint* nameLen, char* nameBuf, DacComNullableByRef<IXCLRDataModule> tokenScope, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EnumStaticFieldCore(handle, value, bufLen, nameLen, nameBuf, tokenScope, token);
    }

    int IXCLRDataTypeInstance.EnumStaticFieldByName3(ulong* handle, DacComNullableByRef<IXCLRDataValue> value, DacComNullableByRef<IXCLRDataModule> tokenScope, uint* token)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return EnumStaticFieldCore(handle, value, 0, null, null, tokenScope, token);
    }

    int IXCLRDataTypeInstance.GetStaticFieldByToken2(IXCLRDataModule? tokenScope, uint token, IXCLRDataTask? tlsTask, DacComNullableByRef<IXCLRDataValue> field, uint bufLen, uint* nameLen, char* nameBuf)
    {
        using Lock.Scope scope = _apiLock.EnterScope();

        return GetStaticFieldByTokenCore(tokenScope, token, tlsTask, field, bufLen, nameLen, nameBuf);
    }
}
