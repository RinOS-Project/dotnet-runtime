// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;

using Internal.Text;
using Internal.TypeSystem;

namespace ILCompiler.DependencyAnalysis
{
    /// <summary>
    /// Emits the field identity metadata needed by NativeAOT to produce the
    /// CoreCLR-compatible GCBulkRootStaticVar event. The corresponding runtime
    /// section is ordered exactly like GCStaticRegion, so a record identifies a
    /// static block by its spine index rather than by a potentially shared
    /// DataOnlyEEType.
    /// </summary>
    public sealed class GCStaticMetadataNode : EmbeddedObjectNode
    {
        private const uint Magic = 0x314D5347; // "GSM1"
        private readonly MetadataType _type;

        private readonly struct StaticRootField
        {
            public StaticRootField(int offset, string name)
            {
                Offset = offset;
                Name = name;
            }

            public int Offset { get; }
            public string Name { get; }
        }

        public GCStaticMetadataNode(MetadataType type)
        {
            _type = type;
        }

        protected override string GetName(NodeFactory factory) =>
            $"GC static metadata for {_type.GetDisplayName()}";

        public override bool StaticDependenciesAreComputed => true;

        public override IEnumerable<DependencyListEntry> GetStaticDependencies(NodeFactory factory) =>
            Array.Empty<DependencyListEntry>();

        public override void EncodeData(ref ObjectDataBuilder builder, NodeFactory factory, bool relocsOnly)
        {
            List<StaticRootField> fields = GetStaticRootFields();
            int headerSize = 24;
            int recordSize = headerSize;

            foreach (StaticRootField field in fields)
            {
                int nameCharacters = checked(field.Name.Length + 1);
                recordSize = checked(recordSize + 12 + nameCharacters * sizeof(short));
            }

            int alignment = factory.Target.PointerSize;
            int padding = (alignment - (recordSize % alignment)) % alignment;
            recordSize = checked(recordSize + padding);

            builder.EmitUInt(Magic);
            builder.EmitShort(1); // format version
            builder.EmitShort(0); // flags; reserved for future completeness bits
            builder.EmitUInt(checked((uint)recordSize));
            builder.EmitUInt(checked((uint)IndexFromBeginningOfArray));
            builder.EmitUInt(checked((uint)fields.Count));
            builder.EmitUInt(0); // reserved

            foreach (StaticRootField field in fields)
            {
                builder.EmitUInt(checked((uint)field.Offset));
                builder.EmitUInt(0); // GCRootStaticVar flags
                builder.EmitUInt(checked((uint)field.Name.Length + 1));
                foreach (char character in field.Name)
                    builder.EmitShort((short)character);
                builder.EmitShort(0);
            }

            if (padding != 0)
                builder.EmitZeros(padding);
        }

        private List<StaticRootField> GetStaticRootFields()
        {
            var fields = new List<StaticRootField>();
            _type.ComputeStaticFieldLayout(StaticLayoutKind.StaticRegionSizesAndFields);

            foreach (FieldDesc field in _type.GetFields())
            {
                if (!field.IsStatic || field.HasRva || field.IsLiteral ||
                    field.IsThreadStatic || !field.HasGCStaticBase)
                {
                    continue;
                }

                string name = field.GetName();
                if (field.FieldType.IsGCPointer)
                {
                    fields.Add(new StaticRootField(field.Offset.AsInt, name));
                }
                else if (field.FieldType.IsValueType && field.FieldType is DefType valueType)
                {
                    AppendValueTypeFields(fields, valueType, field.Offset.AsInt, name);
                }
            }

            return fields;
        }

        private static void AppendValueTypeFields(
            List<StaticRootField> fields,
            DefType type,
            int baseOffset,
            string namePrefix)
        {
            if (!type.ContainsGCPointers)
                return;

            if (!type.IsValueType && type.HasBaseType && type.BaseType is DefType baseType)
                AppendValueTypeFields(fields, baseType, baseOffset, namePrefix);

            type.ComputeInstanceLayout(InstanceLayoutKind.TypeAndFields);
            int repeat = type is MetadataType metadataType && metadataType.IsInlineArray
                ? metadataType.GetClassLayout().InlineArrayLength
                : 1;
            int pointerSize = type.Context.Target.PointerSize;

            foreach (FieldDesc field in type.GetFields())
            {
                if (field.IsStatic)
                    continue;

                int elementStride = pointerSize;
                if (field.FieldType.IsValueType && field.FieldType is DefType elementType)
                    elementStride = elementType.InstanceByteCount.AsInt;

                for (int i = 0; i < repeat; i++)
                {
                    int offset = checked(baseOffset + field.Offset.AsInt + elementStride * i);
                    string fieldName = repeat == 1
                        ? $"{namePrefix}.{field.GetName()}"
                        : $"{namePrefix}.{field.GetName()}[{i}]";

                    if (field.FieldType.IsGCPointer)
                    {
                        fields.Add(new StaticRootField(offset, fieldName));
                    }
                    else if (field.FieldType.IsValueType && field.FieldType is DefType nestedType)
                    {
                        AppendValueTypeFields(fields, nestedType, offset, fieldName);
                    }
                }
            }
        }

        public override int ClassCode => -1908464751;

        public override int CompareToImpl(ISortableNode other, CompilerComparer comparer) =>
            comparer.Compare(_type, ((GCStaticMetadataNode)other)._type);
    }
}
