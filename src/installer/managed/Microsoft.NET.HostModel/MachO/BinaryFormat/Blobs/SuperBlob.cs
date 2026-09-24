// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

#nullable enable

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace Microsoft.NET.HostModel.MachO;

/// <summary>
/// See https://github.com/apple-oss-distributions/Security/blob/3dab46a11f45f2ffdbd70e2127cc5a8ce4a1f222/SecurityTool/sharedTool/codesign.c#L61
/// This is the base class for a super blob, which is a blob containing other blobs.
/// This class handles reading and writing of all the sub-blobs.
/// </summary>
internal class SuperBlob : IBlob
{
    public SuperBlob(BlobMagic magic, IEnumerable<BlobIndex> blobIndices, IEnumerable<IBlob> blobs)
    {
        if (blobIndices.Count() != blobs.Count())
        {
            throw new ArgumentException("Blob indices and blobs count must match.");
        }
        Magic = magic;
        Blobs = blobs.ToImmutableArray();
        BlobIndices = blobIndices.ToImmutableArray();
        ValidateBlobs(Blobs, BlobIndices);
    }

    protected SuperBlob(BlobMagic magic)
    {
        Magic = magic;
        Blobs = ImmutableArray<IBlob>.Empty;
        BlobIndices = ImmutableArray<BlobIndex>.Empty;
    }

    public SuperBlob(SuperBlob other)
    {
        Magic = other.Magic;
        Blobs = other.Blobs;
        BlobIndices = other.BlobIndices;
    }

    /// <inheritdoc />
    public BlobMagic Magic { get; }

    /// <inheritdoc />
    public uint Size => (uint)(
        sizeof(uint) + sizeof(uint) // magic + size
        + sizeof(uint) // sub blob count
        + (uint)BlobIndices.Length * BlobIndex.Size
        + Blobs.Sum(b => b.Size));

    public uint SubBlobCount => (uint)Blobs.Length;

    public ImmutableArray<BlobIndex> BlobIndices { get; }
    public ImmutableArray<IBlob> Blobs { get; }


    [Conditional("DEBUG")]
    private static void ValidateBlobs(IEnumerable<IBlob> blobs, IEnumerable<BlobIndex> blobIndices)
    {
        if (blobs.Count() != blobIndices.Count())
        {
            throw new InvalidOperationException("Blobs and blob indices count must match.");
        }
        uint expectedBlobOffset = (uint)(sizeof(uint) * 3 + blobIndices.Count() * BlobIndex.Size);
        uint count = (uint)blobs.Count();
        for (int i = 0; i < count; i++)
        {
            var blob = blobs.ElementAt(i);
            var blobidx = blobIndices.ElementAt(i);
            if (blob.Size == 0)
            {
                throw new InvalidOperationException("Blob size cannot be zero.");
            }
            if (blobidx.Offset != expectedBlobOffset)
            {
                throw new InvalidOperationException($"Blob index offset {blobidx.Offset} does not match expected offset {expectedBlobOffset}.");
            }
            expectedBlobOffset += blob.Size;
        }
    }

    public int Write(IMachOFileWriter file, long offset)
    {
        // Write magic and size
        file.WriteUInt32BigEndian(offset, (uint)Magic);
        file.WriteUInt32BigEndian(offset + sizeof(uint), Size);

        // Write sub blob count
        uint count = (uint)Blobs.Length;
        file.WriteUInt32BigEndian(offset + sizeof(uint) * 2, count);

        // Write blob indices
        for (int i = 0; i < Blobs.Length; i++)
        {
            var blobIndex = BlobIndices[i];
            file.Write(offset + sizeof(uint) * 3 + (i * BlobIndex.Size), ref blobIndex);
        }

        // Write blobs
        long currentOffset = offset + sizeof(uint) * 3 + (Blobs.Length * BlobIndex.Size);
        for (int i = 0; i < Blobs.Length; i++)
        {
            currentOffset += Blobs[i].Write(file, currentOffset);
        }

        return (int)Size;
    }

    /// <summary>
    /// Creates a SuperBlob by reading from a memory-mapped file.
    /// </summary>
    public static SuperBlob Read(IMachOFileReader reader, long offset)
    {
        if (offset < 0)
        {
            throw new InvalidDataException("Super blob offset cannot be negative.");
        }

        BlobMagic magic = (BlobMagic)reader.ReadUInt32BigEndian(offset);
        uint size = reader.ReadUInt32BigEndian(offset + sizeof(BlobMagic));
        uint count = reader.ReadUInt32BigEndian(offset + sizeof(BlobMagic) + sizeof(uint));
        const uint headerSize = sizeof(uint) * 3;
        if (size < headerSize)
        {
            throw new InvalidDataException($"Super blob size {size} is smaller than its header.");
        }

        ulong indexBytes = (ulong)count * BlobIndex.Size;
        if (indexBytes > size - headerSize)
        {
            throw new InvalidDataException("Super blob index table exceeds the declared blob size.");
        }

        uint firstBlobOffset = checked((uint)(headerSize + indexBytes));

        var blobs = new List<IBlob>((int)count);
        var blobIndices = new List<BlobIndex>((int)count);
        for (int i = 0; i < count; i++)
        {
            reader.Read(offset + sizeof(uint) * 3 + (i * BlobIndex.Size), out BlobIndex blobIndex);
            uint blobOffset = blobIndex.Offset;
            if (blobOffset < firstBlobOffset || blobOffset > size - sizeof(uint) * 2)
            {
                throw new InvalidDataException($"Super blob child offset {blobOffset} is outside the declared blob.");
            }

            if (blobOffset > long.MaxValue - offset)
            {
                throw new InvalidDataException("Super blob child offset overflows the reader position.");
            }

            long childOffset = offset + blobOffset;
            if (childOffset > long.MaxValue - sizeof(uint))
            {
                throw new InvalidDataException("Super blob child header overflows the reader position.");
            }

            uint childSize = reader.ReadUInt32BigEndian(childOffset + sizeof(uint));
            if (childSize < sizeof(uint) * 2 || childSize > size - blobOffset || childSize > int.MaxValue)
            {
                throw new InvalidDataException($"Super blob child size {childSize} is outside the declared blob.");
            }

            blobIndices.Add(blobIndex);
            IBlob blob = BlobParser.ParseBlob(reader, childOffset);
            if (blob.Size > childSize)
            {
                throw new InvalidDataException("Parsed super blob child exceeds its declared size.");
            }
            blobs.Add(blob);
        }
        Debug.Assert(size == sizeof(uint) + sizeof(uint) + sizeof(uint)
                             + blobIndices.Count * BlobIndex.Size
                             + blobs.Sum(b => b.Size));

        return new SuperBlob(magic, blobIndices, blobs);
    }
}
