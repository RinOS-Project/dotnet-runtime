// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections;
using System.Collections.Generic;

namespace Microsoft.Internal.Collections
{
    internal static partial class CollectionServices
    {
        public static ICollection<object> GetCollectionWrapper(Type itemType, object collectionObject)
        {
            ArgumentNullException.ThrowIfNull(itemType);
            ArgumentNullException.ThrowIfNull(collectionObject);

            var underlyingItemType = itemType.UnderlyingSystemType;

            if (underlyingItemType == typeof(object))
            {
                return (ICollection<object>)collectionObject;
            }

            // Most common .NET collections implement IList as well so for those
            // cases we can optimize the wrapping instead of using reflection to create
            // a generic type.
            if (typeof(IList).IsAssignableFrom(collectionObject.GetType()))
            {
                return new CollectionOfObjectList((IList)collectionObject);
            }

            Type collectionType = typeof(CollectionOfObject<>).MakeGenericType(underlyingItemType);

            return (ICollection<object>)Activator.CreateInstance(collectionType, collectionObject)!;
        }

        private sealed class CollectionOfObjectList : ICollection<object>
        {
            private readonly IList _list;

            public CollectionOfObjectList(IList list)
            {
                _list = list;
            }

            public void Add(object item)
            {
                _list.Add(item);
            }

            public void Clear()
            {
                _list.Clear();
            }

            public bool Contains(object item)
            {
                return _list.Contains(item);
            }

            public void CopyTo(object[] array, int arrayIndex)
            {
                _list.CopyTo(array, arrayIndex);
            }

            public int Count
            {
                get { return _list.Count; }
            }

            public bool IsReadOnly
            {
                get { return _list.IsReadOnly; }
            }

            public bool Remove(object item)
            {
                int index = _list.IndexOf(item);
                if (index < 0)
                {
                    return false;
                }

                _list.RemoveAt(index);
                return true;
            }

            public IEnumerator<object> GetEnumerator()
            {
                foreach (object item in _list)
                {
                    yield return item;
                }
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return _list.GetEnumerator();
            }
        }

        private sealed class CollectionOfObject<T> : ICollection<object>
        {
            private readonly ICollection<T> _collectionOfT;

            public CollectionOfObject(object collectionOfT)
            {
                _collectionOfT = (ICollection<T>)collectionOfT;
            }

            public void Add(object item)
            {
                _collectionOfT.Add((T)item);
            }

            public void Clear()
            {
                _collectionOfT.Clear();
            }

            public bool Contains(object item)
            {
                if (item is null)
                {
                    return default(T) is null && _collectionOfT.Contains(default!);
                }

                return item is T itemOfT && _collectionOfT.Contains(itemOfT);
            }

            public void CopyTo(object[] array, int arrayIndex)
            {
                ArgumentNullException.ThrowIfNull(array);
                if ((uint)arrayIndex > (uint)array.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(arrayIndex));
                }

                if (array.Length - arrayIndex < _collectionOfT.Count)
                {
                    throw new ArgumentException("The destination array is not long enough to copy all the items in the collection.", nameof(array));
                }

                foreach (T item in _collectionOfT)
                {
                    array[arrayIndex++] = item!;
                }
            }

            public int Count
            {
                get { return _collectionOfT.Count; }
            }

            public bool IsReadOnly
            {
                get { return _collectionOfT.IsReadOnly; }
            }

            public bool Remove(object item)
            {
                if (item is null)
                {
                    return default(T) is null && _collectionOfT.Remove(default!);
                }

                return item is T itemOfT && _collectionOfT.Remove(itemOfT);
            }

            public IEnumerator<object> GetEnumerator()
            {
                foreach (T item in _collectionOfT)
                {
                    yield return item!;
                }
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return ((IEnumerable)_collectionOfT).GetEnumerator();
            }
        }
    }
}
