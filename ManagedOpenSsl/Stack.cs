using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	/// <summary>
	/// This interface is used by the generic Stack class. 
	/// An IStackable must have Handle get and set accessors.
	/// </summary>
	public interface IStackable
	{
		/// <summary>
		/// Access to the raw unmanaged pointer.
		/// </summary>
		IntPtr Handle { get; set; }
	}

	public class Stack<T> : Base, IDisposable, IList<T> where T : IStackable, new()
	{
		#region Initialization
		public Stack() : base(Native.ExpectNonNull(Native.sk_new_null()))
		{
		}

		internal Stack(IntPtr ptr) : base(ptr) {}

		public T Shift()
		{
			T item = new T();
			item.Handle = Native.sk_shift(this.ptr);
			return item;
		}
		#endregion

		#region Enumerator
		class Enumerator : IEnumerator<T>
		{
			private Stack<T> parent;
			private int index = -1;
			public Enumerator(Stack<T> parent)
			{
				this.parent = parent;
			}

			#region IEnumerator<T> Members

			public T Current
			{
				get
				{
					if (this.index < 0 || this.index >= this.parent.Count)
						throw new InvalidOperationException();

					IntPtr ptr = Native.ExpectNonNull(Native.sk_value(this.parent.Handle, index));
					T item = new T();
					item.Handle = ptr;
					return item;
				}
			}

			#endregion

			#region IDisposable Members
			public void Dispose()
			{
			}
			#endregion

			#region IEnumerator Members

			object System.Collections.IEnumerator.Current
			{
				get { return this.Current; }
			}

			public bool MoveNext()
			{
				this.index++;
				if (this.index < this.parent.Count)
					return true;
				return false;
			}

			public void Reset()
			{
				this.index = -1;
			}

			#endregion
		}
		#endregion

		#region IDisposable Members
		public void Dispose()
		{
			Native.sk_free(this.ptr);
		}
		#endregion

		#region IList<T> Members

		public int IndexOf(T item)
		{
			return Native.sk_find(this.ptr, item.Handle);
		}

		public void Insert(int index, T item)
		{
			Native.ExpectSuccess(Native.sk_insert(this.ptr, item.Handle, index));
		}

		public void RemoveAt(int index)
		{
			IntPtr ptr = Native.ExpectNonNull(Native.sk_delete(this.ptr, index));
		}

		public T this[int index]
		{
			get
			{
				IntPtr ptr = Native.ExpectNonNull(Native.sk_value(this.ptr, index));
				T item = new T();
				item.Handle = ptr;
				return item;
			}
			set
			{
				int ret = Native.sk_insert(this.ptr, value.Handle, index);
				if (ret < 0)
					throw new OpenSslException();
			}
		}

		#endregion

		#region ICollection<T> Members

		public void Add(T item)
		{
			if (Native.sk_push(this.ptr, item.Handle) <= 0)
				throw new OpenSslException();
		}

		public void Clear()
		{
			Native.sk_zero(this.ptr);
		}

		public bool Contains(T item)
		{
			int ret = Native.sk_find(this.ptr, item.Handle);
			if (ret >= 0 && ret < this.Count)
				return true;
			return false;
		}

		public void CopyTo(T[] array, int arrayIndex)
		{
			throw new Exception("The method or operation is not implemented.");
		}

		public int Count
		{
			get
			{
				int ret = Native.sk_num(this.ptr);
				if (ret < 0)
					throw new OpenSslException();
				return ret;
			}
		}

		public bool IsReadOnly
		{
			get { return false; }
		}

		public bool Remove(T item)
		{
			IntPtr ptr = Native.sk_delete_ptr(this.ptr, item.Handle);
			if (ptr != IntPtr.Zero)
				return true;
			return false;
		}

		#endregion

		#region IEnumerable<T> Members

		public IEnumerator<T> GetEnumerator()
		{
			return new Enumerator(this);
		}

		#endregion

		#region IEnumerable Members

		System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator()
		{
			return new Enumerator(this);
		}

		#endregion
	}
}
