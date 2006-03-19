using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	/// <summary>
	/// Wraps an X509_NAME object.
	/// </summary>
	public class X509Name : Base, IDisposable, IComparable<X509Name>
	{
		#region Initialization
		/// <summary>
		/// Calls X509_NAME_new()
		/// </summary>
		public X509Name() : base(Native.ExpectNonNull(Native.X509_NAME_new())) { }
		internal X509Name(IntPtr ptr) : base(ptr) { }
		/// <summary>
		/// Copy constructor. Calls X509_NAME_dup()
		/// </summary>
		/// <param name="rhs">Name to be duplicated</param>
		public X509Name(X509Name rhs)
			: base(Native.ExpectNonNull(Native.X509_NAME_dup(rhs.ptr)))
		{
		}

		/// <summary>
		/// Creates an X509Name object given a formatted string.
		/// </summary>
		/// <param name="str">Formatted string</param>
		/// <example>/CN=commonName/O=organization/OU=org unit/C=country</example>
		public X509Name(string str)
			: this()
		{
			if (str.IndexOf('/') == -1 &&
				str.IndexOf('=') == -1)
			{
				this.Common = str;
				return;
			}

			string[] parts = str.Split('/');
			foreach (string part in parts)
			{
				if (part == "")
					continue;
				string[] nv = part.Split('=');
				string name = nv[0];
				string value = nv[1];
				this.AddEntryByName(name, value);
			}
		}

		/// <summary>
		/// Implicit conversion from a string into an X509Name
		/// </summary>
		/// <param name="value">Formatted string</param>
		/// <returns>A newly created X509Name object</returns>
		public static implicit operator X509Name(string value)
		{
			return new X509Name(value);
		}
		#endregion

		#region Properties
		/// <summary>
		/// Calls X509_NAME_oneline()
		/// </summary>
		public string OneLine
		{
			get { return Native.PtrToStringAnsi(Native.X509_NAME_oneline(this.ptr, null, 0), true);	}
		}
		
		/// <summary>
		/// Access to the name entry with a short name of CN.
		/// </summary>
		public string Common
		{
			get { return this.GetTextByName("CN"); }
			set { this.AddEntryByName("CN", value); }
		}
		
		/// <summary>
		/// Access to the name entry with a short name of C.
		/// </summary>
		public string Country
		{
			get { return this.GetTextByName("C"); }
			set { this.AddEntryByName("C", value); }
		}

		/// <summary>
		/// Access to the name entry with a short name of L.
		/// </summary>
		public string Locality
		{
			get { return this.GetTextByName("L"); }
			set { this.AddEntryByName("L", value); }
		}

		/// <summary>
		/// Access to the name entry with a short name of ST.
		/// </summary>
		public string StateOrProvince
		{
			get { return this.GetTextByName("ST"); }
			set { this.AddEntryByName("ST", value); }
		}

		/// <summary>
		/// Access to the name entry with a short name of O.
		/// </summary>
		public string Organization
		{
			get { return this.GetTextByName("O"); }
			set { this.AddEntryByName("O", value); }
		}

		/// <summary>
		/// Access to the name entry with a short name of OU.
		/// </summary>
		public string OrganizationUnit
		{
			get { return this.GetTextByName("OU"); }
			set { this.AddEntryByName("OU", value); }
		}

		/// <summary>
		/// Access to the name entry with a short name of X509.
		/// </summary>
		public string X509
		{
			get { return this.GetTextByName("X509"); }
			set { this.AddEntryByName("X509", value); }
		}

		/// <summary>
		/// Calls X509_NAME_entry_count()
		/// </summary>
		public int Count
		{
			get { return Native.X509_NAME_entry_count(this.ptr); }
		}

		/// <summary>
		/// Indexer by name. Calls GetTextByName().
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public string this[string name]
		{
			get { return this.GetTextByName(name); }
			set { this.AddEntryByName(name, value); }
		}

		/// <summary>
		/// Calls X509_NAME_get_entry()
		/// </summary>
		/// <param name="index"></param>
		/// <returns></returns>
		public string this[int index]
		{
			get 
			{
				IntPtr pEntry = Native.X509_NAME_get_entry(this.ptr, index);
				return null;
			}
		}
		#endregion

		#region Methods
		/// <summary>
		/// Add a name entry by its short name. 
		/// For instance, CN is the short name for the commonName entry.
		/// Calls X509_NAME_add_entry_by_NID() after converting the name argument to a nid.
		/// </summary>
		/// <param name="name">The short name for which this entry is called.</param>
		/// <param name="value">The value that this entry should contain.</param>
		public void AddEntryByName(string name, string value)
		{
			this.AddEntryByNid(Native.TextToNID(name), value);
		}

		/// <summary>
		/// Add a name entry by its nid.
		/// Calls X509_NAME_add_entry_by_NID()
		/// </summary>
		/// <param name="nid">The nid that this name entry is called.</param>
		/// <param name="value">The value that this entry should contain.</param>
		public void AddEntryByNid(int nid, string value)
		{
			byte[] buf = Encoding.ASCII.GetBytes(value);
			Native.ExpectSuccess(Native.X509_NAME_add_entry_by_NID(
				this.ptr,
				nid,
				Native.MBSTRING_ASC,
				buf,
				buf.Length,
				-1,
				0));
		}

		/// <summary>
		/// Calls X509_NAME_get_text_by_NID()
		/// </summary>
		/// <param name="nid"></param>
		/// <returns>The value of the name entry indexed by nid</returns>
		public string GetTextByNid(int nid)
		{
			if (this.GetIndexByNid(nid, -1) == -1)
				return null;

			byte[] buf = new byte[1024];
			int len = Native.X509_NAME_get_text_by_NID(this.ptr, nid, buf, buf.Length);
			if (len <= 0)
				throw new OpenSslException();
			return Encoding.ASCII.GetString(buf, 0, len);
		}

		/// <summary>
		/// Calls GetTextByNid() after converting the name argument into a nid.
		/// </summary>
		/// <param name="name">The short name for the entry to be returned.</param>
		/// <returns>The entry requsted by name.</returns>
		public string GetTextByName(string name)
		{
			return this.GetTextByNid(Native.TextToNID(name));
		}

		/// <summary>
		/// Calls X509_NAME_get_index_by_NID()
		/// </summary>
		/// <param name="nid">Specifies the nid for the entry to be found.</param>
		/// <param name="lastpos">Use -1 here if you which to find the first entry by the specified nid.</param>
		/// <returns>The index that this entry occurs. Returns lastpos if this entry cannot be found.</returns>
		public int GetIndexByNid(int nid, int lastpos)
		{
			int ret = Native.X509_NAME_get_index_by_NID(this.ptr, nid, lastpos);
			if (ret == lastpos)
				return lastpos;
			if (ret < 0)
				throw new OpenSslException();
			return ret;
		}

		/// <summary>
		/// Uses GetIndexByNid() after converting the name argument into a nid.
		/// </summary>
		/// <param name="name">The short name of the entry to be found.</param>
		/// <param name="lastpos">If multiple entries of the same type are contained, use this argument to keep finding subsequent entries.</param>
		/// <returns>If not found, returns lastpos. Otherwise returns the index that this entry resides.</returns>
		public int IndexOf(string name, int lastpos)
		{
			return GetIndexByNid(Native.TextToNID(name), lastpos);
		}

		/// <summary>
		/// Uses GetIndexByNid() after converting the name argument into a nid.
		/// This method does not allow the user to iterate through multiple entries of the same type.
		/// Use GetIndexByNid(string name, int lastpos) for this functionality.
		/// </summary>
		/// <param name="name">The short name of the entry to be found.</param>
		/// <returns>If this entry cannot be found, returns -1. Otherwise returns the index that this entry lives.</returns>
		public int IndexOf(string name)
		{
			return this.IndexOf(name, -1);
		}

		/// <summary>
		/// Determines if an entry by a particular nid is contained within this name.
		/// </summary>
		/// <param name="name">The short name of the entry to be queried.</param>
		/// <returns>true if the entry could be found, otherwise false.</returns>
		public bool Contains(string name)
		{
			return this.IndexOf(name) >= 0;
		}

		/// <summary>
		/// Calls X509_NAME_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="cbSize"></param>
		/// <returns></returns>
		public ArraySegment<byte> Digest(MessageDigest type, int cbSize)
		{
			byte[] buf = new byte[cbSize];
			uint len = (uint)cbSize;
			Native.ExpectSuccess(Native.X509_NAME_digest(this.ptr, type.Handle, buf, ref len));
			return new ArraySegment<byte>(buf, 0, (int)len);
		}

		/// <summary>
		/// Calls X509_NAME_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.X509_NAME_print(bio.Handle, this.Handle, 0));
		}
		#endregion 

		#region IDisposable Members

		/// <summary>
		/// Calls X509_NAME_free()
		/// </summary>
		public void Dispose()
		{
			Native.X509_NAME_free(this.ptr);
		}

		#endregion

		#region IComparable<X509Name> Members

		/// <summary>
		/// Calls X509_NAME_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(X509Name other)
		{
			return Native.X509_NAME_cmp(this.ptr, other.ptr);
		}

		#endregion
	}
}
