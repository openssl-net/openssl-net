// Copyright (c) 2006-2007 Frank Laub
// All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

using OpenSSL.Core;
using OpenSSL.Crypto;
using System;
using System.Text;

namespace OpenSSL.X509
{
	/// <summary>
	/// Encapsulates the X509_NAME_* functions
	/// </summary>
	public class X509Name : BaseValue, IComparable<X509Name>, IStackable
	{
		#region Initialization
		internal X509Name(IntPtr ptr, bool owner) 
			: base(ptr, owner) 
		{ }

		/// <summary>
		/// Calls X509_NAME_new()
		/// </summary>
		public X509Name() 
			: base(Native.ExpectNonNull(Native.X509_NAME_new()), true) 
		{ }

		/// <summary>
		/// Calls X509_NAME_dup()
		/// </summary>
		/// <param name="rhs"></param>
		public X509Name(X509Name rhs)
			: base(Native.ExpectNonNull(Native.X509_NAME_dup(rhs.ptr)), true)
		{
		}

		internal X509Name(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{ }

		/// <summary>
		/// Calls X509_NAME_new()
		/// </summary>
		/// <param name="str"></param>
		public X509Name(string str)
			: this()
		{
			if (str.IndexOf('/') == -1 &&
				str.IndexOf('=') == -1)
			{
				Common = str;
				return;
			}

			var parts = str.Split('/');
			foreach (var part in parts)
			{
				if (part == "")
					continue;

				var nv = part.Split('=');
				var name = nv[0];
				var value = nv[1];

				AddEntryByName(name, value);
			}
		}

		/// <summary>
		/// Parses the string and returns an X509Name based on value.
		/// </summary>
		/// <param name="value"></param>
		/// <returns></returns>
		public static implicit operator X509Name(string value)
		{
			return new X509Name(value);
		}
		#endregion

		#region Properties

		/// <summary>
		/// Returns X509_NAME_oneline()
		/// </summary>
		public string OneLine
		{
			get { return Native.PtrToStringAnsi(Native.X509_NAME_oneline(ptr, null, 0), true);	 }
		}
		
		/// <summary>
		/// Accessor to the name entry for 'CN'
		/// </summary>
		public string Common
		{
			get { return GetTextByName("CN"); }
			set { AddEntryByName("CN", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'C'
		/// </summary>
		public string Country
		{
			get { return GetTextByName("C"); }
			set { AddEntryByName("C", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'L'
		/// </summary>
		public string Locality
		{
			get { return GetTextByName("L"); }
			set { AddEntryByName("L", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'ST'
		/// </summary>
		public string StateOrProvince
		{
			get { return GetTextByName("ST"); }
			set { AddEntryByName("ST", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'O'
		/// </summary>
		public string Organization
		{
			get { return GetTextByName("O"); }
			set { AddEntryByName("O", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'OU'
		/// </summary>
		public string OrganizationUnit
		{
			get { return GetTextByName("OU"); }
			set { AddEntryByName("OU", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'G'
		/// </summary>
		public string Given
		{
			get { return GetTextByName("G"); }
			set { AddEntryByName("G", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'S'
		/// </summary>
		public string Surname
		{
			get { return GetTextByName("S"); }
			set { AddEntryByName("S", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'I'
		/// </summary>
		public string Initials
		{
			get { return GetTextByName("I"); }
			set { AddEntryByName("I", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'UID'
		/// </summary>
		public string UniqueIdentifier
		{
			get { return GetTextByName("UID"); }
			set { AddEntryByName("UID", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'SN'
		/// </summary>
		public string SerialNumber
		{
			get { return GetTextByName("SN"); }
			set { AddEntryByName("SN", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'T'
		/// </summary>
		public string Title
		{
			get { return GetTextByName("T"); }
			set { AddEntryByName("T", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'D'
		/// </summary>
		public string Description
		{
			get { return GetTextByName("D"); }
			set { AddEntryByName("D", value); }
		}

		/// <summary>
		/// Accessor to the name entry for 'X509'
		/// </summary>
		public string X509
		{
			get { return GetTextByName("X509"); }
			set { AddEntryByName("X509", value); }
		}

		/// <summary>
		/// Returns X509_NAME_entry_count()
		/// </summary>
		public int Count
		{
			get { return Native.X509_NAME_entry_count(ptr); }
		}

		/// <summary>
		/// Indexer to a name entry by name
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public string this[string name]
		{
			get { return GetTextByName(name); }
			set { AddEntryByName(name, value); }
		}

		/// <summary>
		/// Indexer to a name entry by index
		/// </summary>
		/// <param name="index"></param>
		/// <returns></returns>
		public string this[int index]
		{
			get 
			{
				// TODO: finish this
//				IntPtr pEntry = Native.X509_NAME_get_entry(this.ptr, index);
				return null;
			}
		}
		#endregion

		#region Methods
		/// <summary>
		/// Calls X509_NAME_add_entry_by_NID after converting the 
		/// name to a NID using OBJ_txt2nid()
		/// </summary>
		/// <param name="name"></param>
		/// <param name="value"></param>
		public void AddEntryByName(string name, string value)
		{
			AddEntryByNid(Native.TextToNID(name), value);
		}

		/// <summary>
		/// Calls X509_NAME_add_entry_by_NID()
		/// </summary>
		/// <param name="nid"></param>
		/// <param name="value"></param>
		public void AddEntryByNid(int nid, string value)
		{
			var buf = Encoding.ASCII.GetBytes(value);
			
			Native.ExpectSuccess(Native.X509_NAME_add_entry_by_NID(
				ptr,
				nid,
				Native.MBSTRING_ASC,
				buf,
				buf.Length,
				-1,
				0));
		}

		/// <summary>
		/// Returns X509_NAME_get_text_by_NID()
		/// </summary>
		/// <param name="nid"></param>
		/// <returns></returns>
		public string GetTextByNid(int nid)
		{
			if (GetIndexByNid(nid, -1) == -1)
				return null;

			var buf = new byte[1024];
			var len = Native.X509_NAME_get_text_by_NID(ptr, nid, buf, buf.Length);

			if (len <= 0)
				throw new OpenSslException();
			
			return Encoding.ASCII.GetString(buf, 0, len);
		}

		/// <summary>
		/// Returns X509_NAME_get_text_by_NID() after converting the name
		/// into a NID using OBJ_txt2nid()
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public string GetTextByName(string name)
		{
			return GetTextByNid(Native.TextToNID(name));
		}

		/// <summary>
		/// Calls X509_NAME_get_index_by_NID()
		/// </summary>
		/// <param name="nid"></param>
		/// <param name="lastpos"></param>
		/// <returns></returns>
		public int GetIndexByNid(int nid, int lastpos)
		{
			var ret = Native.X509_NAME_get_index_by_NID(ptr, nid, lastpos);

			if (ret == lastpos)
				return lastpos;
			if (ret < 0)
				throw new OpenSslException();

			return ret;
		}

		/// <summary>
		/// Returns the index of a name entry using GetIndexByNid()
		/// </summary>
		/// <param name="name"></param>
		/// <param name="lastpos"></param>
		/// <returns></returns>
		public int IndexOf(string name, int lastpos)
		{
			return GetIndexByNid(Native.TextToNID(name), lastpos);
		}

		/// <summary>
		/// Returns the index of a name entry using GetIndexByNid()
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public int IndexOf(string name)
		{
			return IndexOf(name, -1);
		}

		/// <summary>
		/// Returns true if the name entry with the specified name exists.
		/// </summary>
		/// <param name="name"></param>
		/// <returns></returns>
		public bool Contains(string name)
		{
			return IndexOf(name) >= 0;
		}

		/// <summary>
		/// Returns X509_NAME_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="cbSize"></param>
		/// <returns></returns>
		public ArraySegment<byte> Digest(MessageDigest type, int cbSize)
		{
			var buf = new byte[cbSize];
			var len = (uint)cbSize;
			Native.ExpectSuccess(Native.X509_NAME_digest(this.ptr, type.Handle, buf, ref len));
			
			return new ArraySegment<byte>(buf, 0, (int)len);
		}

		/// <summary>
		/// Calls X509_NAME_print_ex()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			const int flags = 
				Native.ASN1_STRFLGS_RFC2253 |  
				Native.ASN1_STRFLGS_ESC_QUOTE | 
				Native.XN_FLAG_SEP_COMMA_PLUS | 
				Native.XN_FLAG_FN_SN;
			
			var ret = Native.X509_NAME_print_ex(bio.Handle, Handle, 0, flags);
			if (ret <= 0)
				throw new OpenSslException();
		}

		#endregion 

		#region Overrides

		/// <summary>
		/// Calls X509_NAME_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_NAME_free(ptr);
		}

		internal override IntPtr DuplicateHandle()
		{
			return Native.X509_NAME_dup(ptr);
		}

		/// <summary>
		/// Returns CompareTo(rhs) == 0
		/// </summary>
		public override bool Equals(object rhs)
		{
			var other = rhs as X509Name;

			if(other == null)
				return false;

			return CompareTo(other) == 0;
		}

		/// <summary>
		/// Returns ToString().GetHashCode()
		/// </summary>
		public override int GetHashCode()
		{
			return ToString().GetHashCode();
		}

		#endregion

		#region IComparable<X509Name> Members

		/// <summary>
		/// Returns X509_NAME_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(X509Name other)
		{
			return Native.X509_NAME_cmp(ptr, other.ptr);
		}

		#endregion
	}
}
