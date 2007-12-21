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

using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	public class X509Name : Base, IDisposable, IComparable<X509Name>
	{
		#region Initialization
		public X509Name() : base(Native.ExpectNonNull(Native.X509_NAME_new()), true) { }
		internal X509Name(IntPtr ptr, bool owner) : base(ptr, owner) { }
		public X509Name(X509Name rhs)
			: base(Native.ExpectNonNull(Native.X509_NAME_dup(rhs.ptr)), true)
		{
		}

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

		public static implicit operator X509Name(string value)
		{
			return new X509Name(value);
		}
		#endregion

		#region Properties
		public string OneLine
		{
			get { return Native.PtrToStringAnsi(Native.X509_NAME_oneline(this.ptr, null, 0), true);	 }
		}
		
		public string Common
		{
			get { return this.GetTextByName("CN"); }
			set { this.AddEntryByName("CN", value); }
		}

		public string Country
		{
			get { return this.GetTextByName("C"); }
			set { this.AddEntryByName("C", value); }
		}

		public string Locality
		{
			get { return this.GetTextByName("L"); }
			set { this.AddEntryByName("L", value); }
		}

		public string StateOrProvince
		{
			get { return this.GetTextByName("ST"); }
			set { this.AddEntryByName("ST", value); }
		}

		public string Organization
		{
			get { return this.GetTextByName("O"); }
			set { this.AddEntryByName("O", value); }
		}

		public string OrganizationUnit
		{
			get { return this.GetTextByName("OU"); }
			set { this.AddEntryByName("OU", value); }
		}

		public string Given
		{
			get { return this.GetTextByName("G"); }
			set { this.AddEntryByName("G", value); }
		}

		public string Surname
		{
			get { return this.GetTextByName("S"); }
			set { this.AddEntryByName("S", value); }
		}

		public string Initials
		{
			get { return this.GetTextByName("I"); }
			set { this.AddEntryByName("I", value); }
		}

		public string UniqueIdentifier
		{
			get { return this.GetTextByName("UID"); }
			set { this.AddEntryByName("UID", value); }
		}

		public string SerialNumber
		{
			get { return this.GetTextByName("SN"); }
			set { this.AddEntryByName("SN", value); }
		}

		public string Title
		{
			get { return this.GetTextByName("T"); }
			set { this.AddEntryByName("T", value); }
		}

		public string Description
		{
			get { return this.GetTextByName("D"); }
			set { this.AddEntryByName("D", value); }
		}

		public string X509
		{
			get { return this.GetTextByName("X509"); }
			set { this.AddEntryByName("X509", value); }
		}

		public int Count
		{
			get { return Native.X509_NAME_entry_count(this.ptr); }
		}

		public string this[string name]
		{
			get { return this.GetTextByName(name); }
			set { this.AddEntryByName(name, value); }
		}

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
		public void AddEntryByName(string name, string value)
		{
			this.AddEntryByNid(Native.TextToNID(name), value);
		}

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

		public string GetTextByName(string name)
		{
			return this.GetTextByNid(Native.TextToNID(name));
		}

		public int GetIndexByNid(int nid, int lastpos)
		{
			int ret = Native.X509_NAME_get_index_by_NID(this.ptr, nid, lastpos);
			if (ret == lastpos)
				return lastpos;
			if (ret < 0)
				throw new OpenSslException();
			return ret;
		}

		public int IndexOf(string name, int lastpos)
		{
			return GetIndexByNid(Native.TextToNID(name), lastpos);
		}

		public int IndexOf(string name)
		{
			return this.IndexOf(name, -1);
		}

		public bool Contains(string name)
		{
			return this.IndexOf(name) >= 0;
		}

		public ArraySegment<byte> Digest(MessageDigest type, int cbSize)
		{
			byte[] buf = new byte[cbSize];
			uint len = (uint)cbSize;
			Native.ExpectSuccess(Native.X509_NAME_digest(this.ptr, type.Handle, buf, ref len));
			return new ArraySegment<byte>(buf, 0, (int)len);
		}

		public override void Print(BIO bio)
		{
			const int flags = 
				Native.ASN1_STRFLGS_RFC2253 |  
				Native.ASN1_STRFLGS_ESC_QUOTE | 
				Native.XN_FLAG_SEP_COMMA_PLUS | 
				Native.XN_FLAG_FN_SN;
			int ret = Native.X509_NAME_print_ex(bio.Handle, this.Handle, 0, flags);
			if (ret <= 0)
				throw new OpenSslException();
		}
		#endregion 

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.X509_NAME_free(this.ptr);
		}

		#endregion

		#region IComparable<X509Name> Members

		public int CompareTo(X509Name other)
		{
			return Native.X509_NAME_cmp(this.ptr, other.ptr);
		}

		#endregion
	}
}
