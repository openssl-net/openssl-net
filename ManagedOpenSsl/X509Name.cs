using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	public class X509Name : Base, IDisposable, IComparable<X509Name>
	{
		#region Initialization
		public X509Name() : base(Native.ExpectNonNull(Native.X509_NAME_new())) { }
		internal X509Name(IntPtr ptr) : base(ptr) { }
		public X509Name(X509Name rhs)
			: base(Native.ExpectNonNull(Native.X509_NAME_dup(rhs.ptr)))
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
			get { return Native.PtrToStringAnsi(Native.X509_NAME_oneline(this.ptr, null, 0), true);	}
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
			Native.ExpectSuccess(Native.X509_NAME_print(bio.Handle, this.Handle, 0));
		}
		#endregion 

		#region IDisposable Members

		public void Dispose()
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
