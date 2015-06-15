// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
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

using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
	/// <summary>
	/// Asn1 object.
	/// </summary>
	public class Asn1Object
	{
		[StructLayout(LayoutKind.Sequential)]
		struct asn1_object_st
		{
			public string sn;
			public string ln;
			public int nid;
			public int length;
			public byte[] data;
			public int flags;
		}
		
		private int nid;

		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSSL.Core.Asn1Object"/> class.
		/// </summary>
		/// <param name="nid">Nid.</param>
		public Asn1Object(int nid) 
		{
			this.nid = nid;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSSL.Core.Asn1Object"/> class.
		/// </summary>
		/// <param name="sn">Sn.</param>
		public Asn1Object(string sn) 
		{
			nid = Native.OBJ_sn2nid(sn);
		}

		/// <summary>
		/// Gets the NID.
		/// </summary>
		/// <value>The NID.</value>
		public int NID 
		{ 
			get { return nid; } 
		}

		/// <summary>
		/// Gets the short name.
		/// </summary>
		/// <value>The short name.</value>
		public string ShortName 
		{
			get { return Native.StaticString(Native.OBJ_nid2sn(nid)); }
		}

		/// <summary>
		/// Gets the long name.
		/// </summary>
		/// <value>The long name.</value>
		public string LongName 
		{
			get { return Native.StaticString(Native.OBJ_nid2ln(nid)); }
		}

		/// <summary>
		/// Froms the short name.
		/// </summary>
		/// <returns>The short name.</returns>
		/// <param name="sn">Sn.</param>
		public static Asn1Object FromShortName(string sn) 
		{
			return new Asn1Object(sn);
		}

		/// <summary>
		/// Froms the long name.
		/// </summary>
		/// <returns>The long name.</returns>
		/// <param name="sn">Sn.</param>
		public static Asn1Object FromLongName(string sn) 
		{
			return new Asn1Object(Native.OBJ_ln2nid(sn));
		}

		/// <summary>
		/// Determines whether the specified <see cref="System.Object"/> is equal to the current <see cref="OpenSSL.Core.Asn1Object"/>.
		/// </summary>
		/// <param name="obj">The <see cref="System.Object"/> to compare with the current <see cref="OpenSSL.Core.Asn1Object"/>.</param>
		/// <returns><c>true</c> if the specified <see cref="System.Object"/> is equal to the current
		/// <see cref="OpenSSL.Core.Asn1Object"/>; otherwise, <c>false</c>.</returns>
		public override bool Equals(object obj) 
		{
			var rhs = obj as Asn1Object;

			if (rhs == null)
				return false;
			
			return nid == rhs.nid;
		}

		/// <summary>
		/// Serves as a hash function for a <see cref="OpenSSL.Core.Asn1Object"/> object.
		/// </summary>
		/// <returns>A hash code for this instance that is suitable for use in hashing algorithms and data structures such as a hash table.</returns>
		public override int GetHashCode() 
		{
			return nid;
		}
	}
}

