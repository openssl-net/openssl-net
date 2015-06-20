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

using OpenSSL.Core;
using System;
using System.Runtime.InteropServices;

namespace OpenSSL.Crypto.EC
{
	/// <summary>
	/// Wraps EC_builtin_curve
	/// </summary>
	public class BuiltinCurve
	{
		[StructLayout(LayoutKind.Sequential)]
		private struct EC_builtin_curve
		{
			public int nid;
			public string comment;
		}

		private Asn1Object obj;
		private string comment;

		private BuiltinCurve(int nid, string comment)
		{
			obj = new Asn1Object(nid);
			this.comment = comment;
		}

		/// <summary>
		/// Returns obj
		/// </summary>
		public Asn1Object Object { get { return obj; } }

		/// <summary>
		/// Returns comment
		/// </summary>
		public string Comment { get { return comment; } }

		/// <summary>
		/// Calls EC_get_builtin_curves()
		/// </summary>
		/// <returns></returns>
		public static BuiltinCurve[] Get()
		{
			var count = Native.EC_get_builtin_curves(IntPtr.Zero, 0);
			var curves = new BuiltinCurve[count];
			var ptr = Native.OPENSSL_malloc(Marshal.SizeOf(typeof(EC_builtin_curve)) * count);

			try
			{
				Native.ExpectSuccess(Native.EC_get_builtin_curves(ptr, count));
				var pItem = ptr;

				for (var i = 0; i < count; i++)
				{
					var raw = (EC_builtin_curve)Marshal.PtrToStructure(pItem, typeof(EC_builtin_curve));
					curves[i] = new BuiltinCurve(raw.nid, raw.comment);
					pItem = new IntPtr(pItem.ToInt64() + Marshal.SizeOf(typeof(EC_builtin_curve)));
				}
			}
			finally
			{
				Native.OPENSSL_free(ptr);
			}

			return curves;
		}
	}
}

