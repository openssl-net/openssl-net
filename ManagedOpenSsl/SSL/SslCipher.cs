// Copyright (c) 2009 Ben Henderson
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
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;

namespace OpenSSL.SSL
{
	/// <summary>
	/// Wraps a SSL_CIPHER
	/// </summary>
	public class SslCipher : BaseReference, IStackable
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSSL.SSL.SslCipher"/> class.
		/// </summary>
		public SslCipher() :
			this(IntPtr.Zero, false)
		{
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="OpenSSL.SSL.SslCipher"/> class.
		/// </summary>
		/// <param name="ptr">Ptr.</param>
		/// <param name="owner">If set to <c>true</c> owner.</param>
		public SslCipher(IntPtr ptr, bool owner) :
			base(ptr, owner)
		{
		}

		internal SslCipher(IStack stack, IntPtr ptr) :
			base(ptr, true)
		{
		}

		/// <summary>
		/// see https://www.openssl.org/docs/apps/ciphers.html
		/// for details about OpenSSL cipher string
		/// </summary>
		/// <returns>The string.</returns>
		/// <param name="sslProtocols">SSL protocols.</param>
		/// <param name="sslStrength">SSL strength.</param>
		public static string MakeString(SslProtocols sslProtocols, SslStrength sslStrength)
		{
			var parts = new List<string>();

			if (EnumExtensions.HasFlag(sslStrength, SslStrength.High))
			{
				parts.Add("HIGH");
			}

			if (EnumExtensions.HasFlag(sslStrength, SslStrength.Medium))
			{
				parts.Add("MEDIUM");
			}

			if (EnumExtensions.HasFlag(sslStrength, SslStrength.Low))
			{
				parts.Add("LOW");
			}

			if ((sslProtocols == SslProtocols.Default) ||
				(sslProtocols == SslProtocols.Tls) ||
				(sslProtocols == SslProtocols.Ssl3))
			{
				parts.Add("!SSLv2");
			}

			parts.Add("!ADH");
			parts.Add("!aNULL");
			parts.Add("!eNULL");
			parts.Add("@STRENGTH");

			return string.Join(":", parts.ToArray());
		}

		/// <summary>
		/// Returns SSL_CIPHER_get_name()
		/// </summary>
		public string Name
		{
			get { return Native.StaticString(Native.SSL_CIPHER_get_name(Handle)); }
		}

		/// <summary>
		/// Returns SSL_CIPHER_description()
		/// </summary>
		public string Description
		{
			get { return Native.SSL_CIPHER_description(Handle, null, 0); }
		}

		/// <summary>
		/// Returns SSL_CIPHER_get_version()
		/// </summary>
		/// <value>The version.</value>
		public string Version
		{
			get { return Native.StaticString(Native.SSL_CIPHER_get_version(Handle)); }
		}

		/// <summary>
		/// Returns SSL_CIPHER_get_bits()
		/// </summary>
		public int Bits
		{
			get
			{
				var alg_bits = 0;
				return Native.SSL_CIPHER_get_bits(Handle, out alg_bits);
			}
		}

		internal override void AddRef()
		{
			// SSL_CIPHERs come from a static list in ssl_ciph.c
			// nothing to do here
		}

		/// <summary>
		/// This method must be implemented in derived classes.
		/// </summary>
		protected override void OnDispose()
		{
			// SSL_CIPHERs come from a static list in ssl_ciph.c
			// nothing to do here
		}
	}
}
