// Copyright (c) 2009 Frank Laub
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

namespace OpenSSL.X509
{
	/// <summary>
	/// Wraps the X509_STORE_CTX object
	/// </summary>
	public class X509StoreContext : Base
	{
		#region Initialization

		/// <summary>
		/// Calls X509_STORE_CTX_new()
		/// </summary>
		public X509StoreContext() : base(Native.ExpectNonNull(Native.X509_STORE_CTX_new()), true)
		{
		}

		internal X509StoreContext(IntPtr ptr, bool isOwner) : base(ptr, isOwner)
		{
		}

		#endregion

		#region Properties

		/// <summary>
		/// Returns X509_STORE_CTX_get_current_cert()
		/// </summary>
		public X509Certificate CurrentCert
		{
			get
			{
				var cert = Native.X509_STORE_CTX_get_current_cert(ptr);
				return new X509Certificate(cert, false);
			}
		}

		/// <summary>
		/// Returns X509_STORE_CTX_get_error_depth()
		/// </summary>
		public int ErrorDepth
		{
			get { return Native.X509_STORE_CTX_get_error_depth(ptr); }
		}

		/// <summary>
		/// Getter returns X509_STORE_CTX_get_error(), setter calls X509_STORE_CTX_set_error()
		/// </summary>
		public int Error
		{
			get { return Native.X509_STORE_CTX_get_error(ptr); }
			set { Native.X509_STORE_CTX_set_error(ptr, value); }
		}

		/// <summary>
		/// Returns an X509Store based on this context
		/// </summary>
		public X509Store Store
		{
			get { return new X509Store(Native.X509_STORE_CTX_get0_store(Handle), false); }
		}

		/// <summary>
		/// Returns X509_verify_cert_error_string()
		/// </summary>
		public string ErrorString
		{
			get { return Native.PtrToStringAnsi(Native.X509_verify_cert_error_string(Error), false); }
		}

		#endregion

		#region Methods

		/// <summary>
		/// Calls X509_STORE_CTX_init()
		/// </summary>
		/// <param name="store"></param>
		/// <param name="cert"></param>
		/// <param name="uchain"></param>
		public void Init(X509Store store, X509Certificate cert, X509Chain uchain)
		{
			Native.ExpectSuccess(Native.X509_STORE_CTX_init(
				ptr,
				store.Handle,
				cert != null ? cert.Handle : IntPtr.Zero,
				uchain.Handle));
		}

		/// <summary>
		/// Returns X509_verify_cert()
		/// </summary>
		/// <returns></returns>
		public bool Verify()
		{
			var ret = Native.X509_verify_cert(ptr);

			if (ret < 0)
				throw new OpenSslException();

			return ret == 1;
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls X509_STORE_CTX_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_STORE_CTX_free(ptr);
		}

		#endregion
	}
}
