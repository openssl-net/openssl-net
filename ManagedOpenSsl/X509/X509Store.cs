// Copyright (c) 2006-2009 Frank Laub
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
	/// Wraps the X509_STORE object
	/// </summary>
	public class X509Store : BaseReferenceImpl
	{
		#region X509_STORE
		[StructLayout(LayoutKind.Sequential)]
		struct X509_STORE
		{
			public int cache;
			public IntPtr objs;
			public IntPtr get_cert_methods;
			public IntPtr param;
			public IntPtr verify;
			public IntPtr verify_cb;
			public IntPtr get_issuer;
			public IntPtr check_issued;
			public IntPtr check_revocation;
			public IntPtr get_crl;
			public IntPtr check_crl;
			public IntPtr cert_crl;
			public IntPtr lookup_certs;
			public IntPtr lookup_crls;
			public IntPtr cleanup;
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public int references;
		}
		#endregion

		#region Initialization

		/// <summary>
		/// Calls X509_STORE_new()
		/// </summary>
		public X509Store()
			: base(Native.ExpectNonNull(Native.X509_STORE_new()), true)
		{ }

		/// <summary>
		/// Initializes the X509Store object with a pre-existing native X509_STORE pointer
		/// </summary>
		/// <param name="ptr"></param>
		/// <param name="takeOwnership"></param>
		internal X509Store(IntPtr ptr, bool takeOwnership) :
			base(ptr, takeOwnership)
		{ }

		/// <summary>
		/// Calls X509_STORE_new() and then adds the specified chain as trusted.
		/// </summary>
		/// <param name="chain"></param>
		public X509Store(X509Chain chain)
			: this(chain, true)
		{ }

		/// <summary>
		/// Calls X509_STORE_new() and then adds the specified chain as trusted.
		/// </summary>
		/// <param name="chain"></param>
		/// <param name="takeOwnership"></param>
		public X509Store(X509Chain chain, bool takeOwnership)
			: base(Native.ExpectNonNull(Native.X509_STORE_new()), takeOwnership)
		{
			foreach (var cert in chain)
			{
				AddTrusted(cert);
			}
		}

		#endregion

		#region Properties

		/// <summary>
		/// Wraps the <code>objs</code> member on the raw X509_STORE structure
		/// </summary>
		public Core.Stack<X509Object> Objects
		{
			get
			{
				var raw = (X509_STORE)Marshal.PtrToStructure(ptr, typeof(X509_STORE));
				return new Core.Stack<X509Object>(raw.objs, false);
			}
		}

		/// <summary>
		/// Accessor to the untrusted list
		/// </summary>
		public X509Chain Untrusted
		{
			get { return untrusted; }
			set { untrusted = value; }
		}

		#endregion

		#region Methods

		/// <summary>
		/// Returns the trusted state of the specified certificate
		/// </summary>
		/// <param name="cert"></param>
		/// <param name="error"></param>
		/// <returns></returns>
		public bool Verify(X509Certificate cert, out string error)
		{
			using (var ctx = new X509StoreContext())
			{
				ctx.Init(this, cert, untrusted);
				if (ctx.Verify())
				{
					error = "";
					return true;
				}

				error = ctx.ErrorString;
			}

			return false;
		}

		/// <summary>
		/// Adds a chain to the trusted list.
		/// </summary>
		/// <param name="chain"></param>
		public void AddTrusted(X509Chain chain)
		{
			foreach (var cert in chain)
			{
				AddTrusted(cert);
			}
		}

		/// <summary>
		/// Adds a certificate to the trusted list, calls X509_STORE_add_cert()
		/// </summary>
		/// <param name="cert"></param>
		public void AddTrusted(X509Certificate cert)
		{
			// Don't Addref here -- X509_STORE_add_cert increases the refcount of the certificate pointer
			Native.ExpectSuccess(Native.X509_STORE_add_cert(ptr, cert.Handle));
		}

		/// <summary>
		/// Add an untrusted certificate
		/// </summary>
		/// <param name="cert"></param>
		public void AddUntrusted(X509Certificate cert)
		{
			untrusted.Add(cert);
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls X509_STORE_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.X509_STORE_free(ptr);
			if (untrusted != null)
			{
				untrusted.Dispose();
				untrusted = null;
			}
		}

		internal override CryptoLockTypes LockType
		{
			get { return CryptoLockTypes.CRYPTO_LOCK_X509_STORE; }
		}

		internal override Type RawReferenceType
		{
			get { return typeof(X509_STORE); }
		}

		#endregion

		#region Fields
		private X509Chain untrusted = new X509Chain();
		#endregion
	}
}
