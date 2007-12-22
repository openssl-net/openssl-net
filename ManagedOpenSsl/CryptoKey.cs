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
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public delegate string PasswordHandler(bool verify, object userdata);

	public class PasswordCallback
	{
		private string password;
		public PasswordCallback(string password)
		{
			this.password = password;
		}

		public string OnPassword(bool verify, object userdata)
		{
			return this.password;
		}
	}

	/// <summary>
	/// Wraps the native OpenSSL EVP_PKEY object
	/// </summary>
	public class CryptoKey : Base, IDisposable
	{
		#region Initialization
		internal CryptoKey(IntPtr ptr, bool owner) : base(ptr, owner) { }
		public CryptoKey() : base(Native.ExpectNonNull(Native.EVP_PKEY_new()), true) {}
		
		public static CryptoKey FromPublicKey(string pem, string password)
		{
			return FromPublicKey(new BIO(pem), password);
		}

		public static CryptoKey FromPublicKey(BIO bio, string password)
		{
			PasswordCallback callback = new PasswordCallback(password);
			return FromPublicKey(bio, callback.OnPassword, null);
		}

		public static CryptoKey FromPublicKey(BIO bio, PasswordHandler handler, object arg)
		{
			PasswordThunk thunk = new PasswordThunk(handler, arg);
			IntPtr ptr = Native.ExpectNonNull(Native.PEM_read_bio_PUBKEY(
				bio.Handle,
				IntPtr.Zero,
				thunk.Callback,
				IntPtr.Zero
			));

			return new CryptoKey(ptr, true);
		}

		public static CryptoKey FromPrivateKey(string pem, string password)
		{
			return FromPrivateKey(new BIO(pem), password);
		}

		public static CryptoKey FromPrivateKey(BIO bio, string passwd)
		{
			PasswordCallback callback = new PasswordCallback(passwd);
			return FromPrivateKey(bio, callback.OnPassword, null);
		}

		public static CryptoKey FromPrivateKey(BIO bio, PasswordHandler handler, object arg)
		{
			PasswordThunk thunk = new PasswordThunk(handler, arg);
			IntPtr ptr = Native.ExpectNonNull(Native.PEM_read_bio_PrivateKey(
				bio.Handle, 
				IntPtr.Zero,
				thunk.Callback, 
				IntPtr.Zero
			));

			return new CryptoKey(ptr, true);
		}

		public CryptoKey(DSA dsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DSA(this.ptr, dsa.Handle));
		}

		public CryptoKey(RSA rsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_RSA(this.ptr, rsa.Handle));
		}

		public CryptoKey(DH dh)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DH(this.ptr, dh.Handle));
		}
		#endregion

		#region Properties
		public int Bits
		{
			get { return Native.EVP_PKEY_bits(this.ptr); }
		}

		public int Size
		{
			get { return Native.EVP_PKEY_size(this.ptr); }
		}
		#endregion

		#region Methods
		public void Assign(int type, byte[] key)
		{
			Native.ExpectSuccess(Native.EVP_PKEY_assign(this.ptr, type, key));
		}

		public DSA GetDSA()
		{
			return new DSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_DSA(this.ptr)), false);
		}
		
		public DH GetDH()
		{
			return new DH(Native.ExpectNonNull(Native.EVP_PKEY_get1_DH(this.ptr)), false);
		}
		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.EVP_PKEY_free(this.ptr);
		}

		#endregion
	}
}
