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
	/// <summary>
	/// Callback prototype. Must return the password or prompt for one.
	/// </summary>
	/// <param name="verify"></param>
	/// <param name="userdata"></param>
	/// <returns></returns>
	public delegate string PasswordHandler(bool verify, object userdata);

	/// <summary>
	/// Simple password callback that returns the contained password.
	/// </summary>
	public class PasswordCallback
	{
		private string password;
		/// <summary>
		/// Constructs a PasswordCallback
		/// </summary>
		/// <param name="password"></param>
		public PasswordCallback(string password)
		{
			this.password = password;
		}

		/// <summary>
		/// Suitable callback to be used as a PasswordHandler
		/// </summary>
		/// <param name="verify"></param>
		/// <param name="userdata"></param>
		/// <returns></returns>
		public string OnPassword(bool verify, object userdata)
		{
			return this.password;
		}
	}

	internal class PasswordThunk
	{
		private PasswordHandler OnPassword;
		private object arg;

		public Native.pem_password_cb Callback
		{
			get
			{
				if (this.OnPassword == null)
					return null;
				return this.OnPasswordThunk;
			}
		}

		public PasswordThunk(PasswordHandler client, object arg)
		{
			this.OnPassword = client;
			this.arg = arg;
		}

		internal int OnPasswordThunk(IntPtr buf, int size, int rwflag, IntPtr userdata)
		{
			try
			{
				string ret = OnPassword(rwflag != 0, this.arg);
				byte[] pass = Encoding.ASCII.GetBytes(ret);
				int len = pass.Length;
				if (len > size)
					len = size;

				Marshal.Copy(pass, 0, buf, len);
				return len;
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.Message);
				return -1;
			}
		}
	}

	/// <summary>
	/// Wraps the native OpenSSL EVP_PKEY object
	/// </summary>
	public class CryptoKey : Base, IDisposable
	{
		#region Initialization
		internal CryptoKey(IntPtr ptr, bool owner) : base(ptr, owner) { }
		/// <summary>
		/// Calls EVP_PKEY_new()
		/// </summary>
		public CryptoKey() : base(Native.ExpectNonNull(Native.EVP_PKEY_new()), true) {}
		
		/// <summary>
		/// Calls PEM_read_bio_PUBKEY()
		/// </summary>
		/// <param name="pem"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static CryptoKey FromPublicKey(string pem, string password)
		{
			return FromPublicKey(new BIO(pem), password);
		}

		/// <summary>
		/// Calls PEM_read_bio_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static CryptoKey FromPublicKey(BIO bio, string password)
		{
			PasswordCallback callback = new PasswordCallback(password);
			return FromPublicKey(bio, callback.OnPassword, null);
		}

		/// <summary>
		/// Calls PEM_read_bio_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="handler"></param>
		/// <param name="arg"></param>
		/// <returns></returns>
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

		/// <summary>
		/// Calls PEM_read_bio_PrivateKey()
		/// </summary>
		/// <param name="pem"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static CryptoKey FromPrivateKey(string pem, string password)
		{
			return FromPrivateKey(new BIO(pem), password);
		}

		/// <summary>
		/// Calls PEM_read_bio_PrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="passwd"></param>
		/// <returns></returns>
		public static CryptoKey FromPrivateKey(BIO bio, string passwd)
		{
			PasswordCallback callback = new PasswordCallback(passwd);
			return FromPrivateKey(bio, callback.OnPassword, null);
		}

		/// <summary>
		/// Calls PEM_read_bio_PrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="handler"></param>
		/// <param name="arg"></param>
		/// <returns></returns>
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

		/// <summary>
		/// Calls EVP_PKEY_set1_DSA()
		/// </summary>
		/// <param name="dsa"></param>
		public CryptoKey(DSA dsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DSA(this.ptr, dsa.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_set1_RSA()
		/// </summary>
		/// <param name="rsa"></param>
		public CryptoKey(RSA rsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_RSA(this.ptr, rsa.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_set1_DH()
		/// </summary>
		/// <param name="dh"></param>
		public CryptoKey(DH dh)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DH(this.ptr, dh.Handle));
		}
		#endregion

		#region Properties
		/// <summary>
		/// Returns EVP_PKEY_bits()
		/// </summary>
		public int Bits
		{
			get { return Native.EVP_PKEY_bits(this.ptr); }
		}

		/// <summary>
		/// Returns EVP_PKEY_size()
		/// </summary>
		public int Size
		{
			get { return Native.EVP_PKEY_size(this.ptr); }
		}
		#endregion

		#region Methods
		/// <summary>
		/// Calls EVP_PKEY_assign()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="key"></param>
		public void Assign(int type, byte[] key)
		{
			Native.ExpectSuccess(Native.EVP_PKEY_assign(this.ptr, type, key));
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_DSA()
		/// </summary>
		/// <returns></returns>
		public DSA GetDSA()
		{
			return new DSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_DSA(this.ptr)), false);
		}
		
		/// <summary>
		/// Returns EVP_PKEY_get1_DH()
		/// </summary>
		/// <returns></returns>
		public DH GetDH()
		{
			return new DH(Native.ExpectNonNull(Native.EVP_PKEY_get1_DH(this.ptr)), false);
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_RSA()
		/// </summary>
		/// <returns></returns>
		public RSA GetRSA()
		{
			return new RSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_RSA(this.ptr)), false);
		}
		#endregion

		#region IDisposable Members

		/// <summary>
		/// Calls EVP_PKEY_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.EVP_PKEY_free(this.ptr);
		}

		#endregion
	}
}
