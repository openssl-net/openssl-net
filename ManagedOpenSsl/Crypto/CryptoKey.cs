// Copyright (c) 2006-2012 Frank Laub
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

namespace OpenSSL.Crypto
{
	/// <summary>
	/// Wraps the native OpenSSL EVP_PKEY object
	/// </summary>
	public class CryptoKey : BaseReferenceImpl
	{
		/// <summary>
		/// Set of types that this CryptoKey can be.
		/// </summary>
		public enum KeyType
		{
			/// <summary>
			/// EVP_PKEY_RSA 
			/// </summary>
			RSA = 6,
			/// <summary>
			/// EVP_PKEY_DSA
			/// </summary>
			DSA = 116,
			/// <summary>
			/// EVP_PKEY_DH
			/// </summary>
			DH = 28,
			/// <summary>
			/// EVP_PKEY_EC
			/// </summary>
			EC = 408
		}

		[StructLayout(LayoutKind.Sequential)]
		struct EVP_PKEY
		{
			public int type;
			public int save_type;
			public int references;
			public IntPtr ameth;
			public IntPtr engine;
			public IntPtr pkey;
			public int save_parameters;
			public IntPtr attributes;
		}

		#region Initialization

		internal CryptoKey(IntPtr ptr, bool owner)
			: base(ptr, owner)
		{
		}

		/// <summary>
		/// Calls EVP_PKEY_new()
		/// </summary>
		public CryptoKey()
			: base(Native.ExpectNonNull(Native.EVP_PKEY_new()), true)
		{
		}

		private CryptoKey(CryptoKey other)
			: base(other.Handle, true)
		{
			AddRef();
		}

		/// <summary>
		/// Returns a copy of this object.
		/// </summary>
		/// <returns></returns>
		public CryptoKey CopyRef()
		{
			return new CryptoKey(this);
		}

		/// <summary>
		/// Calls PEM_read_bio_PUBKEY()
		/// </summary>
		/// <param name="pem"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static CryptoKey FromPublicKey(string pem, string password)
		{
			using (var bio = new BIO(pem))
			{
				return FromPublicKey(bio, password);
			}
		}

		/// <summary>
		/// Calls PEM_read_bio_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="password"></param>
		/// <returns></returns>
		public static CryptoKey FromPublicKey(BIO bio, string password)
		{
			var callback = new PasswordCallback(password);
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
			var thunk = new PasswordThunk(handler, arg);
			var ptr = Native.ExpectNonNull(Native.PEM_read_bio_PUBKEY(
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
			using (var bio = new BIO(pem))
			{
				return FromPrivateKey(bio, password);
			}
		}

		/// <summary>
		/// Calls PEM_read_bio_PrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="passwd"></param>
		/// <returns></returns>
		public static CryptoKey FromPrivateKey(BIO bio, string passwd)
		{
			var callback = new PasswordCallback(passwd);
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
			var thunk = new PasswordThunk(handler, arg);
			var ptr = Native.ExpectNonNull(Native.PEM_read_bio_PrivateKey(
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
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DSA(ptr, dsa.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_set1_RSA()
		/// </summary>
		/// <param name="rsa"></param>
		public CryptoKey(RSA rsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_RSA(ptr, rsa.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_set1_EC()
		/// </summary>
		/// <param name="ec"></param>
		public CryptoKey(EC.Key ec)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_EC_KEY(ptr, ec.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_set1_DH()
		/// </summary>
		/// <param name="dh"></param>
		public CryptoKey(DH dh)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DH(ptr, dh.Handle));
		}

		#endregion

		#region Properties

		private EVP_PKEY Raw
		{
			get { return (EVP_PKEY)Marshal.PtrToStructure(ptr, typeof(EVP_PKEY)); }
		}

		/// <summary>
		/// Returns EVP_PKEY_type()
		/// </summary>
		public KeyType Type
		{
			get { return (KeyType)Native.EVP_PKEY_type(Raw.type); }
		}

		/// <summary>
		/// Returns EVP_PKEY_bits()
		/// </summary>
		public int Bits
		{
			get { return Native.EVP_PKEY_bits(ptr); }
		}

		/// <summary>
		/// Returns EVP_PKEY_size()
		/// </summary>
		public int Size
		{
			get { return Native.EVP_PKEY_size(ptr); }
		}

		#endregion

		#region Methods

		/// <summary>
		/// Calls EVP_PKEY_assign()
		/// </summary>
		/// <param name="key">Key.</param>
		public void Assign(RSA key)
		{
			key.AddRef();
			Native.ExpectSuccess(Native.EVP_PKEY_assign(ptr, (int)KeyType.RSA, key.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_assign()
		/// </summary>
		/// <param name="key">Key.</param>
		public void Assign(DSA key)
		{
			key.AddRef();
			Native.ExpectSuccess(Native.EVP_PKEY_assign(ptr, (int)KeyType.DSA, key.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_assign()
		/// </summary>
		/// <param name="key">Key.</param>
		public void Assign(DH key)
		{
			key.AddRef();
			Native.ExpectSuccess(Native.EVP_PKEY_assign(ptr, (int)KeyType.DH, key.Handle));
		}

		/// <summary>
		/// Calls EVP_PKEY_assign()
		/// </summary>
		/// <param name="key">Key.</param>
		public void Assign(EC.Key key)
		{
			key.AddRef();
			Native.ExpectSuccess(Native.EVP_PKEY_assign(ptr, (int)KeyType.EC, key.Handle));
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_DSA()
		/// </summary>
		/// <returns></returns>
		public DSA GetDSA()
		{
			if (Type != KeyType.DSA)
				throw new InvalidOperationException();

			return new DSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_DSA(ptr)), true);
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_DH()
		/// </summary>
		/// <returns></returns>
		public DH GetDH()
		{
			if (Type != KeyType.DH)
				throw new InvalidOperationException();

			return new DH(Native.ExpectNonNull(Native.EVP_PKEY_get1_DH(ptr)), true);
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_RSA()
		/// </summary>
		/// <returns></returns>
		public RSA GetRSA()
		{
			if (Type != KeyType.RSA)
				throw new InvalidOperationException();

			return new RSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_RSA(ptr)), true);
		}

		/// <summary>
		/// Returns EVP_PKEY_get1_EC()
		/// </summary>
		/// <returns></returns>
		public EC.Key GetEC()
		{
			if (Type != KeyType.EC)
				throw new InvalidOperationException();

			return new EC.Key(Native.ExpectNonNull(Native.EVP_PKEY_get1_EC_KEY(ptr)), true);
		}


		/// <summary>
		/// Calls PEM_write_bio_PKCS8PrivateKey
		/// </summary>
		/// <param name="bp"></param>
		/// <param name="cipher"></param>
		/// <param name="password"></param>
		public void WritePrivateKey(BIO bp, Cipher cipher, string password)
		{
			PasswordCallback callback = new PasswordCallback(password);
			WritePrivateKey(bp, cipher, callback.OnPassword, null);
		}

		/// <summary>
		/// Calls PEM_write_bio_PKCS8PrivateKey
		/// </summary>
		/// <param name="bp"></param>
		/// <param name="cipher"></param>
		/// <param name="handler"></param>
		/// <param name="arg"></param>
		public void WritePrivateKey(BIO bp, Cipher cipher, PasswordHandler handler, object arg)
		{
			var thunk = new PasswordThunk(handler, null);
			Native.ExpectSuccess(Native.PEM_write_bio_PKCS8PrivateKey(bp.Handle, ptr, cipher.Handle, IntPtr.Zero, 0, thunk.Callback, IntPtr.Zero));
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls EVP_PKEY_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.EVP_PKEY_free(ptr);
		}

		/// <summary>
		/// Returns CompareTo(obj)
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object obj)
		{
			var rhs = obj as CryptoKey;

			if (rhs == null)
				return false;

			return Native.EVP_PKEY_cmp(ptr, rhs.Handle) == 1;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public override int GetHashCode()
		{
			return base.GetHashCode();
		}

		/// <summary>
		/// Calls appropriate Print() based on the type.
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			switch (Type)
			{
				case KeyType.RSA:
					GetRSA().Print(bio);
					break;
				case KeyType.DSA:
					GetDSA().Print(bio);
					break;
				case KeyType.EC:
					break;
				case KeyType.DH:
					GetDH().Print(bio);
					break;
			}
		}

		internal override CryptoLockTypes LockType
		{
			get { return CryptoLockTypes.CRYPTO_LOCK_EVP_PKEY; }
		}

		internal override Type RawReferenceType
		{
			get { return typeof(EVP_PKEY); }
		}

		#endregion
	}
}
