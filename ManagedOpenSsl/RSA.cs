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
	/// Wraps the RSA_* functions
	/// </summary>
	public class RSA : Base, IDisposable
	{
		#region rsa_st
		[StructLayout(LayoutKind.Sequential)]
		struct rsa_st
		{
			public int pad;
			public int version;
			public IntPtr meth;

			public IntPtr engine;
			public IntPtr n;
			public IntPtr e;
			public IntPtr d;
			public IntPtr p;
			public IntPtr q;
			public IntPtr dmp1;
			public IntPtr dmq1;
			public IntPtr iqmp;
	
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public int references;
			public int flags;

			public IntPtr _method_mod_n;
			public IntPtr _method_mod_p;
			public IntPtr _method_mod_q;

			public IntPtr bignum_data;
			public IntPtr blinding;
			public IntPtr mt_blinding;
		}
		#endregion

		/// <summary>
		/// Not sure
		/// </summary>
		public const int PKCS1_Padding = 1;

		/// <summary>
		/// Not sure
		/// </summary>
		public const int PKCS1_OAEP_Padding = 4;

		private const int FlagCacheMont_P = 0x01;
		private const int FlagNoExpConstTime = 0x02;
		private const int FlagNoConstTime = 0x100;

		private BigNumber.GeneratorThunk thunk = null;

		#region Initialization
		internal RSA(IntPtr ptr, bool owner) : base(ptr, owner) {}

		/// <summary>
		/// Calls RSA_new()
		/// </summary>
		public RSA() 
			: base(Native.ExpectNonNull(Native.RSA_new()), true)
		{ }

		/// <summary>
		/// Calls PEM_read_bio_RSA_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static RSA FromPublicKey(BIO bio)
		{
			return FromPublicKey(bio, null, null);
		}

		/// <summary>
		/// Calls PEM_read_bio_RSAPrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static RSA FromPrivateKey(BIO bio)
		{
			return FromPrivateKey(bio, null, null);
		}

		/// <summary>
		/// Calls PEM_read_bio_RSA_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="callback"></param>
		/// <param name="arg"></param>
		/// <returns></returns>
		public static RSA FromPublicKey(BIO bio, PasswordHandler callback, object arg)
		{
			PasswordThunk thunk = new PasswordThunk(callback, arg);
			IntPtr ptr = Native.PEM_read_bio_RSA_PUBKEY(bio.Handle, IntPtr.Zero, thunk.Callback, IntPtr.Zero);
			return new RSA(Native.ExpectNonNull(ptr), true);
		}

		/// <summary>
		/// Calls PEM_read_bio_RSAPrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="callback"></param>
		/// <param name="arg"></param>
		/// <returns></returns>
		public static RSA FromPrivateKey(BIO bio, PasswordHandler callback, object arg)
		{
			PasswordThunk thunk = new PasswordThunk(callback, arg);
			IntPtr ptr = Native.PEM_read_bio_RSAPrivateKey(bio.Handle, IntPtr.Zero, thunk.Callback, IntPtr.Zero);
			return new RSA(Native.ExpectNonNull(ptr), true);
		}

		#endregion

		#region Properties
		private rsa_st Raw
		{
			get { return (rsa_st)Marshal.PtrToStructure(this.ptr, typeof(rsa_st)); }
			set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		/// <summary>
		/// Returns RSA_size()
		/// </summary>
		public int Size
		{
			get { return Native.ExpectSuccess(Native.RSA_size(this.ptr)); }
		}

		/// <summary>
		/// Not finished
		/// </summary>
		public bool ConstantTime
		{
			get { return false; }
			set 
			{ 
			}
		}

		/// <summary>
		/// Accessor for the e field
		/// </summary>
		public BigNumber E
		{
			get { return new BigNumber(this.Raw.e, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.e = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the n field
		/// </summary>
		public BigNumber N
		{
			get { return new BigNumber(this.Raw.n, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.n = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the d field
		/// </summary>
		public BigNumber D
		{
			get { return new BigNumber(this.Raw.d, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.d = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the p field
		/// </summary>
		public BigNumber P
		{
			get { return new BigNumber(this.Raw.p, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.p = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the q field
		/// </summary>
		public BigNumber Q
		{
			get { return new BigNumber(this.Raw.q, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.q = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the dmp1 field
		/// </summary>
		public BigNumber Dmp1
		{
			get { return new BigNumber(this.Raw.dmp1, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.dmp1 = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the dmq1 field
		/// </summary>
		public BigNumber Dmq1
		{
			get { return new BigNumber(this.Raw.dmq1, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.dmq1 = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Accessor for the iqmp field
		/// </summary>
		public BigNumber Iqmp
		{
			get { return new BigNumber(this.Raw.iqmp, false); }
			set
			{
				rsa_st raw = this.Raw;
				raw.iqmp = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		/// <summary>
		/// Returns the public key field as a PEM string
		/// </summary>
		public string PublicKeyAsPEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.WritePublicKey(bio);
					return bio.ReadString();
				}
			}
		}

		/// <summary>
		/// Returns the private key field as a PEM string
		/// </summary>
		public string PrivateKeyAsPEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.WritePrivateKey(bio, null, null, null);
					return bio.ReadString();
				}
			}
		}
		#endregion

		#region Methods
		/// <summary>
		/// Calls RSA_generate_key_ex()
		/// </summary>
		/// <param name="bits"></param>
		/// <param name="e"></param>
		/// <param name="callback"></param>
		/// <param name="arg"></param>
		public void GenerateKeys(int bits, BigNumber e, BigNumber.GeneratorHandler callback, object arg)
		{
			this.thunk = new BigNumber.GeneratorThunk(callback, arg);
			Native.ExpectSuccess(Native.RSA_generate_key_ex(this.ptr, bits, e.Handle, this.thunk.CallbackStruct));
		}

		/// <summary>
		/// Calls RSA_public_encrypt()
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="padding"></param>
		/// <returns></returns>
		public byte[] PublicEncrypt(byte[] msg, int padding)
		{
			byte[] ret = new byte[this.Size];
			int len = Native.ExpectSuccess(Native.RSA_public_encrypt(msg.Length, msg, ret, this.ptr, padding));
			if (len != ret.Length)
			{
				byte[] tmp = new byte[len];
				Buffer.BlockCopy(ret, 0, tmp, 0, len);
				return tmp;
			}
			return ret;
		}

		/// <summary>
		/// Calls RSA_private_encrypt()
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="padding"></param>
		/// <returns></returns>
		public byte[] PrivateEncrypt(byte[] msg, int padding)
		{
			byte[] ret = new byte[this.Size];
			int len = Native.ExpectSuccess(Native.RSA_private_encrypt(msg.Length, msg, ret, this.ptr, padding));
			if (len != ret.Length)
			{
				byte[] tmp = new byte[len];
				Buffer.BlockCopy(ret, 0, tmp, 0, len);
				return tmp;
			}
			return ret;
		}

		/// <summary>
		/// Calls RSA_public_decrypt()
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="padding"></param>
		/// <returns></returns>
		public byte[] PublicDecrypt(byte[] msg, int padding)
		{
			byte[] ret = new byte[this.Size];
			int len = Native.ExpectSuccess(Native.RSA_public_decrypt(msg.Length, msg, ret, this.ptr, padding));
			if (len != ret.Length)
			{
				byte[] tmp = new byte[len];
				Buffer.BlockCopy(ret, 0, tmp, 0, len);
				return tmp;
			}
			return ret;
		}

		/// <summary>
		/// Calls RSA_private_decrypt()
		/// </summary>
		/// <param name="msg"></param>
		/// <param name="padding"></param>
		/// <returns></returns>
		public byte[] PrivateDecrypt(byte[] msg, int padding)
		{
			byte[] ret = new byte[this.Size];
			int len = Native.ExpectSuccess(Native.RSA_private_decrypt(msg.Length, msg, ret, this.ptr, padding));
			if (len != ret.Length)
			{
				byte[] tmp = new byte[len];
				Buffer.BlockCopy(ret, 0, tmp, 0, len);
				return tmp;
			}
			return ret;
		}

		/// <summary>
		/// Calls PEM_write_bio_RSA_PUBKEY()
		/// </summary>
		/// <param name="bio"></param>
		public void WritePublicKey(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_RSA_PUBKEY(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Calls PEM_write_bio_RSAPrivateKey()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="enc"></param>
		/// <param name="passwd"></param>
		/// <param name="arg"></param>
		public void WritePrivateKey(BIO bio, Cipher enc, PasswordHandler passwd, object arg)
		{
			PasswordThunk thunk = new PasswordThunk(passwd, arg);
			Native.ExpectSuccess(Native.PEM_write_bio_RSAPrivateKey(
				bio.Handle,
				this.ptr,
				enc == null ? IntPtr.Zero : enc.Handle,
				null,
				0,
				thunk.Callback,
				IntPtr.Zero));
		}

		/// <summary>
		/// Returns RSA_check_key()
		/// </summary>
		/// <returns></returns>
		public bool Check()
		{
			int ret = Native.ExpectSuccess(Native.RSA_check_key(this.ptr));
			return ret == 1;
		}

		/// <summary>
		/// Calls RSA_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.RSA_print(bio.Handle, this.ptr, 0));
		}

		#endregion

		#region IDisposable Members

		/// <summary>
		/// Calls RSA_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.RSA_free(this.ptr);
		}

		#endregion
	}
}