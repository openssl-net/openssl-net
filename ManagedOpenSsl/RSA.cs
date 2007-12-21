// Copyright (c) 2007 Frank Laub
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

		public const int PKCS1_Padding = 1;
		public const int PKCS1_OAEP_Padding = 4;

		private const int FlagCacheMont_P = 0x01;
		private const int FlagNoExpConstTime = 0x02;
		private const int FlagNoConstTime = 0x100;

		#region Initialization
		internal RSA(IntPtr ptr, bool owner) : base(ptr, owner) {}
		public RSA() 
			: base(Native.ExpectNonNull(Native.RSA_new()), true)
		{ }
		#endregion

		#region Properties
		private rsa_st Raw
		{
			get { return (rsa_st)Marshal.PtrToStructure(this.ptr, typeof(rsa_st)); }
			set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		public int Size
		{
			get { return Native.ExpectSuccess(Native.RSA_size(this.ptr)); }
		}

		public bool ConstantTime
		{
			get { return false; }
			set 
			{ 
			}
		}

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
		#endregion

		#region Methods
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

		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.RSA_free(this.ptr);
		}

		#endregion
	}
}