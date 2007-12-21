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
	#region DSAParameters
	public class DSAParameters : Base, IDisposable
	{
		public DSAParameters(BIO bio) 
			: base(Native.ExpectNonNull(Native.PEM_read_bio_DSAparams(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true)
		{
		}

		public DSAParameters(string pem)
			: this(new BIO(pem))
		{
		}

		public DSAParameters(int bits)
			: base(Native.ExpectNonNull(Native.DSA_generate_parameters(
				bits,
				null,
				0,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero,
				IntPtr.Zero)), true)
		{
		}

		internal IntPtr TakeOwnership()
		{
			IntPtr ptr = this.ptr;
			this.ptr = IntPtr.Zero;
			return ptr;
		}

		public string PEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.Write(bio);
					return bio.ReadString();
				}
			}
		}

		public void Write(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DSAparams(bio.Handle, this.ptr));
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.DSAparams_print(bio.Handle, this.ptr));
		}

		#region IDisposable Members
		public override void OnDispose()
		{
			Native.DSA_free(this.ptr);
		}
		#endregion
	}
	#endregion

	public class DSA : Base, IDisposable
	{
		#region dsa_st

		[StructLayout(LayoutKind.Sequential)]
		struct dsa_st
		{
			public int pad;
			public int version;
			public int write_params;
			public IntPtr p;
			public IntPtr q;	
			public IntPtr g;

			public IntPtr pub_key;  
			public IntPtr priv_key; 

			public IntPtr kinv;	
			public IntPtr r;	

			public int flags;
			public IntPtr method_mont_p;
			public int references;
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public IntPtr meth;
			public IntPtr engine;
		}
		#endregion

		private const int FlagCacheMont_P = 0x01;
		private const int FlagNoExpConstTime = 0x02;
		private int counter = 0;
		private int h = 0;
		private BigNumber.GeneratorThunk thunk = null;

		#region Initialization

		internal DSA(IntPtr ptr, bool owner) : base(ptr, owner) {}
		public DSA(DSAParameters parameters)
			: base(parameters.TakeOwnership(), true)
		{
//			this.GenerateKeys();
		}

		public DSA(int bits, byte[] seed, int counter, BigNumber.GeneratorHandler callback, object arg)
			: base(Native.ExpectNonNull(Native.DSA_new()), true)
		{
			this.counter = counter;
			this.thunk = new BigNumber.GeneratorThunk(callback, arg);
			Native.ExpectSuccess(Native.DSA_generate_parameters_ex(
				this.ptr,
				bits,
				seed, seed.Length,
				out this.counter,
				out this.h,
				this.thunk.CallbackStruct)
			);
		}

		public static DSA FromPublicKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		public static DSA FromPublicKey(BIO bio)
		{
			return new DSA(Native.ExpectNonNull(Native.PEM_read_bio_DSA_PUBKEY(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true);
		}

		public static DSA FromPrivateKey(string pem)
		{
			return FromPrivateKey(new BIO(pem));
		}
		
		public static DSA FromPrivateKey(BIO bio)
		{
			return new DSA(Native.ExpectNonNull(Native.PEM_read_bio_DSAPrivateKey(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true);
		}

		#endregion

		#region Properites
		private dsa_st Raw
		{
			get { return (dsa_st)Marshal.PtrToStructure(this.ptr, typeof(dsa_st)); }
			set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		public BigNumber P
		{
			get { return new BigNumber(this.Raw.p, false); }
		}

		public BigNumber Q
		{
			get { return new BigNumber(this.Raw.q, false); }
		}

		public BigNumber G
		{
			get { return new BigNumber(this.Raw.g, false); }
		}

		public int Size
		{
			get { return Native.ExpectSuccess(Native.DSA_size(this.ptr)); }
		}

		public BigNumber PublicKey
		{
			get { return new BigNumber(this.Raw.pub_key, false); }
			set
			{
				dsa_st raw = this.Raw;
				raw.pub_key = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		public BigNumber PrivateKey
		{
			get { return new BigNumber(this.Raw.priv_key, false); }
			set
			{
				dsa_st raw = this.Raw;
				raw.priv_key = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		public string PemPublicKey
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

		public string PemPrivateKey
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

		public int Counter
		{
			get { return this.counter; }
		}

		public int H
		{
			get { return this.h; }
		}

		public bool ConstantTime
		{
			get { return (this.Raw.flags & FlagNoExpConstTime) != 0; }
			set
			{
				dsa_st raw = this.Raw;
				if (value)
					raw.flags |= FlagNoExpConstTime;
				else
					raw.flags &= ~FlagNoExpConstTime;
				this.Raw = raw;
			}
		}
		#endregion

		#region Methods
		public void GenerateKeys()
		{
			Native.ExpectSuccess(Native.DSA_generate_key(this.ptr));
		}

		public byte[] Sign(byte[] msg)
		{
			byte[] sig = new byte[this.Size];
			uint siglen;
			Native.ExpectSuccess(Native.DSA_sign(0, msg, msg.Length, sig, out siglen, this.ptr));
			if (sig.Length != siglen)
			{
				byte[] ret = new byte[siglen];
				Buffer.BlockCopy(sig, 0, ret, 0, (int)siglen);
				return ret;
			}
			return sig;
		}

		public bool Verify(byte[] msg, byte[] sig)
		{
			return Native.ExpectSuccess(
				Native.DSA_verify(0, msg, msg.Length, sig, sig.Length, this.ptr)
			) == 1;
		}
		
		public void WritePublicKey(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DSA_PUBKEY(bio.Handle, this.ptr));
		}

		public void WritePrivateKey(BIO bio, Cipher enc, Native.PasswordHandler passwd, object arg)
		{
			Native.PasswordThunk thunk = new Native.PasswordThunk(passwd, arg);
			Native.ExpectSuccess(Native.PEM_write_bio_DSAPrivateKey(
				bio.Handle,
				this.ptr,
				enc == null ? IntPtr.Zero : enc.Handle,
				null,
				0,
				thunk.Callback,
				IntPtr.Zero));
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.DSA_print(bio.Handle, this.ptr, 0));
		}
		#endregion

		#region IDisposable Members
		public override void OnDispose()
		{
			Native.DSA_free(this.ptr);
		}
		#endregion
	}
}
