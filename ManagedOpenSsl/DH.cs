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
	/// <summary>
	/// Encapsulates the natives openssl Diffie-Hellman functions (DH_*)
	/// </summary>
	public class DH : Base, IDisposable
	{
		public const int Generator2 = 2;
		public const int Generator5 = 5;
		
		private const int FlagCacheMont_P = 0x01;
		private const int FlagNoExpConstTime = 0x02;

		[Flags]
		public enum CheckCode
		{
			CheckP_NotPrime = 1,
			CheckP_NotSafePrime = 2,
			UnableToCheckGenerator = 4,
			NotSuitableGenerator = 8,
		}

		private BigNumber.GeneratorThunk thunk = null;

		#region dh_st

		[StructLayout(LayoutKind.Sequential)]
		struct dh_st
		{
			public int pad;
			public int version;
			public IntPtr p;
			public IntPtr g;
			public int length;
			public IntPtr pub_key;
			public IntPtr priv_key;

			public int flags;
			public IntPtr method_mont_p;
			public IntPtr q;
			public IntPtr j;
			public IntPtr seed;
			public int seedlen;
			public IntPtr counter;

			public int references;
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public IntPtr meth;
			public IntPtr engine;
		}
		#endregion

		#region Initialization
		internal DH(IntPtr ptr, bool owner) : base(ptr, owner) { }
		/// <summary>
		/// Calls DH_generate_parameters()
		/// </summary>
		/// <param name="primeLen"></param>
		/// <param name="generator"></param>
		public DH(int primeLen, int generator)
			: base(Native.ExpectNonNull(Native.DH_generate_parameters(primeLen, generator, IntPtr.Zero, IntPtr.Zero)), true)
		{
			//this.GenerateKeys();
		}

		/// <summary>
		/// Calls DH_generate_parameters_ex()
		/// </summary>
		/// <param name="primeLen"></param>
		/// <param name="generator"></param>
		/// <param name="callback"></param>
		/// <param name="arg"></param>
		public DH(int primeLen, int generator, BigNumber.GeneratorHandler callback, object arg)
			: base(Native.ExpectNonNull(Native.DH_new()), true)
		{
			this.thunk = new BigNumber.GeneratorThunk(callback, arg);
			Native.ExpectSuccess(Native.DH_generate_parameters_ex(
				this.ptr,
				primeLen,
 				generator,
				this.thunk.CallbackStruct)
			);
		}

		/// <summary>
		/// Calls DH_new(). Then calls GenerateKeys() with p and g equal to 1.
		/// </summary>
		public DH() 
			: base(Native.ExpectNonNull(Native.DH_new()), true) 
		{
			dh_st raw = this.Raw;
			raw.p = Native.BN_dup(BigNumber.One.Handle);
			raw.g = Native.BN_dup(BigNumber.One.Handle);
			this.Raw = raw;

			//this.GenerateKeys();
		}

		/// <summary>
		/// Calls DH_new(). Then calls GenerateKeys() with the provided parameters.
		/// </summary>
		/// <param name="p"></param>
		/// <param name="g"></param>
        public DH(BigNumber p, BigNumber g)
            : base(Native.ExpectNonNull(Native.DH_new()), true)
        {
            dh_st raw = this.Raw;
            raw.p = Native.BN_dup(p.Handle);
            raw.g = Native.BN_dup(g.Handle);
            this.Raw = raw;

			//this.GenerateKeys();
        }

		/// <summary>
		/// Calls DH_new(). Then calls GenerateKeys() with the provide parameters
		/// and public/private key pair.
		/// </summary>
		/// <param name="p"></param>
		/// <param name="g"></param>
		/// <param name="pub_key"></param>
		/// <param name="priv_key"></param>
		public DH(BigNumber p, BigNumber g, BigNumber pub_key, BigNumber priv_key)
			: base(Native.ExpectNonNull(Native.DH_new()), true)
		{
			dh_st raw = this.Raw;
			raw.p = Native.BN_dup(p.Handle);
			raw.g = Native.BN_dup(g.Handle);
			raw.pub_key = Native.BN_dup(pub_key.Handle);
			raw.priv_key = Native.BN_dup(priv_key.Handle);
			this.Raw = raw;

			//this.GenerateKeys();
		}

		/// <summary>
		/// Factory method that calls FromParametersPEM() to deserialize
		/// a DH object from a PEM-formatted string.
		/// </summary>
		/// <param name="pem"></param>
		/// <returns></returns>
		public static DH FromParameters(string pem)
		{
			return FromParametersPEM(new BIO(pem));
		}

		/// <summary>
		/// Factory method that calls PEM_read_bio_DHparams() to deserialize 
		/// a DH object from a PEM-formatted string using the BIO interface.
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static DH FromParametersPEM(BIO bio)
		{
			DH dh = new DH(Native.ExpectNonNull(Native.PEM_read_bio_DHparams(
				bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true);
//			dh.GenerateKeys();
			return dh;
		}

		/// <summary>
		/// Factory method that calls XXX() to deserialize
		/// a DH object from a DER-formatted buffer using the BIO interface.
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static DH FromParametersDER(BIO bio)
		{
			IntPtr hModule = Native.LoadLibrary(Native.DLLNAME);
			IntPtr d2i = Native.GetProcAddress(hModule, "d2i_DHparams");
			IntPtr xnew = Native.GetProcAddress(hModule, "DH_new");
			Native.FreeLibrary(hModule);

			IntPtr ptr = Native.ExpectNonNull(Native.ASN1_d2i_bio(xnew, d2i, bio.Handle, IntPtr.Zero));
			DH dh = new DH(ptr, true);
//			dh.GenerateKeys();
			return dh;
		}
		#endregion

		#region Methods
		public void GenerateKeys()
		{
			Native.ExpectSuccess(Native.DH_generate_key(this.ptr));
		}

		public byte[] ComputeKey(BigNumber pubkey)
		{
			int len = Native.DH_size(this.ptr);
			byte[] key = new byte[len];
			Native.DH_compute_key(key, pubkey.Handle, this.ptr);
			return key;
		}

		public void WriteParametersPEM(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DHparams(bio.Handle, this.ptr));
		}

		public void WriteParametersDER(BIO bio)
		{
			IntPtr hModule = Native.LoadLibrary(Native.DLLNAME);
			IntPtr i2d = Native.GetProcAddress(hModule, "i2d_DHparams");
			Native.FreeLibrary(hModule);
			
			Native.ExpectSuccess(Native.ASN1_i2d_bio(i2d, bio.Handle, this.ptr));
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.DHparams_print(bio.Handle, this.ptr));
		}

		public CheckCode Check()
		{
			int codes = 0;
			Native.ExpectSuccess(Native.DH_check(this.ptr, out codes));
			return (CheckCode)codes;
		}
		#endregion

		#region Properties
		private dh_st Raw
		{
			get { return (dh_st)Marshal.PtrToStructure(this.ptr, typeof(dh_st)); }
            set { Marshal.StructureToPtr(value, this.ptr, false); }
		}

		public BigNumber P
		{
			get { return new BigNumber(this.Raw.p, false); }
			set 
			{
				dh_st raw = this.Raw;
				raw.p = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		public BigNumber G
		{
			get { return new BigNumber(this.Raw.g, false); }
			set 
			{
				dh_st raw = this.Raw;
				raw.g = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		public BigNumber PublicKey
		{
			get { return new BigNumber(this.Raw.pub_key, false); }
            set
            {
                dh_st raw = this.Raw;
                raw.pub_key = Native.BN_dup(value.Handle);
                this.Raw = raw;
            }
        }

		public BigNumber PrivateKey
		{
			get { return new BigNumber(this.Raw.priv_key, false); } 
			set
            {
                dh_st raw = this.Raw;
                raw.priv_key = Native.BN_dup(value.Handle);
                this.Raw = raw;
            }
		}

		public string PEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.WriteParametersPEM(bio);
					return bio.ReadString();
				}
			}
		}
	
		public byte[] DER
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.WriteParametersPEM(bio);
					return bio.ReadBytes((int)bio.NumberWritten).Array;
				}
			}
		}

		public bool ConstantTime
		{
			get { return (this.Raw.flags & FlagNoExpConstTime) != 0; }
			set
			{
				dh_st raw = this.Raw;
				if (value)
					raw.flags |= FlagNoExpConstTime;
				else
					raw.flags &= ~FlagNoExpConstTime;
				this.Raw = raw;
			}
		}

		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.DH_free(this.ptr);
		}

		#endregion
	}
}