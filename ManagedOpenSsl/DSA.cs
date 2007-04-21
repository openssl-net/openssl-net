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

		#region Initialization

		internal DSA(IntPtr ptr, bool owner) : base(ptr, owner) {}
		public DSA(DSAParameters parameters)
			: base(parameters.TakeOwnership(), true)
		{
			this.GenerateKeys();
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
			get
			{
				return new BigNumber(this.Raw.p, false);
			}
		}

		public BigNumber Q
		{
			get
			{
				return new BigNumber(this.Raw.q, false);
			}
		}

		public BigNumber G
		{
			get
			{
				return new BigNumber(this.Raw.g, false);
			}
		}

		public BigNumber PublicKey
		{
			get
			{
				return new BigNumber(this.Raw.pub_key, false);
			}
			set
			{
				dsa_st raw = this.Raw;
				raw.pub_key = Native.BN_dup(value.Handle);
				this.Raw = raw;
			}
		}

		public BigNumber PrivateKey
		{
			get
			{
				return new BigNumber(this.Raw.priv_key, false);
			}
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
					this.WritePrivateKey(bio);
					return bio.ReadString();
				}
			}
		}
		#endregion

		#region Methods
		private void GenerateKeys()
		{
			Native.ExpectSuccess(Native.DSA_generate_key(this.ptr));
		}
		
		public void WritePublicKey(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DSA_PUBKEY(bio.Handle, this.ptr));
		}

		public void WritePrivateKey(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DSAPrivateKey(
				bio.Handle,
				this.ptr,
				IntPtr.Zero,
				null,
				0,
				IntPtr.Zero,
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
