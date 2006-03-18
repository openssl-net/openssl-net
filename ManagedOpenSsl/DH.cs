using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class DH : Base, IDisposable
	{
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
		private DH(IntPtr ptr) : base(ptr) { }
		public DH(int primeLen, int generator)
			: base(Native.ExpectNonNull(Native.DH_generate_parameters(primeLen, generator, IntPtr.Zero, IntPtr.Zero)))
		{
			this.GenerateKeys();
		}

		public DH() 
			: base(Native.ExpectNonNull(Native.DH_new())) 
		{
			dh_st raw = this.Raw;
			raw.p = BigNumber.One.Handle;
			raw.g = BigNumber.One.Handle;
			this.Raw = raw;

			this.GenerateKeys();
		}

        public DH(BigNumber p, BigNumber g)
            : base(Native.ExpectNonNull(Native.DH_new()))
        {
            dh_st raw = this.Raw;
            raw.p = p.Handle;
            raw.g = g.Handle;
            this.Raw = raw;

			this.GenerateKeys();
        }

		public static DH FromParameters(string pem)
		{
			return FromParameters(new BIO(pem));
		}

		public static DH FromParameters(BIO bio)
		{
			DH dh = new DH(Native.ExpectNonNull(Native.PEM_read_bio_DHparams(
				bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
			dh.GenerateKeys();
			return dh;
		}
		#endregion

		#region Methods
		private void GenerateKeys()
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

		public void WriteParameters(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_DHparams(bio.Handle, this.ptr));
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.DHparams_print(bio.Handle, this.ptr));
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
			get
			{
				return new BigNumber(this.Raw.p);
			}
		}

		public BigNumber G
		{
			get
			{
				return new BigNumber(this.Raw.g);
			}
		}

		public BigNumber PublicKey
		{
			get
            {
                return new BigNumber(this.Raw.pub_key);
            }
            set
            {
                dh_st raw = this.Raw;
                raw.pub_key = value.Handle;
                this.Raw = raw;
            }
        }

		public BigNumber PrivateKey
		{
			get
            {
                return new BigNumber(this.Raw.priv_key);
            }
			set
            {
                dh_st raw = this.Raw;
                raw.priv_key = value.Handle;
                this.Raw = raw;
            }
		}

		public string PEM
		{
			get
			{
				using (BIO bio = BIO.MemoryBuffer())
				{
					this.WriteParameters(bio);
					return bio.ReadString();
				}
			}
		}
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			Native.DH_free(this.ptr);
		}

		#endregion
	}
}