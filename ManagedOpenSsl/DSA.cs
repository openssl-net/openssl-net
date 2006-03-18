using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	#region DSAParameters
	public class DSAParameters : Base, IDisposable
	{
		public DSAParameters(BIO bio) 
			: base(Native.ExpectNonNull(Native.PEM_read_bio_DSAparams(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)))
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
				IntPtr.Zero)))
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
		public void Dispose()
		{
			Native.DSA_free(this.ptr);
		}
		#endregion
	}
	#endregion

	public class DSA : Base, IDisposable
	{
		#region Initialization

		private DSA(IntPtr ptr) : base(ptr) {}

		public DSA(DSAParameters parameters)
			: base(parameters.TakeOwnership())
		{
			this.GenerateKeys();
		}

		public static DSA FromPublicKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		public static DSA FromPublicKey(BIO bio)
		{
			return new DSA(Native.ExpectNonNull(Native.PEM_read_bio_DSA_PUBKEY(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
		}

		public static DSA FromPrivateKey(string pem)
		{
			return FromPrivateKey(new BIO(pem));
		}
		
		public static DSA FromPrivateKey(BIO bio)
		{
			return new DSA(Native.ExpectNonNull(Native.PEM_read_bio_DSAPrivateKey(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
		}

		#endregion

		#region Properites
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
		public void Dispose()
		{
			Native.DSA_free(this.ptr);
		}
		#endregion
	}
}
