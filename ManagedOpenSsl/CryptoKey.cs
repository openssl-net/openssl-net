using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	/// <summary>
	/// Wraps the native OpenSSL EVP_PKEY object
	/// </summary>
	public class CryptoKey : Base, IDisposable
	{
		#region Initialization
		internal CryptoKey(IntPtr ptr)
			: base(ptr)
		{}

		public CryptoKey()
			: base(Native.ExpectNonNull(Native.EVP_PKEY_new()))
		{
		}
		
		public static CryptoKey FromPublicKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		public static CryptoKey FromPublicKey(BIO bio)
		{
			return new CryptoKey(Native.ExpectNonNull(Native.PEM_read_bio_PUBKEY(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
		}

		public static CryptoKey FromPrivateKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		public static CryptoKey FromPrivateKey(BIO bio)
		{
			return new CryptoKey(Native.ExpectNonNull(Native.PEM_read_bio_PrivateKey(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
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
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			Native.EVP_PKEY_free(this.ptr);
		}

		#endregion
	}
}
