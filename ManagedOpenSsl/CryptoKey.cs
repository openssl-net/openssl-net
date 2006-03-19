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

		/// <summary>
		/// Default constructor for a CryptoKey.  EVP_PKEY_new() is called.
		/// </summary>
		public CryptoKey()
			: base(Native.ExpectNonNull(Native.EVP_PKEY_new()))
		{
		}
		
		/// <summary>
		/// Creates a CryptoKey given a string of a public key in PEM format.
		/// </summary>
		/// <param name="pem">The public key in PEM format</param>
		/// <returns>A newly created CryptoKey</returns>
		public static CryptoKey FromPublicKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		/// <summary>
		/// Creates a CryptoKey given a BIO that contains the public key in PEM format.
		/// This method calls PEM_read_bio_PUBKEY().
		/// </summary>
		/// <param name="bio">The stream object that contains a public key in PEM format.</param>
		/// <returns>A newly created CryptoKey</returns>
		public static CryptoKey FromPublicKey(BIO bio)
		{
			return new CryptoKey(Native.ExpectNonNull(Native.PEM_read_bio_PUBKEY(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
		}

		/// <summary>
		/// Creates a CryptoKey given a string of a private key in PEM format.
		/// </summary>
		/// <param name="pem">The private key in PEM format</param>
		/// <returns>A newly created CryptoKey</returns>
		public static CryptoKey FromPrivateKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		/// <summary>
		/// Creates a CryptoKey given a BIO that contains the private key in PEM format.
		/// This method calls PEM_read_bio_PrivateKey().
		/// </summary>
		/// <param name="bio">The stream object that contains a private key in PEM format.</param>
		/// <returns>A newly created CryptoKey</returns>
		public static CryptoKey FromPrivateKey(BIO bio)
		{
			return new CryptoKey(Native.ExpectNonNull(Native.PEM_read_bio_PrivateKey(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)));
		}

		/// <summary>
		/// Constructs a CryptoKey using the DSA algorithm.
		/// </summary>
		/// <param name="dsa">This object contains a DSA public/private key pair</param>
		public CryptoKey(DSA dsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DSA(this.ptr, dsa.Handle));
		}

		/// <summary>
		/// Constrcuts a CryptoKey using the RSA algorithm.
		/// </summary>
		/// <param name="rsa">This object contains an RSA public/private key pair</param>
		public CryptoKey(RSA rsa)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_RSA(this.ptr, rsa.Handle));
		}

		/// <summary>
		/// Constructs a CryptoKey using the DH algorithm.
		/// </summary>
		/// <param name="dh">This object contains a DH public/private key pair</param>
		public CryptoKey(DH dh)
			: this()
		{
			Native.ExpectSuccess(Native.EVP_PKEY_set1_DH(this.ptr, dh.Handle));
		}
		#endregion

		#region Properties
		/// <summary>
		/// Calls EVP_PKEY_bits()
		/// </summary>
		public int Bits
		{
			get { return Native.EVP_PKEY_bits(this.ptr); }
		}

		/// <summary>
		/// Calls EVP_PKEY_size()
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
		/// <param name="type">Not sure</param>
		/// <param name="key">Not sure</param>
		public void Assign(int type, byte[] key)
		{
			Native.ExpectSuccess(Native.EVP_PKEY_assign(this.ptr, type, key));
		}
		#endregion

		#region IDisposable Members

		/// <summary>
		/// Calls EVP_PKEY_free()
		/// </summary>
		public void Dispose()
		{
			Native.EVP_PKEY_free(this.ptr);
		}

		#endregion
	}
}
