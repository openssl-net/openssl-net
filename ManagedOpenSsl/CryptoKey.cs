using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	/// <summary>
	/// Wraps the native OpenSSL EVP_PKEY object
	/// </summary>
	public class CryptoKey : Base, IDisposable
	{
		#region Initialization
		internal CryptoKey(IntPtr ptr, bool owner) : base(ptr, owner) { }
		public CryptoKey() : base(Native.ExpectNonNull(Native.EVP_PKEY_new()), true) {}
		
		public static CryptoKey FromPublicKey(string pem)
		{
			return FromPublicKey(new BIO(pem));
		}

		public static CryptoKey FromPublicKey(BIO bio)
		{
			return new CryptoKey(Native.ExpectNonNull(Native.PEM_read_bio_PUBKEY(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true);
		}

		public static CryptoKey FromPrivateKey(string pem, string password)
		{
			return FromPrivateKey(new BIO(pem), password);
		}

		class PasswordCallback
		{
			private string password;
			public PasswordCallback(string password)
			{
				this.password = password;
			}

			public int OnPassword(
				IntPtr buf,
				int size,
				int rwflag,
				IntPtr userdata)
			{
				byte[] bytes = Encoding.ASCII.GetBytes(this.password);
				Marshal.Copy(bytes, 0, buf, bytes.Length);
				return bytes.Length;
			}
		}

		public static CryptoKey FromPrivateKey(BIO bio, string password)
		{
			PasswordCallback cb = new PasswordCallback(password);
			Native.pem_password_cb pem_cb = new Native.pem_password_cb(cb.OnPassword);
			IntPtr ptr = Native.ExpectNonNull(Native.PEM_read_bio_PrivateKey(
				bio.Handle, 
				IntPtr.Zero, 
				pem_cb, 
				IntPtr.Zero));

			return new CryptoKey(ptr, true);
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

		public DSA GetDSA()
		{
			return new DSA(Native.ExpectNonNull(Native.EVP_PKEY_get1_DSA(this.ptr)), false);
		}
		
		public DH GetDH()
		{
			return new DH(Native.ExpectNonNull(Native.EVP_PKEY_get1_DH(this.ptr)), false);
		}
		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.EVP_PKEY_free(this.ptr);
		}

		#endregion
	}
}
