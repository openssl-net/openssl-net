using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class X509Chain : Stack<X509Certificate>
	{
		#region X509_INFO
		[StructLayout(LayoutKind.Sequential)]
		struct X509_INFO
		{
			public IntPtr x509;
			public IntPtr crl;
			public IntPtr x_pkey;
			#region EVP_CIPHER_INFO enc_cipher;
			public IntPtr cipher;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.EVP_MAX_IV_LENGTH)]
			public byte[] iv;
			#endregion
			public int enc_len;
			public IntPtr enc_data;
			public int references;
		}

		class X509CertificateInfo : IStackable, IDisposable
		{
			private IntPtr ptr;
			private X509Certificate cert;
			private CryptoKey key;

			private X509_INFO Raw
			{
				get
				{
					return (X509_INFO)Marshal.PtrToStructure(this.ptr, typeof(X509_INFO));
				}
				set
				{
					Marshal.StructureToPtr(value, this.ptr, false);
				}
			}

			public X509Certificate Certificate
			{
				get
				{
					if (this.cert != null)
						return this.cert;

					X509_INFO xi = this.Raw;
					if (xi.x509 == IntPtr.Zero)
						return null;

					this.cert = new X509Certificate(xi.x509);
					xi.x509 = IntPtr.Zero;
					this.Raw = xi;
					return this.cert;
				}
			}

			public CryptoKey Key
			{
				get
				{
					if (this.key != null)
						return this.key;

					X509_INFO xi = this.Raw;
					if (xi.x_pkey == IntPtr.Zero)
						return null;

					this.key = new CryptoKey(xi.x_pkey);
					xi.x_pkey= IntPtr.Zero;
					this.Raw = xi;
					return this.key;
				}
			}

			#region IStackable Members
			public IntPtr Handle
			{
				get { return this.ptr; }
				set { this.ptr = value; }
			}
			#endregion

			#region IDisposable Members
			public void Dispose()
			{
				Native.X509_INFO_free(this.ptr);
			}
			#endregion
		}
		#endregion

		#region Initialization
		public X509Chain() { }

		public X509Chain(BIO bio)
		{
			IntPtr sk = Native.ExpectNonNull(
				Native.PEM_X509_INFO_read_bio(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero));
			using (Stack<X509CertificateInfo> stack = new Stack<X509CertificateInfo>(sk))
			{
				while (stack.Count > 0)
				{
					using (X509CertificateInfo xi = stack.Shift())
					{
						if(xi.Certificate != null)
							this.Add(xi.Certificate);
					}
				}
			}
		}

		public X509Chain(string pem)
			: this(new BIO(pem))
		{
		}
		#endregion

		#region Methods
		public X509Certificate FindByIssuerAndSerial(X509Name issuer, int serial)
		{
			IntPtr ptr = Native.X509_find_by_issuer_and_serial(this.ptr, issuer.Handle, Native.IntegerToAsnInteger(serial));
			if(ptr == IntPtr.Zero)
				return null;
			return new X509Certificate(ptr);
		}

		public X509Certificate FindBySubject(X509Name subject)
		{
			IntPtr ptr = Native.X509_find_by_subject(this.ptr, subject.Handle);
			if (ptr == IntPtr.Zero)
				return null;
			return new X509Certificate(ptr);
		}
		#endregion
	}
}
