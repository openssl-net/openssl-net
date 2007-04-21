using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class X509Request : Base, IDisposable
	{
		#region Initialization
		public X509Request() : base(Native.ExpectNonNull(Native.X509_REQ_new()), true) { }
		internal X509Request(IntPtr ptr, bool owner) : base(ptr, owner) { }

		public X509Request(int version, X509Name subject, CryptoKey key)
			: this()
		{
			this.Version = version;
			this.Subject = subject;
			this.PublicKey = key;
		}

		public X509Request(BIO bio)
			: base(Native.ExpectNonNull(Native.PEM_read_bio_X509_REQ(bio.Handle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero)), true)
		{
		}

		public X509Request(string pem)
			: this(new BIO(pem))
		{
		}
		#endregion

		#region X509_REQ_INFO
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_REQ_INFO
		{
			#region ASN1_ENCODING enc;
			public IntPtr enc_enc;
			public int enc_len;
			public int enc_modified;
			#endregion
			public IntPtr version;
			public IntPtr subject;
			public IntPtr pubkey;
			public IntPtr attributes;
		}
		#endregion

		#region X509_REQ
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_REQ
		{
			public IntPtr req_info;
			public IntPtr sig_alg;
			public IntPtr signature;
			public int references;
		}
		#endregion

		#region Properties
		private X509_REQ Raw
		{
			get
			{
				return (X509_REQ)Marshal.PtrToStructure(this.ptr, typeof(X509_REQ));
			}
		}

		private X509_REQ_INFO RawInfo
		{
			get
			{
				return (X509_REQ_INFO)Marshal.PtrToStructure(this.Raw.req_info, typeof(X509_REQ_INFO));
			}
		}
		
		public int Version
		{
			get
			{
				return Native.ASN1_INTEGER_get(this.RawInfo.version);
			}
			set
			{
				Native.ExpectSuccess(Native.X509_REQ_set_version(this.ptr, value));
			}
		}

		public CryptoKey PublicKey
		{
			get
			{
				return new CryptoKey(Native.ExpectNonNull(Native.X509_REQ_get_pubkey(this.ptr)), true);
			}
			set
			{
				Native.ExpectSuccess(Native.X509_REQ_set_pubkey(this.ptr, value.Handle));
			}
		}

		public X509Name Subject
		{
			get
			{
				return new X509Name(Native.X509_NAME_dup(this.RawInfo.subject), true);
			}
			set
			{
				Native.ExpectSuccess(Native.X509_REQ_set_subject_name(this.ptr, value.Handle));
			}
		}

        public string DSAPublicKeyString
        {
            get
            {
                return PublicKey.GetDSA().PemPublicKey;
            }
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
		#endregion

		#region Methods
		public void Sign(CryptoKey pkey, MessageDigest digest)
		{
			if (Native.X509_REQ_sign(this.ptr, pkey.Handle, digest.Handle) == 0)
				throw new OpenSslException();
		}

		public bool Verify(CryptoKey pkey)
		{
			int ret = Native.X509_REQ_verify(this.ptr, pkey.Handle);
			if (ret < 0)
				throw new OpenSslException();
			return ret == 1;
		}

		public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
		{
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.X509_REQ_digest(this.ptr, type, digest, ref len));
			return new ArraySegment<byte>(digest, 0, (int)len);
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.X509_REQ_print(bio.Handle, this.ptr));
		}

		public void Write(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_X509_REQ(bio.Handle, this.ptr));
		}

		public X509Certificate CreateCertificate(int days, CryptoKey pkey)
		{
			return new X509Certificate(Native.ExpectNonNull(Native.X509_REQ_to_X509(this.ptr, days, pkey.Handle)), true);
		}
		#endregion

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.X509_REQ_free(this.ptr);
		}

		#endregion
	}
}
