// Copyright (c) 2006-2007 Frank Laub
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
	/// Wraps the X509 object
	/// </summary>
	public class X509Certificate : Base, IDisposable, IStackable, IComparable<X509Certificate>
	{
		#region Initialization
		internal X509Certificate(IntPtr ptr, bool owner) : base(ptr, owner) {}

		/// <summary>
		/// 
		/// </summary>
		public X509Certificate()
			: base(Native.ExpectNonNull(Native.X509_new()), true)
		{
		}

		/// <summary>
		/// Calls PEM_read_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public X509Certificate(BIO bio)
			: base(Native.ExpectNonNull(Native.PEM_read_bio_X509(bio.Handle, IntPtr.Zero, null, IntPtr.Zero)), true)
		{
		}

		/// <summary>
		/// Factory method that returns a X509 using d2i_X509_bio()
		/// </summary>
		/// <param name="bio"></param>
		/// <returns></returns>
		public static X509Certificate FromDER(BIO bio)
		{
			IntPtr pX509 = IntPtr.Zero;
			IntPtr ptr = Native.ExpectNonNull(Native.d2i_X509_bio(bio.Handle, ref pX509));
			return new X509Certificate(ptr, true);
		}

		/// <summary>
		/// Calls Dispose()
		/// </summary>
		~X509Certificate()
		{
			Dispose();
		}

		/// <summary>
		/// Creates a new X509 certificate
		/// </summary>
		/// <param name="serial"></param>
		/// <param name="subject"></param>
		/// <param name="issuer"></param>
		/// <param name="pubkey"></param>
		/// <param name="start"></param>
		/// <param name="end"></param>
		public X509Certificate(
			int serial,
			X509Name subject, 
			X509Name issuer, 
			CryptoKey pubkey,
            DateTime start,
			DateTime end)
			: this()
		{
			this.Version = 2;
			this.SerialNumber = serial;
			this.Subject = subject;
			this.Issuer = issuer;
			this.PublicKey = pubkey;
			this.NotBefore = start;
			this.NotAfter = end;
		}

		#endregion

		#region Raw Structures

		#region X509_VAL
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_VAL
		{
			public IntPtr notBefore;
			public IntPtr notAfter;
		}
		#endregion

		#region X509_CINF
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_CINF
		{
			public IntPtr version;
			public IntPtr serialNumber;
			public IntPtr signature;
			public IntPtr issuer;
			public IntPtr validity;
			public IntPtr subject;
			public IntPtr key;
			public IntPtr issuerUID;
			public IntPtr subjectUID;
			public IntPtr extensions;
		}
		#endregion

		#region X509
		[StructLayout(LayoutKind.Sequential)]
		private struct X509
		{
			public IntPtr cert_info;
			public IntPtr sig_alg;
			public IntPtr signature;
			public int valid;
			public int references;
			public IntPtr name;
			#region CRYPTO_EX_DATA ex_data
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
			public int ex_pathlen;
			public uint ex_flags;
			public uint ex_kusage;
			public uint ex_xkusage;
			public uint ex_nscert;
			public IntPtr skid;
			public IntPtr akid;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = Native.SHA_DIGEST_LENGTH)]
			public byte[] sha1_hash;
			public IntPtr aux;
		}
		#endregion
		
		#endregion

		#region Properties
		private X509 Raw
		{
			get { return (X509)Marshal.PtrToStructure(this.ptr, typeof(X509)); }
		}

		private X509_CINF RawCertInfo
		{
			get { return (X509_CINF)Marshal.PtrToStructure(this.Raw.cert_info, typeof(X509_CINF)); }
		}

		private X509_VAL RawValidity
		{
			get { return (X509_VAL)Marshal.PtrToStructure(this.RawCertInfo.validity, typeof(X509_VAL)); }
		}

		/// <summary>
		/// Uses X509_get_subject_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Subject
		{
			get { return new X509Name(Native.ExpectNonNull(Native.X509_get_subject_name(this.ptr)), false); }
			set { Native.ExpectSuccess(Native.X509_set_subject_name(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_issuer_name() and X509_set_issuer_name()
		/// </summary>
		public X509Name Issuer
		{
			get { return new X509Name(Native.ExpectNonNull(Native.X509_get_issuer_name(this.ptr)), false); }
			set { Native.ExpectSuccess(Native.X509_set_issuer_name(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Uses X509_get_serialNumber() and X509_set_serialNumber()
		/// </summary>
		public int SerialNumber
		{
			get { return Native.ASN1_INTEGER_get(Native.X509_get_serialNumber(this.ptr)); }
			set { Native.ExpectSuccess(Native.X509_set_serialNumber(this.ptr, Native.IntegerToAsnInteger(value))); }
		}

		/// <summary>
		/// Uses the notBefore field and X509_set_notBefore()
		/// </summary>
		public DateTime NotBefore
		{
			get { return Native.AsnTimeToDateTime(this.RawValidity.notBefore); }
			set { Native.ExpectSuccess(Native.X509_set_notBefore(this.ptr, Native.DateTimeToAsnTime(value))); }
		}

		/// <summary>
		/// Uses the notAfter field and X509_set_notAfter()
		/// </summary>
		public DateTime NotAfter
		{
			get { return Native.AsnTimeToDateTime(this.RawValidity.notAfter); }
			set { Native.ExpectSuccess(Native.X509_set_notAfter(this.ptr, Native.DateTimeToAsnTime(value))); }
		}

		/// <summary>
		/// Uses the version field and X509_set_version()
		/// </summary>
		public int Version
		{
			get { return Native.ASN1_INTEGER_get(this.RawCertInfo.version); }
			set { Native.ExpectSuccess(Native.X509_set_version(this.ptr, value)); }
		}

		/// <summary>
		/// Uses X509_get_pubkey() and X509_set_pubkey()
		/// </summary>
		public CryptoKey PublicKey
		{
			get { return new CryptoKey(Native.ExpectNonNull(Native.X509_get_pubkey(this.ptr)), true); }
			set { Native.ExpectSuccess(Native.X509_set_pubkey(this.ptr, value.Handle)); }
		}

		/// <summary>
		/// Returns the PEM formatted string of this object
		/// </summary>
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
		/// <summary>
		/// Calls X509_sign()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		public void Sign(CryptoKey pkey, MessageDigest digest)
		{
			if (Native.X509_sign(this.ptr, pkey.Handle, digest.Handle) == 0)
				throw new OpenSslException();
		}

		/// <summary>
		/// Returns X509_check_private_key()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool CheckPrivateKey(CryptoKey pkey)
		{
			return Native.X509_check_private_key(this.ptr, pkey.Handle) == 1;
		}

		/// <summary>
		/// Returns X509_check_trust()
		/// </summary>
		/// <param name="id"></param>
		/// <param name="flags"></param>
		/// <returns></returns>
		public bool CheckTrust(int id, int flags)
		{
			return Native.X509_check_trust(this.ptr, id, flags) == 1;
		}

		/// <summary>
		/// Returns X509_verify()
		/// </summary>
		/// <param name="pkey"></param>
		/// <returns></returns>
		public bool Verify(CryptoKey pkey)
		{
			int ret = Native.X509_verify(this.ptr, pkey.Handle);
			if (ret < 0)
				throw new OpenSslException();
			return ret == 1;
		}

		/// <summary>
		/// Returns X509_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> Digest(IntPtr type, byte[] digest)
		{
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.X509_digest(this.ptr, type, digest, ref len));
			return new ArraySegment<byte>(digest, 0, (int)len);
		}

		/// <summary>
		/// Returns X509_pubkey_digest()
		/// </summary>
		/// <param name="type"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public ArraySegment<byte> DigestPublicKey(IntPtr type, byte[] digest)
		{
			uint len = (uint)digest.Length;
			Native.ExpectSuccess(Native.X509_pubkey_digest(this.ptr, type, digest, ref len));
			return new ArraySegment<byte>(digest, 0, (int)len);
		}

		/// <summary>
		/// Calls PEM_write_bio_X509()
		/// </summary>
		/// <param name="bio"></param>
		public void Write(BIO bio)
		{
			Native.ExpectSuccess(Native.PEM_write_bio_X509(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Calls X509_print()
		/// </summary>
		/// <param name="bio"></param>
		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.X509_print(bio.Handle, this.ptr));
		}

		/// <summary>
		/// Converts a X509 into a request using X509_to_X509_REQ()
		/// </summary>
		/// <param name="pkey"></param>
		/// <param name="digest"></param>
		/// <returns></returns>
		public X509Request CreateRequest(CryptoKey pkey, MessageDigest digest)
		{
			return new X509Request(Native.ExpectNonNull(Native.X509_to_X509_REQ(this.ptr, pkey.Handle, digest.Handle)), true);
		}

		/// <summary>
		/// Calls X509_add_ext()
		/// </summary>
		/// <param name="ext"></param>
		public void AddExtension(X509Extension ext)
		{
			Native.ExpectSuccess(Native.X509_add_ext(this.ptr, ext.Handle, -1));
		}

		/// <summary>
		/// Calls X509_add1_ext_i2d()
		/// </summary>
		/// <param name="name"></param>
		/// <param name="value"></param>
		/// <param name="crit"></param>
		/// <param name="flags"></param>
		public void AddExtension(string name, byte[] value, int crit, uint flags)
		{
			Native.ExpectSuccess(Native.X509_add1_ext_i2d(this.ptr, Native.TextToNID(name), value, crit, flags));
		}

		#endregion

		#region IDisposable Members
		/// <summary>
		/// Calls X509_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.X509_free(this.ptr);
			this.ptr = IntPtr.Zero;
			GC.SuppressFinalize(this);
		}
		#endregion

		#region Overrides
		/// <summary>
		/// Compares X509Certificate
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object obj)
		{
			X509Certificate rhs = obj as X509Certificate;
			if (rhs == null)
				return false;
			return this.CompareTo(rhs) == 0;
		}

		/// <summary>
		/// Returns the hash code of the issuer's oneline xor'd with the serial number
		/// </summary>
		/// <returns></returns>
		public override int GetHashCode()
		{
			return this.Issuer.OneLine.GetHashCode() ^ this.SerialNumber;
		}
		#endregion

		#region IComparable Members

		/// <summary>
		/// Returns X509_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(X509Certificate other)
		{
			return Native.X509_cmp(this.ptr, other.ptr);
		}

		#endregion
	}


	/// <summary>
	/// Wraps the X509_EXTENSION object
	/// </summary>
	public class X509Extension : Base, IDisposable, IStackable
	{
		/// <summary>
		/// Calls X509_EXTENSION_new()
		/// </summary>
		public X509Extension()
			: base(Native.ExpectNonNull(Native.X509_EXTENSION_new()), true)
		{ }

		#region IDisposable Members

		/// <summary>
		/// Calls X509_EXTENSION_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.X509_EXTENSION_free(this.ptr);
		}

		#endregion
	}
}
