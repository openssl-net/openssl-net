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
        #region Members
        private CryptoKey privateKey;
        #endregion

        public override void Addref()
        {
            long offset = (long)Marshal.OffsetOf(typeof(X509), "references");
            IntPtr offset_ptr = new IntPtr((long)ptr + offset);
            Native.CRYPTO_add_lock(offset_ptr, 1, Native.CryptoLockTypes.CRYPTO_LOCK_X509, "X509Certificate.cs", 0);
        }

        private void PrintRefCount(string method)
        {
            int offset = (int)Marshal.OffsetOf(typeof(X509), "references");
            IntPtr offset_ptr = new IntPtr((int)ptr + offset);
            int ref_count = Marshal.ReadInt32(offset_ptr);
            Console.WriteLine("X509Certificate:method={0}:ptr={1}:refcount={2}", method, this.ptr, ref_count);
        }

        #region Initialization
		internal X509Certificate(IntPtr ptr, bool owner) : base(ptr, owner)
        {
        }

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

        public static X509Certificate FromPKCS7_PEM(BIO bio)
        {
            PKCS7 pkcs7 = PKCS7.FromPEM(bio);
            X509Chain chain = pkcs7.Certificates;
            if (chain != null && chain.Count > 0)
            {
                return new X509Certificate(chain[0].Handle, false);
            }
            else
            {
                throw new OpenSslException();
            }
        }

        public static X509Certificate FromPKCS7_ASN1(BIO bio)
        {
            PKCS7 pkcs7 = PKCS7.FromASN1(bio);
            X509Chain chain = pkcs7.Certificates;
            if (chain != null && chain.Count > 0)
            {
                return new X509Certificate(chain[0].Handle, false);
            }
            return null;
        }

        public static X509Certificate FromPKCS12(BIO bio, string password)
        {
            X509Certificate ret = null;

            PKCS12 p12 = new PKCS12(bio, password);
            if (p12 != null)
            {
                X509Certificate p12Cert = p12.Certificate;
                if (p12Cert != null)
                {
                    ret = p12Cert;
                }
                p12.Dispose();
            }
            return ret;
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
			public int ex_pcpathlen;
			public uint ex_flags;
			public uint ex_kusage;
			public uint ex_xkusage;
			public uint ex_nscert;
			public IntPtr skid;
			public IntPtr akid;
			public IntPtr policy_cache;
			public IntPtr rfc3779_addr;
			public IntPtr rfc3779_asid;
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
            get
            {
                // Get the native pointer for the subject name
                IntPtr name_ptr = Native.ExpectNonNull(Native.X509_get_subject_name(this.ptr));
                // Duplicate the native pointer, as the X509_get_subject_name returns a pointer
                // that is owned by the X509 object
                IntPtr dupe_name_ptr = Native.ExpectNonNull(Native.X509_NAME_dup(name_ptr));
                // Create the X509Name object, and set the duplicated native pointer with ownership
                return new X509Name(dupe_name_ptr, true);
            }
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
			set 
            {
                IntPtr serASN = Native.IntegerToAsnInteger(value);
                //!!Native.ExpectSuccess(Native.X509_set_serialNumber(this.ptr, Native.IntegerToAsnInteger(value)));
                Native.ExpectSuccess(Native.X509_set_serialNumber(this.ptr, serASN));
                Native.ASN1_INTEGER_free(serASN);
            }
		}

		/// <summary>
		/// Uses the notBefore field and X509_set_notBefore()
		/// </summary>
		public DateTime NotBefore
		{
//!!			get { return Native.AsnTimeToDateTime(this.RawValidity.notBefore); }
			get { return Native.AsnTimeToDateTime(this.RawValidity.notBefore).ToLocalTime(); }
			set 
            { 
//!!                Native.ExpectSuccess(Native.X509_set_notBefore(this.ptr, Native.DateTimeToAsnTime(value))); 
                IntPtr datetimeASN = Native.DateTimeToAsnTime(value.ToUniversalTime());
                Native.ExpectSuccess(Native.X509_set_notBefore(this.ptr, datetimeASN));
                Native.ASN1_TIME_free(datetimeASN);
            }
		}

		/// <summary>
		/// Uses the notAfter field and X509_set_notAfter()
		/// </summary>
		public DateTime NotAfter
		{
//!!			get { return Native.AsnTimeToDateTime(this.RawValidity.notAfter); }
			get { return Native.AsnTimeToDateTime(this.RawValidity.notAfter).ToLocalTime(); }
			set 
            {
                //!!Native.ExpectSuccess(Native.X509_set_notAfter(this.ptr, Native.DateTimeToAsnTime(value)));
                IntPtr datetimeASN = Native.DateTimeToAsnTime(value.ToUniversalTime());
                Native.ExpectSuccess(Native.X509_set_notAfter(this.ptr, datetimeASN));
                Native.ASN1_TIME_free(datetimeASN);
            }
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

        public bool HasPrivateKey
        {
            get
            {
                return privateKey != null;
            }
        }

        public CryptoKey PrivateKey
        {
            get { return privateKey; }
            set
            {
                if (CheckPrivateKey(value))
                {
                    privateKey = value;
                }
                else
                {
                    throw new ArgumentException("Private key doesn't correspond to the this certificate");
                }
            }
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

        public Stack<X509Extension> Extensions
        {
            get
            {
                if (RawCertInfo.extensions != IntPtr.Zero)
                {
                    return new Stack<X509Extension>(RawCertInfo.extensions, false);
                }
                return null;
            }
        }

        public void AddExtensions(Stack<X509Extension> sk_ext)
        {
            foreach (X509Extension ext in sk_ext)
            {
                AddExtension(ext);
            }
        }

		#endregion

		#region IDisposable Members
		/// <summary>
		/// Calls X509_free()
		/// </summary>
		public override void OnDispose()
		{
            //!!PrintRefCount("OnDispose");

            Native.X509_free(this.ptr);
			this.ptr = IntPtr.Zero;
            if (privateKey != null)
            {
                privateKey.Dispose();
                privateKey = null;
            }
			//!!GC.SuppressFinalize(this);
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

    public class Asn1String : Base, IDisposable, IStackable, IComparable<Asn1String>
    {
        public Asn1String()
            : base(Native.ASN1_STRING_type_new(Native.V_ASN1_OCTET_STRING), true)
        {
        }

        public Asn1String(IntPtr ptr, bool takeOwnership)
            : base(ptr, takeOwnership)
        {
        }

        public Asn1String(byte[] data)
            : this()
        {
            Native.ExpectSuccess(Native.ASN1_STRING_set(this.ptr, data, data.Length));
        }

        ~Asn1String()
        {
            Dispose();
        }

        public int Length
        {
            get
            {
                return Native.ASN1_STRING_length(this.ptr);
            }
        }

        public byte[] Data
        {
            get
            {
                IntPtr ret = Native.ASN1_STRING_data(this.ptr);
                byte[] byteArray = new byte[Length];
                Marshal.Copy(ret, byteArray, 0, Length);
                return byteArray;
            }
        }

        public override void Addref()
        {
            // No reference counting on this object, so dup it
            IntPtr new_ptr = Native.ExpectNonNull(Native.ASN1_STRING_dup(this.ptr));
            this.ptr = new_ptr;
        }

        public override bool Equals(object obj)
        {
            Asn1String asn1 = obj as Asn1String;
            if (asn1 == null)
            {
                return false;
            }
            return (CompareTo(asn1) == 0);
        }

        public override void OnDispose()
        {
            Native.ASN1_STRING_free(this.ptr);
        }

        #region IComparable<Asn1String> Members

        public int CompareTo(Asn1String other)
        {
            return Native.ASN1_STRING_cmp(this.ptr, other.Handle);
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

        public X509Extension(X509Certificate issuer, X509Certificate subject, string name, bool critical, string value)
            : base(IntPtr.Zero, false)
        {
            X509v3Context ctx = new X509v3Context();
            Native.X509V3_set_ctx(ctx.Handle, issuer.Handle, subject.Handle, IntPtr.Zero, IntPtr.Zero, 0);
            this.ptr = Native.ExpectNonNull(Native.X509V3_EXT_conf_nid(IntPtr.Zero, ctx.Handle, Native.TextToNID(name), value));
            this.owner = true;
            ctx.Dispose();
        }

        public string Name
        {
            get
            {
                string ret = "";

                // Don't free the obj_ptr
                IntPtr obj_ptr = Native.X509_EXTENSION_get_object(this.ptr);
                if (obj_ptr != IntPtr.Zero)
                {
                    int nid = Native.OBJ_obj2nid(obj_ptr);
                    ret = Marshal.PtrToStringAnsi(Native.OBJ_nid2ln(nid));
                }
                return ret;
            }
        }

        public int NID
        {
            get
            {
                int ret = 0;

                // Don't free the obj_ptr
                IntPtr obj_ptr = Native.X509_EXTENSION_get_object(this.ptr);
                if (obj_ptr != IntPtr.Zero)
                {
                    ret = Native.OBJ_obj2nid(obj_ptr);
                }
                return ret;
            }
        }

        public bool IsCritical
        {
            get
            {
                int nCritical = Native.X509_EXTENSION_get_critical(this.ptr);
                return (nCritical == 1);
            }
        }

        public byte[] Data
        {
            get
            {
                Asn1String str_data = new Asn1String(Native.X509_EXTENSION_get_data(this.ptr), false);
                return str_data.Data;
            }
        }

        public override void Addref()
        {
            // No reference counting availabe, do dupe the object
            IntPtr new_ptr = Native.ExpectNonNull(Native.X509_EXTENSION_dup(this.ptr));
            this.ptr = new_ptr;
            this.owner = true;
        }

		#region IDisposable Members

		/// <summary>
		/// Calls X509_EXTENSION_free()
		/// </summary>
		public override void OnDispose()
		{
			Native.X509_EXTENSION_free(this.ptr);
		}

		#endregion
    
        public override void Print(BIO bio)
        {
            Native.X509V3_EXT_print(bio.Handle, this.ptr, 0, 0);
        }

    }

}
