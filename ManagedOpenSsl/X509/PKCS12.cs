// Copyright (c) 2009 Frank Laub
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
	/// Wraps PCKS12_*
	/// </summary>
	public class PKCS12 : Base
	{
		#region PKCS12 structure

		[StructLayout(LayoutKind.Sequential)]
		struct _PKCS12
		{
			IntPtr version;     //ASN1_INTEGER *version;
			IntPtr mac;         //PKCS12_MAC_DATA *mac;
			IntPtr authsafes;   //PKCS7 *authsafes;
		}
		#endregion

		#region Initialization

		/// <summary>
		/// Calls d2i_PKCS12_bio() and then PKCS12_parse()
		/// </summary>
		/// <param name="bio"></param>
		/// <param name="password"></param>
		public PKCS12(BIO bio, string password)
			: base(Native.ExpectNonNull(Native.d2i_PKCS12_bio(bio.Handle, IntPtr.Zero)), true)
		{
			IntPtr cert;
			IntPtr pkey;
			IntPtr cacerts;

			// Parse the PKCS12 object and get privatekey, cert, cacerts if available
			Native.ExpectSuccess(Native.PKCS12_parse(this.ptr, password, out pkey, out cert, out cacerts));

			if (cert != IntPtr.Zero)
			{
				this.certificate = new X509Certificate(cert, true);
				if (pkey != IntPtr.Zero)
				{
					this.privateKey = new CryptoKey(pkey, true);

					// We have a private key, assign it to the cert
					this.certificate.PrivateKey = this.privateKey.CopyRef();
				}
			}
			if (cacerts != IntPtr.Zero)
			{
				this.caCertificates = new Stack<X509Certificate>(cacerts, true);
			}
		}

		#endregion

		#region Properties

		/// <summary>
		/// Returns the Certificate, with the PrivateKey attached if there is one.
		/// </summary>
		public X509Certificate Certificate
		{
			get
			{
				if (certificate != null)
				{
					X509Certificate cert = this.certificate.CopyRef();
					if (privateKey != null)
						cert.PrivateKey = this.privateKey.CopyRef();
					return cert;
				}
				return null;
			}
		}

		/// <summary>
		/// Returns the PrivateKey
		/// </summary>
		public CryptoKey PrivateKey
		{
			get
			{
				if (privateKey != null)
					return this.privateKey.CopyRef();
				return null;
			}
		}

		/// <summary>
		/// Returns a stack of CA Certificates
		/// </summary>
		public Stack<X509Certificate> CACertificates
		{
			get { return caCertificates; }
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls PKCS12_free()
		/// </summary>
		protected override void OnDispose()
		{
			if (certificate != null)
			{
				certificate.Dispose();
				certificate = null;
			}
			if (privateKey != null)
			{
				privateKey.Dispose();
				privateKey = null;
			}
			if (caCertificates != null)
			{
				caCertificates.Dispose();
				caCertificates = null;
			}
			Native.PKCS12_free(this.ptr);
		}

		#endregion

		#region Fields
		private CryptoKey privateKey;
		private X509Certificate certificate;
		private Stack<X509Certificate> caCertificates;
		#endregion
	}
}
