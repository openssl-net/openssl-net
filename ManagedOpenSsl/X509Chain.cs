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
	#region X509_INFO
	[StructLayout(LayoutKind.Sequential)]
	internal struct X509_INFO
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

	internal class X509CertificateInfo : IStackable, IDisposable
	{
		private IntPtr ptr;
		private X509Certificate cert;
		private CryptoKey key;
		private X509_INFO raw;

		~X509CertificateInfo()
		{
			Dispose();
		}

		public X509Certificate Certificate
		{
			get
			{
				if (this.cert != null)
					return this.cert;

				if (this.raw.x509 == IntPtr.Zero)
					return null;

				this.cert = new X509Certificate(this.raw.x509, true);
				this.raw.x509 = IntPtr.Zero;
				Marshal.StructureToPtr(this.raw, this.ptr, false);
				return this.cert;
			}
		}

		public CryptoKey Key
		{
			get
			{
				if (this.key != null)
					return this.key;

				if (this.raw.x_pkey == IntPtr.Zero)
					return null;

				this.key = new CryptoKey(this.raw.x_pkey, true);
				this.raw.x_pkey = IntPtr.Zero;
				Marshal.StructureToPtr(this.raw, this.ptr, false);
				return this.key;
			}
		}

		#region IStackable Members
		public IntPtr Handle
		{
			get { return this.ptr; }
			set 
			{
				this.ptr = value;
				this.raw = (X509_INFO)Marshal.PtrToStructure(this.ptr, typeof(X509_INFO));
			}
		}

		#endregion

		#region IDisposable Members
		private bool isDisposed = false;
		public void Dispose()
		{
			if (this.isDisposed)
				return;
			if (this.ptr != IntPtr.Zero)
				Native.X509_INFO_free(this.ptr);
			this.isDisposed = true;
		}
		#endregion
	}
	#endregion

	/// <summary>
	/// Contains a chain X509_INFO objects.
	/// </summary>
	public class X509Chain : Stack<X509Certificate>
	{
		#region Initialization
		/// <summary>
		/// Default null constructor
		/// </summary>
		public X509Chain() { }

		/// <summary>
		/// Creates a chain from a BIO. Expects the stream to contain
		/// a collection of X509_INFO objects in PEM format by calling
		/// PEM_X509_INFO_read_bio()
		/// </summary>
		/// <param name="bio"></param>
		public X509Chain(BIO bio)
		{
			IntPtr sk = Native.ExpectNonNull(
				Native.PEM_X509_INFO_read_bio(bio.Handle, IntPtr.Zero, null, IntPtr.Zero));
			using (Stack<X509CertificateInfo> stack = new Stack<X509CertificateInfo>(sk, true))
			{
				while (stack.Count > 0)
				{
					using (X509CertificateInfo xi = stack.Shift())
					{
						if (xi.Certificate != null)
							this.Add(xi.Certificate);
					}
				}
			}
		}

		/// <summary>
		/// Creates a new chain from the specified PEM-formatted string
		/// </summary>
		/// <param name="pem"></param>
		public X509Chain(string pem)
			: this(new BIO(pem))
		{
		}
		#endregion

		#region Methods
		/// <summary>
		/// Returns X509_find_by_issuer_and_serial()
		/// </summary>
		/// <param name="issuer"></param>
		/// <param name="serial"></param>
		/// <returns></returns>
		public X509Certificate FindByIssuerAndSerial(X509Name issuer, int serial)
		{
			IntPtr ptr = Native.X509_find_by_issuer_and_serial(this.ptr, issuer.Handle, Native.IntegerToAsnInteger(serial));
			if(ptr == IntPtr.Zero)
				return null;
			return new X509Certificate(ptr, false);
		}

		/// <summary>
		/// Returns X509_find_by_subject()
		/// </summary>
		/// <param name="subject"></param>
		/// <returns></returns>
		public X509Certificate FindBySubject(X509Name subject)
		{
			IntPtr ptr = Native.X509_find_by_subject(this.ptr, subject.Handle);
			if (ptr == IntPtr.Zero)
				return null;
			return new X509Certificate(ptr, false);
		}
		#endregion
	}

	/// <summary>
	/// A List for X509Certificate types.
	/// </summary>
	public class X509List : List<X509Certificate>
	{
		#region Initialization
		/// <summary>
		/// Creates an empty X509List
		/// </summary>
		public X509List() { }

		/// <summary>
		/// Calls PEM_x509_INFO_read_bio()
		/// </summary>
		/// <param name="bio"></param>
		public X509List(BIO bio)
		{
			IntPtr sk = Native.ExpectNonNull(
				Native.PEM_X509_INFO_read_bio(bio.Handle, IntPtr.Zero, null, IntPtr.Zero));
			using (Stack<X509CertificateInfo> stack = new Stack<X509CertificateInfo>(sk, true))
			{
				while (stack.Count > 0)
				{
					using (X509CertificateInfo xi = stack.Shift())
					{
						if (xi.Certificate != null)
							this.Add(xi.Certificate);
					}
				}
			}
		}

		/// <summary>
		/// Populates this list from a PEM-formatted string
		/// </summary>
		/// <param name="pem"></param>
		public X509List(string pem)
			: this(new BIO(pem))
		{
		}

		/// <summary>
		/// Populates this list from a DER buffer.
		/// </summary>
		/// <param name="der"></param>
		public X509List(byte[] der)
		{
			BIO bio = new BIO(der);
			while (bio.NumberRead < der.Length)
			{
				X509Certificate x509 = X509Certificate.FromDER(bio);
				this.Add(x509);
			}
		}
		#endregion
	}
}
