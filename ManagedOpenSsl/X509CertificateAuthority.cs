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
using System.IO;
using System.Threading;

namespace OpenSSL
{
	/// <summary>
	/// Used for generating sequence numbers by the CertificateAuthority
	/// </summary>
	public interface ISequenceNumber
	{
		/// <summary>
		/// Returns the next available sequence number
		/// </summary>
		/// <returns></returns>
		int Next();
	}

	/// <summary>
	/// Implements the ISequenceNumber interface. 
	/// The sequence number is read from a file, incremented, 
	/// then written back to the file
	/// </summary>
	public class FileSerialNumber : ISequenceNumber
	{
		private FileInfo serialFile;
		/// <summary>
		/// Constructs a FileSerialNumber. The path specifies where 
		/// the serial number should be read and written to.
		/// </summary>
		/// <param name="path"></param>
		public FileSerialNumber(string path)
		{
			this.serialFile = new FileInfo(path);
		}

		#region ISequenceNumber Members
		/// <summary>
		/// Implements the Next() method of the ISequenceNumber interface.
		/// The sequence number is read from a file, incremented, 
		/// then written back to the file
		/// </summary>
		/// <returns></returns>
		public int Next()
		{
			string name = this.serialFile.FullName.Replace('\\', '/');
			using (Mutex mutex = new Mutex(true, name))
			{
				mutex.WaitOne();
				int serial = 1;
				if (this.serialFile.Exists)
				{
					using (StreamReader sr = new StreamReader(this.serialFile.FullName))
					{
						string text = sr.ReadToEnd();
						serial = Convert.ToInt32(text);
						++serial;
					}
				}

				using(StreamWriter sr = new StreamWriter(this.serialFile.FullName))
				{
					sr.Write(serial.ToString());
				}
			
				return serial;
			}
		}
		#endregion
	}

	/// <summary>
	/// Simple implementation of the ISequenceNumber interface.
	/// </summary>
	public class SimpleSerialNumber : ISequenceNumber
	{
		private int seq;

		/// <summary>
		/// Construct a SimpleSerialNumber with the initial sequence number set to 0.
		/// </summary>
		public SimpleSerialNumber() { this.seq = 0; }

		/// <summary>
		/// Construct a SimpleSerialNumber with the initial sequence number
		/// set to the value specified by the seed parameter.
		/// </summary>
		/// <param name="seed"></param>
		public SimpleSerialNumber(int seed) { this.seq = seed; }

		#region ISequenceNumber Members

		/// <summary>
		/// Returns the next available sequence number.
		/// This implementation simply increments the current 
		/// sequence number and returns it.
		/// </summary>
		/// <returns></returns>
		public int Next()
		{
			return ++seq;
		}

		#endregion
	}

	/// <summary>
	/// High-level interface which does the job of a CA (Certificate Authority)
	/// Duties include processing incoming X509 requests and responding
	/// with signed X509 certificates, signed by this CA's private key.
	/// </summary>
	public class X509CertificateAuthority  
	{
		private X509Certificate caCert;
		private CryptoKey caKey;
		private ISequenceNumber serial;
		private Configuration cfg;

		/// <summary>
		/// Factory method which creates a X509CertifiateAuthority where
		/// the internal certificate is self-signed
		/// </summary>
		/// <param name="cfg"></param>
		/// <param name="seq"></param>
		/// <param name="subject"></param>
		/// <param name="start"></param>
		/// <param name="validity"></param>
		/// <returns></returns>
		public static X509CertificateAuthority SelfSigned(
			Configuration cfg,
			ISequenceNumber seq,
			X509Name subject,
            DateTime start,
			TimeSpan validity)
		{
			CryptoKey key = new CryptoKey(new DSA());
			X509Certificate cert = new X509Certificate(
				seq.Next(),
				subject,
				subject,
				key,
                start,
				start + validity);

			if(cfg != null)
				cfg.ApplyExtensions("v3_ca", cert, cert, null);

			cert.Sign(key, MessageDigest.DSS1);

			return new X509CertificateAuthority(cert, key, seq, cfg);
		}

		/// <summary>
		/// Accessor to the CA's X509 Certificate
		/// </summary>
		public X509Certificate Certificate
		{
			get { return this.caCert; }
		}

		/// <summary>
		/// Accessor to the CA's key used for signing.
		/// </summary>
		public CryptoKey Key
		{
			get { return this.caKey; }
		}

		/// <summary>
		/// Constructs a X509CertifcateAuthority with the specified parameters.
		/// </summary>
		/// <param name="caCert"></param>
		/// <param name="caKey"></param>
		/// <param name="serial"></param>
		/// <param name="cfg"></param>
		public X509CertificateAuthority(X509Certificate caCert, CryptoKey caKey, ISequenceNumber serial, Configuration cfg)
		{
			if (!caCert.CheckPrivateKey(caKey))
				throw new Exception("The specified CA Private Key does match the specified CA Certificate");
			this.caCert = caCert;
			this.caKey = caKey;
			this.serial = serial;
			this.cfg = cfg;
		}

		/// <summary>
		/// Process and X509Request. This includes creating a new X509Certificate
		/// and signing this certificate with this CA's private key.
		/// </summary>
		/// <param name="request"></param>
		/// <param name="startTime"></param>
		/// <param name="endTime"></param>
		/// <returns></returns>
		public X509Certificate ProcessRequest(X509Request request, DateTime startTime, DateTime endTime)
		{
			//using (CryptoKey pkey = request.PublicKey)
			//{
			//    if (!request.Verify(pkey))
			//        throw new Exception("Request signature validation failed");
			//}

			X509Certificate cert = new X509Certificate(
				serial.Next(),
				request.Subject,
				this.caCert.Subject,
				request.PublicKey,
				startTime,
				endTime);

			if(this.cfg != null)
				this.cfg.ApplyExtensions("v3_ca", this.caCert, cert, request);
            
			cert.Sign(this.caKey, MessageDigest.DSS1);

			return cert;
		}
	}
}
