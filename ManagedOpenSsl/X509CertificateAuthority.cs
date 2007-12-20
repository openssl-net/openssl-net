// Copyright (c) 2007 Frank Laub
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
	public interface ISequenceNumber
	{
		int Next();
	}

	public class FileSerialNumber : ISequenceNumber
	{
		private FileInfo serialFile;
		public FileSerialNumber(string path)
		{
			this.serialFile = new FileInfo(path);
		}

		#region ISequenceNumber Members
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

	public class SimpleSerialNumber : ISequenceNumber
	{
		private int seq;

		public SimpleSerialNumber() { this.seq = 0; }
		public SimpleSerialNumber(int seed) { this.seq = seed; }

		#region ISequenceNumber Members

		public int Next()
		{
			return ++seq;
		}

		#endregion
	}

	public class X509CertificateAuthority  
	{
		private X509Certificate caCert;
		private CryptoKey caKey;
		private ISequenceNumber serial;
		private Configuration cfg;

		public static X509CertificateAuthority SelfSigned(
			Configuration cfg,
			ISequenceNumber seq,
			X509Name subject,
            DateTime start,
			TimeSpan validity)
		{
			DSA dsa = new DSA(new DSAParameters(512));
			CryptoKey key = new CryptoKey(dsa);
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

		public X509Certificate Certificate
		{
			get { return this.caCert; }
		}

		public CryptoKey Key
		{
			get { return this.caKey; }
		}

		public X509CertificateAuthority(X509Certificate caCert, CryptoKey caKey, ISequenceNumber serial, Configuration cfg)
		{
			if (!caCert.CheckPrivateKey(caKey))
				throw new Exception("The specified CA Private Key does match the specified CA Certificate");
			this.caCert = caCert;
			this.caKey = caKey;
			this.serial = serial;
			this.cfg = cfg;
		}

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
