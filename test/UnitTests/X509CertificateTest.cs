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
using System.IO;
using OpenSSL;
using NUnit.Framework;

namespace UnitTests.OpenSSL
{
	[TestFixture]
	public class X509CertificateTest
	{
		[Test]
		public void CanCreateAndDispose()
		{
			using (X509Certificate cert = new X509Certificate()) 
			{
				cert.PrintRefCount();				
			}
		}

		[Test]
		public void CanLoadFromPEM()
		{
			using(BIO bio = BIO.File(Paths.CaCrt, "r"))
			{
				using(X509Certificate cert = new X509Certificate(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromDER()
		{
			using(BIO bio = BIO.File(Paths.CaDer, "r"))
			{
				using(X509Certificate cert = X509Certificate.FromDER(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPKCS7_PEM()
		{
			using(BIO bio = BIO.File(Paths.CaChainP7cPem, "r"))
			{
				using(X509Certificate cert = X509Certificate.FromPKCS7_PEM(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPKCS7_DER()
		{
			using(BIO bio = BIO.File(Paths.CaChainP7c, "r"))
			{
				using(X509Certificate cert = X509Certificate.FromPKCS7_DER(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPCKS12()
		{
			using(BIO bio = BIO.File(Paths.ServerPfx, "r"))
			{
				using(X509Certificate cert = X509Certificate.FromPKCS12(bio, password))
				{
					TestCert(cert, "CN=localhost", "CN=Root", 1235);
				}
			}
		}

		[Test]
		public void CanCreateWithArgs()
		{
			int serial = 101;
			X509Name subject = new X509Name("CN=localhost");
			X509Name issuer = new X509Name("CN=Root");

			CryptoKey key;
			using (DSA dsa = new DSA(true))
			{
				key = new CryptoKey(dsa);
			}

			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);

			using(X509Certificate cert = new X509Certificate(serial, subject, issuer, key, start, end))
			{
				Assert.AreEqual(subject, cert.Subject);
				Assert.AreEqual(issuer, cert.Issuer);
				Assert.AreEqual(serial, cert.SerialNumber);

				// We compare short date/time strings here because the wrapper can't handle milliseconds
				Assert.AreEqual(start.ToShortDateString(), cert.NotBefore.ToShortDateString());
				Assert.AreEqual(start.ToShortTimeString(), cert.NotBefore.ToShortTimeString());
			}	
		}

		[Test]
		public void CanGetAndSetProperties()
		{
			int serial = 101;
			X509Name subject = new X509Name("CN=localhost");
			X509Name issuer = new X509Name("CN=Root");

			CryptoKey key;
			using (DSA dsa = new DSA(true))
			{
				key = new CryptoKey(dsa);
			}

			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);

			using(X509Certificate cert = new X509Certificate())
			{
				cert.Subject = subject;
				cert.Issuer = issuer;
				cert.SerialNumber = serial;
				cert.NotBefore = start;
				cert.NotAfter = end;

				Assert.AreEqual(subject, cert.Subject);
				Assert.AreEqual(issuer, cert.Issuer);
				Assert.AreEqual(serial, cert.SerialNumber);

				// We compare short date/time strings here because the wrapper can't handle milliseconds
				Assert.AreEqual(start.ToShortDateString(), cert.NotBefore.ToShortDateString());
				Assert.AreEqual(start.ToShortTimeString(), cert.NotBefore.ToShortTimeString());
			}
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanGetAsPEM()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanSign()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCheckPrivateKey()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCheckTrust()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanVerify()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanDigest()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanDigestPublicKey()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanWriteToBIO()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanPrint()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCreateRequest()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanAddExtensions()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void VerifyEquality()
		{
		}

		private void TestCert(X509Certificate cert, string subject, string issuer, int serial)
		{
			Assert.AreEqual(subject, cert.Subject.ToString());
			Assert.AreEqual(issuer, cert.Issuer.ToString());
			Assert.AreEqual(serial, cert.SerialNumber); 
		}

		static class Paths
		{
			const string certsDir = "../../test/certs/";
			public const string CaCrt = certsDir + "ca.crt";
			public const string CaDer = certsDir + "ca.der";
			public const string CaChainP7c = certsDir + "ca_chain.p7c";
			public const string CaChainP7cPem = certsDir + "ca_chain.p7c.pem";
			public const string CaChainPem = certsDir + "ca_chain.pem";
			public const string ClientCrt = certsDir + "client.crt";
			public const string ClientPfx = certsDir + "client.pfx";
			public const string ClientKey = certsDir + "client.key";
			public const string ServerCrt = certsDir + "server.crt";
			public const string ServerPfx = certsDir + "server.pfx";
			public const string ServerKey = certsDir + "server.key";
		}

		const string password = "p@ssw0rd";
	}
}
