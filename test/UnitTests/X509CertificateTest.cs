// Copyright (c) 2009-2010 Frank Laub
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
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;

namespace UnitTests.OpenSSL
{
	[TestFixture]
	public class X509CertificateTest : BaseTest
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
		public void CanCreatePKCS12() {
			using (BIO bio = BIO.File(Paths.ServerPfx, "r")) {
				using (var pfx = new PKCS12(bio, password)) {
					using (var new_pfx = new PKCS12(password, pfx.PrivateKey, pfx.Certificate, pfx.CACertificates)) {
						using (BIO bout = BIO.File(Paths.ServerOutPfx, "w")) {
							new_pfx.Write(bout);
						}
						TestCert(new_pfx.Certificate, "CN=localhost", "CN=Root", 1235);
					}
				}
			}
		}

		[Test]
		public void CanCreateWithArgs()
		{
			int serial = 101;
			X509Name subject = new X509Name("CN=localhost");
			X509Name issuer = new X509Name("CN=Root");

			CryptoKey key = new CryptoKey(new DSA(true));
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
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);

			CryptoKey key = new CryptoKey(new DSA(true));
			int bits = key.Bits;

			X509Name saveIssuer = null;
			X509Name saveSubject = null;
			CryptoKey savePublicKey = null;
			CryptoKey savePrivateKey = null;
			using (X509Certificate cert = new X509Certificate())
			{
				cert.Subject = subject;
				cert.Issuer = issuer;
				cert.SerialNumber = serial;
				cert.NotBefore = start;
				cert.NotAfter = end;
				cert.PublicKey = key;
				cert.PrivateKey = key;

				Assert.AreEqual(subject, cert.Subject);
				Assert.AreEqual(issuer, cert.Issuer);
				Assert.AreEqual(serial, cert.SerialNumber);

				Assert.AreEqual(key, cert.PublicKey);
				Assert.AreEqual(key, cert.PrivateKey);

				// If the original key gets disposed before the internal private key,
				// make sure that memory is correctly managed
				key.Dispose();

				// If the internal private key has already been disposed, this will blowup
				Assert.AreEqual(bits, cert.PublicKey.Bits);
				Assert.AreEqual(bits, cert.PrivateKey.Bits);

				// We compare short date/time strings here because the wrapper can't handle milliseconds
				Assert.AreEqual(start.ToShortDateString(), cert.NotBefore.ToShortDateString());
				Assert.AreEqual(start.ToShortTimeString(), cert.NotBefore.ToShortTimeString());

				saveSubject = cert.Subject;
				saveIssuer = cert.Issuer;
				savePublicKey = cert.PublicKey;
				savePrivateKey = cert.PrivateKey;
			}

			// make sure that a property torn-off from the cert is still valid
			Assert.AreEqual(subject, saveSubject);
			Assert.AreEqual(issuer, saveIssuer);
			Assert.AreEqual(bits, savePublicKey.Bits);
			Assert.AreEqual(bits, savePrivateKey.Bits);
		}

		[Test]
		[ExpectedException(typeof(ArgumentException))]
		public void CannotSetUnmatchedPrivateKey()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				CryptoKey other = new CryptoKey(new DSA(true));
				cert.PrivateKey = other;
			}
		}

		[Test]
		public void CanCompare()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				Assert.AreEqual(cert, cert);
				using (X509Certificate cert2 = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
				{
					Assert.AreEqual(cert, cert2);
				}

				using (X509Certificate cert2 = new X509Certificate(101, "CN=other", "CN=Root", key, start, end))
				{
					Assert.IsFalse(cert == cert2);
				}

				using (X509Certificate cert2 = new X509Certificate(101, "CN=localhost", "CN=other", key, start, end))
				{
					Assert.IsFalse(cert == cert2);
				}

				CryptoKey otherKey = new CryptoKey(new DSA(true));
				using (X509Certificate cert2 = new X509Certificate(101, "CN=localhost", "CN=Root", otherKey, start, end))
				{
					Assert.IsFalse(cert == cert2);
				}
			}
		}

		[Test]
		public void CanGetAsPEM()
		{
			using (BIO bio = BIO.File(Paths.CaCrt, "r"))
			{
				string expected = File.ReadAllText(Paths.CaCrt).Replace("\r\n", "\n");
				using (X509Certificate cert = new X509Certificate(bio))
				{
					string pem = cert.PEM;
					string text = cert.ToString();

					Assert.AreEqual(expected, text + pem);
				}
			}
		}

		[Test]
		public void CanSaveAsDER() {
			using (BIO bio = BIO.File(Paths.CaDer, "r")) {
				byte[] expected = File.ReadAllBytes(Paths.CaDer);
				using (var cert = X509Certificate.FromDER(bio)) {
					byte[] der = cert.DER;
					Assert.AreEqual(expected.Length, der.Length);
					for (int i = 0; i < expected.Length; i++) {
						Assert.AreEqual(expected[i], der[i]);
					}
				}
			}
		}

		[Test]
		public void CanSign()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				cert.Sign(key, MessageDigest.DSS1);
			}
		}

		[Test]
		public void CanCheckPrivateKey()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				Assert.AreEqual(true, cert.CheckPrivateKey(key));

				CryptoKey other = new CryptoKey(new DSA(true));
				Assert.AreEqual(false, cert.CheckPrivateKey(other));
			}
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCheckTrust()
		{
		}

		[Test]
		public void CanVerify()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				cert.Sign(key, MessageDigest.DSS1);
				Assert.AreEqual(true, cert.Verify(key));

				CryptoKey other = new CryptoKey(new DSA(true));
				Assert.AreEqual(false, cert.Verify(other));
			}
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
		public void CanCreateRequest()
		{
			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				X509Request request = cert.CreateRequest(key, MessageDigest.DSS1);
				Assert.AreEqual(true, request.Verify(key));
			}
		}

		[Test]
		public void CanAddExtensions()
		{
			X509V3ExtensionList extList = new X509V3ExtensionList();
			extList.Add(new X509V3ExtensionValue("subjectKeyIdentifier", false, "hash"));
			extList.Add(new X509V3ExtensionValue("authorityKeyIdentifier", false, "keyid:always,issuer:always"));
			extList.Add(new X509V3ExtensionValue("basicConstraints", true, "critical,CA:true"));
			extList.Add(new X509V3ExtensionValue("keyUsage", false, "cRLSign,keyCertSign"));

			DateTime start = DateTime.Now;
			DateTime end = start + TimeSpan.FromMinutes(10);
			CryptoKey key = new CryptoKey(new DSA(true));
			using (X509Certificate cert = new X509Certificate(101, "CN=Root", "CN=Root", key, start, end))
			{
				foreach (X509V3ExtensionValue extValue in extList)
				{
					using (X509Extension ext = new X509Extension(cert, cert, extValue.Name, extValue.IsCritical, extValue.Value))
					{
						cert.AddExtension(ext);
					}
				}

				foreach (X509Extension ext in cert.Extensions)
				{
					Console.WriteLine(ext);
				}

				Assert.AreEqual(extList.Count, cert.Extensions.Count);
			}
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
			public const string ServerOutPfx = certsDir + "server_out.pfx";
			public const string ServerKey = certsDir + "server.key";
		}

		const string password = "p@ssw0rd";
	}
}
