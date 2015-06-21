// Copyright (c) 2009-2010 Frank Laub
// All rights reserved.
//
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
using System.Resources;
using System.Reflection;
using System.Collections.Generic;

namespace UnitTests
{
	[TestFixture]
	public class TestX509Certificate : TestBase
	{
		[Test]
		public void CanCreateAndDispose()
		{
			using (var cert = new X509Certificate())
			{
				cert.PrintRefCount();
			}
		}

		[Test]
		public void CanLoadFromPEM()
		{
			using (var bio = new BIO(Util.LoadString(Resources.CaCrt)))
			{
				using (var cert = new X509Certificate(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromDER()
		{
			using (var bio = new BIO(Util.LoadBytes(Resources.CaDer)))
			{
				using (var cert = X509Certificate.FromDER(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPKCS7_PEM()
		{
			using (var bio = new BIO(Util.LoadString(Resources.CaChainP7cPem)))
			{
				using (var cert = X509Certificate.FromPKCS7_PEM(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPKCS7_DER()
		{
			using (var bio = new BIO(Util.LoadBytes(Resources.CaChainP7c)))
			{
				using (var cert = X509Certificate.FromPKCS7_DER(bio))
				{
					TestCert(cert, "CN=Root", "CN=Root", 1234);
				}
			}
		}

		[Test]
		public void CanLoadFromPCKS12()
		{
			using (var cert = Util.LoadPKCS12Certificate(Resources.ServerPfx, Resources.Password))
			{
				TestCert(cert, "CN=localhost", "CN=Root", 1235);
			}
		}

		[Test]
		public void CanCreatePKCS12()
		{
			using (var bio = new BIO(Util.LoadBytes(Resources.ServerPfx)))
			using (var pfx = new PKCS12(bio, Resources.Password))
			using (var new_pfx = new PKCS12(Resources.Password,
									   pfx.Certificate.PrivateKey,
									   pfx.Certificate,
									   pfx.CACertificates))
			{
				TestCert(new_pfx.Certificate, "CN=localhost", "CN=Root", 1235);
			}
		}

		[Test]
		public void CanCreateWithArgs()
		{
			var serial = 101;
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var subject = new X509Name("CN=localhost"))
			using (var issuer = new X509Name("CN=Root"))
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(serial, subject, issuer, key, start, end))
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
			var serial = 101;
			var subject = new X509Name("CN=localhost");
			var issuer = new X509Name("CN=Root");
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);

			var key = new CryptoKey(new DSA(true));
			var bits = key.Bits;

			X509Name saveIssuer = null;
			X509Name saveSubject = null;
			CryptoKey savePublicKey = null;
			CryptoKey savePrivateKey = null;
			using (var cert = new X509Certificate())
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
			using (subject)
			using (saveSubject)
			{
				Assert.AreEqual(subject, saveSubject);
			}
			using (issuer)
			using (saveIssuer)
			{
				Assert.AreEqual(issuer, saveIssuer);
			}
			using (savePublicKey)
			{
				Assert.AreEqual(bits, savePublicKey.Bits);
			}
			using (savePrivateKey)
			{
				Assert.AreEqual(bits, savePrivateKey.Bits);
			}
		}

		[Test]
		[ExpectedException(typeof(ArgumentException))]
		public void CannotSetUnmatchedPrivateKey()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				var other = new CryptoKey(new DSA(true));
				cert.PrivateKey = other;
			}
		}

		[Test]
		public void CanCompare()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				Assert.AreEqual(cert, cert);
				using (var cert2 = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
				{
					Assert.AreEqual(cert, cert2);
				}

				using (var cert2 = new X509Certificate(101, "CN=other", "CN=Root", key, start, end))
				{
					Assert.AreNotEqual(cert, cert2);
				}

				using (var cert2 = new X509Certificate(101, "CN=localhost", "CN=other", key, start, end))
				{
					Assert.AreNotEqual(cert, cert2);
				}

				using (var otherKey = new CryptoKey(new DSA(true)))
				using (var cert2 = new X509Certificate(101, "CN=localhost", "CN=Root", otherKey, start, end))
				{
					Assert.AreNotEqual(cert, cert2);
				}
			}
		}

		[Test]
		public void CanGetAsPEM()
		{
			var data = Util.LoadString(Resources.CaCrt);
			var expected = data.Replace("\r\n", "\n");
			using (var bio = new BIO(data))
			using (var cert = new X509Certificate(bio))
			{
				var pem = cert.PEM;
				var text = cert.ToString();

				Assert.AreEqual(expected, text + pem);
			}
		}

		[Test]
		public void CanSaveAsDER()
		{
			var data = Util.LoadBytes(Resources.CaDer);
			using (var bio = new BIO(data))
			using (var cert = X509Certificate.FromDER(bio))
			{
				var der = cert.DER;
				Assert.AreEqual(data.Length, der.Length);
				for (var i = 0; i < data.Length; i++)
				{
					Assert.AreEqual(data[i], der[i]);
				}
			}
		}

		[Test]
		public void CanSign()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				cert.Sign(key, MessageDigest.DSS1);
			}
		}

		[Test]
		public void CanCheckPrivateKey()
		{
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				Assert.AreEqual(true, cert.CheckPrivateKey(key));

				using (var other = new CryptoKey(new DSA(true)))
				{
					Assert.AreEqual(false, cert.CheckPrivateKey(other));
				}
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
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			{
				cert.Sign(key, MessageDigest.DSS1);
				Assert.AreEqual(true, cert.Verify(key));

				using (var other = new CryptoKey(new DSA(true)))
				{
					Assert.AreEqual(false, cert.Verify(other));
				}
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
			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=localhost", "CN=Root", key, start, end))
			using (var request = cert.CreateRequest(key, MessageDigest.DSS1))
			{
				Assert.IsTrue(request.Verify(key));
			}
		}

		[Test]
		public void CanAddExtensions()
		{
			var extList = new List<X509V3ExtensionValue> {
				new X509V3ExtensionValue("subjectKeyIdentifier", false, "hash"),
				new X509V3ExtensionValue("authorityKeyIdentifier", false, "keyid:always,issuer:always"),
				new X509V3ExtensionValue("basicConstraints", true, "critical,CA:true"),
				new X509V3ExtensionValue("keyUsage", false, "cRLSign,keyCertSign"),
			};

			var start = DateTime.Now;
			var end = start + TimeSpan.FromMinutes(10);
			using (var key = new CryptoKey(new DSA(true)))
			using (var cert = new X509Certificate(101, "CN=Root", "CN=Root", key, start, end))
			{
				foreach (var extValue in extList)
				{
					using (var ext = new X509Extension(cert, cert, extValue.Name, extValue.IsCritical, extValue.Value))
					{
						cert.AddExtension(ext);
					}
				}

				foreach (var ext in cert.Extensions)
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
	}
}
