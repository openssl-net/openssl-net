// Copyright (c) 2009 Frank Laub
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
using NUnit.Framework;
using OpenSSL.Core;
using System.Reflection;
using System.IO;

namespace UnitTests
{
	public class TestBase
	{
		[SetUp]
		public virtual void Setup()
		{
			MemoryTracker.Start();
		}

		[TearDown]
		public virtual void Teardown()
		{
			MemoryTracker.Finish();
			Assert.AreEqual(0, MemoryTracker.Leaked);
		}
	
		protected string LoadString(string resourceId) {
			using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceId)) {
				using (StreamReader reader = new StreamReader(stream)) {
					return reader.ReadToEnd();
				}
			}
		}
		
		protected byte[] LoadBytes(string resourceId) {
			using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceId)) {
				using (BinaryReader reader = new BinaryReader(stream)) {
					return reader.ReadBytes((int)stream.Length);
				}
			}
		}

		protected static class Resources
		{
			public const string CaCrt = "UnitTests.certs.ca.crt";
			public const string CaDer = "UnitTests.certs.ca.der";
			public const string CaChainP7c = "UnitTests.certs.ca_chain.p7c";
			public const string CaChainP7cPem = "UnitTests.certs.ca_chain.p7c.pem";
			public const string CaChainPem = "UnitTests.certs.ca_chain.pem";
			public const string ClientCrt = "UnitTests.certs.client.crt";
			public const string ClientPfx = "UnitTests.certs.client.pfx";
			public const string ClientKey = "UnitTests.certs.client.key";
			public const string ServerCrt = "UnitTests.certs.server.crt";
			public const string ServerPfx = "UnitTests.certs.server.pfx";
			public const string ServerKey = "UnitTests.certs.server.key";
			public const string PfxPassword = "p@ssw0rd";
		}
	}
}
