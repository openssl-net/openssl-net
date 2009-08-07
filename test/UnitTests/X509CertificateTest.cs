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
using NUnit.Framework;
using OpenSSL;

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
		[Ignore("Not implemented yet")]
		public void CanLoadFromPEM()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanLoadFromDER()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanLoadFromPKCS7_PEM()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanLoadFromPCKS12()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanCreateWithArgs()
		{
		}

		[Test]
		[Ignore("Not implemented yet")]
		public void CanGetAndSetProperties()
		{
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
			throw new NotImplementedException();
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
	}
}
