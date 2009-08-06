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
	}
}
