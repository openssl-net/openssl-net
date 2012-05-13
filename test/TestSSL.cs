using System;
using NUnit.Framework;
using OpenSSL;
using OpenSSL.Core;
using OpenSSL.X509;
using OpenSSL.SSL;
using System.IO;

namespace UnitTests
{
	[TestFixture]
	public class TestSSL
	{
		[Test]
		public void CanCreateAndDispose()
		{
			using (MemoryStream ms = new MemoryStream()) {
				using (SslStream ssl = new SslStream(ms)) {
					ssl.AuthenticateAsClient("localhost");
				}
			}
		}	
	}
}

