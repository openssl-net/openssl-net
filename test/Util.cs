using System;
using System.IO;
using System.Reflection;
using OpenSSL.X509;
using OpenSSL.Core;

namespace UnitTests
{
	public static class Resources
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
		public const string Password = "p@ssw0rd";
	}

	public class Util
    {
		public static string LoadString(string resourceId)
		{
			using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceId))
			using (var reader = new StreamReader(stream))
			{
				return reader.ReadToEnd();
			}
		}

		public static byte[] LoadBytes(string resourceId)
		{
			using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceId))
			using (var reader = new BinaryReader(stream))
			{
				return reader.ReadBytes((int)stream.Length);
			}
		}

		public static X509Certificate LoadPKCS12Certificate(string resource, string password)
		{
			using (var bio = new BIO(LoadBytes(resource)))
			{
				return X509Certificate.FromPKCS12(bio, password);
			}
		}

		public static X509Chain LoadX509Chain(string resource)
		{
			using (var bio = new BIO(LoadBytes(resource)))
			{
				return new X509Chain(bio);
			}
		}
   }
}

