using System;
using System.IO;
using ManagedOpenSsl.NetCore.Core;
using ManagedOpenSsl.NetCore.Crypto;
using ManagedOpenSsl.NetCore.X509;

namespace Afonin.Test
{
    public static class Program
    {
        public static void Main(string[] args)
        {
	        var keyBytes= File.ReadAllBytes(@"C:/docs/cert.key");
	        var certBytes = File.ReadAllBytes(@"C:/docs/cert.crt");

	        var certBio = new BIO(certBytes);
		      var keyBio = new BIO(keyBytes);
					var key = CryptoKey.FromPrivateKey(keyBio, "975994");
	        var cert = new X509Certificate(certBio);

	        Stack<X509Certificate> stacks = new Stack<X509Certificate>();
					stacks.Add(cert);

			    var certRealPkcs12 = new PKCS12("password", key, cert, stacks);

					Console.WriteLine(certRealPkcs12.Certificate.HasPrivateKey);
        }
    }
}
