using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NUnit.Framework;
using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.X509;

namespace UnitTests
{
    [TestFixture]
    class TestX509Request : TestBase
    {
        const string RSA_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIEogIBAAKCAQEA4Bn99hedIW/f096aiCHhS9Zbbj0DRSvsbnjbr5YlYrrsogON\n" +
            "uEoAdGe0aUJS7FHWde8hYubIXMLTVfACxXSJogPw5POYalsTN9LqQ9fEt/q/S9zf\n" +
            "uV1//5ttlEM0KkhciV0m6TvQREDqt1gSeELbgQg04PdN1gkFN9kXy2tbvyq4ehdO\n" +
            "TEwNL/oWcdRdPicyKy/4y8j+fe4+5MaLZ1Ooh//g7d58qLfFy4wOoiHYZ7lWfS2I\n" +
            "B0OrKCt+UWVlOeDMuDsBjGCWqpvv/R880yU/VOBY0m07aFr+ZziCU7mWvFqIqXp6\n" +
            "MkuilNWZtbnzM/1mArc7SS0UnMZFBMLy6N8VfwIDAQABAoIBADHnV9hvVbxWb198\n" +
            "2Kir8sGykFWyHIJQz6uiGjm1k8mymnNRm0OIpyVE2rX94P1jFADbKXIetkuBzxH6\n" +
            "CoPx+ZwsiH5TiINWmKb7vtMwv0vA+Mxp+SAMJC7Fa9dyR7GKv6CPL9UMTsqEMkB1\n" +
            "ylchfEP1keDu8VRSWekf3N6dn6an8ANvg8UVy3oLoJVvr7BTgD9f0RmOd13jeFYj\n" +
            "sPDJxAElQSwVD+6UubjfUnYmiVbzr6DVXawY7h2K0GWSJFZ8MmEmFqNLAos/a9hg\n" +
            "Wy+Ek+lIi+BEIjkdqqT3QXlScbOj02cEcqNv2+FdcZde7eTg9daW0z4HdipWIITG\n" +
            "/93kCeECgYEA9+laKfIPIWSfFuRibt8re3umV4ACxM9Kb9BUSTfMHDP5jmiGHv+O\n" +
            "h5zu7cxvEq5cVk7wL/c5/PyUia4meOSuB86QF8dMDaK4SZBsEWHs+rSHDptwIR0q\n" +
            "hZMomUMVmPp4IlCwxwREGtUfb5xBXBoRw5z+0Sc+jK47VYm1KAyVducCgYEA52nF\n" +
            "HqiV857i1AfzKCcBURr12j8d85SPADPqSxabtPksRsec2PLJ4dnVzIEzgCDo+Kns\n" +
            "rfR8tqbsxP0DdZDvZRPmNP+azOlnHyYBGLXPoDH4TObk7AhSwI/T4DbG83EGzC1/\n" +
            "impdARRF89jW1fkjVVz5HETBugijp2eOZSO30akCgYBDs0T9GW5KVzkevkWnM2ij\n" +
            "cxPs5zdaWaVhPYoW6JbjyMnIuwCNbIqWvCN/awmWF2l95FaxMplyXeOOabF16DUi\n" +
            "SqWM6M77FkmvRTJN2OknWa9cLNSFJnrbOWGn4Or/+L5f2Js97gtPLI5GI2yx4yig\n" +
            "u7nWkhoBvv7TECUZh741VwKBgBGsPTabL2B8mNwSg1pkqDAWfAIf4dyxUr50OIdl\n" +
            "gZyvjtcU9YCIAizyYuaMU2+Mk94xs/aQ/llApEJjBDmdSPsSKvmPL7ZIeOyjDWBi\n" +
            "uimEx26wD3mLJS65jTfJVyZOUnOTYfMjLlkfwDvgKoAK18z0Hb4v7g+UC1OEkBZf\n" +
            "RPGJAoGAU46962KrZPeSZEPfpdN87osXZffEM6+2yJEwp+YCHNApb6CzZrqrdenu\n" +
            "lbYEEryAMqd8GeBCKCjNKNmvBiqw/ChV5soZXCf1dwfBVHDTxFjb8XRK0Gr4XVf1\n" +
            "YA/5vJnCBLxKMQpx18oGInj2Hn+JcSGU4aqMXxM7q8wHKCdE3xQ=\n" +
            "-----END RSA PRIVATE KEY-----";

        const string EXPECTED_CERT = "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIIBgTCCAXYCAQEwDjEMMAoGA1UEAwwDZm9vMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
            "AQ8AMIIBCgKCAQEA4Bn99hedIW/f096aiCHhS9Zbbj0DRSvsbnjbr5YlYrrsogON\n" +
            "uEoAdGe0aUJS7FHWde8hYubIXMLTVfACxXSJogPw5POYalsTN9LqQ9fEt/q/S9zf\n" +
            "uV1//5ttlEM0KkhciV0m6TvQREDqt1gSeELbgQg04PdN1gkFN9kXy2tbvyq4ehdO\n" +
            "TEwNL/oWcdRdPicyKy/4y8j+fe4+5MaLZ1Ooh//g7d58qLfFy4wOoiHYZ7lWfS2I\n" +
            "B0OrKCt+UWVlOeDMuDsBjGCWqpvv/R880yU/VOBY0m07aFr+ZziCU7mWvFqIqXp6\n" +
            "MkuilNWZtbnzM/1mArc7SS0UnMZFBMLy6N8VfwIDAQABoDswOQYJKoZIhvcNAQkO\n" +
            "MSwwKjAbBgNVHREEFDASggdmb28uY29tggdiYXIub3JnMAsGA1UdDwQEAwIBBjAC\n" +
            "BgADAQA=\n" +
            "-----END CERTIFICATE REQUEST-----\n";

        [Test]
        public void CanAddRequestExtensions()
        {
            var extList = new List<X509V3ExtensionValue> {
				new X509V3ExtensionValue("subjectAltName", false, "DNS:foo.com,DNS:bar.org"),
				new X509V3ExtensionValue("keyUsage", false, "cRLSign,keyCertSign"),
			};

            var start = DateTime.Now;
            var end = start + TimeSpan.FromMinutes(10);
            using (var key = new CryptoKey(RSA.FromPrivateKey(new BIO(RSA_KEY))))
            using (var request = new X509Request(1,new X509Name("foo"),key))
            {
                OpenSSL.Core.Stack<X509Extension> extensions = new OpenSSL.Core.Stack<X509Extension>();
                foreach (var extValue in extList)
                {
                    using (var ext = new X509Extension(request, extValue.Name, extValue.IsCritical, extValue.Value))
                    {
                        Console.WriteLine(ext);
                        extensions.Add(ext);
                    }
                }

                request.AddExtensions(extensions);

                Assert.AreEqual(EXPECTED_CERT, request.PEM);
            }
        }
    }
}
