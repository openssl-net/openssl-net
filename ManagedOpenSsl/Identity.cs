using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	public class Identity
	{
		private DSA dsa;
		private X509Certificate cert;

		public Identity(DSAParameters dsaParams)
		{
			this.dsa = new DSA(dsaParams);
		}

		#region Properties

		public string PublicKey
		{
			get { return this.dsa.PemPublicKey; }
		}

		public string PrivateKey
		{
			get { return this.dsa.PemPrivateKey; }
		}

		public X509Certificate Certificate
		{
			get { return this.cert; }
		}

		public CryptoKey Key
		{
			get { return new CryptoKey(this.dsa); }
		}
		#endregion

		#region Methods
		public X509Request CreateRequest(string name)
		{
			CryptoKey key = new CryptoKey(this.dsa);

			X509Name subject = new X509Name(name);
			X509Request request = new X509Request(2, subject, key);

			request.Sign(key, MessageDigest.DSS1);

			return request;
		}

		public bool VerifyResponse(X509Chain chain, out string error)
		{
            this.cert = chain[0];
			X509Store store = new X509Store(chain);
			return store.Verify(cert, out error);
		}
		#endregion
	}
}
