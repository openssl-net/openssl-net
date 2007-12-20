// Copyright (c) 2007 Frank Laub
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
