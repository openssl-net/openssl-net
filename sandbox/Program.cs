// Copyright (c) 2006-2008 Frank Laub
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
using OpenSSL;

namespace sandbox
{
	class Program
	{
		static void Main(string[] args)
		{
			Configuration cfg = new Configuration("openssl.cnf");
			X509CertificateAuthority root = X509CertificateAuthority.SelfSigned(
				cfg, 
				new SimpleSerialNumber(), 
				"Root1", 
				DateTime.Now, 
				TimeSpan.FromDays(365));
			X509CertificateAuthority rogue = X509CertificateAuthority.SelfSigned(
				cfg,
				new SimpleSerialNumber(), 
				"Rogue", 
				DateTime.Now, 
				TimeSpan.FromDays(365));

			Identity comId = new Identity(new CryptoKey(new DSA(true)));
			X509Request comReq = comId.CreateRequest("com");
			X509Certificate comCert = root.ProcessRequest(comReq, DateTime.Now, DateTime.Now + TimeSpan.FromDays(365));

			if (!comCert.Verify(root.Key))
				Console.WriteLine("Invalid com cert");
			X509CertificateAuthority com = new X509CertificateAuthority(
				comCert, 
				comId.PrivateKey, 
				new SimpleSerialNumber(), 
				cfg);

			Identity id1 = new Identity(new CryptoKey(new DSA(true)));
			X509Request req1 = id1.CreateRequest("1");
			X509Certificate cert1 = com.ProcessRequest(
				req1, 
				DateTime.Now, 
				DateTime.Now + TimeSpan.FromDays(365));

			Identity id2 = new Identity(new CryptoKey(new DSA(true)));
			X509Request req2 = id2.CreateRequest("2");
			X509Certificate cert2 = rogue.ProcessRequest(
				req2, 
				DateTime.Now, 
				DateTime.Now + TimeSpan.FromDays(365));

			X509Store store = new X509Store();
			store.AddTrusted(root.Certificate);
			store.AddUntrusted(root.Certificate);
			store.AddUntrusted(com.Certificate);

			string error;
			if (store.Verify(cert1, out error))
				Console.WriteLine("cert1 OK");
			else
				Console.WriteLine("cert1: " + error);

			store.AddUntrusted(rogue.Certificate);
			if (store.Verify(cert2, out error))
				Console.WriteLine("cert2 OK");
			else
				Console.WriteLine("cert2: " + error);

			//Console.WriteLine("root:");
			Console.WriteLine(root.Certificate);
			//Console.WriteLine("com:");
			Console.WriteLine(com.Certificate);
			//Console.WriteLine("rogue:");
			Console.WriteLine(rogue.Certificate);
			//Console.WriteLine("id1:");
			Console.WriteLine(cert1);
			//Console.WriteLine("id2:");
			Console.WriteLine(cert2);
		}
	}
}
