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
			Configuration cfg = new Configuration("\\openssl.cnf");
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

			Identity comId = new Identity(new DSAParameters(512));
			X509Request comReq = comId.CreateRequest("com");
			X509Certificate comCert = root.ProcessRequest(comReq, DateTime.Now, DateTime.Now + TimeSpan.FromDays(365));

			if (!comCert.Verify(root.Key))
				Console.WriteLine("Invalid com cert");
			X509CertificateAuthority com = new X509CertificateAuthority(
				comCert, 
				comId.Key, 
				new SimpleSerialNumber(), 
				cfg);

			Identity id1 = new Identity(new DSAParameters(512));
			X509Request req1 = id1.CreateRequest("1");
			X509Certificate cert1 = com.ProcessRequest(
				req1, 
				DateTime.Now, 
				DateTime.Now + TimeSpan.FromDays(365));

			Identity id2 = new Identity(new DSAParameters(512));
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
