using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

namespace sandbox
{
	class Naming
	{
		class Node
		{
			public Node parent;
			public Dictionary<string, Node> children = new Dictionary<string,Node>();
			public Authority auth;
		}

		private static Node root;

		static Naming()
		{
			root = new Node();
			root.parent = root;
		}

		public static void Publish(string path, Authority auth)
		{
			Node node = root;
			if (path == ".")
			{
				node.auth = auth;
				return;
			}

			string[] parts = path.Split('.');
			for (int i = parts.Length-1; i > 0; --i)
			{
				if (parts[i] == "")
					continue;
				node = node.children[parts[i]];
			}
			
			//string issuer = auth.Certificate.Issuer.Common;
			//if (node.auth.Certificate.Subject.Common != issuer)
			//    throw new InvalidOperationException("This cert is not authorized to be published here");

			if(!auth.Certificate.Verify(node.auth.Certificate.PublicKey))
				throw new InvalidOperationException("This cert is not authorized to be published here");

			string name = auth.Certificate.Subject.Common;
			Node newNode = new Node();
			newNode.parent = node;
			newNode.children.Add(name, newNode);
			newNode.auth = auth;
		}

		public static Authority Lookup(string path)
		{
			if (path == ".")
				return root.auth;

			Node node = root;
			string[] parts = path.Split('.');
			for (int i = parts.Length - 1; i > 0; --i)
			{
				if (parts[i] == "")
					continue;
				node = node.children[parts[i]];
			}
			return node.auth;
		}
	}

	class Authority
	{
		public static Authority Root = MakeRoot();
		private SimpleSerialNumber serial = new SimpleSerialNumber();
		private CryptoKey key;
		private X509CertificateAuthority ca;
		private string name;

		public Authority(string name)
		{
			DSA dsa = new DSA(new DSAParameters(512));
			this.key = new CryptoKey(dsa);
			this.name = name;
		}

		public Authority(X509Certificate cert, CryptoKey key)
		{
			this.key = key;
			this.ca = new X509CertificateAuthority(cert, key, this.serial);
			this.name = cert.Subject.Common;
		}

		private static Authority MakeRoot()
		{
			DSA dsa = new DSA(new DSAParameters(512));
			CryptoKey key = new CryptoKey(dsa);
			X509Name subject = new X509Name("CN=.");
			X509Certificate cert = new X509Certificate(
				0,
				subject,
				subject,
				key,
				TimeSpan.FromDays(365));
			cert.Sign(key, MessageDigest.DSS1);

			return new Authority(cert, key);
		}

		public X509Certificate Certificate
		{
			get { return this.ca.Certificate; }
		}

		public CryptoKey Key
		{
			get { return this.ca.Key; }
		}

		public string FullName
		{
			get 
			{
				if (this.name == ".")
					return this.name;

				return this.Name + "." + this.Parent; 
			}
		}

		public string Name
		{
			get
			{
				return this.name;
			}
		}

		public string Parent
		{
			get
			{
				if (this.ca == null)
					return null;

				string issuer = this.ca.Certificate.Issuer.Common;
				if(issuer == ".")
					return "";
				return GetFullName(issuer);
			}
		}

		private string GetFullName(string issuer)
		{
			Authority parent = Naming.Lookup(issuer);
			string next = parent.Certificate.Issuer.Common;
			return parent.Certificate.Subject.Common + "." + GetFullName(next);
		}

		public X509Request Request
		{
			get
			{
				X509Name subject = new X509Name();
				subject.Common = this.Name;
				X509Request request = new X509Request(0, subject, this.key);
				request.Sign(this.key, MessageDigest.DSS1);
				return request;
			}
		}

		public X509Certificate Authorize(X509Request request)
		{
			return this.ca.ProcessRequest(request, TimeSpan.FromDays(365));
		}

		public void Promote(X509Certificate cert)
		{
			cert.Verify(this.key);
			this.ca = new X509CertificateAuthority(cert, this.key, this.serial);
		}
	}

	class Program
	{
		static void Authorities()
		{
			Authority root = Authority.Root;
			Authority com = new Authority("com");
			Authority coco = new Authority("coco");
			Authority frank = new Authority("frank");

			Naming.Publish(root.FullName, root);

			com.Promote(root.Authorize(com.Request));
			Naming.Publish(com.FullName, com);

			coco.Promote(com.Authorize(coco.Request));
			Naming.Publish(coco.FullName, coco);

			frank.Promote(coco.Authorize(frank.Request));
			Naming.Publish(frank.FullName, frank);

			Console.WriteLine(frank.Certificate);
		}

		static void Main(string[] args)
		{
			Authorities();
			return;

			SimpleSerialNumber seq = new SimpleSerialNumber();
			X509CertificateAuthority ca = X509CertificateAuthority.SelfSigned(
				seq,
				new X509Name("CN=."),
				TimeSpan.FromDays(10)
			);

			Console.WriteLine(ca.Certificate);

			DSA dsa = new DSA(new DSAParameters(512));
			CryptoKey key = new CryptoKey(dsa);
			X509Request req = new X509Request(0, new X509Name("CN=com."), key);
			req.Sign(key, MessageDigest.DSS1);

			X509Certificate cert = ca.ProcessRequest(req, TimeSpan.FromDays(10));
			Console.WriteLine(cert);
			Console.WriteLine("CA Verified: " + cert.Verify(ca.Key));
			Console.WriteLine("Self Verified: " + cert.Verify(key));

			SimpleSerialNumber serial2 = new SimpleSerialNumber();
			X509CertificateAuthority caSelf = new X509CertificateAuthority(
				cert,
				key,
				serial2);

			X509Request req2 = cert.CreateRequest(key, MessageDigest.DSS1);
			X509Name subject = req2.Subject;
			Console.WriteLine("Request1: " + req);
			Console.WriteLine("Request2: " + req2);

			X509Certificate cert2 = caSelf.ProcessRequest(req2, TimeSpan.FromDays(10));
			Console.WriteLine("Cert2: " + cert2);

			DH dh = new DH(128, 5);

			MessageDigestContext mdc = new MessageDigestContext(MessageDigest.DSS1);
			byte[] msg = dh.PublicKey;
			byte[] sig = mdc.Sign(msg, key);

			Console.WriteLine(dh);
			Console.WriteLine("DH P         : " + BitConverter.ToString(dh.P));
			Console.WriteLine("DH G         : " + BitConverter.ToString(dh.G));
			Console.WriteLine("DH Secret Key: " + BitConverter.ToString(dh.PrivateKey));
			Console.WriteLine("DH Public Key: " + BitConverter.ToString(msg));
			Console.WriteLine("DH Signature : " + BitConverter.ToString(sig));

			Console.WriteLine(mdc.Verify(msg, sig, key));
		}
	}
}
