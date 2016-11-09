// Copyright (c) 2009 Ben Henderson
// Copyright (c) 2012 Frank Laub
// All rights reserved.
//
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
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using System.Linq;
using NUnit.Framework;
using OpenSSL;
using OpenSSL.Core;
using OpenSSL.X509;
using OpenSSL.SSL;
using OpenSSL.Crypto;

namespace UnitTests
{
	public class SslTestContext : IDisposable
	{
		public SslTestContext(string configPath = "openssl.cnf")
		{
			using (var cfg = new Configuration(configPath))
			using (var ca = X509CertificateAuthority.SelfSigned(
								cfg,
								new SimpleSerialNumber(),
								"Root",
								DateTime.Now,
								TimeSpan.FromDays(365)))
			{
				CAChain.Add(ca.Certificate);

				ServerCertificate = CreateCertificate(ca, "server", cfg, "tls_server");
				ClientCertificate = CreateCertificate(ca, "client", cfg, "tls_client");
			}

			ClientCertificateList.Add(ClientCertificate);
		}

		X509Certificate CreateCertificate(X509CertificateAuthority ca, string name, Configuration cfg, string section)
		{
			var now = DateTime.Now;
			var future = now + TimeSpan.FromDays(365);

			using (var subject = new X509Name(name))
			using (var rsa = new RSA())
			{
				rsa.GenerateKeys(1024, BigNumber.One, null, null);
				using (var key = new CryptoKey(rsa))
				{
					var request = new X509Request(1, subject, key);
					var cert = ca.ProcessRequest(request, now, future, cfg, section);
					cert.PrivateKey = key;
					return cert;
				}
			}
		}

		public X509Chain CAChain = new X509Chain();
		public X509List ClientCertificateList = new X509List();
		public X509Certificate ServerCertificate;
		public X509Certificate ClientCertificate;

		#region IDisposable implementation

		public void Dispose()
		{
			ClientCertificateList.Clear();
			CAChain.Dispose();
			ServerCertificate.Dispose();
			ClientCertificate.Dispose();
		}

		#endregion
	}

	[TestFixture]
	public class TestSSL : TestBase
	{
		SslTestContext _ctx;
		static byte[] clientMessage = Encoding.ASCII.GetBytes("This is a message from the client");
		static byte[] serverMessage = Encoding.ASCII.GetBytes("This is a message from the server");

		public override void Setup()
		{
			base.Setup();
			Threading.Initialize();
			_ctx = new SslTestContext();
		}

		public override void Teardown()
		{
			_ctx.Dispose();
			Threading.Cleanup();
			base.Teardown();
		}

		[Test]
		public void TestSslCipherList()
		{
			Assert.AreEqual("LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.Low)
			);

			Assert.AreEqual("MEDIUM:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.Medium)
			);

			Assert.AreEqual("HIGH:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.High)
			);

			Assert.AreEqual("HIGH:MEDIUM:LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.None, SslStrength.All)
			);

			Assert.AreEqual("HIGH:MEDIUM:LOW:!SSLv2:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.Default, SslStrength.All)
			);

			Assert.AreEqual("HIGH:MEDIUM:LOW:!ADH:!aNULL:!eNULL:@STRENGTH", 
				SslCipher.MakeString(SslProtocols.Ssl2, SslStrength.All)
			);
		}

		[Test]
		public void TestSyncBasic()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClient())
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Server> authenticate");
					sslStream.AuthenticateAsServer(_ctx.ServerCertificate);

					Console.WriteLine("Server> ALPN: {0}", sslStream.Ssl.AlpnSelectedProtocol);
					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

				using (var tcp = new TcpClient(ep.Address.ToString(), ep.Port))
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Client> authenticate");
					sslStream.AuthenticateAsClient("localhost");

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}
			});

			serverTask.Wait();
			clientTask.Wait();
		}

		[Test]
		public void TestSyncIntermediate()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClient())
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Server> authenticate");
					sslStream.AuthenticateAsServer(
						_ctx.ServerCertificate,
						false,
						null,
						SslProtocols.Default,
						SslStrength.Low,
						false
					);

					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

				using (var tcp = new TcpClient(ep.Address.ToString(), ep.Port))
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Client> authenticate");
					sslStream.AuthenticateAsClient(
						"localhost",
						null,
						null,
						SslProtocols.Default,
						SslStrength.Low,
						false
					);

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("DES-CBC-SHA", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}
			});

			serverTask.Wait();
			clientTask.Wait();
		}

		[Test]
		[Ignore("Frequent crashes")]
		public void TestSyncAdvanced()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClient())
				using (var sslStream = new SslStream(tcp.GetStream(), false, ValidateRemoteCert))
				{
					Console.WriteLine("Server> authenticate");
					sslStream.AuthenticateAsServer(
						_ctx.ServerCertificate,
						true,
						_ctx.CAChain,
						SslProtocols.Tls,
						SslStrength.All,
						true
					);

					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);
					Assert.IsTrue(sslStream.IsMutuallyAuthenticated);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

				using (var tcp = new TcpClient(ep.Address.ToString(), ep.Port))
				using (var sslStream = new SslStream(
										   tcp.GetStream(),
										   false,
										   ValidateRemoteCert,
										   SelectClientCertificate))
				{
					Console.WriteLine("Client> authenticate");
					sslStream.AuthenticateAsClient(
						"localhost",
						_ctx.ClientCertificateList,
						_ctx.CAChain,
						SslProtocols.Tls,
						SslStrength.All,
						true
					);

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);
					Assert.IsTrue(sslStream.IsMutuallyAuthenticated);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}
			});

			Task.WaitAll(clientTask, serverTask);
		}

		[Test]
		public void TestAsyncBasic()
		{
			var listener = new TcpListener(IPAddress.Loopback, 0);
			listener.Start(5);
			var ep = (IPEndPoint)listener.LocalEndpoint;

			Console.WriteLine("Server> waiting for accept");

			listener.BeginAcceptTcpClient((IAsyncResult ar) =>
			{
				var client = listener.EndAcceptTcpClient(ar);

				var sslStream = new SslStream(client.GetStream(), false);
				Console.WriteLine("Server> authenticate");

				sslStream.BeginAuthenticateAsServer(_ctx.ServerCertificate, async (ar2) =>
				{
					sslStream.EndAuthenticateAsServer(ar2);

					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					var buf = new byte[256];
					await sslStream.ReadAsync(buf, 0, buf.Length);
					Assert.AreEqual(clientMessage.ToString(), buf.ToString());

					await sslStream.WriteAsync(serverMessage, 0, serverMessage.Length);

					sslStream.Close();
					client.Close();

					Console.WriteLine("Server> done");
				}, null);
			}, null);

			var evtDone = new AutoResetEvent(false);

			var tcp = new TcpClient(AddressFamily.InterNetwork);
			tcp.BeginConnect(ep.Address.ToString(), ep.Port, (IAsyncResult ar) =>
			{
				tcp.EndConnect(ar);

				var sslStream = new SslStream(tcp.GetStream());
				Console.WriteLine("Client> authenticate");

				sslStream.BeginAuthenticateAsClient("localhost", async (ar2) =>
				{
					sslStream.EndAuthenticateAsClient(ar2);

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					await sslStream.WriteAsync(clientMessage, 0, clientMessage.Length);

					var buf = new byte[256];
					await sslStream.ReadAsync(buf, 0, buf.Length);
					Assert.AreEqual(serverMessage.ToString(), buf.ToString());

					sslStream.Close();
					tcp.Close();

					Console.WriteLine("Client> done");

					evtDone.Set();
				}, null);
			}, null);

			evtDone.WaitOne();
		}

		[Test]
		public void TestSyncLargeCertificate()
		{
			IPEndPoint ep = null;
			var evtReady = new AutoResetEvent(false);
			var largeCtx = new SslTestContext("openssl_largecert.cnf");
			var timeout = TimeSpan.FromMilliseconds(3000);

			var serverTask = Task.Factory.StartNew(() =>
			{
				var listener = new TcpListener(IPAddress.Loopback, 0);
				listener.Start(5);
				ep = (IPEndPoint)listener.LocalEndpoint;

				evtReady.Set();

				Console.WriteLine("Server> waiting for accept");

				using (var tcp = listener.AcceptTcpClient())
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Server> authenticate");
					sslStream.AuthenticateAsServer(largeCtx.ServerCertificate);

					Console.WriteLine("Server> ALPN: {0}", sslStream.Ssl.AlpnSelectedProtocol);
					Console.WriteLine("Server> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Server> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(clientMessage.ToString(), buf.ToString());

					Console.WriteLine("Server> tx msg");
					sslStream.Write(serverMessage, 0, serverMessage.Length);

					Console.WriteLine("Server> done");
				}

				listener.Stop();
			});

			var clientTask = Task.Factory.StartNew(() =>
			{
				evtReady.WaitOne();

				Console.WriteLine("Client> Connecting to: {0}:{1}", ep.Address, ep.Port);

				using (var tcp = new TcpClient(ep.Address.ToString(), ep.Port))
				using (var sslStream = new SslStream(tcp.GetStream()))
				{
					Console.WriteLine("Client> authenticate");
					sslStream.AuthenticateAsClient("localhost");

					Console.WriteLine("Client> CurrentCipher: {0}", sslStream.Ssl.CurrentCipher.Name);
					Assert.AreEqual("AES256-GCM-SHA384", sslStream.Ssl.CurrentCipher.Name);

					Console.WriteLine("Client> tx msg");
					sslStream.Write(clientMessage, 0, clientMessage.Length);

					Console.WriteLine("Client> rx msg");
					var buf = new byte[256];
					sslStream.Read(buf, 0, buf.Length);
					Assert.AreEqual(serverMessage.ToString(), buf.ToString());

					Console.WriteLine("Client> done");
				}
			});

			Assert.IsTrue(Task.WaitAll(new Task[] { serverTask, clientTask }, timeout));
		}

		bool ValidateRemoteCert(
			object obj,
			X509Certificate cert,
			X509Chain chain,
			int depth,
			VerifyResult result)
		{
			Console.WriteLine("Validate> {0} depth: {1}, result: {2}", cert.Subject, depth, result);
			switch (result)
			{
				case VerifyResult.X509_V_ERR_CERT_UNTRUSTED:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
				case VerifyResult.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
				case VerifyResult.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
				case VerifyResult.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
					// Check the chain to see if there is a match for the cert
					var ret = CheckCert(cert, chain);
					if (!ret && depth != 0)
					{
						return true;
					}
					return ret;
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
				case VerifyResult.X509_V_ERR_CERT_NOT_YET_VALID:
					Console.WriteLine("Certificate is not valid yet");
					return false;
				case VerifyResult.X509_V_ERR_CERT_HAS_EXPIRED:
				case VerifyResult.X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
					Console.WriteLine("Certificate is expired");
					return false;
				case VerifyResult.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
					// we received a self signed cert - check to see if it's in our store
					return CheckCert(cert, chain);
				case VerifyResult.X509_V_OK:
					return true;
				default:
					return false;
			}
		}

		bool CheckCert(X509Certificate cert, X509Chain chain)
		{
			if (cert == null || chain == null)
				return false;

			foreach (var certificate in chain)
			{
				if (cert == certificate)
					return true;
			}

			return false;
		}

		X509Certificate SelectClientCertificate(
			object sender,
			string targetHost,
			X509List localCerts,
			X509Certificate remoteCert,
			string[] acceptableIssuers)
		{
			Console.WriteLine("SelectClientCertificate> {0}", targetHost);

			foreach (var issuer in acceptableIssuers)
			{
				Console.WriteLine("SelectClientCertificate> issuer: {0}", issuer);

				using (var name = new X509Name(issuer))
				{
					foreach (var cert in localCerts)
					{
						Console.WriteLine("SelectClientCertificate> local: {0}", cert.Subject);
						if (cert.Issuer.CompareTo(name) == 0)
						{
							return cert;
						}
						cert.Dispose();
					}
				}
			}
			return null;
		}
	}
}
