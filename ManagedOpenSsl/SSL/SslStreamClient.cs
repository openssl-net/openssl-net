// Copyright (c) 2009 Ben Henderson
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

using OpenSSL.Core;
using OpenSSL.Crypto;
using OpenSSL.Extensions;
using OpenSSL.X509;
using System.IO;
using OpenSSL;
using System;

namespace OpenSSL.SSL
{
	internal class SslStreamClient : SslStreamBase
	{
		string targetHost;
		X509List clientCertificates;
		X509Chain caCertificates;

		public SslStreamClient(
			Stream stream,
			string targetHost,
			X509List clientCertificates,
			X509Chain caCertificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocationStatus,
			RemoteCertificateValidationHandler remoteCallback,
			LocalCertificateSelectionHandler localCallback) : base(stream)
		{
			this.targetHost = targetHost;
			this.clientCertificates = clientCertificates;
			this.caCertificates = caCertificates;
			this.checkCertificateRevocationStatus = checkCertificateRevocationStatus;
			OnRemoteCertificate = remoteCallback;
			OnLocalCertificate = localCallback;
			InitializeClientContext(
				clientCertificates, 
				enabledSslProtocols, 
				sslStrength, 
				checkCertificateRevocationStatus
			);
		}

		protected void InitializeClientContext(
			X509List certificates,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation)
		{
			// Initialize the context with specified TLS version
			sslContext = new SslContext(SslMethod.TLSv12_client_method, ConnectionEnd.Client, new[] {
				Protocols.Http2,
				Protocols.Http1
			});
            
			var options = sslContext.Options;

			// Remove support for protocols not specified in the enabledSslProtocols
			if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Ssl2))
			{
				options |= SslOptions.SSL_OP_NO_SSLv2;
			}

			if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Ssl3))
			{
				options |= SslOptions.SSL_OP_NO_SSLv3;
			}

			if (!EnumExtensions.HasFlag(enabledSslProtocols, SslProtocols.Tls))
			{
				options |= SslOptions.SSL_OP_NO_TLSv1;
			}

			sslContext.Options = options;

			// Set the Local certificate selection callback
			sslContext.SetClientCertCallback(OnClientCertificate);
			// Set the enabled cipher list
			sslContext.SetCipherList(SslCipher.MakeString(enabledSslProtocols, sslStrength));
			// Set the callbacks for remote cert verification and local cert selection
			if (OnRemoteCertificate != null)
			{
				sslContext.SetVerify(
					VerifyMode.SSL_VERIFY_PEER |
					VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
					OnRemoteCertificate);
			}
			// Set the CA list into the store
			if (caCertificates != null)
			{
				var store = new X509Store(caCertificates);
				sslContext.SetCertificateStore(store);
			}
			// Set up the read/write bio's
			read_bio = BIO.MemoryBuffer(false);
			write_bio = BIO.MemoryBuffer(false);
			ssl = new Ssl(sslContext);

			sniCb = sniExt.ClientSniCb;
			sniExt.AttachSniExtensionClient(ssl.Handle, sslContext.Handle, sniCb);

			ssl.SetBIO(read_bio, write_bio);
			read_bio.SetClose(BIO.CloseOption.Close);
			write_bio.SetClose(BIO.CloseOption.Close);
			// Set the Ssl object into Client mode
			ssl.SetConnectState();
		}

		internal protected override bool ProcessHandshake()
		{
			var ret = false;
			var nRet = 0;

			if (handShakeState == HandshakeState.InProcess)
			{
				nRet = ssl.Connect();
			}
			else if (handShakeState == HandshakeState.RenegotiateInProcess ||
			         handShakeState == HandshakeState.Renegotiate)
			{
				handShakeState = HandshakeState.RenegotiateInProcess;
				nRet = ssl.DoHandshake();
			}

			if (nRet <= 0)
			{
				var lastError = ssl.GetError(nRet);
				if (lastError == SslError.SSL_ERROR_WANT_READ)
				{
					// Do nothing -- the base stream will write the data from the bio
					// when this call returns
				}
				else if (lastError == SslError.SSL_ERROR_WANT_WRITE)
				{
					// unexpected error
					//!!TODO - debug log
				}
				else
				{
					// We should have alert data in the bio that needs to be written
					// We'll save the exception, allow the write to start, and then throw the exception
					// when we come back into the AsyncHandshakeCall
					if (write_bio.BytesPending > 0)
					{
						handshakeException = new OpenSslException();
					}
					else
					{
						throw new OpenSslException();
					}
				}
			}
			else
			{
				// Successful handshake
				ret = true;
			}

			return ret;
		}

		private int OnClientCertificate(Ssl ssl, out X509Certificate x509_cert, out CryptoKey key)
		{
			x509_cert = null;
			key = null;

			var name_stack = ssl.CAList;
			var strIssuers = new string[name_stack.Count];
			var count = 0;

			foreach (var name in name_stack)
			{
				strIssuers[count++] = name.OneLine;
			}

			if (OnLocalCertificate != null)
			{
				var cert = OnLocalCertificate(
					           this, 
					           targetHost, 
					           clientCertificates, 
					           ssl.GetPeerCertificate(), 
					           strIssuers
				           );
				if (cert != null && cert.HasPrivateKey)
				{
					x509_cert = cert;
					key = cert.PrivateKey;
					// Addref the cert and private key
					x509_cert.AddRef();
					key.AddRef();
					// return success
					return 1;
				}
			}

			return 0;
		}
	}
}
