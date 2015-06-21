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
using OpenSSL.X509;
using System;
using System.IO;
using System.Text;
using OpenSSL;

namespace OpenSSL.SSL
{
	internal class SslStreamServer : SslStreamBase
	{
		public SslStreamServer(
			Stream stream, 
			X509Certificate serverCertificate,
			bool clientCertificateRequired,
			X509Chain caCerts,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation,
			RemoteCertificateValidationHandler remote_callback) : base(stream)
		{
			checkCertificateRevocationStatus = checkCertificateRevocation;
			OnRemoteCertificate = remote_callback;

			// Initialize the SslContext object
			InitializeServerContext(
				serverCertificate, 
				clientCertificateRequired, 
				caCerts, 
				enabledSslProtocols, 
				sslStrength, 
				checkCertificateRevocation);
            
			// Initalize the Ssl object
			ssl = new Ssl(sslContext);

			sniCb = sniExt.ServerSniCb;
			sniExt.AttachSniExtensionServer(ssl.Handle, sslContext.Handle, sniCb);

			// Initialze the read/write bio
			read_bio = BIO.MemoryBuffer(false);
			write_bio = BIO.MemoryBuffer(false);
			// Set the read/write bio's into the the Ssl object
			ssl.SetBIO(read_bio, write_bio);
			read_bio.SetClose(BIO.CloseOption.Close);
			write_bio.SetClose(BIO.CloseOption.Close);
			// Set the Ssl object into server mode
			ssl.SetAcceptState();
		}

		internal protected override bool ProcessHandshake()
		{
			var nRet = 0;
            
			if (handShakeState == HandshakeState.InProcess)
			{
				nRet = ssl.Accept();
			}
			else if (handShakeState == HandshakeState.RenegotiateInProcess)
			{
				nRet = ssl.DoHandshake();
			}
			else if (handShakeState == HandshakeState.Renegotiate)
			{
				nRet = ssl.DoHandshake();
				ssl.State = Ssl.SSL_ST_ACCEPT;
				handShakeState = HandshakeState.RenegotiateInProcess;
			}

			var lastError = ssl.GetError(nRet);
			if (lastError == SslError.SSL_ERROR_WANT_READ || 
				lastError == SslError.SSL_ERROR_WANT_WRITE || 
				lastError == SslError.SSL_ERROR_NONE)
			{
				return nRet == 1;
			}

			// Check to see if we have alert data in the write_bio that needs to be sent
			if (write_bio.BytesPending > 0)
			{
				// We encountered an error, but need to send the alert
				// set the handshakeException so that it will be processed
				// and thrown after the alert is sent
				handshakeException = new OpenSslException();
				return false;
			}

			// No alert to send, throw the exception
			throw new OpenSslException();
		}

		private void InitializeServerContext(
			X509Certificate serverCertificate,
			bool clientCertificateRequired,
			X509Chain caCerts,
			SslProtocols enabledSslProtocols,
			SslStrength sslStrength,
			bool checkCertificateRevocation)
		{
			if (serverCertificate == null)
			{
				throw new ArgumentNullException("serverCertificate", "Server certificate cannot be null");
			}
			if (!serverCertificate.HasPrivateKey)
			{
				throw new ArgumentException("Server certificate must have a private key", "serverCertificate");
			}

			// Initialize the context with specified TLS version
			sslContext = new SslContext(SslMethod.TLSv12_server_method, ConnectionEnd.Server, new[] {
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

			// Set the workaround options
			sslContext.Options = options | SslOptions.SSL_OP_ALL;

			// Set the context mode
			sslContext.Mode = SslMode.SSL_MODE_AUTO_RETRY;

			// Set the client certificate verification callback if we are requiring client certs
			if (clientCertificateRequired)
			{
				sslContext.SetVerify(VerifyMode.SSL_VERIFY_PEER | VerifyMode.SSL_VERIFY_FAIL_IF_NO_PEER_CERT, OnRemoteCertificate);
			}
			else
			{
				sslContext.SetVerify(VerifyMode.SSL_VERIFY_NONE, null);
			}

			// Set the client certificate max verification depth
			sslContext.SetVerifyDepth(10);
			// Set the certificate store and ca list
			if (caCerts != null)
			{
				// Don't take ownership of the X509Store IntPtr.  When we
				// SetCertificateStore, the context takes ownership of the store pointer.
				sslContext.SetCertificateStore(new X509Store(caCerts, false));
				var name_stack = new Core.Stack<X509Name>();
				foreach (var cert in caCerts)
				{
					var subject = cert.Subject;
					name_stack.Add(subject);
				}
				// Assign the stack to the context
				sslContext.CAList = name_stack;
			}
			// Set the cipher string
			sslContext.SetCipherList(SslCipher.MakeString(enabledSslProtocols, sslStrength));
			// Set the certificate
			sslContext.UseCertificate(serverCertificate);
			// Set the private key
			sslContext.UsePrivateKey(serverCertificate.PrivateKey);
			// Set the session id context
			sslContext.SetSessionIdContext(Encoding.ASCII.GetBytes(AppDomain.CurrentDomain.FriendlyName));
		}
	}
}
