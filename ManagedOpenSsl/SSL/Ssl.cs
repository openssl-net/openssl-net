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
using System.Runtime.InteropServices;
using OpenSSL.Extensions;
using OpenSSL.Exceptions;
using System.Text;
using System.Collections.Generic;

namespace OpenSSL.SSL
{
	internal enum SslError
	{
		SSL_ERROR_NONE = 0,
		SSL_ERROR_SSL = 1,
		SSL_ERROR_WANT_READ = 2,
		SSL_ERROR_WANT_WRITE = 3,
		SSL_ERROR_WANT_X509_LOOKUP = 4,
		SSL_ERROR_SYSCALL = 5,
		SSL_ERROR_ZERO_RETURN = 6,
		SSL_ERROR_WANT_CONNECT = 7,
		SSL_ERROR_WANT_ACCEPT = 8
	}

	/// <summary>
	/// Ssl.
	/// </summary>
	public class Ssl : Base
	{
		internal const int SSL_ST_CONNECT = 0x1000;
		internal const int SSL_ST_ACCEPT = 0x2000;

		#region Initialization

		/// <summary>
		/// Calls SSL_new()
		/// </summary>
		/// <param name="ctx"></param>
		internal Ssl(SslContext ctx) :
			base(Native.ExpectNonNull(Native.SSL_new(ctx.Handle)), true)
		{
		}

		internal Ssl(IntPtr ptr, bool takeOwnership) : base(ptr, takeOwnership)
		{
		}

		#endregion

		#region Properties

		internal int State
		{
			get { return Native.SSL_state(Handle); }
			set { Native.SSL_set_state(Handle, value); }
		}

		/// <summary>
		/// Gets the current cipher.
		/// </summary>
		/// <value>The current cipher.</value>
		public SslCipher CurrentCipher
		{
			get { return new SslCipher(Native.SSL_get_current_cipher(Handle), false); }
		}

		internal Core.Stack<X509Name> CAList
		{
			get { return new Core.Stack<X509Name>(Native.SSL_get_client_CA_list(ptr), false); }
			set { Native.SSL_set_client_CA_list(ptr, value.Handle); }
		}

		internal X509Certificate LocalCertificate
		{
			get
			{
				var cert = Native.SSL_get_certificate(ptr);
				if (cert == IntPtr.Zero)
					return null;
				return new X509Certificate(cert, false);
			}
			set
			{
				Native.ExpectSuccess(Native.SSL_use_certificate(ptr, value.Handle));
			}
		}

		internal X509Certificate RemoteCertificate
		{
			get { return GetPeerCertificate(); }
		}

		internal Core.Stack<SslCipher> Ciphers
		{
			get { return new Core.Stack<SslCipher>(Native.SSL_get_ciphers(Handle), false); }
		}

		#endregion

		#region Methods

		internal int Accept()
		{
			return Native.SSL_accept(ptr);
		}

		internal int Connect()
		{
			return Native.SSL_connect(ptr);
		}

		internal SslError GetError(int ret_code)
		{
			return (SslError)Native.SSL_get_error(ptr, ret_code);
		}

		internal X509Certificate GetPeerCertificate()
		{
			var cert = Native.SSL_get_peer_certificate(ptr);
			if (cert == IntPtr.Zero)
				return null;
			return new X509Certificate(cert, true);
		}

		internal VerifyResult GetVerifyResult()
		{
			return (VerifyResult)Native.SSL_get_verify_result(ptr);
		}

		internal void SetVerifyResult(VerifyResult result)
		{
			Native.SSL_set_verify_result(ptr, (int)result);
		}

		internal int Shutdown()
		{
			return Native.SSL_shutdown(ptr);
		}

		internal int Write(byte[] buf, int len)
		{
			return Native.SSL_write(ptr, buf, len);
		}

		internal int Read(byte[] buf, int len)
		{
			return Native.SSL_read(ptr, buf, len);
		}

		internal int SetSessionIdContext(byte[] sid_ctx, uint sid_ctx_len)
		{
			return Native.ExpectSuccess(Native.SSL_set_session_id_context(ptr, sid_ctx, sid_ctx_len));
		}

		internal int Renegotiate()
		{
			return Native.ExpectSuccess(Native.SSL_renegotiate(ptr));
		}

		internal int DoHandshake()
		{
			return Native.SSL_do_handshake(ptr);
		}

		internal void SetAcceptState()
		{
			Native.SSL_set_accept_state(ptr);
		}

		internal void SetConnectState()
		{
			Native.SSL_set_connect_state(ptr);
		}

		internal void SetBIO(BIO read, BIO write)
		{
			Native.SSL_set_bio(ptr, read.Handle, write.Handle);
		}

		internal int UseCertificateFile(string filename, SslFileType type)
		{
			return Native.ExpectSuccess(Native.SSL_use_certificate_file(ptr, filename, (int)type));
		}

		internal int UsePrivateKeyFile(string filename, SslFileType type)
		{
			return Native.ExpectSuccess(Native.SSL_use_PrivateKey_file(ptr, filename, (int)type));
		}

		internal int Clear()
		{
			return Native.ExpectSuccess(Native.SSL_clear(ptr));
		}

		/// <summary>
		/// Gets the alpn selected protocol.
		/// </summary>
		/// <value>The alpn selected protocol.</value>
		public string AlpnSelectedProtocol
		{
			get
			{
				var ptr = new IntPtr();
				var len = 0;

				Native.SSL_get0_alpn_selected(Handle, out ptr, out len);

				if (ptr == IntPtr.Zero)
					throw new AlpnException("Cant get selected protocol. See if ALPN was included into client/server hello");

				var buf = new byte[len];
				Marshal.Copy(ptr, buf, 0, len);
				return Encoding.ASCII.GetString(buf, 0, len);
			}
		}

		#endregion

		#region Overrides

		/// <summary>
		/// Calls SSL_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.SSL_free(Handle);
		}

		#endregion

	}
}
