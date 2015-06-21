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
using OpenSSL.X509;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using OpenSSL.Extensions;

namespace OpenSSL.SSL
{
	internal delegate int ClientCertCallbackHandler(
		Ssl ssl, 
		out X509Certificate cert, 
		out CryptoKey key
	);

	/// <summary>
	///     Wraps the SST_CTX structure and methods
	/// </summary>
	internal sealed class SslContext : Base
	{
		#region Members

		private AlpnExtension alpnExt;
		private ClientCertCallbackThunk _clientCertCallbackThunk;
		private VerifyCertCallbackThunk _verifyCertCallbackThunk;

		#endregion


		/// <summary>
		///     Calls SSL_CTX_new()
		/// </summary>
		/// <param name="sslMethod"></param>
		/// <param name="end"></param>
		/// <param name="protoList"></param>
		public SslContext(
			SslMethod sslMethod,
			ConnectionEnd end,
			IEnumerable<string> protoList = null) :
			base(Native.ExpectNonNull(Native.SSL_CTX_new(sslMethod.Handle)), true)
		{
			alpnExt = new AlpnExtension(Handle, protoList);
			if (end == ConnectionEnd.Server)
			{
				Native.SSL_CTX_set_alpn_select_cb(Handle, alpnExt.AlpnCb, IntPtr.Zero);
			}
		}

		#region Properties

		/// <summary>
		///     Calls SSL_CTX_set_options
		/// </summary>
		public SslOptions Options
		{
			set { Native.ExpectSuccess(Native.SSL_CTX_set_options(ptr, (int)value)); }
			get { return (SslOptions)Native.SSL_CTX_get_options(ptr); }
		}

		public SslMode Mode
		{
			set { Native.ExpectSuccess(Native.SSL_CTX_set_mode(ptr, (int)value)); }
			get { return (SslMode)Native.SSL_CTX_get_mode(ptr); }
		}

		#endregion

		internal class ClientCertCallbackThunk
		{
			private ClientCertCallbackHandler OnClientCertCallback;

			public ClientCertCallbackThunk(ClientCertCallbackHandler callback)
			{
				OnClientCertCallback = callback;
			}

			public Native.client_cert_cb Callback
			{
				get
				{
					if (OnClientCertCallback == null)
						return null;
					return OnClientCertThunk;
				}
			}

			internal int OnClientCertThunk(IntPtr ssl_ptr, out IntPtr cert_ptr, out IntPtr key_ptr)
			{
				X509Certificate cert = null;
				CryptoKey key = null;
				var ssl = new Ssl(ssl_ptr, false);
				cert_ptr = IntPtr.Zero;
				key_ptr = IntPtr.Zero;

				var nRet = OnClientCertCallback(ssl, out cert, out key);
				if (nRet != 0)
				{
					if (cert != null)
					{
						cert_ptr = cert.Handle;
					}

					if (key != null)
					{
						key_ptr = key.Handle;
					}
				}
				return nRet;
			}
		}

		internal class VerifyCertCallbackThunk
		{
			private RemoteCertificateValidationHandler OnVerifyCert;

			public VerifyCertCallbackThunk(RemoteCertificateValidationHandler callback)
			{
				OnVerifyCert = callback;
			}

			public Native.VerifyCertCallback Callback
			{
				get
				{
					if (OnVerifyCert == null)
						return null;
					return OnVerifyCertThunk;
				}
			}

			internal int OnVerifyCertThunk(int ok, IntPtr store_ctx)
			{
				var ctx = new X509StoreContext(store_ctx, false);

				// build the X509Chain from the store
				using (var chain = new X509Chain())
				{
					foreach (var obj in ctx.Store.Objects)
					{
						var cert = obj.Certificate;
						if (cert != null)
						{
							chain.Add(cert);
						}
					}

					// Call the managed delegate
					return OnVerifyCert(
						this, 
						ctx.CurrentCert, 
						chain, 
						ctx.ErrorDepth, 
						(VerifyResult)ctx.Error
					) ? 1 : 0;
				}
			}
		}

		#region Methods

		/// <summary>
		///     Sets the certificate store for the context - calls SSL_CTX_set_cert_store
		///     The X509Store object and contents will be freed when the context is disposed.
		///     Ensure that the store object and it's contents have IsOwner set to false
		///     before assigning them into the context.
		/// </summary>
		/// <param name="store"></param>
		public void SetCertificateStore(X509Store store)
		{
			// Remove the native pointer ownership from the object
			// Reference counts don't work for the X509_STORE, so
			// we just remove ownership from the X509Store object
			store.IsOwner = false;
			Native.SSL_CTX_set_cert_store(ptr, store.Handle);
		}

		/// <summary>
		///     Sets the certificate verification mode and callback - calls SSL_CTX_set_verify
		/// </summary>
		/// <param name="mode"></param>
		/// <param name="callback"></param>
		public void SetVerify(VerifyMode mode, RemoteCertificateValidationHandler callback)
		{
			_verifyCertCallbackThunk = new VerifyCertCallbackThunk(callback);
			Native.SSL_CTX_set_verify(ptr, (int)mode, _verifyCertCallbackThunk.Callback);
		}

		/// <summary>
		///     Sets the certificate verification depth - calls SSL_CTX_set_verify_depth
		/// </summary>
		/// <param name="depth"></param>
		public void SetVerifyDepth(int depth)
		{
			Native.SSL_CTX_set_verify_depth(ptr, depth);
		}

		public Core.Stack<X509Name> LoadClientCAFile(string filename)
		{
			var stack = Native.SSL_load_client_CA_file(filename);
			return new Core.Stack<X509Name>(stack, true);
		}

		/// <summary>
		///     Calls SSL_CTX_set_client_CA_list/SSL_CTX_get_client_CA_list
		///     The Stack and the X509Name objects contined within them
		///     are freed when the context is disposed.  Make sure that
		///     the Stack and X509Name objects have set IsOwner to false
		///     before assigning them to the context.
		/// </summary>
		public Core.Stack<X509Name> CAList
		{
			get
			{
				var ptr = Native.SSL_CTX_get_client_CA_list(this.ptr);
				return new Core.Stack<X509Name>(ptr, false);
			}
			set
			{
				// Remove the native pointer ownership from the Stack object
				value.IsOwner = false;
				Native.SSL_CTX_set_client_CA_list(ptr, value.Handle);
			}
		}

		public int LoadVerifyLocations(string caFile, string caPath)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_load_verify_locations(ptr, caFile, caPath));
		}

		public int SetDefaultVerifyPaths()
		{
			return Native.ExpectSuccess(Native.SSL_CTX_set_default_verify_paths(ptr));
		}

		public int SetCipherList(string cipherList)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_set_cipher_list(ptr, cipherList));
		}

		public int UseCertificate(X509Certificate cert)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_use_certificate(ptr, cert.Handle));
		}

		public int UseCertificateChainFile(string filename)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_use_certificate_chain_file(ptr, filename));
		}

		public int UsePrivateKey(CryptoKey key)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_use_PrivateKey(ptr, key.Handle));
		}

		public int UsePrivateKeyFile(string filename, SslFileType type)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_use_PrivateKey_file(ptr, filename, (int)type));
		}

		public int CheckPrivateKey()
		{
			return Native.ExpectSuccess(Native.SSL_CTX_check_private_key(ptr));
		}

		public int SetSessionIdContext(byte[] sid_ctx)
		{
			return Native.ExpectSuccess(Native.SSL_CTX_set_session_id_context(ptr, sid_ctx, (uint)sid_ctx.Length));
		}

		public void SetClientCertCallback(ClientCertCallbackHandler callback)
		{
			_clientCertCallbackThunk = new ClientCertCallbackThunk(callback);
			Native.SSL_CTX_set_client_cert_cb(ptr, _clientCertCallbackThunk.Callback);
		}

		#endregion

		#region IDisposable Members

		/// <summary>
		///     base override - calls SSL_CTX_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.SSL_CTX_free(ptr);
		}

		#endregion
	}
}