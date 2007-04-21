using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class X509Store : Base, IDisposable
	{
		#region X509_STORE_CONTEXT
		[StructLayout(LayoutKind.Sequential)]
		private struct X509_STORE_CONTEXT
		{
			public IntPtr ctx;
			public int current_method;
			public IntPtr cert;
			public IntPtr untrusted;
			public int purpose;
			public int trust;
#if PocketPC
            public uint check_time;
#else
			public long check_time;
#endif
			public uint flags;
			public IntPtr other_ctx;
			public IntPtr verify;
			public IntPtr verify_cb;
			public IntPtr get_issuer;
			public IntPtr check_issued;
			public IntPtr check_revocation;
			public IntPtr get_crl;
			public IntPtr check_crl;
			public IntPtr cert_crl;
			public IntPtr cleanup;
			public int depth;
			public int valid;
			public int last_untrusted;
			public IntPtr chain;
			public int error_depth;
			public int error;
			public IntPtr current_cert;
			public IntPtr current_issuer;
			public IntPtr current_crl;
			#region CRYPTO_EX_DATA ex_data;
			public IntPtr ex_data_sk;
			public int ex_data_dummy;
			#endregion
		}
		#endregion

		#region Context
		public class Context : IDisposable
		{
			private IntPtr ptr;

			public Context()
			{
				this.ptr = Native.ExpectNonNull(Native.X509_STORE_CTX_new());
			}

			public void init(X509Store store, X509Certificate cert, X509Chain uchain)
			{
				Native.ExpectSuccess(Native.X509_STORE_CTX_init(
					this.ptr,
					store.Handle,
					cert != null ? cert.Handle : IntPtr.Zero,
					uchain.Handle));
			}

			public bool verify()
			{
				int ret = Native.X509_verify_cert(this.ptr);
				if (ret < 0)
					throw new OpenSslException();
				return ret == 1;
			}

			private X509_STORE_CONTEXT Raw
			{
				get
				{
					return (X509_STORE_CONTEXT)Marshal.PtrToStructure(this.ptr, typeof(X509_STORE_CONTEXT));
				}
			}

			public string ErrorString
			{
				get
				{
					return Native.PtrToStringAnsi(Native.X509_verify_cert_error_string(this.Raw.error), false);
				}
			}

			#region IDisposable Members
			public void Dispose()
			{
				Native.X509_STORE_CTX_free(this.ptr);
			}
			#endregion
		}
		#endregion

		private X509Chain untrusted = new X509Chain();
		//private X509Chain trusted = new X509Chain();

		public X509Store() : base(Native.ExpectNonNull(Native.X509_STORE_new()), true) {}
		public X509Store(X509Chain chain)
			: base(Native.ExpectNonNull(Native.X509_STORE_new()), true)
		{
			foreach (X509Certificate cert in chain)
			{
				this.AddTrusted(cert);
			}
		}

		public bool Verify(X509Certificate cert, out string error)
		{
			Context ctx = new Context();
			ctx.init(this, cert, this.untrusted);
			if (ctx.verify())
			{
				error = "";
				return true;
			}
			error = ctx.ErrorString;
			return false;
		}

		public void AddTrusted(X509Chain chain)
		{
			foreach (X509Certificate cert in chain)
				AddTrusted(cert);
		}

		public void AddTrusted(X509Certificate cert)
		{
			Native.ExpectSuccess(Native.X509_STORE_add_cert(this.ptr, cert.Handle));
		}

		public void AddUntrusted(X509Certificate cert)
		{
			this.untrusted.Add(cert);
		}

		//public X509Chain Trusted
		//{
		//    get { return this.trusted; }
		//    set { this.trusted = value; }
		//}

		public X509Chain Untrusted
		{
			get { return this.untrusted; }
			set { this.untrusted = value; }
		}

		#region IDisposable Members
		public override void OnDispose()
		{
			Native.X509_STORE_free(this.ptr);
		}
		#endregion
	}
}
