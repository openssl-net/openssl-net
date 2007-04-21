using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class Configuration : Base, IDisposable
	{
		private Configuration()
			: base(Native.NCONF_new(IntPtr.Zero), true)
		{ }

		public Configuration(string filename)
			: this()
		{
			this.Load(filename);
		}

		public void Load(string filename)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(filename);
			int eline = 0;
			Native.ExpectSuccess(Native.NCONF_load(this.ptr, bytes, ref eline));
		}

		#region X509v3Context
		#region X509V3_CTX
		[StructLayout(LayoutKind.Sequential)]
		public struct X509V3_CTX
		{
			public int flags;
			public IntPtr issuer_cert;
			public IntPtr subject_cert;
			public IntPtr subject_req;
			public IntPtr crl;
			public IntPtr db_meth;
			public IntPtr db;
		}
		#endregion

		class X509v3Context : Base, IDisposable
		{
			public X509v3Context()
				: base(Native.OPENSSL_malloc(Marshal.SizeOf(typeof(X509V3_CTX))), true)
			{ }

			#region IDisposable Members

			public override void OnDispose()
			{
				Native.OPENSSL_free(this.ptr);
			}

			#endregion
		}
		#endregion

		public void ApplyExtensions(
			string section,
			X509Certificate issuer,
			X509Certificate subject,
			X509Request request)
		{
			X509v3Context ctx = new X509v3Context();
			Native.X509V3_set_ctx(
				ctx.Handle,
				issuer != null ? issuer.Handle : IntPtr.Zero,
				subject.Handle,
				request != null ? request.Handle : IntPtr.Zero,
				IntPtr.Zero,
				0);
			Native.X509V3_set_nconf(ctx.Handle, this.ptr);
			Native.ExpectSuccess(Native.X509V3_EXT_add_nconf(
				this.ptr,
				ctx.Handle,
				Encoding.ASCII.GetBytes(section),
				subject.Handle));
		}

		#region IDisposable Members

		public override void OnDispose()
		{
			Native.NCONF_free(this.ptr);
		}

		#endregion
	}
}