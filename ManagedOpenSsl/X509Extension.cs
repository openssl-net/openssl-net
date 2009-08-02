using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	/// <summary>
	/// Wraps the X509_EXTENSION object
	/// </summary>
	public class X509Extension : BaseValueType, IStackable
	{
		/// <summary>
		/// Calls X509_EXTENSION_new()
		/// </summary>
		public X509Extension()
			: base(Native.ExpectNonNull(Native.X509_EXTENSION_new()), true) 
		{ }

		internal X509Extension(IStack stack, IntPtr ptr)
			: base(ptr, true)
		{ }

		public X509Extension(X509Certificate issuer, X509Certificate subject, string name, bool critical, string value)
			: base(IntPtr.Zero, false) {
			X509v3Context ctx = new X509v3Context();
			Native.X509V3_set_ctx(ctx.Handle, issuer.Handle, subject.Handle, IntPtr.Zero, IntPtr.Zero, 0);
			this.ptr = Native.ExpectNonNull(Native.X509V3_EXT_conf_nid(IntPtr.Zero, ctx.Handle, Native.TextToNID(name), value));
			this.owner = true;
			ctx.Dispose();
		}

		public string Name {
			get {
				string ret = "";

				// Don't free the obj_ptr
				IntPtr obj_ptr = Native.X509_EXTENSION_get_object(this.ptr);
				if (obj_ptr != IntPtr.Zero) {
					int nid = Native.OBJ_obj2nid(obj_ptr);
					ret = Marshal.PtrToStringAnsi(Native.OBJ_nid2ln(nid));
				}
				return ret;
			}
		}

		public int NID {
			get {
				int ret = 0;

				// Don't free the obj_ptr
				IntPtr obj_ptr = Native.X509_EXTENSION_get_object(this.ptr);
				if (obj_ptr != IntPtr.Zero) {
					ret = Native.OBJ_obj2nid(obj_ptr);
				}
				return ret;
			}
		}

		public bool IsCritical {
			get {
				int nCritical = Native.X509_EXTENSION_get_critical(this.ptr);
				return (nCritical == 1);
			}
		}

		public byte[] Data {
			get {
				Asn1String str_data = new Asn1String(Native.X509_EXTENSION_get_data(this.ptr), false);
				return str_data.Data;
			}
		}

		#region IDisposable Members

		/// <summary>
		/// Calls X509_EXTENSION_free()
		/// </summary>
		protected override void OnDispose() {
			Native.X509_EXTENSION_free(this.ptr);
		}

		#endregion

		public override void Print(BIO bio) {
			Native.X509V3_EXT_print(bio.Handle, this.ptr, 0, 0);
		}

		protected override IntPtr DuplicateHandle()
		{
			return Native.X509_EXTENSION_dup(this.ptr);
		}
	}

}
