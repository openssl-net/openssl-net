using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	public class Asn1String : Base, IDisposable, IStackable, IComparable<Asn1String>
	{
		public Asn1String()
			: base(Native.ASN1_STRING_type_new(Native.V_ASN1_OCTET_STRING), true) {
		}

		public Asn1String(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership) {
		}

		public Asn1String(byte[] data)
			: this() {
			Native.ExpectSuccess(Native.ASN1_STRING_set(this.ptr, data, data.Length));
		}

		public int Length {
			get {
				return Native.ASN1_STRING_length(this.ptr);
			}
		}

		public byte[] Data {
			get {
				IntPtr ret = Native.ASN1_STRING_data(this.ptr);
				byte[] byteArray = new byte[Length];
				Marshal.Copy(ret, byteArray, 0, Length);
				return byteArray;
			}
		}

		public override void Addref() {
			// No reference counting on this object, so dup it
			IntPtr new_ptr = Native.ExpectNonNull(Native.ASN1_STRING_dup(this.ptr));
			this.ptr = new_ptr;
		}

		public override bool Equals(object obj) {
			Asn1String asn1 = obj as Asn1String;
			if (asn1 == null) {
				return false;
			}
			return (CompareTo(asn1) == 0);
		}

		protected override void OnDispose() {
			Native.ASN1_STRING_free(this.ptr);
		}

		#region IComparable<Asn1String> Members

		public int CompareTo(Asn1String other) {
			return Native.ASN1_STRING_cmp(this.ptr, other.Handle);
		}

		#endregion
	}
}
