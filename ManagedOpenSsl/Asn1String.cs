using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	/// <summary>
	/// Wraps ASN1_STRING_*
	/// </summary>
	public class Asn1String : BaseValueType, IComparable<Asn1String>
	{
		/// <summary>
		/// Calls ASN1_STRING_type_new()
		/// </summary>
		public Asn1String()
			: base(Native.ASN1_STRING_type_new(Native.V_ASN1_OCTET_STRING), true)
		{
		}

		/// <summary>
		/// Wrap existing native pointer
		/// </summary>
		/// <param name="ptr"></param>
		/// <param name="takeOwnership"></param>
		public Asn1String(IntPtr ptr, bool takeOwnership)
			: base(ptr, takeOwnership)
		{
		}

		/// <summary>
		/// Calls ASN1_STRING_set()
		/// </summary>
		/// <param name="data"></param>
		public Asn1String(byte[] data)
			: this()
		{
			Native.ExpectSuccess(Native.ASN1_STRING_set(this.ptr, data, data.Length));
		}

		/// <summary>
		/// Returns ASN1_STRING_length()
		/// </summary>
		public int Length
		{
			get { return Native.ASN1_STRING_length(this.ptr); }
		}

		/// <summary>
		/// Returns ASN1_STRING_data()
		/// </summary>
		public byte[] Data
		{
			get
			{
				IntPtr ret = Native.ASN1_STRING_data(this.ptr);
				byte[] byteArray = new byte[this.Length];
				Marshal.Copy(ret, byteArray, 0, byteArray.Length);
				return byteArray;
			}
		}

		protected override IntPtr DuplicateHandle()
		{
			return Native.ASN1_STRING_dup(this.ptr);
		}

		/// <summary>
		/// Calls CompareTo()
		/// </summary>
		/// <param name="obj"></param>
		/// <returns></returns>
		public override bool Equals(object obj)
		{
			Asn1String asn1 = obj as Asn1String;
			if (asn1 == null)
				return false;

			return (CompareTo(asn1) == 0);
		}

		public override int GetHashCode()
		{
			return base.GetHashCode();
		}

		/// <summary>
		/// Calls ASN1_STRING_free()
		/// </summary>
		protected override void OnDispose()
		{
			Native.ASN1_STRING_free(this.ptr);
		}

		#region IComparable<Asn1String> Members

		/// <summary>
		/// Returns ASN1_STRING_cmp()
		/// </summary>
		/// <param name="other"></param>
		/// <returns></returns>
		public int CompareTo(Asn1String other)
		{
			return Native.ASN1_STRING_cmp(this.ptr, other.Handle);
		}

		#endregion
	}
}
