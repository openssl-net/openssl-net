using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	public class BigNumber : Base, IDisposable, IComparable<BigNumber>
	{
		#region Predefined Values
		public static BigNumber One = new BigNumber(Native.BN_value_one());
		#endregion

		#region Initialization
		internal BigNumber(IntPtr ptr) : base(ptr) { }
		public BigNumber()
			: base(Native.ExpectNonNull(Native.BN_new()))
		{
		}

		public BigNumber(BigNumber rhs)
			: base(Native.BN_dup(rhs.ptr))
		{
		}

		public BigNumber(uint value)
			: this()
		{
			Native.ExpectSuccess(Native.BN_set_word(this.ptr, value));
		}
		#endregion

		#region Conversion
		public static BigNumber FromDecimalString(string str)
		{
			byte[] buf = Encoding.ASCII.GetBytes(str);
			IntPtr ptr;
            int ret = Native.BN_dec2bn(out ptr, buf);
            if (ret <= 0)
                throw new OpenSslException();
            return new BigNumber(ptr);
		}

		public static BigNumber FromHexString(string str)
		{
			byte[] buf = Encoding.ASCII.GetBytes(str);
			IntPtr ptr;
            int ret = Native.BN_hex2bn(out ptr, buf);
            if (ret <= 0)
                throw new OpenSslException();
			return new BigNumber(ptr);
		}

		public string ToDecimalString()
		{
			return Native.PtrToStringAnsi(Native.BN_bn2dec(this.ptr), true);
		}

		public string ToHexString()
		{
			return Native.PtrToStringAnsi(Native.BN_bn2hex(this.ptr), true);
		}

		public static implicit operator uint(BigNumber rhs)
		{
			return Native.BN_get_word(rhs.ptr);
		}

		public static implicit operator BigNumber(uint value)
		{
			return new BigNumber(value);
		}

		public static implicit operator byte[](BigNumber rhs)
		{
			byte[] bytes = new byte[rhs.Bytes];
			int ret = Native.BN_bn2bin(rhs.ptr, bytes);
			return bytes;
		}

		#endregion

		#region Properties
		public int Bits
		{
			get { return Native.BN_num_bits(this.ptr); }
		}

		public int Bytes
		{
			get { return (this.Bits + 7) / 8; }
		}
		#endregion

		#region Methods
		public void Clear()
		{
			Native.BN_clear(this.ptr);
		}
		#endregion

		#region Operators
		public static BigNumber operator + (BigNumber lhs, BigNumber rhs)
		{
			BigNumber ret = new BigNumber();
			Native.ExpectSuccess(Native.BN_add(ret.Handle, lhs.Handle, rhs.Handle));
			return ret;
		}

		public static BigNumber operator -(BigNumber lhs, BigNumber rhs)
		{
			BigNumber ret = new BigNumber();
			Native.ExpectSuccess(Native.BN_sub(ret.Handle, lhs.Handle, rhs.Handle));
			return ret;
		}
		#endregion

		#region Overrides
		public override bool Equals(object obj)
		{
			return Native.BN_cmp(this.ptr, ((BigNumber)obj).ptr) == 0;
		}

		public override int GetHashCode()
		{
			return ToDecimalString().GetHashCode();
		}

		public override void Print(BIO bio)
		{
			Native.ExpectSuccess(Native.BN_print(bio.Handle, this.ptr));
		}
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			Native.BN_free(this.ptr);
		}

		#endregion

		#region IComparable<BigNumber> Members

		public int CompareTo(BigNumber other)
		{
			return Native.BN_cmp(this.ptr, other.ptr);
		}

		#endregion
	}
}