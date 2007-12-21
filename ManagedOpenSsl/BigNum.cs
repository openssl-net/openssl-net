// Copyright (c) 2006-2007 Frank Laub
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

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace OpenSSL
{
	public class BigNumber : Base, IDisposable, IComparable<BigNumber>
	{
		#region Predefined Values
		public static BigNumber One = new BigNumber(Native.BN_value_one(), false);
		#endregion

		#region Initialization
		internal BigNumber(IntPtr ptr, bool owner) : base(ptr, owner) { }
		public BigNumber()
			: base(Native.ExpectNonNull(Native.BN_new()), true)
		{
		}

		public BigNumber(BigNumber rhs)
			: base(Native.BN_dup(rhs.ptr), true)
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
            return new BigNumber(ptr, true);
		}

		public static BigNumber FromHexString(string str)
		{
			byte[] buf = Encoding.ASCII.GetBytes(str);
			IntPtr ptr;
            int ret = Native.BN_hex2bn(out ptr, buf);
            if (ret <= 0)
                throw new OpenSslException();
			return new BigNumber(ptr, true);
		}

		public static BigNumber FromArray(byte[] buf)
		{
			IntPtr ptr = Native.BN_bin2bn(buf, buf.Length, IntPtr.Zero);
			return new BigNumber(Native.ExpectNonNull(ptr), true);
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

        public static bool operator ==(BigNumber lhs, BigNumber rhs)
        {
			if (object.ReferenceEquals(lhs, rhs))
				return true;
			if ((object)lhs == null || (object)rhs == null)
				return false;
			return lhs.Equals(rhs);
        }

        public static bool operator !=(BigNumber lhs, BigNumber rhs)
        {
			return !(lhs == rhs);
        }
		#endregion

		#region Overrides
		public override bool Equals(object obj)
		{
			BigNumber rhs = obj as BigNumber;
			if ((object)rhs == null)
				return false;
			return Native.BN_cmp(this.ptr, rhs.ptr) == 0;
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

		public override void OnDispose()
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

		#region Callbacks

		public delegate int GeneratorHandler(int p, int n, object arg);

		internal class GeneratorThunk
		{
			private Native.bn_gencb_st gencb = new Native.bn_gencb_st();
			private GeneratorHandler OnGenerator;
			private object arg;

			public Native.bn_gencb_st CallbackStruct
			{
				get { return this.gencb; }
			}

			public GeneratorThunk(GeneratorHandler client, object arg) 
			{
				this.OnGenerator = client;
				this.arg = arg;

				this.gencb.ver = 2;
				this.gencb.arg = IntPtr.Zero;
				this.gencb.cb = this.OnGeneratorThunk;
			}

			internal int OnGeneratorThunk(int p, int n, IntPtr arg)
			{
				try
				{
					return OnGenerator(p, n, this.arg);
				}
				catch (Exception ex)
				{
					return 0;
				}
			}
		}

		#endregion
	}
}