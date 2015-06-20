// Copyright (c) 2006-2012 Frank Laub
// All rights reserved.
//
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
using System.Runtime.InteropServices;
using System.Text;

namespace OpenSSL.Core
{
	/// <summary>
	/// Exposes the RAND_* functions.
	/// </summary>
	public class Random
	{
		/// <summary>
		/// Calls RAND_seed()
		/// </summary>
		/// <param name="seed"></param>
		public static void Seed(byte[] seed)
		{
			Native.RAND_seed(seed, seed.Length);
		}

		/// <summary>
		/// Calls RAND_seed()
		/// </summary>
		/// <param name="seed"></param>
		public static void Seed(string seed)
		{
			var tmp = Encoding.ASCII.GetBytes(seed);
			Native.RAND_seed(tmp, tmp.Length);
		}

		/// <summary>
		/// Calls RAND_pseudo_bytes()
		/// </summary>
		/// <param name="len"></param>
		/// <returns></returns>
		public static byte[] PseudoBytes(int len)
		{
			var buf = new byte[len];
			Native.ExpectSuccess(Native.RAND_pseudo_bytes(buf, buf.Length));

			return buf;
		}

		/// <summary>
		/// Calls RAND_cleanup()
		/// </summary>
		public static void Cleanup()
		{
			Native.RAND_cleanup();
		}

		/// <summary>
		/// Calls RAND_bytes()
		/// </summary>
		/// <param name="len"></param>
		/// <returns></returns>
		public static byte[] Bytes(int len)
		{
			var buf = new byte[len];
			Native.ExpectSuccess(Native.RAND_bytes(buf, len));

			return buf;
		}

		/// <summary>
		/// Calls RAND_add()
		/// </summary>
		/// <param name="buf"></param>
		/// <param name="entropy"></param>
		public static void Add(byte[] buf, double entropy)
		{
			Native.RAND_add(buf, buf.Length, entropy);
		}

		/// <summary>
		/// Calls RAND_load_file()
		/// </summary>
		/// <param name="filename"></param>
		/// <param name="max_bytes"></param>
		public static void LoadFile(string filename, int max_bytes)
		{
			Native.ExpectSuccess(Native.RAND_load_file(filename, max_bytes));
		}

		/// <summary>
		/// Calls RAND_write_file()
		/// </summary>
		/// <param name="filename"></param>
		public static void WriteFile(string filename)
		{
			Native.ExpectSuccess(Native.RAND_write_file(filename));
		}

		/// <summary>
		/// Calls RAND_file_name()
		/// </summary>
		/// <returns></returns>
		public static string GetFilename()
		{
			var buf = new byte[1024];
			return Native.RAND_file_name(buf, (uint)buf.Length);
		}

		/// <summary>
		/// Returns RAND_status()
		/// </summary>
		public static int Status
		{
			get { return Native.RAND_status(); }
		}

		/// <summary>
		/// Calls RAND_query_egd_bytes()
		/// </summary>
		/// <param name="path"></param>
		/// <param name="buf"></param>
		/// <param name="bytes"></param>
		public static void GatherEntropy(string path, byte[] buf, int bytes)
		{
			Native.ExpectSuccess(Native.RAND_query_egd_bytes(path, buf, bytes));
		}

		/// <summary>
		/// Calls RAND_egd()
		/// </summary>
		/// <param name="path"></param>
		public static void GatherEntropy(string path)
		{
			Native.ExpectSuccess(Native.RAND_egd(path));
		}

		/// <summary>
		/// Calls RAND_egd_bytes()
		/// </summary>
		/// <param name="path"></param>
		/// <param name="bytes"></param>
		public static void GatherEntropy(string path, int bytes)
		{
			Native.ExpectSuccess(Native.RAND_egd_bytes(path, bytes));
		}

		/// <summary>
		/// Calls RAND_poll()
		/// </summary>
		public static void Poll()
		{
			Native.ExpectSuccess(Native.RAND_poll());
		}

		/// <summary>
		/// Calls BN_rand()
		/// </summary>
		/// <param name="bits"></param>
		/// <param name="top"></param>
		/// <param name="bottom"></param>
		/// <returns></returns>
		public static BigNumber Next(int bits, int top, int bottom)
		{
			var bn = new BigNumber();
			Native.ExpectSuccess(Native.BN_rand(bn.Handle, bits, top, bottom));

			return bn;
		}

		/// <summary>
		/// Function types
		/// </summary>
		public class Delegates
		{
			/// <summary>
			/// 
			/// </summary>
			/// <param name="buf"></param>
			/// <param name="num"></param>
			/// <returns></returns>
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Seed(IntPtr buf, int num);

			/// <summary>
			/// 
			/// </summary>
			/// <param name="buf"></param>
			/// <param name="num"></param>
			/// <returns></returns>
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Bytes([MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] byte[] buf, int num);

			/// <summary>
			/// 
			/// </summary>
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate void Cleanup();

			/// <summary>
			/// 
			/// </summary>
			/// <param name="buf"></param>
			/// <param name="num"></param>
			/// <param name="entropy"></param>
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate void Add(IntPtr buf, int num, double entropy);

			/// <summary>
			/// 
			/// </summary>
			/// <returns></returns>
			[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
			public delegate int Status();
		};

		[StructLayout(LayoutKind.Sequential)]
		struct rand_meth_st
		{
			public Delegates.Seed seed;
			public Delegates.Bytes bytes;
			public Delegates.Cleanup cleanup;
			public Delegates.Add add;
			public Delegates.Bytes pseudorand;
			public Delegates.Status status;
		};

		#region Random Method
		/// <summary>
		/// 
		/// </summary>
		public class Method : Base
		{
			#region Data Structures and Variables
			private static IntPtr original;
			private rand_meth_st raw = new rand_meth_st();
			#endregion

			#region Initialization
			static Method()
			{
				original = Native.ExpectNonNull(Native.RAND_get_rand_method());
			}

			/// <summary>
			/// 
			/// </summary>
			public Method()
				: base(Marshal.AllocHGlobal(Marshal.SizeOf(typeof(rand_meth_st))), true)
			{
				rand_meth_st raw = (rand_meth_st)Marshal.PtrToStructure(original, typeof(rand_meth_st));
				this.raw.add = raw.add;
				this.raw.bytes = raw.bytes;
				this.raw.seed = raw.seed;
				this.raw.cleanup = raw.cleanup;
				this.raw.pseudorand = raw.pseudorand;
				this.raw.status = raw.status;
			}

			/// <summary>
			/// 
			/// </summary>
			~Method()
			{
				Dispose();
			}
			#endregion

			#region Properties
			/// <summary>
			/// 
			/// </summary>
			public Delegates.Seed Seed
			{
				get { return raw.seed; }
				set { raw.seed = value; }
			}

			/// <summary>
			/// 
			/// </summary>
			public Delegates.Bytes Bytes
			{
				get { return raw.bytes; }
				set { raw.bytes = value; }
			}

			/// <summary>
			/// 
			/// </summary>
			public Delegates.Cleanup Cleanup
			{
				get { return raw.cleanup; }
				set { raw.cleanup = value; }
			}

			/// <summary>
			/// 
			/// </summary>
			public Delegates.Add Add
			{
				get { return raw.add; }
				set { raw.add = value; }
			}

			/// <summary>
			/// 
			/// </summary>
			public Delegates.Bytes PseudoRand
			{
				get { return raw.pseudorand; }
				set { raw.pseudorand = value; }
			}

			/// <summary>
			/// 
			/// </summary>
			public Delegates.Status Status
			{
				get { return raw.status; }
				set { raw.status = value; }
			}
			#endregion

			#region Methods
			/// <summary>
			/// 
			/// </summary>
			public void Override()
			{
				Marshal.StructureToPtr(raw, ptr, false);
				Native.ExpectSuccess(Native.RAND_set_rand_method(ptr));
			}

			private void Restore()
			{
				Native.ExpectSuccess(Native.RAND_set_rand_method(original));
			}
			#endregion

			#region IDisposable implementation
			/// <summary>
			/// 
			/// </summary>
			protected override void OnDispose()
			{
				Restore();
				Marshal.FreeHGlobal(ptr);
			}
			#endregion
		};
		#endregion
	}
}
