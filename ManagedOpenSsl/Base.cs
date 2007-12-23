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

namespace OpenSSL
{
	#region Base
	/// <summary>
	/// Base class for all openssl wrapped objects. 
	/// Contains the raw unmanaged pointer and has a Handle property to get access to it. 
	/// Also overloads the ToString() method with a BIO print.
	/// </summary>
	public abstract class Base : IStackable, IDisposable
	{
		/// <summary>
		/// Raw unmanaged pointer
		/// </summary>
		protected IntPtr ptr;

		/// <summary>
		/// If this object is the owner, then call the appropriate native free function.
		/// </summary>
		protected bool owner = false;

		/// <summary>
		/// This is to prevent double-deletion issues.
		/// </summary>
		protected bool isDisposed = false;

		/// <summary>
		/// This destructor just calls Dispose().
		/// </summary>
		~Base()
		{
			Dispose();
		}

		/// <summary>
		/// Access to the raw unmanaged pointer. Implements the IStackable interface.
		/// </summary>
		public IntPtr Handle
		{
			get { return this.ptr; }
			set
			{
				if (this.owner && this.ptr != IntPtr.Zero)
					this.OnDispose();
				this.owner = false;
				this.ptr = value;
			}
		}

		/// <summary>
		/// Constructor which takes the raw unmanged pointer. 
		/// This is the only way to construct this object and all dervied types.
		/// </summary>
		/// <param name="ptr"></param>
		/// <param name="takeOwnership"></param>
		public Base(IntPtr ptr, bool takeOwnership)
		{
			this.ptr = ptr;
			this.owner = takeOwnership;
		}

		/// <summary>
		/// This method is used by the ToString() implementation. A great number of
		/// openssl objects support printing, so this is a conveinence method.
		/// Dervied types should override this method and not ToString().
		/// </summary>
		/// <param name="bio">The BIO stream object to print into</param>
		public virtual void Print(BIO bio) { }

		/// <summary>
		/// Override of ToString() which uses Print() into a BIO memory buffer.
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			try
			{
				if (this.ptr == IntPtr.Zero)
					return "(null)";

				using (BIO bio = BIO.MemoryBuffer())
				{
					this.Print(bio);
					return bio.ReadString();
				}
			}
			catch (Exception)
			{
				return "<exception>";
			}
		}

		/// <summary>
		/// Default base implementation does nothing.
		/// </summary>
		public virtual void OnDispose() { }

		#region IDisposable Members

		/// <summary>
		/// Implementation of the IDisposable interface.
		/// If the native pointer is not null, we haven't been disposed, and we are the owner,
		/// then call the virtual OnDispose() method.
		/// </summary>
		public void Dispose()
		{
			if (!this.isDisposed && this.owner && this.ptr != IntPtr.Zero)
				this.OnDispose();
			this.isDisposed = true;
		}

		#endregion
	}
	#endregion

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
			byte[] tmp = Encoding.ASCII.GetBytes(seed);
			Native.RAND_seed(tmp, tmp.Length);
		}
	}

	/// <summary>
	/// V_CRYPTO_MDEBUG_*
	/// </summary>
	[Flags]
	public enum DebugOptions
	{
		/// <summary>
		/// V_CRYPTO_MDEBUG_TIME 
		/// </summary>
		Time = 0x01,

		/// <summary>
		/// V_CRYPTO_MDEBUG_THREAD
		/// </summary>
		Thread = 0x02,

		/// <summary>
		/// V_CRYPTO_MDEBUG_ALL 
		/// </summary>
		All = Time | Thread,
	}

	/// <summary>
	/// CRYPTO_MEM_CHECK_*
	/// </summary>
	public enum MemoryCheck
	{
		/// <summary>
		/// CRYPTO_MEM_CHECK_OFF 
		/// </summary>
		Off = 0x00,

		/// <summary>
		/// CRYPTO_MEM_CHECK_ON 
		/// </summary>
		On = 0x01,

		/// <summary>
		/// CRYPTO_MEM_CHECK_ENABLE
		/// </summary>
		Enable = 0x02,

		/// <summary>
		/// CRYPTO_MEM_CHECK_DISABLE
		/// </summary>
		Disable = 0x03,
	}

	/// <summary>
	/// Exposes the CRYPTO_* functions
	/// </summary>
	public class Crypto
	{
		/// <summary>
		/// Calls CRYPTO_malloc_debug_init()
		/// </summary>
		public static void MallocDebugInit()
		{
			Native.CRYPTO_malloc_debug_init();
		}

		/// <summary>
		/// Calls CRYPTO_dbg_set_options()
		/// </summary>
		/// <param name="options"></param>
		public static void SetDebugOptions(DebugOptions options)
		{
			Native.CRYPTO_dbg_set_options((int)options);
		}

		/// <summary>
		/// Calls CRYPTO_mem_ctrl()
		/// </summary>
		/// <param name="options"></param>
		public static void SetMemoryCheck(MemoryCheck options)
		{
			Native.CRYPTO_mem_ctrl((int)options);
		}

		/// <summary>
		/// Calls CRYPTO_cleanup_all_ex_data()
		/// </summary>
		public static void Cleanup()
		{
			Native.CRYPTO_cleanup_all_ex_data();
		}

		/// <summary>
		/// Calls ERR_remove_state()
		/// </summary>
		/// <param name="value"></param>
		public static void RemoveState(uint value)
		{
			Native.ERR_remove_state(value);
		}

		/// <summary>
		/// CRYPTO_MEM_LEAK_CB
		/// </summary>
		/// <param name="order"></param>
		/// <param name="file"></param>
		/// <param name="line"></param>
		/// <param name="num_bytes"></param>
		/// <param name="addr"></param>
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate void MemoryLeakHandler(uint order, string file, int line, int num_bytes, IntPtr addr);

		/// <summary>
		/// Calls CRYPTO_mem_leaks_cb()
		/// </summary>
		/// <param name="callback"></param>
		public static void CheckMemoryLeaks(MemoryLeakHandler callback)
		{
			Native.CRYPTO_mem_leaks_cb(callback);
		}
	}
}
