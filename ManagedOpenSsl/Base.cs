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

	public class Random
	{
		public static void Seed(byte[] seed)
		{
			Native.RAND_seed(seed, seed.Length);
		}

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

	public class Crypto
	{
		public static void MallocDebugInit()
		{
			Native.CRYPTO_malloc_debug_init();
		}

		public static void SetDebugOptions(DebugOptions options)
		{
			Native.CRYPTO_dbg_set_options((int)options);
		}

		public static void SetMemoryCheck(MemoryCheck options)
		{
			Native.CRYPTO_mem_ctrl((int)options);
		}

		public static void Cleanup()
		{
			Native.CRYPTO_cleanup_all_ex_data();
		}

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

		public static void CheckMemoryLeaks(MemoryLeakHandler callback)
		{
			Native.CRYPTO_mem_leaks_cb(callback);
		}
	}
}
