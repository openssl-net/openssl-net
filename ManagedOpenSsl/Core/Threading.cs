using System;
using System.Threading;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace OpenSSL.Core
{
	/// <summary>
	/// Threading.
	/// </summary>
    public class Threading
    {
		[StructLayout(LayoutKind.Sequential)]
		struct CRYPTO_THREADID
		{
			public IntPtr ptr;
			public uint val;
		}

		private const int CRYPTO_LOCK = 1;

		// These are used to pin the functions down so they don't get yanked while in use
		static Native.CRYPTO_locking_callback _ptrOnLocking = OnLocking;
		static Native.CRYPTO_id_callback _ptrOnThreadId = OnThreadId;

		private static List<object> lock_objects;
		private static List<uint> _threadIDs;

		/// <summary>
		/// Initialize this instance.
		/// </summary>
		public static void Initialize()
		{
			// Initialize the threading locks
			var nLocks = Native.CRYPTO_num_locks();
			lock_objects = new List<object>(nLocks);

			for (var i = 0; i < nLocks; i++)
			{
				var obj = new object();
				lock_objects.Add(obj);
			}

			// Initialize the internal thread id stack
			_threadIDs = new List<uint>();

			// Initialize the delegate for the locking callback
			Native.CRYPTO_set_locking_callback(_ptrOnLocking);

			// Initialize the thread id callback
			Native.CRYPTO_THREADID_set_callback(_ptrOnThreadId);
		}

		/// <summary>
		/// Cleanup this instance.
		/// </summary>
		public static void Cleanup()
		{
			// Cleanup the thread lock objects
			Native.CRYPTO_set_locking_callback(null);
			lock_objects.Clear();

			// Clean up error state for each thread that was used by OpenSSL
			if (_threadIDs != null)
			{
				foreach (var id in _threadIDs)
				{
					RemoveState(id);
				}
				_threadIDs.Clear();
			}
		}

		private static void RemoveState(uint threadId)
		{
			var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(CRYPTO_THREADID)));
			Native.CRYPTO_THREADID_set_numeric(ptr, threadId);
			Native.ERR_remove_thread_state(ptr);
			Marshal.FreeHGlobal(ptr);
		}

		private static void OnLocking(int mode, int type, string file, int line)
		{
			if ((mode & CRYPTO_LOCK) == CRYPTO_LOCK)
			{
				Monitor.Enter(lock_objects[type]);
			}
			else
			{
				Monitor.Exit(lock_objects[type]);
			}
		}

		private static void OnThreadId(IntPtr tid)
		{
			var threadId = (uint)Thread.CurrentThread.ManagedThreadId;
			if (!_threadIDs.Contains(threadId))
			{
				_threadIDs.Add(threadId);
			}
			Native.CRYPTO_THREADID_set_numeric(tid, threadId);
		}
    }
}

