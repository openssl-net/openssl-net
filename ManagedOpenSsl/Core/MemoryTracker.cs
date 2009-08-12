using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace OpenSSL.Core
{
	/// <summary>
	/// Useful for tracking down memory leaks
	/// </summary>
	public class MemoryTracker
	{
		private static int leaked = 0;

		/// <summary>
		/// Returns the number of bytes leaked between Start() and Finish()
		/// </summary>
		public static int Leaked { get { return leaked; } }

		/// <summary>
		/// Begins memory tracking
		/// </summary>
		public static void Start()
		{
			leaked = 0;
			Crypto.MallocDebugInit();
			Crypto.SetDebugOptions(DebugOptions.All);
			Crypto.SetMemoryCheck(MemoryCheck.On);
		}

		/// <summary>
		/// Stops memory tracking and reports any leaks found since Start() was called.
		/// </summary>
		public static void Finish()
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			Crypto.Cleanup();
			Crypto.RemoveState(0);

			Crypto.CheckMemoryLeaks(OnMemoryLeak);
			if (leaked > 0)
				Console.WriteLine("Leaked total bytes: {0}", leaked);

			Crypto.SetMemoryCheck(MemoryCheck.Off);
		}

		private static void OnMemoryLeak(uint order, string file, int line, int num_bytes, IntPtr addr)
		{
			Console.WriteLine("[{0}] file: {1} line: {2} bytes: {3}", order, file, line, num_bytes);
			leaked += num_bytes;
		}
	}
}
