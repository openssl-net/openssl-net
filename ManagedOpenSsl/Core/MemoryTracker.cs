using System;

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
			CryptoUtil.MallocDebugInit();
			CryptoUtil.SetDebugOptions(DebugOptions.All);
			CryptoUtil.SetMemoryCheck(MemoryCheck.On);
		}

		/// <summary>
		/// Stops memory tracking and reports any leaks found since Start() was called.
		/// </summary>
		public static void Finish()
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			CryptoUtil.Cleanup();
			CryptoUtil.ClearErrors();
			Threading.RemoveState();

			CryptoUtil.CheckMemoryLeaks(OnMemoryLeak);
			if (leaked > 0)
				Console.WriteLine("Leaked total bytes: {0}", leaked);

			CryptoUtil.SetMemoryCheck(MemoryCheck.Off);
		}

		private static void OnMemoryLeak(uint order, IntPtr file, int line, int num_bytes, IntPtr addr)
		{
			string filename = (file != IntPtr.Zero) ? Native.StaticString(file) : "<null>";

			Console.WriteLine("[{0}] file: {1} line: {2} bytes: {3}", order, filename, line, num_bytes);
			leaked += num_bytes;

			Native.CRYPTO_dbg_free(addr, 0);
		}
	}
}
