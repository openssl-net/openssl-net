using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace OpenSSL.Core
{
	/// <summary>
	/// 
	/// </summary>
	public enum MemoryProblemType
	{
		/// <summary>
		/// 
		/// </summary>
		Leaked,
		/// <summary>
		/// 
		/// </summary>
		MultipleFree,
	}

	/// <summary>
	/// 
	/// </summary>
	public class MemoryProblem
	{
		/// <summary>
		/// 
		/// </summary>
		public MemoryProblemType Type { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public uint Size { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public int FreeCount { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public StackTrace StackTrace { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public string File { get; set; }
		/// <summary>
		/// 
		/// </summary>
		public int Line { get; set; }

		/// <summary>
		/// 
		/// </summary>
		/// <returns></returns>
		public override string ToString()
		{
			return string.Format("{0}: {1} bytes, {2} count, {3}, {4}:{5}",
				Type,
				Size,
				FreeCount,
				StackTrace.GetFrame(0).GetMethod().Name,
				File,
				Line
			);
		}
	}

	/// <summary>
	/// Useful for tracking down memory leaks
	/// </summary>
	public class MemoryTracker
	{
		class Block
		{
			public string file;
			public int line;
			public StackTrace stack;
			public uint bytes;
			public IntPtr ptr;
			public bool skip;
			public int count;

			public override string ToString()
			{
				return string.Format("{0}{1}: {2} bytes at {3}:{4}", skip ? "*" : " ", count, bytes, file, line);
			}
		}

		// These are used to pin the functions down so they don't get yanked while in use
		static Native.MallocFunctionPtr _ptrMalloc = malloc;
		static Native.ReallocFunctionPtr _ptrRealloc = realloc;
		static Native.FreeFunctionPtr _ptrFree = free;

		static bool _tracking = false;
		static Dictionary<IntPtr, Block> _memory = new Dictionary<IntPtr, Block>();

		/// <summary>
		/// Initialize memory routines
		/// </summary>
		public static void Init()
		{
			Native.CRYPTO_set_mem_ex_functions(_ptrMalloc, _ptrRealloc, _ptrFree);
		}

		/// <summary>
		/// Begins memory tracking
		/// </summary>
		public static void Start()
		{
			lock (_memory)
			{
				_tracking = true;
				foreach (var item in _memory)
				{
					item.Value.skip = true;
				}
			}
		}

		/// <summary>
		/// Stops memory tracking and reports any leaks found since Start() was called.
		/// </summary>
		public static List<MemoryProblem> Finish()
		{
			GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			CryptoUtil.Cleanup();
			CryptoUtil.ClearErrors();
			Native.ERR_remove_thread_state(IntPtr.Zero);

			GC.Collect();
			GC.WaitForPendingFinalizers();
			GC.Collect();

			_tracking = false;

			return Flush();
		}

		static List<MemoryProblem> Flush()
		{
			var problems = new List<MemoryProblem>();

			lock (_memory)
			{
				var frees = new List<Block>();

				foreach (var item in _memory)
				{
					var block = item.Value;
					if (block.skip)
						continue;

					if (block.count == 0)
						block.skip = true;

					if (block.count > 0)
						frees.Add(block);

					if (block.count == 0 || block.count > 1)
					{
						var problem = new MemoryProblem
						{
							Type = block.count == 0 ? MemoryProblemType.Leaked : MemoryProblemType.MultipleFree,
							Size = block.bytes,
							FreeCount = block.count,
							StackTrace = block.stack,
							File = block.file,
							Line = block.line,
						};
						Console.WriteLine(problem);
						problems.Add(problem);
					}
				}

				foreach (var block in frees)
				{
					Marshal.FreeHGlobal(block.ptr);
					_memory.Remove(block.ptr);
				}
			}

			return problems;
		}

		static IntPtr malloc(uint num, IntPtr file, int line)
		{
			lock (_memory)
			{
				var block = new Block
				{
					file = Native.StaticString(file),
					line = line,
					stack = new StackTrace(1, true),
					bytes = num,
					ptr = Marshal.AllocHGlobal((int)num),
				};
				_memory.Add(block.ptr, block);
				return block.ptr;
			}
		}

		static void free(IntPtr addr)
		{
			lock (_memory)
			{
				Block block;
				if (!_memory.TryGetValue(addr, out block))
					return;

				if (_tracking)
				{
					block.count++;
				}
				else
				{
					Marshal.FreeHGlobal(addr);
					_memory.Remove(addr);
				}
			}
		}

		static IntPtr realloc(IntPtr addr, uint num, IntPtr file, int line)
		{
			lock (_memory)
			{
				if (!_memory.Remove(addr))
					return malloc(num, file, line);

				var block = new Block
				{
					stack = new StackTrace(1, true),
					file = Native.StaticString(file),
					line = line,
					bytes = num,
					ptr = Marshal.ReAllocHGlobal(addr, (IntPtr)num),
				};

				_memory.Add(block.ptr, block);
				return block.ptr;
			}
		}
	}
}
