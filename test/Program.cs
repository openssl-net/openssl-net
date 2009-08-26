// Copyright (c) 2006-2008 Frank Laub
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
using OpenSSL;
using System.Threading;
using OpenSSL.Core;

namespace test
{
	interface ICommand
	{
		void Execute(string[] args);
	}

	#region NullCommand
	class NullCommand : ICommand
	{
		private string name;
		public NullCommand(string name)
		{
			this.name = name;
		}

		#region ICommand Members
		public void Execute(string[] args)
		{
			Console.WriteLine("{0}: {1}", this.name, string.Join(" ", args));
			Console.WriteLine("Not implemented yet!");
		}
		#endregion
	}
	#endregion

	class Program
	{
		static void Main(string[] args)
		{
			Program program = new Program();
			program.Run(args);
		}
		SortedDictionary<string, ICommand> tests = new SortedDictionary<string, ICommand>();

		void AddNullCommand(SortedDictionary<string, ICommand> map, string name)
		{
			map.Add(name, new NullCommand(name));
		}

		Program()
		{
			tests.Add("dh", new TestDH());
			tests.Add("dsa", new TestDSA());
			tests.Add("sha1", new TestSHA1());
			tests.Add("sha", new TestSHA());
			tests.Add("sha256", new TestSHA256());
			tests.Add("sha512", new TestSHA512());
			tests.Add("rsa", new TestRSA());
			tests.Add("rand", new TestRandom());
			tests.Add("x509", new TestX509());
			tests.Add("aes", new TestAES());
            tests.Add("hmac", new TestHMAC());
            tests.Add("server", new TestServer());

			AddNullCommand(tests, "bf");
			AddNullCommand(tests, "bn");
			AddNullCommand(tests, "cast");
			AddNullCommand(tests, "des");
			AddNullCommand(tests, "dummy");
			AddNullCommand(tests, "ecdh");
			AddNullCommand(tests, "ecdsa");
			AddNullCommand(tests, "ec");
			AddNullCommand(tests, "engine");
			AddNullCommand(tests, "evp");
			AddNullCommand(tests, "exp");
			AddNullCommand(tests, "idea");
			AddNullCommand(tests, "ige");
			AddNullCommand(tests, "md2");
			AddNullCommand(tests, "md4");
			AddNullCommand(tests, "md5");
			AddNullCommand(tests, "mdc2");
			AddNullCommand(tests, "meth");
			AddNullCommand(tests, "r160");
			AddNullCommand(tests, "rc2");
			AddNullCommand(tests, "rc4");
			AddNullCommand(tests, "rc5");
			AddNullCommand(tests, "rmd");
		}

		void PrintCommands(IEnumerable<string> cmds)
		{
			int col = 0;
			foreach (string cmd in cmds)
			{
				Console.Write(cmd);
				if (col++ == 4)
				{
					Console.WriteLine();
					col = 0;
					continue;
				}

				int remain = 15 - cmd.Length;
				string padding = new string(' ', remain);
				Console.Write(padding);
			}
			Console.WriteLine();
		}

		void Usage()
		{
			PrintCommands(tests.Keys);
		}

		void Run(string[] args)
		{
			if (args.Length == 0)
			{
				Usage();
				return;
			}

			if (args[0] == "all") {
				TestAll();
				return;
			}

			ICommand cmd;
			if(!this.tests.TryGetValue(args[0], out cmd))
			{
				Usage();
				return;
			}
            
            // Check to see if "fips" is an argument, if so, set FIPS mode 
            // here (before any other calls to the crypto lib)
            foreach (string arg in args)
            {
                if (arg.ToLower() == "fips")
                {
                    Console.WriteLine("Executing test in FIPS mode.");
                    FIPS.Enabled = true;
                    break;
                }
            }

			MemoryTracker.Start();
			cmd.Execute(args);
			MemoryTracker.Finish();
		}

		void TestAll() {
			foreach (KeyValuePair<string, ICommand> item in tests) {
				MemoryTracker.Start();
				string[] args = new string[1];
				args[0] = item.Key;
				item.Value.Execute(args);
				MemoryTracker.Finish();
			}
		}
	}
}
