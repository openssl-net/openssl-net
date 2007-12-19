using System;
using System.Collections.Generic;
using System.Text;

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
			AddNullCommand(tests, "hmac");
			AddNullCommand(tests, "idea");
			AddNullCommand(tests, "ige");
			AddNullCommand(tests, "md2");
			AddNullCommand(tests, "md4");
			AddNullCommand(tests, "md5");
			AddNullCommand(tests, "mdc2");
			AddNullCommand(tests, "meth");
			AddNullCommand(tests, "r160");
			AddNullCommand(tests, "rand");
			AddNullCommand(tests, "rc2");
			AddNullCommand(tests, "rc4");
			AddNullCommand(tests, "rc5");
			AddNullCommand(tests, "rmd");
			AddNullCommand(tests, "rsa");
			AddNullCommand(tests, "sha256");
			AddNullCommand(tests, "sha512");
			AddNullCommand(tests, "sha");
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

			ICommand cmd;
			if(!this.tests.TryGetValue(args[0], out cmd))
			{
				Usage();
				return;
			}

			cmd.Execute(args);
		}
	}
}
