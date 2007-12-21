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
using OpenSSL;
using System.IO;
using System.Runtime.InteropServices;

namespace OpenSSL.CLI
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

		SortedDictionary<string, ICommand> std_cmds = new SortedDictionary<string, ICommand>();
		SortedDictionary<string, ICommand> md_cmds = new SortedDictionary<string, ICommand>();
		SortedDictionary<string, ICommand> cipher_cmds = new SortedDictionary<string, ICommand>();

		void AddNullCommand(SortedDictionary<string, ICommand> map, string name)
		{
			map.Add(name, new NullCommand(name));
		}

		Program()
		{
			std_cmds.Add("dh", new CmdDH());
			std_cmds.Add("gendh", new CmdGenDH());
			std_cmds.Add("rsa", new CmdRSA());
			std_cmds.Add("genrsa", new CmdGenRSA());

			#region Standard Commands
			AddNullCommand(std_cmds, "asn1parse");
			AddNullCommand(std_cmds, "ca");
			AddNullCommand(std_cmds, "ciphers");
			AddNullCommand(std_cmds, "crl");
			AddNullCommand(std_cmds, "crl2pkcs7");
			AddNullCommand(std_cmds, "dgst");
			AddNullCommand(std_cmds, "dhparam");
			AddNullCommand(std_cmds, "dsa");
			AddNullCommand(std_cmds, "dsaparam");
			AddNullCommand(std_cmds, "ec");
			AddNullCommand(std_cmds, "ecparam");
			AddNullCommand(std_cmds, "enc");
			AddNullCommand(std_cmds, "engine");
			AddNullCommand(std_cmds, "errstr");
			AddNullCommand(std_cmds, "gendsa");
			AddNullCommand(std_cmds, "nseq");
			AddNullCommand(std_cmds, "ocsp");
			AddNullCommand(std_cmds, "passwd");
			AddNullCommand(std_cmds, "pkcs12");
			AddNullCommand(std_cmds, "pkcs7");
			AddNullCommand(std_cmds, "pkcs8");
			AddNullCommand(std_cmds, "prime");
			AddNullCommand(std_cmds, "rand");
			AddNullCommand(std_cmds, "req");
			AddNullCommand(std_cmds, "rsautl");
			AddNullCommand(std_cmds, "s_client");
			AddNullCommand(std_cmds, "s_server");
			AddNullCommand(std_cmds, "s_time");
			AddNullCommand(std_cmds, "sess_id");
			AddNullCommand(std_cmds, "smime");
			AddNullCommand(std_cmds, "speed");
			AddNullCommand(std_cmds, "spkac");
			AddNullCommand(std_cmds, "verify");
			AddNullCommand(std_cmds, "version");
			AddNullCommand(std_cmds, "x509");
			#endregion

			#region Message Digest commands
			AddNullCommand(md_cmds, "md2");
			AddNullCommand(md_cmds, "md4");
			AddNullCommand(md_cmds, "md5");
			AddNullCommand(md_cmds, "rmd160");
			AddNullCommand(md_cmds, "sha");
			AddNullCommand(md_cmds, "sha1");
			#endregion

			#region Cipher commands
			AddNullCommand(cipher_cmds, "aes-128-cbc");
			#endregion
		}

		ICommand FindCommand(string name)
		{
			if (std_cmds.ContainsKey(name))
				return std_cmds[name];
			if (md_cmds.ContainsKey(name))
				return md_cmds[name];
			if (cipher_cmds.ContainsKey(name))
				return cipher_cmds[name];
			return null;
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
			Console.WriteLine("Standard commands");
			PrintCommands(std_cmds.Keys);
			Console.WriteLine();
			Console.WriteLine("Message Digest commands");
			PrintCommands(md_cmds.Keys);
			Console.WriteLine();
			Console.WriteLine("Cipher commands");
			PrintCommands(cipher_cmds.Keys);
		}

		void Run(string[] args)
		{
			if (args.Length == 0)
			{
				Usage();
				return;
			}
			ICommand cmd = FindCommand(args[0]);
			if (cmd == null)
			{
				Usage();
				return;
			}

			cmd.Execute(args);
		}

		public static int OnGenerator(int p, int n, object arg)
		{
			TextWriter cout = Console.Out;

			switch (p)
			{
				case 0: cout.Write('.'); break;
				case 1: cout.Write('+'); break;
				case 2: cout.Write('*'); break;
				case 3: cout.WriteLine(); break;
			}

			return 1;
		}

		private static string ReadPassword()
		{
			Console.TreatControlCAsInput = true;
			StringBuilder sb = new StringBuilder();
			while (true)
			{
				ConsoleKeyInfo key = Console.ReadKey(true);
				if (key.Key == ConsoleKey.Enter)
					break;

				if (key.Key == ConsoleKey.C && key.Modifiers == ConsoleModifiers.Control)
				{
					Console.WriteLine();
					throw new Exception("Cancelled");
				}

				sb.Append(key.KeyChar);
			}
			Console.TreatControlCAsInput = false;
			return sb.ToString();
		}

		public static string OnPassword(bool verify, object arg)
		{
			string passwd = null;
			while (true)
			{
				Console.Write("Enter pass phrase:");
				string str1 = ReadPassword();
				Console.WriteLine();

				if (str1.Length == 0)
					continue;

				if (!verify)
					break;

				Console.Write("Verifying - Enter pass phrase:");
				string str2 = ReadPassword();
				Console.WriteLine();
	
				if (str1 == str2)
				{
					passwd = str1;
					break;
				}

				Console.WriteLine("Passwords don't match, try again.");
			}

			return passwd;
		}
	}
}
