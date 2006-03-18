using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

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
			#region Standard Commands
			std_cmds.Add("dh", new DH());

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
			AddNullCommand(std_cmds, "gendh");
			AddNullCommand(std_cmds, "gendsa");
			AddNullCommand(std_cmds, "genrsa");
			AddNullCommand(std_cmds, "nseq");
			AddNullCommand(std_cmds, "ocsp");
			AddNullCommand(std_cmds, "passwd");
			AddNullCommand(std_cmds, "pkcs12");
			AddNullCommand(std_cmds, "pkcs7");
			AddNullCommand(std_cmds, "pkcs8");
			AddNullCommand(std_cmds, "prime");
			AddNullCommand(std_cmds, "rand");
			AddNullCommand(std_cmds, "req");
			AddNullCommand(std_cmds, "rsa");
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
	}
}
