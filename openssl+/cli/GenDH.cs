using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using OpenSSL;

namespace OpenSSL.CLI
{
	class CmdGenDH : ICommand
	{
		OptionParser options = new OptionParser();
		public CmdGenDH()
		{
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-2", new Option("2", false));
			options.AddOption("-5", new Option("5", false));
			options.AddOption("-rand", new Option("rand", ""));
			options.AddOption("-engine", new Option("engine", ""));
		}

		void Usage()
		{
			string str =
@"usage: gendh [args] [numbits]
 -out file - output the key to 'file
 -2        - use 2 as the generator value
 -5        - use 5 as the generator value
 -engine e - use engine e, possibly a hardware device.
 -rand file:file:...
           - load the file (or the files in the directory) into
             the random number generator";

			Console.WriteLine(str);
		}

		#region ICommand Members

		public void Execute(string[] args)
		{
			try
			{
				options.ParseArguments(args);
			}
			catch (Exception)
			{
				Usage();
				return;
			}

			int g = DH.Generator2;
			if (this.options.IsSet("2"))
				g = DH.Generator2;

			if (this.options.IsSet("5"))
				g = DH.Generator5;

			int bits = 512;
			if (this.options.Arguments.Count == 1)
				bits = Convert.ToInt32(this.options.Arguments[0]);

			Console.WriteLine("Generating DH parameters, {0} bit long safe prime, generator {1}", bits, g);
			Console.WriteLine("This is going to take a long time");

			OpenSSL.DH dh = new OpenSSL.DH(bits, g, new BigNumber.GeneratorHandler(this.OnStatus), null);

			string outfile = this.options["out"] as string;
			if (string.IsNullOrEmpty(outfile))
			{
				Console.WriteLine(dh.PEM);
			}
			else
			{
				File.WriteAllText(outfile, dh.PEM);
			}
		}

		private int OnStatus(int p, int n, object arg)
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

		#endregion
	}
}
