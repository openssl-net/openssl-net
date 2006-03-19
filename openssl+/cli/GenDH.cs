using System;
using System.Collections.Generic;
using System.Text;
using System.IO;	

namespace OpenSSL.CLI
{
	class GenDH : ICommand
	{
		OptionParser options = new OptionParser();
		public GenDH()
		{
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-2", new Option("2", false));
			options.AddOption("-5", new Option("5", false));
			options.AddOption("-rand", new Option("rand", ""));
			options.AddOption("-engine", new Option("engine", ""));
		}

		#region ICommand Members

		public void Execute(string[] args)
		{
			options.ParseArguments(args);

			Random rand = new Random();
			int g = rand.Next();
			if (this.options.IsSet("2"))
				g = 2;

			if (this.options.IsSet("5"))
				g = 5;

			int bits = Convert.ToInt32(this.options.Arguments[0]);

			OpenSSL.DH dh = new OpenSSL.DH(bits, g);

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

		#endregion
	}
}
