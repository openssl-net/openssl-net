using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;
using System.Reflection;
using System.Security.Permissions;

namespace OpenSSL.CLI
{
	class DH : ICommand
	{
		OptionParser options = new OptionParser();
		public DH()
		{
			options.AddOption("-inform", new Option("inform", "PEM"));
			options.AddOption("-outform", new Option("outform", "PEM"));
			options.AddOption("-in", new Option("infile", ""));
			options.AddOption("-out", new Option("outfile", ""));
			options.AddOption("-check", new Option("check", false));
			options.AddOption("-text", new Option("text", false));
			options.AddOption("-C", new Option("code", false));
			options.AddOption("-noout", new Option("noout", false));
			options.AddOption("-engine", new Option("engine", ""));
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
			}

			BIO bin;
			string infile = this.options.GetString("infile");
			if(string.IsNullOrEmpty(infile))
			{
				string input = Console.In.ReadToEnd();
				bin = new BIO(Encoding.ASCII.GetBytes(input));
			}
			else
			{
				bin = BIO.File(infile, "r");
			}
			OpenSSL.DH dh = OpenSSL.DH.FromParameters(bin);
			
			if (this.options.IsSet("text"))
			{
				Console.WriteLine(dh);
			}

			//if (this.options.IsSet("check"))
			//{
			//    OpenSSL.DH.CheckCode codes = dh.Check();
			//    if ((codes & OpenSSL.DH.CheckCode.NotSuitableGenerator) > 0)
			//        Console.WriteLine("the g value is not a generator");
			//    if ((codes & OpenSSL.DH.CheckCode.P_NotPrime) > 0)
			//        Console.WriteLine("p value is not prime");
			//    if ((codes & OpenSSL.DH.CheckCode.P_NotSafePrime) > 0)
			//        Console.WriteLine("p value is not a safe prime");
			//    if ((codes & OpenSSL.DH.CheckCode.UnableToCheckGenerator) > 0)
			//        Console.WriteLine("unable to check the generator value");
			//    if (codes == 0)
			//        Console.WriteLine("DH parameters appear to be ok");
			//}

			if (this.options.IsSet("code"))
			{
			}

			if (!this.options.IsSet("noout"))
			{
			}
		}
		#endregion

		void Usage()
		{
			Console.WriteLine("dh [options] <infile >outfile");
			Console.WriteLine("where options are");
			Console.WriteLine(" -inform arg   input format - one of DER | PEM");
			Console.WriteLine(" -outform arg  output format - one of DER | PEM");
			Console.WriteLine(" -in arg       input file");
			Console.WriteLine(" -out arg      output file");
			Console.WriteLine(" -check        check the DH parameters");
			Console.WriteLine(" -text         print a text form of the DH parameters");
			Console.WriteLine(" -C            output C code");
			Console.WriteLine(" -noout        no output");
			Console.WriteLine(" -engine e     use engine e, possibly a hardware device.");
		}
	}
}
