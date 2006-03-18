using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

namespace OpenSSL.CLI
{
	class DH : ICommand
	{
		string inform = "PEM";
		string outform = "PEM";
		string infile;
		string outfile;
		bool check = false;
		bool text = false;
		bool code = false;
		bool noout = false;
		string engine;

		void ParseOptions(string[] args)
		{
			for (int i = 1; i < args.Length; i++)
			{
				switch (args[i])
				{
					case "-inform":
						inform = args[++i];
						break;
					case "-outform":
						outform = args[++i];
						break;
					case "-in":
						infile = args[++i];
						break;
					case "-out":
						outfile = args[++i];
						break;
					case "-check":
						check = true;
						break;
					case "-text":
						text = true;
						break;
					case "-C":
						code = true;
						break;
					case "-noout":
						noout = true;
						break;
					case "-engine":
						engine = args[++i];
						break;
					default:
						Usage();
						break;
				}
			}
		}

		#region ICommand Members
		public void Execute(string[] args)
		{
			try
			{
				ParseOptions(args);
			}
			catch (Exception)
			{
				Usage();
			}

			BIO bin;
			if (infile == null)
			{
				string input = Console.In.ReadToEnd();
				bin = new BIO(Encoding.ASCII.GetBytes(input));
			}
			else
			{
				bin = BIO.File(infile, "r");
			}
			OpenSSL.DH dh = OpenSSL.DH.FromParameters(bin);
			
			if (text)
			{
				Console.WriteLine(dh);
			}

			if (check)
			{
				OpenSSL.DH.CheckCode codes = dh.Check();
				if ((codes & OpenSSL.DH.CheckCode.NotSuitableGenerator) > 0)
					Console.WriteLine("the g value is not a generator");
				if ((codes & OpenSSL.DH.CheckCode.P_NotPrime) > 0)
					Console.WriteLine("p value is not prime");
				if ((codes & OpenSSL.DH.CheckCode.P_NotSafePrime) > 0)
					Console.WriteLine("p value is not a safe prime");
				if ((codes & OpenSSL.DH.CheckCode.UnableToCheckGenerator) > 0)
					Console.WriteLine("unable to check the generator value");
				if (codes == 0)
					Console.WriteLine("DH parameters appear to be ok");
			}

			if (code)
			{
			}

			if (!noout)
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
