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
using System.Reflection;
using System.Security.Permissions;
using System.IO;

namespace OpenSSL.CLI
{
	class CmdDH : ICommand
	{
		OptionParser options = new OptionParser();
		public CmdDH()
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
			Console.WriteLine(" -C            output C# code");
			Console.WriteLine(" -noout        no output");
			Console.WriteLine(" -engine e     use engine e, possibly a hardware device.");
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

			string infile = this.options.GetString("infile");
			BIO bin;
			if (string.IsNullOrEmpty(infile))
			{
				bin = BIO.MemoryBuffer();
				Stream cin = Console.OpenStandardInput();
				byte[] buf = new byte[1024];
				while (true)
				{
					int len = cin.Read(buf, 0, buf.Length);
					if (len == 0)
						break;
					bin.Write(buf, len);
				}
			}
			else
				bin = BIO.File(infile, "r");

			OpenSSL.DH dh;
			string inform = this.options["inform"] as string;
			if (inform == "PEM")
				dh = OpenSSL.DH.FromParametersPEM(bin);
			else if (inform == "DER")
				dh = OpenSSL.DH.FromParametersDER(bin);
			else
			{
				Usage();
				return;
			}
			
			if (this.options.IsSet("text"))
			{
				Console.WriteLine(dh);
			}

			if (this.options.IsSet("check"))
			{
				Console.WriteLine("-check is currently not implemented.");
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
			}

			if (this.options.IsSet("code"))
			{
				Console.WriteLine("-code is currently not implemented.");
			}

			if (!this.options.IsSet("noout"))
			{
				string outfile = this.options["outfile"] as string;
				BIO bout;
				bool outmem = false;
				if (string.IsNullOrEmpty(outfile))
				{
					bout = BIO.MemoryBuffer();
					outmem = true;
				}
				else
					bout = BIO.File(outfile, "w");

				string outform = this.options["outform"] as string;
				if (outform == "DER")
					dh.WriteParametersDER(bout);
				else if (outform == "PEM")
					dh.WriteParametersPEM(bout);
				else
				{
					Usage();
					return;
				}

				if (outmem)
				{
					Stream cout = Console.OpenStandardOutput();
					ArraySegment<byte> segment = bout.ReadBytes((int)bout.NumberWritten);
					cout.Write(segment.Array, segment.Offset, segment.Count);
				}
			}
		}
		#endregion
	}
}
