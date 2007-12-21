using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace OpenSSL.CLI
{
	class CmdGenRSA : ICommand
	{
		OptionParser options = new OptionParser();

		public CmdGenRSA()
		{
			options.AddOption("-des", new Option("des", false));
			options.AddOption("-des3", new Option("des3", false));
			options.AddOption("-idea", new Option("idea", false));
			options.AddOption("-aes128", new Option("aes128", false));
			options.AddOption("-aes192", new Option("aes192", false));
			options.AddOption("-aes256", new Option("aes256", false));
			options.AddOption("-out", new Option("out", ""));
			options.AddOption("-passout", new Option("passout", ""));
			options.AddOption("-f4", new Option("f4", true));
			options.AddOption("-3", new Option("3", false));
			options.AddOption("-engine", new Option("engine", ""));
			options.AddOption("-rand", new Option("rand", ""));
		}

		void Usage()
		{
			Console.WriteLine(
@"usage: genrsa [args] [numbits]
 -des            encrypt the generated key with DES in cbc mode
 -des3           encrypt the generated key with DES in ede cbc mode (168 bit key)
 -idea           encrypt the generated key with IDEA in cbc mode
 -aes128, -aes192, -aes256
                 encrypt PEM output with cbc aes
 -out file       output the key to 'file
 -passout arg    output file pass phrase source
 -f4             use F4 (0x10001) for the E value
 -3              use 3 for the E value
 -engine e       use engine e, possibly a hardware device.
 -rand file;file;...
                 load the file (or the files in the directory) into
                 the random number generator");
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

			int bits = 512;
			if (this.options.Arguments.Count == 1)
				bits = Convert.ToInt32(this.options.Arguments[0]);

			BigNumber e = null;
			if (options.IsSet("3"))
				e = 3;
			else if (options.IsSet("f4"))
				e = 0x10001;

			Console.WriteLine("Generating RSA private key, {0} bit long modulus", bits);

			RSA rsa = new RSA();
			rsa.GenerateKeys(bits, e, Program.OnGenerator, null);

			Console.WriteLine("e is {0} (0x{1})", e.ToDecimalString(), e.ToHexString());

			Cipher enc = null;
			if (options.IsSet("des"))
				enc = Cipher.DES_CBC;
			else if (options.IsSet("des3"))
				enc = Cipher.DES_EDE3_CBC;
			else if (options.IsSet("idea"))
				enc = Cipher.Idea_CBC;
			else if (options.IsSet("aes128"))
				enc = Cipher.AES_128_CBC;
			else if (options.IsSet("aes192"))
				enc = Cipher.AES_192_CBC;
			else if (options.IsSet("aes256"))
				enc = Cipher.AES_256_CBC;

			using (BIO bio = BIO.MemoryBuffer())
			{
				rsa.WritePrivateKey(bio, enc, Program.OnPassword, null);
				string str = bio.ReadString();
				Console.WriteLine(str);
			}
		}

		#endregion
	}
}
