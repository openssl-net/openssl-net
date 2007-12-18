using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;
using System.Runtime.InteropServices;
using System.IO;

namespace test
{
	class TestDH : ICommand
	{
		const string rnd_seed = "string to make the random number generator think it has entropy";

		#region ICommand Members

		public void Execute(string[] args)
		{
			Native.CRYPTO_malloc_debug_init();
			Native.CRYPTO_dbg_set_options(Native.V_CRYPTO_MDEBUG_ALL);
			Native.CRYPTO_mem_ctrl(Native.CRYPTO_MEM_CHECK_ON);

			byte[] seed = Encoding.ASCII.GetBytes(rnd_seed);
			Native.RAND_seed(seed, seed.Length);

			BigNumber.GeneratorHandler cb = new BigNumber.GeneratorHandler(this.OnStatus);
			DH a = new DH(64, DH.Generator5, cb, Console.Out);

			DH.CheckCode check = a.Check();
			if ((check & DH.CheckCode.CheckP_NotPrime) != 0)
				Console.WriteLine("p value is not prime");
			if ((check & DH.CheckCode.CheckP_NotSafePrime) != 0)
				Console.WriteLine("p value is not safe prime");
			if ((check & DH.CheckCode.UnableToCheckGenerator) != 0)
				Console.WriteLine("unable to check the generator value");
			if ((check & DH.CheckCode.NotSuitableGenerator) != 0)
				Console.WriteLine("the g value is not a generator");

			Console.WriteLine();
			Console.WriteLine("p    ={0}", a.P);
			Console.WriteLine("g    ={0}", a.G);

			DH b = new DH();

			b.P = a.P;
			b.G = a.G;

			a.ConstantTime = false;
			b.ConstantTime = true;

			a.GenerateKeys();
			Console.WriteLine("pri 1={0}", a.PrivateKey);
			Console.WriteLine("pub 1={0}", a.PublicKey);

			b.GenerateKeys();
			Console.WriteLine("pri 2={0}", b.PrivateKey);
			Console.WriteLine("pub 2={0}", b.PublicKey);

			byte[] aout = a.ComputeKey(b.PublicKey);
			string astr = BitConverter.ToString(aout);
			Console.WriteLine("key1 ={0}", astr);

			byte[] bout = b.ComputeKey(a.PublicKey);
			string bstr = BitConverter.ToString(bout);
			Console.WriteLine("key2 ={0}", bstr);

			if (aout.Length < 4 || astr != bstr)
			{
				throw new Exception("Error in DH routines");
			}
		}

		#endregion

		private int OnStatus(int p, int n, object arg)
		{
			TextWriter cout = (TextWriter)arg;

			switch (p)
			{
				case 0: cout.Write('.'); break;
				case 1: cout.Write('+'); break;
				case 2: cout.Write('*'); break;
				case 3: cout.WriteLine(); break;
			}

			return 1;
		}
	}
}
