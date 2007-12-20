using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

namespace test
{
	class TestSHA : ICommand
	{
		readonly string[] tests = 
		{
			"abc",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		};

		readonly string[] results =
		{
			"01-64-B8-A9-14-CD-2A-5E-74-C4-F7-FF-08-2C-4D-97-F1-ED-F8-80",
			"D2-51-6E-E1-AC-FA-5B-AF-33-DF-C1-C4-71-E4-38-44-9E-F1-34-C8",
		};

		const string bigret = "32-32-AF-FA-48-62-8A-26-65-3B-5A-AA-44-54-1F-D9-0D-69-06-03";
		#region ICommand Members

		public void Execute(string[] args)
		{
			MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA);

			for (int i = 0; i < tests.Length; i++)
			{
				byte[] msg = Encoding.ASCII.GetBytes(this.tests[i]);
				byte[] ret = ctx.Digest(msg);

				string str = BitConverter.ToString(ret);
				if (str != this.results[i])
				{
					Console.WriteLine("error calculating SHA on {0}", this.tests[i]);
					Console.WriteLine("got {0} instead of {1}", str, this.results[i]);
				}
				else
					Console.WriteLine("test {0} ok", i);
			}

			byte[] buf = Encoding.ASCII.GetBytes(new string('a', 1000));
			ctx.Init();
			for (int i = 0; i < 1000; i++)
			{
				ctx.Update(buf);
			}

			byte[] retx = ctx.DigestFinal();
			string strx = BitConverter.ToString(retx);
			if (strx != bigret)
			{
				Console.WriteLine("error calculating SHA 'a' * 1000");
				Console.WriteLine("got {0} instead of {1}", strx, bigret);
			}
			else
				Console.WriteLine("test 3 ok");
		}

		#endregion
	}
}
