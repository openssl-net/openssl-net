using System;
using System.Collections.Generic;
using System.Text;
using OpenSSL;

namespace test
{
	class TestSHA1 : ICommand
	{
		readonly string[] tests = 
		{
			"abc",
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		};

		readonly string[] results =
		{
			"A9-99-3E-36-47-06-81-6A-BA-3E-25-71-78-50-C2-6C-9C-D0-D8-9D",
			"84-98-3E-44-1C-3B-D2-6E-BA-AE-4A-A1-F9-51-29-E5-E5-46-70-F1",
		};

		const string bigret = "34-AA-97-3C-D4-C4-DA-A4-F6-1E-EB-2B-DB-AD-27-31-65-34-01-6F";

		#region ICommand Members

		public void Execute(string[] args)
		{
			MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA1);

			for (int i = 0; i < tests.Length; i++)
			{
				byte[] msg = Encoding.ASCII.GetBytes(this.tests[i]);
				byte[] ret = ctx.Digest(msg);

				string str = BitConverter.ToString(ret);
				if (str != this.results[i])
				{
					Console.WriteLine("error calculating SHA1 on {0}", this.tests[i]);
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
				Console.WriteLine("error calculating SHA1 'a' * 1000");
				Console.WriteLine("got {0} instead of {1}", strx, bigret);
			}
			else
				Console.WriteLine("test 3 ok");
		}

		#endregion
	}
}
