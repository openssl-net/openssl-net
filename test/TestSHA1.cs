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
			"a9-99-3e-36-47-06-81-6a-ba-3e-25-71-78-50-c2-6c-9c-d0-d8-9d",
			"84-98-3e-44-1c-3b-d2-6e-ba-ae-4a-a1-f9-51-29-e5-e5-46-70-f1",
		};

		const string bigret = "34-aa-97-3c-d4-c4-da-a4-f6-1e-eb-2b-db-ad-27-31-65-34-01-6f";

		#region ICommand Members

		public void Execute(string[] args)
		{
			MessageDigestContext ctx = new MessageDigestContext(MessageDigest.SHA1);

			for (int i = 0; i < tests.Length; i++)
			{
				byte[] msg = Encoding.ASCII.GetBytes(this.tests[i]);
				byte[] ret = ctx.Digest(msg);

				string str = BitConverter.ToString(ret);
				if (str.ToUpper() != this.results[i].ToUpper())
				{
					Console.WriteLine("error calculating SHA1 on {0}", this.tests[i]);
					Console.WriteLine("got {0} instead of {1}", str, this.results[i].ToUpper());
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
			if (strx.ToUpper() != bigret.ToUpper())
			{
				Console.WriteLine("error calculating SHA1 'a' * 1000");
				Console.WriteLine("got {0} instead of {1}", strx, bigret.ToUpper());
			}
			else
				Console.WriteLine("test 3 ok");
		}

		#endregion
	}
}
