using System;
using NUnit.Framework;
using OpenSSL.Crypto;
using System.Text;
using System.Reflection;
using OpenSSL.Core;
using System.Collections.Generic;
using System.Collections;
using System.Linq;

namespace UnitTests
{
	[TestFixture]
	public class TestCipher
	{
		static CryptoKey[] Keys;

		static TestCipher()
		{
			const int numKeys = 10;
			Keys = new CryptoKey[numKeys];
			for (int i = 0; i < numKeys; i++)
			{
				using (var rsa = new RSA())
				{
					rsa.GenerateKeys(1024, BigNumber.One, null, null);
					Keys[i] = new CryptoKey(rsa);
				}
			}
		}

		public class WithNullFactory : IEnumerable
		{
			public IEnumerator GetEnumerator()
			{
				var fields = typeof(Cipher).GetFields(BindingFlags.Public | BindingFlags.Static);
				return fields
					.Where(x => x.Name != "DES_EDE3_CFB1")
					.Select(x => new TestCaseData(x.GetValue(null)).SetName(x.Name))
					.GetEnumerator();
			}
		}

		public class Factory : IEnumerable
		{
			public IEnumerator GetEnumerator()
			{
				var fields = typeof(Cipher).GetFields(BindingFlags.Public | BindingFlags.Static);
				return fields
					.Where(x => x.Name != "Null")
					.Where(x => x.Name != "DES_EDE3_CFB1")
					.Select(x => new TestCaseData(x.GetValue(null)).SetName(x.Name))
					.GetEnumerator();
			}
		}

		[Test]
		[TestCaseSource(typeof(WithNullFactory))]
		public void TestEncryptDecrypt(Cipher cipher)
		{
			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);
			var iv = Encoding.ASCII.GetBytes("12345678");
			var key = Encoding.ASCII.GetBytes("This is the key");

			Console.Write("Using cipher {0}: ", cipher.LongName);
			using (var cc = new CipherContext(cipher))
			{
				Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);

				var pt = cc.Encrypt(input, key, iv);
				if (cipher == Cipher.Null)
					Assert.AreEqual(input, pt);
				else
					Assert.AreNotEqual(input, pt);

				var ct = cc.Decrypt(pt, key, iv);
				var msg = Encoding.ASCII.GetString(ct);
				Console.WriteLine("\"{0}\"", msg);
				Assert.AreEqual(inputMsg, msg);
			}
		}

		[Test]
		[TestCaseSource(typeof(Factory))]
		public void TestEncryptDecryptWithSalt(Cipher cipher)
		{
			if (cipher == Cipher.Null)
				Assert.Ignore();

			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);
			var salt = Encoding.ASCII.GetBytes("salt");
			var secret = Encoding.ASCII.GetBytes("Password!");

			Console.Write("Using cipher {0}: ", cipher.LongName);
			using (var cc = new CipherContext(cipher))
			{
				Console.Write(" KeyLength: {0}, IVLength: {1}, BlockSize: {2}, Stream: {3} ",
					cipher.KeyLength, cipher.IVLength, cipher.BlockSize, cc.IsStream);
				byte[] iv;
				var key = cc.BytesToKey(MessageDigest.SHA1, salt, secret, 1, out iv);

				var pt = cc.Encrypt(input, key, iv);
				Assert.AreNotEqual(input, pt);

				var ct = cc.Decrypt(pt, key, iv);
				var msg = Encoding.ASCII.GetString(ct);
				Console.WriteLine("\"{0}\"", msg);
				Assert.AreEqual(inputMsg, msg);
			}
		}

		[Test]
		[TestCaseSource(typeof(Factory))]
		public void TestSealOpen(Cipher cipher)
		{
			if (cipher == Cipher.Null)
				Assert.Ignore();

			var inputMsg = "This is a message";
			var input = Encoding.ASCII.GetBytes(inputMsg);

			using (var cc = new CipherContext(cipher))
			{
				var env = cc.Seal(Keys, input);
				Assert.AreNotEqual(input, env.Data);

				for (int i = 0; i < Keys.Length; i++)
				{
					var result = cc.Open(env.Data, env.Keys[i], env.IV, Keys[i]);
					Assert.AreEqual(input, result);
				}
			}
		}
	}
}


