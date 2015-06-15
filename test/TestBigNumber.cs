using System;
using OpenSSL.Core;
using NUnit.Framework;

namespace UnitTests
{
	[TestFixture]
	public class TestBigNumber
	{
		[Test]
		public void Basic()
		{
			Console.WriteLine(BigNumber.Options);
		}
	}
}

