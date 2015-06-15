using System;
using NUnit.Framework;
using OpenSSL.Core;
using Version = OpenSSL.Core.Version;

namespace UnitTests
{
	[TestFixture]
	public class TestVersion
	{
		[Test]
		public void Zero()
		{
			var version = new Version(0x00000000);
			Assert.AreEqual(0, version.Major);
			Assert.AreEqual(0, version.Minor);
			Assert.AreEqual(0, version.Fix);
			Assert.AreEqual(null, version.Patch);
			Assert.AreEqual(Version.StatusType.Development, version.Status);
			Assert.AreEqual(0, version.Raw);
			Assert.AreEqual("0.0.0 Development (0x00000000)", version.ToString());
		}

		[Test]
		public void Basic1()
		{
			var version = new Version(0x102031af);
			Assert.AreEqual(1, version.Major);
			Assert.AreEqual(2, version.Minor);
			Assert.AreEqual(3, version.Fix);
			Assert.AreEqual('z', version.Patch);
			Assert.AreEqual(Version.StatusType.Release, version.Status);
			Assert.AreEqual(0x102031af, version.Raw);
			Assert.AreEqual("1.2.3z Release (0x102031af)", version.ToString());
		}

		[Test]
		public void Basic2()
		{
			var version = new Version(0x1000200f);
			Assert.AreEqual(1, version.Major);
			Assert.AreEqual(0, version.Minor);
			Assert.AreEqual(2, version.Fix);
			Assert.AreEqual(null, version.Patch);
			Assert.AreEqual(Version.StatusType.Release, version.Status);
			Assert.AreEqual(0x1000200f, version.Raw);
			Assert.AreEqual("1.0.2 Release (0x1000200f)", version.ToString());
		}

		[Test]
		public void Basic3()
		{
			var version = new Version(0x1000201f);
			Assert.AreEqual(1, version.Major);
			Assert.AreEqual(0, version.Minor);
			Assert.AreEqual(2, version.Fix);
			Assert.AreEqual('a', version.Patch);
			Assert.AreEqual(Version.StatusType.Release, version.Status);
			Assert.AreEqual(0x1000201f, version.Raw);
			Assert.AreEqual("1.0.2a Release (0x1000201f)", version.ToString());
		}
	}
}
