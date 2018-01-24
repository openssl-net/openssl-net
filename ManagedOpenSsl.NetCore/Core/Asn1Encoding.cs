using System;
using System.Runtime.InteropServices;

namespace ManagedOpenSsl.NetCore.Core
{
	
	[StructLayout(LayoutKind.Sequential)]
	internal struct Asn1Encoding
	{
		public IntPtr enc;
		public int len;
		public int modified;
	}
}

