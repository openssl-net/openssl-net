using System;
using System.Runtime.InteropServices;

namespace OpenSSL
{
	
	[StructLayout(LayoutKind.Sequential)]
	internal struct Asn1Encoding
	{
		public IntPtr enc;
		public int len;
		public int modified;
	}
}

