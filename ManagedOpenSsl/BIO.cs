using System;
using System.Collections.Generic;
using System.Text;

namespace OpenSSL
{
	public class BIO : Base, IDisposable
	{
		#region Initialization
		internal BIO(IntPtr ptr) : base(ptr) {}

		public BIO(byte[] buf) 
			: base(Native.ExpectNonNull(Native.BIO_new_mem_buf(buf, buf.Length)))
		{
		}

		public BIO(string str)
			: this(Encoding.ASCII.GetBytes(str))
		{
		}

		public static BIO MemoryBuffer()
		{
			IntPtr ptr = Native.ExpectNonNull(Native.BIO_new(Native.BIO_s_mem()));
			return new BIO(ptr);
		}

		public static BIO File(string filename, string mode)
		{
			byte[] bufFilename = Encoding.ASCII.GetBytes(filename);
			byte[] bufMode = Encoding.ASCII.GetBytes(mode);
			IntPtr ptr = Native.ExpectNonNull(Native.BIO_new_file(bufFilename, bufMode));
			return new BIO(ptr);
		}
		#endregion

		#region Methods
		public void Write(byte[] buf)
		{
			if (Native.BIO_write(this.ptr, buf, buf.Length) != buf.Length)
				throw new OpenSslException();
		}

		public void Write(string str)
		{
			byte[] buf = Encoding.ASCII.GetBytes(str);
			if (Native.BIO_puts(this.ptr, buf) != buf.Length)
				throw new OpenSslException();
		}

		public ArraySegment<byte> ReadBytes(int count)
		{
			byte[] buf = new byte[count];
			int ret = Native.BIO_read(this.ptr, buf, buf.Length);
			if (ret <= 0)
				throw new OpenSslException();

			return new ArraySegment<byte>(buf, 0, ret);
		}

		public string ReadString()
		{
			StringBuilder sb = new StringBuilder();
			const int BLOCK_SIZE = 64;
			byte[] buf = new byte[BLOCK_SIZE];
			int ret = 0;
			while(true)
			{
				ret = Native.BIO_gets(this.ptr, buf, buf.Length);
				if (ret == 0)
					break;
				if (ret < 0)
					throw new OpenSslException();

				sb.Append(Encoding.ASCII.GetString(buf, 0, ret));
			}
			return sb.ToString();
		}
		#endregion

		#region IDisposable Members

		public void Dispose()
		{
			Native.BIO_free(this.ptr);
		}

		#endregion
	}
}
